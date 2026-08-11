use std::collections::VecDeque;
use std::fmt;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicU8, Ordering};
use std::sync::{Arc, Mutex as StdMutex, Weak};
use std::time::{Duration, Instant};

use chrono::{DateTime, Utc};
use dashmap::DashMap;
use rvoip_core::broadcast::{
    BroadcastDrainReason, BroadcastDrainRequest, BroadcastEndpoint, BroadcastHealthDescriptor,
    BroadcastHealthIssue, BroadcastHealthStatus, BroadcastLifecycleDescriptor,
    BroadcastLifecycleState, BroadcastProtocolDescriptor, BroadcastProtocolFamily,
    BroadcastPublisher, BroadcastResource, BroadcastSubstrate,
};
use rvoip_core::capability::default_audio_codec;
use rvoip_core::events::Event;
use rvoip_core::ids::{ConnectionId, SessionId, StreamId};
use rvoip_core::media_graph::{
    ManagedMediaRoute, MediaGraphHandle, MediaGraphRouteState, MediaGraphRouteStatus,
};
use rvoip_core::{ManagedVirtualPublisher, Orchestrator, VirtualPublisherDescriptor};
use rvoip_moq::{MoqBroadcastPublisher, MoqPublisherConfig, MoqRelayClient, MoqRelayPublication};
use serde::Serialize;
use tokio::sync::Mutex;
use url::Url;

use super::context_events::SanitizedContextEventPolicy;
use super::token::{
    BroadcastGrantLease, BroadcastGrantRegistry, BroadcastGrantTransport, BroadcastTokenError,
};
use super::{RedisBroadcastGrantLease, RedisBroadcastGrantStore};

pub const MAX_DIRECT_UCTP_SUBSCRIBERS: usize = 1_000;
const UCTP_STREAM_ID: &str = "audio/main";
const UCTP_TRANSPORT_VERSION: &str = "uctp/0.2";
const UCTP_MEDIA_PROFILE: &str = "rtp-datagram/1";
const STATE_READY: u8 = 0;
const STATE_DRAINING: u8 = 1;
const STATE_CLOSED: u8 = 2;
const STATE_FAILED: u8 = 3;
const EVENT_REPLAY_WINDOW_MESSAGES: usize = 1_024;

#[derive(Clone)]
pub struct MoqRelayTarget {
    pub client: MoqRelayClient,
    /// Private publisher-facing mTLS ingress used by the worker origin.
    pub publisher_endpoint: Url,
    /// Public receive-only listener advertised to subscribers.
    pub subscriber_endpoint: Url,
}

impl fmt::Debug for MoqRelayTarget {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MoqRelayTarget")
            .field(
                "publisher_endpoint_scheme",
                &self.publisher_endpoint.scheme(),
            )
            .field(
                "subscriber_endpoint_scheme",
                &self.subscriber_endpoint.scheme(),
            )
            .finish()
    }
}

#[derive(Clone)]
pub enum ManagedBroadcastTransport {
    UctpQuic {
        endpoint: Url,
    },
    Moqt {
        publisher: MoqPublisherConfig,
        relay: Option<Box<MoqRelayTarget>>,
        /// Explicit per-broadcast opt-in. `None` creates no catalog event
        /// track and registers no context event route.
        sanitized_events: Option<ManagedSanitizedEventBinding>,
    },
}

impl fmt::Debug for ManagedBroadcastTransport {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UctpQuic { endpoint } => formatter
                .debug_struct("UctpQuic")
                .field("endpoint_scheme", &endpoint.scheme())
                .field("endpoint_has_host", &endpoint.host_str().is_some())
                .finish(),
            Self::Moqt {
                relay,
                sanitized_events,
                ..
            } => formatter
                .debug_struct("Moqt")
                .field("relay_configured", &relay.is_some())
                .field("sanitized_events_enabled", &sanitized_events.is_some())
                .finish(),
        }
    }
}

/// Exact authenticated call source allowed to emit fixed sanitized events.
#[derive(Clone, Eq, PartialEq)]
pub struct ManagedSanitizedEventBinding {
    call_id: String,
    source_leg_id: String,
    policy: SanitizedContextEventPolicy,
}

impl fmt::Debug for ManagedSanitizedEventBinding {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ManagedSanitizedEventBinding")
            .field("call_id_present", &!self.call_id.is_empty())
            .field("source_leg_id_present", &!self.source_leg_id.is_empty())
            .field("policy_configured", &true)
            .finish()
    }
}

impl ManagedSanitizedEventBinding {
    pub fn new(
        call_id: impl Into<String>,
        source_leg_id: impl Into<String>,
        policy: SanitizedContextEventPolicy,
    ) -> Result<Self, ManagedBroadcastError> {
        let call_id = call_id.into();
        let source_leg_id = source_leg_id.into();
        if !valid_context_identifier(&call_id) || !valid_context_identifier(&source_leg_id) {
            return Err(ManagedBroadcastError::InvalidConfiguration(
                "sanitized event call and source leg identifiers must be bounded and safe",
            ));
        }
        Ok(Self {
            call_id,
            source_leg_id,
            policy,
        })
    }
}

fn valid_context_identifier(value: &str) -> bool {
    !value.is_empty() && value.len() <= 512 && !value.contains(['\r', '\n', '\0'])
}

#[derive(Clone)]
pub struct ManagedBroadcastService {
    orchestrator: Arc<Orchestrator>,
    grants: BroadcastGrantRegistry,
    shared_grants: Option<Arc<RedisBroadcastGrantStore>>,
    max_direct_uctp_subscribers: usize,
    sanitized_event_router: Arc<SanitizedEventRouter>,
}

impl fmt::Debug for ManagedBroadcastService {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ManagedBroadcastService")
            .field("grants", &self.grants)
            .field("shared_grants", &self.shared_grants.is_some())
            .field(
                "max_direct_uctp_subscribers",
                &self.max_direct_uctp_subscribers,
            )
            .field(
                "sanitized_event_routes",
                &self.sanitized_event_router.route_count(),
            )
            .finish_non_exhaustive()
    }
}

impl ManagedBroadcastService {
    pub fn new(
        orchestrator: Arc<Orchestrator>,
        grants: BroadcastGrantRegistry,
        max_direct_uctp_subscribers: usize,
    ) -> Result<Self, ManagedBroadcastError> {
        if max_direct_uctp_subscribers == 0
            || max_direct_uctp_subscribers > MAX_DIRECT_UCTP_SUBSCRIBERS
        {
            return Err(ManagedBroadcastError::InvalidConfiguration(
                "direct UCTP subscriber limit must be between 1 and 1000",
            ));
        }
        Ok(Self {
            sanitized_event_router: SanitizedEventRouter::start(&orchestrator),
            orchestrator,
            grants,
            shared_grants: None,
            max_direct_uctp_subscribers,
        })
    }

    pub fn with_shared_grants(
        orchestrator: Arc<Orchestrator>,
        grants: BroadcastGrantRegistry,
        shared_grants: Arc<RedisBroadcastGrantStore>,
        max_direct_uctp_subscribers: usize,
    ) -> Result<Self, ManagedBroadcastError> {
        let mut service = Self::new(orchestrator, grants, max_direct_uctp_subscribers)?;
        service.shared_grants = Some(shared_grants);
        Ok(service)
    }

    pub fn grants(&self) -> BroadcastGrantRegistry {
        self.grants.clone()
    }

    /// Aggregate route count for readiness/cleanup diagnostics. It never
    /// exposes tenant, call, leg, connection, or message identifiers.
    pub fn sanitized_event_route_count(&self) -> usize {
        self.sanitized_event_router.route_count()
    }

    pub async fn start(
        &self,
        tenant_id: impl Into<String>,
        broadcast_id: impl Into<String>,
        source_connection_id: ConnectionId,
        expires_at: DateTime<Utc>,
        transport: ManagedBroadcastTransport,
    ) -> Result<Arc<ManagedBroadcast>, ManagedBroadcastError> {
        let tenant_id = tenant_id.into();
        let broadcast_id = broadcast_id.into();
        if let ManagedBroadcastTransport::UctpQuic { endpoint } = &transport {
            validate_uctp_endpoint(endpoint)?;
        }
        let grant_transport = match transport {
            ManagedBroadcastTransport::UctpQuic { .. } => BroadcastGrantTransport::UctpQuic,
            ManagedBroadcastTransport::Moqt { .. } => BroadcastGrantTransport::Moqt,
        };
        let grant = self.grants.register(
            tenant_id.clone(),
            broadcast_id.clone(),
            grant_transport,
            expires_at,
        )?;
        let shared_grant = match &self.shared_grants {
            Some(store) => match store
                .register(
                    tenant_id.clone(),
                    broadcast_id.clone(),
                    grant_transport,
                    expires_at,
                )
                .await
            {
                Ok(grant) => Some(grant),
                Err(error) => {
                    drop(grant);
                    return Err(error.into());
                }
            },
            None => None,
        };
        let graph = match self
            .orchestrator
            .media_graph_for_connection(source_connection_id.clone())
            .await
        {
            Ok(graph) => graph,
            Err(error) => {
                drop(grant);
                drop(shared_grant);
                return Err(error.into());
            }
        };

        let created_at = Utc::now();
        let result = match transport {
            ManagedBroadcastTransport::UctpQuic { endpoint } => {
                self.start_uctp(
                    tenant_id,
                    broadcast_id,
                    source_connection_id,
                    expires_at,
                    created_at,
                    endpoint,
                    graph,
                    grant,
                    shared_grant,
                )
                .await
            }
            ManagedBroadcastTransport::Moqt {
                mut publisher,
                relay,
                sanitized_events,
            } => {
                if publisher.tenant_id != tenant_id || publisher.broadcast_id != broadcast_id {
                    drop(grant);
                    return Err(ManagedBroadcastError::InvalidConfiguration(
                        "MOQT publisher namespace does not match the managed broadcast",
                    ));
                }
                publisher.queue_frames = publisher.queue_frames.clamp(1, 10);
                self.start_moq(
                    tenant_id,
                    broadcast_id,
                    source_connection_id,
                    expires_at,
                    created_at,
                    publisher,
                    relay,
                    sanitized_events,
                    graph,
                    grant,
                    shared_grant,
                )
                .await
            }
        };
        let managed = result?;
        ManagedBroadcast::arm_expiry(&managed);
        Ok(managed)
    }

    #[allow(clippy::too_many_arguments)]
    async fn start_uctp(
        &self,
        tenant_id: String,
        broadcast_id: String,
        source_connection_id: ConnectionId,
        expires_at: DateTime<Utc>,
        created_at: DateTime<Utc>,
        endpoint: Url,
        graph: MediaGraphHandle,
        grant: BroadcastGrantLease,
        shared_grant: Option<RedisBroadcastGrantLease>,
    ) -> Result<Arc<ManagedBroadcast>, ManagedBroadcastError> {
        validate_uctp_endpoint(&endpoint)?;
        let descriptor = VirtualPublisherDescriptor::new(
            SessionId::from_string(broadcast_id.clone()),
            StreamId::from_string(UCTP_STREAM_ID),
            format!("bridgefu-broadcast-{broadcast_id}"),
        );
        let publisher = self
            .orchestrator
            .register_virtual_publisher_with_codec(
                source_connection_id.clone(),
                descriptor.clone(),
                default_audio_codec(),
            )
            .await?;
        let route_status = publisher.route_status();
        let endpoint = BroadcastEndpoint {
            uri: Some(endpoint.to_string()),
            resource: BroadcastResource::Uctp {
                session_id: descriptor.session_id.to_string(),
                stream_id: descriptor.stream_id.to_string(),
            },
            relay_path: Vec::new(),
        };
        Ok(Arc::new(ManagedBroadcast {
            tenant_id,
            broadcast_id,
            source_connection_id,
            expires_at,
            created_at,
            graph,
            orchestrator: Arc::clone(&self.orchestrator),
            max_direct_uctp_subscribers: self.max_direct_uctp_subscribers,
            sanitized_event_binding: None,
            sanitized_event_router: Arc::clone(&self.sanitized_event_router),
            sanitized_event_route_registered: AtomicBool::new(false),
            sanitized_event_admission: StdMutex::new(SanitizedEventAdmission::new()),
            sanitized_event_counters: SanitizedEventCounters::default(),
            runtime: ManagedBroadcastRuntime::Uctp {
                descriptor,
                endpoint: Box::new(endpoint),
                route_status,
            },
            resources: Mutex::new(Some(ManagedBroadcastResources {
                grant,
                shared_grant,
                transport: ManagedTransportResources::Uctp { publisher },
            })),
            state: AtomicU8::new(STATE_READY),
            terminal: tokio::sync::Notify::new(),
            expiry_task: StdMutex::new(None),
        }))
    }

    #[allow(clippy::too_many_arguments)]
    async fn start_moq(
        &self,
        tenant_id: String,
        broadcast_id: String,
        source_connection_id: ConnectionId,
        expires_at: DateTime<Utc>,
        created_at: DateTime<Utc>,
        publisher_config: MoqPublisherConfig,
        relay_target: Option<Box<MoqRelayTarget>>,
        sanitized_events: Option<ManagedSanitizedEventBinding>,
        graph: MediaGraphHandle,
        grant: BroadcastGrantLease,
        shared_grant: Option<RedisBroadcastGrantLease>,
    ) -> Result<Arc<ManagedBroadcast>, ManagedBroadcastError> {
        let publisher = match sanitized_events.as_ref() {
            Some(binding) => MoqBroadcastPublisher::new_with_sanitized_events(
                publisher_config,
                binding.policy.moq_config().map_err(|_| {
                    ManagedBroadcastError::InvalidConfiguration(
                        "sanitized event queue or history configuration is invalid",
                    )
                })?,
            )?,
            None => MoqBroadcastPublisher::new(publisher_config)?,
        };
        let route = graph.add_managed_sink(publisher.codec(), publisher.frames_out())?;
        if let Err(reason) = route.wait_active().await {
            drop(route);
            let _ = publisher.clone().close().await;
            return Err(ManagedBroadcastError::RouteTerminated(reason));
        }
        let route_status = route.status();
        let (relay, subscriber_endpoint) = if let Some(target) = relay_target {
            match publisher
                .publish_to_relay(&target.client, &target.publisher_endpoint)
                .await
            {
                Ok(relay) => (Some(relay), Some(target.subscriber_endpoint.clone())),
                Err(error) => {
                    let _ = route.remove().await;
                    let _ = publisher.clone().close().await;
                    return Err(error.into());
                }
            }
        } else {
            (None, None)
        };
        let managed = Arc::new(ManagedBroadcast {
            tenant_id,
            broadcast_id,
            source_connection_id,
            expires_at,
            created_at,
            graph,
            orchestrator: Arc::clone(&self.orchestrator),
            max_direct_uctp_subscribers: self.max_direct_uctp_subscribers,
            sanitized_event_binding: sanitized_events,
            sanitized_event_router: Arc::clone(&self.sanitized_event_router),
            sanitized_event_route_registered: AtomicBool::new(false),
            sanitized_event_admission: StdMutex::new(SanitizedEventAdmission::new()),
            sanitized_event_counters: SanitizedEventCounters::default(),
            runtime: ManagedBroadcastRuntime::Moq {
                publisher: Arc::clone(&publisher),
                route_status,
                subscriber_endpoint,
            },
            resources: Mutex::new(Some(ManagedBroadcastResources {
                grant,
                shared_grant,
                transport: ManagedTransportResources::Moq {
                    publisher,
                    route,
                    _relay: relay,
                },
            })),
            state: AtomicU8::new(STATE_READY),
            terminal: tokio::sync::Notify::new(),
            expiry_task: StdMutex::new(None),
        });
        if managed.sanitized_event_binding.is_some() {
            self.sanitized_event_router.register(&managed);
            managed
                .sanitized_event_route_registered
                .store(true, Ordering::Release);
        }
        Ok(managed)
    }
}

fn validate_uctp_endpoint(endpoint: &Url) -> Result<(), ManagedBroadcastError> {
    if endpoint.scheme() != "uctp+quic"
        || endpoint.host_str().is_none()
        || endpoint.port().is_none()
        || !endpoint.username().is_empty()
        || endpoint.password().is_some()
        || endpoint.path() != ""
        || endpoint.query().is_some()
        || endpoint.fragment().is_some()
    {
        Err(ManagedBroadcastError::InvalidConfiguration(
            "UCTP endpoint must be a credential-free uctp+quic://host:port authority",
        ))
    } else {
        Ok(())
    }
}

#[derive(Clone)]
struct SanitizedEventRoute {
    broadcast_id: String,
    broadcast: Weak<ManagedBroadcast>,
}

struct SanitizedEventRouter {
    routes: Arc<DashMap<ConnectionId, Vec<SanitizedEventRoute>>>,
    task: tokio::task::AbortHandle,
}

impl SanitizedEventRouter {
    fn start(orchestrator: &Arc<Orchestrator>) -> Arc<Self> {
        let routes = Arc::new(DashMap::<ConnectionId, Vec<SanitizedEventRoute>>::new());
        let task_routes = Arc::clone(&routes);
        let mut events = orchestrator.subscribe_events();
        let task = tokio::spawn(async move {
            loop {
                let event = match events.recv().await {
                    Ok(event) => event,
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {
                        metrics::counter!(
                            "bridgefu_sanitized_broadcast_events_total",
                            "result" => "dropped",
                            "reason" => "router_lagged"
                        )
                        .increment(1);
                        continue;
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                };
                let Event::DataMessageReceived {
                    connection_id,
                    message,
                    at,
                } = event
                else {
                    continue;
                };
                let candidates = task_routes
                    .get(&connection_id)
                    .map(|routes| routes.value().clone())
                    .unwrap_or_default();
                let mut saw_dead = false;
                for route in candidates {
                    if let Some(broadcast) = route.broadcast.upgrade() {
                        broadcast.try_publish_context_event(&message, at);
                    } else {
                        saw_dead = true;
                    }
                }
                if saw_dead {
                    prune_dead_event_routes(&task_routes, &connection_id);
                }
            }
        });
        Arc::new(Self {
            routes,
            task: task.abort_handle(),
        })
    }

    fn register(&self, broadcast: &Arc<ManagedBroadcast>) {
        let route = SanitizedEventRoute {
            broadcast_id: broadcast.broadcast_id.clone(),
            broadcast: Arc::downgrade(broadcast),
        };
        self.routes
            .entry(broadcast.source_connection_id.clone())
            .or_default()
            .push(route);
    }

    fn unregister(&self, connection_id: &ConnectionId, broadcast_id: &str) {
        let empty = self
            .routes
            .get_mut(connection_id)
            .is_some_and(|mut routes| {
                routes.retain(|route| {
                    route.broadcast_id != broadcast_id && route.broadcast.strong_count() > 0
                });
                routes.is_empty()
            });
        if empty {
            self.routes
                .remove_if(connection_id, |_, routes| routes.is_empty());
        }
    }

    fn route_count(&self) -> usize {
        self.routes.iter().map(|entry| entry.value().len()).sum()
    }
}

impl Drop for SanitizedEventRouter {
    fn drop(&mut self) {
        self.task.abort();
        self.routes.clear();
    }
}

fn prune_dead_event_routes(
    routes: &DashMap<ConnectionId, Vec<SanitizedEventRoute>>,
    connection_id: &ConnectionId,
) {
    let empty = routes.get_mut(connection_id).is_some_and(|mut routes| {
        routes.retain(|route| route.broadcast.strong_count() > 0);
        routes.is_empty()
    });
    if empty {
        routes.remove_if(connection_id, |_, routes| routes.is_empty());
    }
}

enum ManagedBroadcastRuntime {
    Uctp {
        descriptor: VirtualPublisherDescriptor,
        endpoint: Box<BroadcastEndpoint>,
        route_status: MediaGraphRouteStatus,
    },
    Moq {
        publisher: Arc<MoqBroadcastPublisher>,
        route_status: MediaGraphRouteStatus,
        subscriber_endpoint: Option<Url>,
    },
}

struct ManagedBroadcastResources {
    grant: BroadcastGrantLease,
    shared_grant: Option<RedisBroadcastGrantLease>,
    transport: ManagedTransportResources,
}

enum ManagedTransportResources {
    Uctp {
        publisher: ManagedVirtualPublisher,
    },
    Moq {
        publisher: Arc<MoqBroadcastPublisher>,
        route: ManagedMediaRoute,
        _relay: Option<MoqRelayPublication>,
    },
}

pub struct ManagedBroadcast {
    tenant_id: String,
    broadcast_id: String,
    source_connection_id: ConnectionId,
    expires_at: DateTime<Utc>,
    created_at: DateTime<Utc>,
    graph: MediaGraphHandle,
    orchestrator: Arc<Orchestrator>,
    max_direct_uctp_subscribers: usize,
    sanitized_event_binding: Option<ManagedSanitizedEventBinding>,
    sanitized_event_router: Arc<SanitizedEventRouter>,
    sanitized_event_route_registered: AtomicBool,
    sanitized_event_admission: StdMutex<SanitizedEventAdmission>,
    sanitized_event_counters: SanitizedEventCounters,
    runtime: ManagedBroadcastRuntime,
    resources: Mutex<Option<ManagedBroadcastResources>>,
    state: AtomicU8,
    terminal: tokio::sync::Notify,
    expiry_task: StdMutex<Option<tokio::task::AbortHandle>>,
}

impl fmt::Debug for ManagedBroadcast {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ManagedBroadcast")
            .field("transport", &self.transport())
            .field("state", &self.lifecycle().state)
            .field("expires_at", &self.expires_at)
            .finish_non_exhaustive()
    }
}

impl ManagedBroadcast {
    fn arm_expiry(this: &Arc<Self>) {
        let weak = Arc::downgrade(this);
        let delay = (this.expires_at - Utc::now()).to_std().unwrap_or_default();
        let task = tokio::spawn(async move {
            tokio::time::sleep(delay).await;
            if let Some(broadcast) = weak.upgrade() {
                let _ = broadcast.close(BroadcastDrainReason::Shutdown).await;
            }
        });
        *this.expiry_task.lock().expect("expiry task lock") = Some(task.abort_handle());
    }

    pub fn tenant_id(&self) -> &str {
        &self.tenant_id
    }

    pub fn broadcast_id(&self) -> &str {
        &self.broadcast_id
    }

    pub fn source_connection_id(&self) -> &ConnectionId {
        &self.source_connection_id
    }

    pub fn transport(&self) -> BroadcastGrantTransport {
        match self.runtime {
            ManagedBroadcastRuntime::Uctp { .. } => BroadcastGrantTransport::UctpQuic,
            ManagedBroadcastRuntime::Moq { .. } => BroadcastGrantTransport::Moqt,
        }
    }

    pub fn endpoint(&self) -> BroadcastEndpoint {
        match &self.runtime {
            ManagedBroadcastRuntime::Uctp { endpoint, .. } => endpoint.as_ref().clone(),
            ManagedBroadcastRuntime::Moq {
                publisher,
                subscriber_endpoint,
                ..
            } => {
                let mut endpoint = publisher.endpoint();
                if let Some(subscriber_endpoint) = subscriber_endpoint {
                    endpoint.uri = Some(subscriber_endpoint.to_string());
                }
                endpoint
            }
        }
    }

    pub fn protocol(&self) -> BroadcastProtocolDescriptor {
        match &self.runtime {
            ManagedBroadcastRuntime::Uctp { .. } => BroadcastProtocolDescriptor {
                family: BroadcastProtocolFamily::Uctp,
                substrate: Some(BroadcastSubstrate::RawQuic),
                transport_version: UCTP_TRANSPORT_VERSION.into(),
                media_format_version: None,
                object_format_version: None,
                media_profile: Some(UCTP_MEDIA_PROFILE.into()),
            },
            ManagedBroadcastRuntime::Moq { publisher, .. } => publisher.protocol(),
        }
    }

    pub fn lifecycle(&self) -> BroadcastLifecycleDescriptor {
        match self.state.load(Ordering::Acquire) {
            STATE_DRAINING => BroadcastLifecycleDescriptor {
                state: BroadcastLifecycleState::Draining,
                since: None,
            },
            STATE_CLOSED => BroadcastLifecycleDescriptor {
                state: BroadcastLifecycleState::Closed,
                since: None,
            },
            STATE_FAILED => BroadcastLifecycleDescriptor {
                state: BroadcastLifecycleState::Failed,
                since: None,
            },
            _ => match &self.runtime {
                ManagedBroadcastRuntime::Moq { publisher, .. } => publisher.lifecycle(),
                ManagedBroadcastRuntime::Uctp { route_status, .. } => {
                    let state = match route_status.state() {
                        MediaGraphRouteState::Pending => BroadcastLifecycleState::Starting,
                        MediaGraphRouteState::Active => BroadcastLifecycleState::Ready,
                        MediaGraphRouteState::Terminal(_) => BroadcastLifecycleState::Failed,
                    };
                    BroadcastLifecycleDescriptor {
                        state,
                        since: Some(self.created_at),
                    }
                }
            },
        }
    }

    pub fn health(&self) -> BroadcastHealthDescriptor {
        let mut health = match &self.runtime {
            ManagedBroadcastRuntime::Moq { publisher, .. } => publisher.health(),
            ManagedBroadcastRuntime::Uctp {
                descriptor,
                route_status,
                ..
            } => {
                let subscribers = self
                    .orchestrator
                    .subscribers_for(
                        &descriptor.session_id,
                        &self.source_connection_id,
                        &descriptor.stream_id,
                    )
                    .len();
                let (status, issues) =
                    if !matches!(route_status.state(), MediaGraphRouteState::Active) {
                        (
                            BroadcastHealthStatus::Unhealthy,
                            vec![BroadcastHealthIssue::MediaStalled],
                        )
                    } else if subscribers >= self.max_direct_uctp_subscribers {
                        (
                            BroadcastHealthStatus::Degraded,
                            vec![BroadcastHealthIssue::CapacityExhausted],
                        )
                    } else {
                        (BroadcastHealthStatus::Healthy, Vec::new())
                    };
                BroadcastHealthDescriptor {
                    status,
                    issues,
                    active_subscribers: Some(subscribers.min(u32::MAX as usize) as u32),
                    subscriber_capacity: Some(
                        self.max_direct_uctp_subscribers.min(u32::MAX as usize) as u32,
                    ),
                    checked_at: Utc::now(),
                }
            }
        };
        match self.state.load(Ordering::Acquire) {
            STATE_DRAINING => {
                health.status = BroadcastHealthStatus::Degraded;
                if !health.issues.contains(&BroadcastHealthIssue::Draining) {
                    health.issues.push(BroadcastHealthIssue::Draining);
                }
            }
            STATE_CLOSED => {
                health.status = BroadcastHealthStatus::Closed;
                health.issues.clear();
            }
            STATE_FAILED => {
                health.status = BroadcastHealthStatus::Unhealthy;
                if health.issues.is_empty() {
                    health
                        .issues
                        .push(BroadcastHealthIssue::TransportUnavailable);
                }
            }
            _ => {}
        }
        health.checked_at = Utc::now();
        health
    }

    pub fn diagnostics(&self) -> ManagedBroadcastDiagnostics {
        let snapshot = self.graph.latest_snapshot();
        let route_status = match &self.runtime {
            ManagedBroadcastRuntime::Uctp { route_status, .. }
            | ManagedBroadcastRuntime::Moq { route_status, .. } => route_status,
        };
        let sink = snapshot
            .sinks
            .iter()
            .find(|sink| sink.route_id == *route_status.id());
        ManagedBroadcastDiagnostics {
            tenant_id: self.tenant_id.clone(),
            broadcast_id: self.broadcast_id.clone(),
            source_connection_id: self.source_connection_id.to_string(),
            transport: self.transport(),
            endpoint: self.endpoint(),
            protocol: self.protocol(),
            lifecycle: self.lifecycle(),
            health: self.health(),
            expires_at: self.expires_at,
            graph_id: snapshot.graph_id.to_string(),
            route_state: route_status.state(),
            source_frames: snapshot.source_frames,
            graph_dropped_frames: snapshot.dropped_frames,
            graph_evictions: snapshot.evictions,
            transcode_operations: snapshot.transcode_operations,
            route_queue_depth: sink.map(|sink| sink.queue_depth),
            route_queue_capacity: sink.map(|sink| sink.queue_capacity),
            route_offered_frames: sink.map(|sink| sink.offered_frames),
            route_dropped_frames: sink.map(|sink| sink.dropped_frames),
            sanitized_events: self.sanitized_event_diagnostics(),
        }
    }

    fn sanitized_event_diagnostics(&self) -> ManagedSanitizedEventDiagnostics {
        ManagedSanitizedEventDiagnostics {
            enabled: self.sanitized_event_binding.is_some(),
            route_registered: self
                .sanitized_event_route_registered
                .load(Ordering::Acquire),
            received: self
                .sanitized_event_counters
                .received
                .load(Ordering::Relaxed),
            published: self
                .sanitized_event_counters
                .published
                .load(Ordering::Relaxed),
            rejected_invalid_or_unauthorized: self
                .sanitized_event_counters
                .rejected_invalid_or_unauthorized
                .load(Ordering::Relaxed),
            rejected_replay: self
                .sanitized_event_counters
                .rejected_replay
                .load(Ordering::Relaxed),
            rejected_rate_limited: self
                .sanitized_event_counters
                .rejected_rate_limited
                .load(Ordering::Relaxed),
            rejected_publisher: self
                .sanitized_event_counters
                .rejected_publisher
                .load(Ordering::Relaxed),
        }
    }

    fn try_publish_context_event(&self, message: &rvoip_core::DataMessage, at: DateTime<Utc>) {
        let Some(binding) = &self.sanitized_event_binding else {
            return;
        };
        // A router delivery may already be in flight while close unregisters
        // this publication. The lifecycle fence closes event admission before
        // any further sanitization or publisher queue operation.
        if self.state.load(Ordering::Acquire) != STATE_READY {
            record_sanitized_event_metric("dropped", "lifecycle_closed");
            return;
        }
        self.sanitized_event_counters
            .received
            .fetch_add(1, Ordering::Relaxed);
        let event = match binding.policy.sanitize(
            message,
            &self.tenant_id,
            &binding.call_id,
            &binding.source_leg_id,
            at,
        ) {
            Ok(event) => event,
            Err(_) => {
                self.sanitized_event_counters
                    .rejected_invalid_or_unauthorized
                    .fetch_add(1, Ordering::Relaxed);
                record_sanitized_event_metric("dropped", "invalid_or_unauthorized");
                return;
            }
        };

        let mut admission = self
            .sanitized_event_admission
            .lock()
            .expect("sanitized event admission lock");
        if admission
            .message_ids
            .iter()
            .any(|message_id| message_id == message.message_id.as_str())
        {
            self.sanitized_event_counters
                .rejected_replay
                .fetch_add(1, Ordering::Relaxed);
            record_sanitized_event_metric("dropped", "replay");
            return;
        }
        let now = Instant::now();
        if now.duration_since(admission.window_started) >= Duration::from_secs(1) {
            admission.window_started = now;
            admission.admitted_in_window = 0;
        }
        if admission.admitted_in_window >= binding.policy.max_events_per_second() {
            self.sanitized_event_counters
                .rejected_rate_limited
                .fetch_add(1, Ordering::Relaxed);
            record_sanitized_event_metric("dropped", "rate_limited");
            return;
        }
        admission.admitted_in_window += 1;
        if admission.message_ids.len() == EVENT_REPLAY_WINDOW_MESSAGES {
            admission.message_ids.pop_front();
        }
        admission
            .message_ids
            .push_back(message.message_id.to_string());
        drop(admission);

        let ManagedBroadcastRuntime::Moq { publisher, .. } = &self.runtime else {
            self.sanitized_event_counters
                .rejected_publisher
                .fetch_add(1, Ordering::Relaxed);
            record_sanitized_event_metric("dropped", "unsupported_transport");
            return;
        };
        match publisher.try_publish_sanitized_event(event) {
            Ok(()) => {
                self.sanitized_event_counters
                    .published
                    .fetch_add(1, Ordering::Relaxed);
                record_sanitized_event_metric("published", "accepted");
            }
            Err(_) => {
                self.sanitized_event_counters
                    .rejected_publisher
                    .fetch_add(1, Ordering::Relaxed);
                record_sanitized_event_metric("dropped", "publisher_rejected");
            }
        }
    }

    fn unregister_sanitized_event_route(&self) {
        if self
            .sanitized_event_route_registered
            .swap(false, Ordering::AcqRel)
        {
            self.sanitized_event_router
                .unregister(&self.source_connection_id, &self.broadcast_id);
        }
    }

    pub async fn close(&self, reason: BroadcastDrainReason) -> Result<(), ManagedBroadcastError> {
        match self.state.compare_exchange(
            STATE_READY,
            STATE_DRAINING,
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) => {}
            Err(STATE_DRAINING) => {
                loop {
                    // Register before checking state so a completion between
                    // the check and await cannot strand an idempotent closer.
                    let notified = self.terminal.notified();
                    if self.state.load(Ordering::Acquire) != STATE_DRAINING {
                        break;
                    }
                    notified.await;
                }
                return if self.state.load(Ordering::Acquire) == STATE_CLOSED {
                    Ok(())
                } else {
                    Err(ManagedBroadcastError::CleanupFailed)
                };
            }
            Err(STATE_CLOSED) => return Ok(()),
            Err(_) => return Err(ManagedBroadcastError::CleanupFailed),
        }

        let Some(resources) = self.resources.lock().await.take() else {
            self.unregister_sanitized_event_route();
            self.state.store(STATE_CLOSED, Ordering::Release);
            self.terminal.notify_waiters();
            return Ok(());
        };
        // Dropping the exact-generation grant closes admission before media
        // and registry cleanup begins.
        self.unregister_sanitized_event_route();
        drop(resources.grant);
        let shared_grant = match resources.shared_grant {
            Some(grant) => grant.revoke().await.map(|_| ()).map_err(Into::into),
            None => Ok(()),
        };
        let transport = match resources.transport {
            ManagedTransportResources::Uctp { publisher } => {
                let descriptor = publisher.descriptor().clone();
                self.orchestrator
                    .drop_session_subscriptions(&descriptor.session_id);
                publisher.close().await.map_err(Into::into)
            }
            ManagedTransportResources::Moq {
                publisher,
                route,
                _relay,
            } => {
                let deadline = Utc::now() + chrono::Duration::seconds(5);
                let drain = publisher
                    .drain(BroadcastDrainRequest { reason, deadline })
                    .await;
                let remove = if matches!(route.state(), MediaGraphRouteState::Terminal(_)) {
                    drop(route);
                    Ok(())
                } else {
                    route.remove().await.map(|_| ()).map_err(Into::into)
                };
                drain.map(|_| ()).map_err(Into::into).and(remove)
            }
        };
        let result = shared_grant.and(transport);
        self.state.store(
            if result.is_ok() {
                STATE_CLOSED
            } else {
                STATE_FAILED
            },
            Ordering::Release,
        );
        self.terminal.notify_waiters();
        result
    }
}

impl Drop for ManagedBroadcast {
    fn drop(&mut self) {
        self.unregister_sanitized_event_route();
        if let Some(task) = self.expiry_task.lock().expect("expiry task lock").take() {
            task.abort();
        }
        if let Ok(mut resources) = self.resources.try_lock() {
            // Both managed route types have generation-scoped, synchronous
            // Drop fallbacks. Explicit close remains preferred because it
            // observes acknowledgements.
            resources.take();
        }
        if let ManagedBroadcastRuntime::Uctp { descriptor, .. } = &self.runtime {
            self.orchestrator
                .drop_session_subscriptions(&descriptor.session_id);
        }
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct ManagedBroadcastDiagnostics {
    pub tenant_id: String,
    pub broadcast_id: String,
    pub source_connection_id: String,
    pub transport: BroadcastGrantTransport,
    pub endpoint: BroadcastEndpoint,
    pub protocol: BroadcastProtocolDescriptor,
    pub lifecycle: BroadcastLifecycleDescriptor,
    pub health: BroadcastHealthDescriptor,
    pub expires_at: DateTime<Utc>,
    pub graph_id: String,
    pub route_state: MediaGraphRouteState,
    pub source_frames: u64,
    pub graph_dropped_frames: u64,
    pub graph_evictions: u64,
    pub transcode_operations: u64,
    pub route_queue_depth: Option<usize>,
    pub route_queue_capacity: Option<usize>,
    pub route_offered_frames: Option<u64>,
    pub route_dropped_frames: Option<u64>,
    pub sanitized_events: ManagedSanitizedEventDiagnostics,
}

#[derive(Clone, Debug, Serialize)]
pub struct ManagedSanitizedEventDiagnostics {
    pub enabled: bool,
    pub route_registered: bool,
    pub received: u64,
    pub published: u64,
    pub rejected_invalid_or_unauthorized: u64,
    pub rejected_replay: u64,
    pub rejected_rate_limited: u64,
    pub rejected_publisher: u64,
}

struct SanitizedEventAdmission {
    window_started: Instant,
    admitted_in_window: u32,
    message_ids: VecDeque<String>,
}

impl SanitizedEventAdmission {
    fn new() -> Self {
        Self {
            window_started: Instant::now(),
            admitted_in_window: 0,
            message_ids: VecDeque::with_capacity(EVENT_REPLAY_WINDOW_MESSAGES),
        }
    }
}

#[derive(Default)]
struct SanitizedEventCounters {
    received: AtomicU64,
    published: AtomicU64,
    rejected_invalid_or_unauthorized: AtomicU64,
    rejected_replay: AtomicU64,
    rejected_rate_limited: AtomicU64,
    rejected_publisher: AtomicU64,
}

fn record_sanitized_event_metric(result: &'static str, reason: &'static str) {
    metrics::counter!(
        "bridgefu_sanitized_broadcast_events_total",
        "result" => result,
        "reason" => reason
    )
    .increment(1);
}

#[derive(Debug, thiserror::Error)]
pub enum ManagedBroadcastError {
    #[error("invalid managed broadcast configuration: {0}")]
    InvalidConfiguration(&'static str),
    #[error("broadcast grant failed")]
    Token(#[from] BroadcastTokenError),
    #[error("rvoip media graph operation failed")]
    Core(#[from] rvoip_core::RvoipError),
    #[error("MOQT publication operation failed")]
    Moq(#[from] rvoip_moq::MoqError),
    #[error("broadcast media route terminated during setup")]
    RouteTerminated(rvoip_core::media_graph::MediaGraphRouteTerminalReason),
    #[error("managed broadcast cleanup failed")]
    CleanupFailed,
}

#[cfg(test)]
mod shape_tests {
    use super::*;
    use std::time::Duration;

    use async_trait::async_trait;
    use rvoip_core::adapter::{
        AdapterEvent, AdapterKind, ConnectionAdapter, ConnectionHandle, EndReason,
        OriginateRequest, RejectReason, SignatureHeaders, TransferTarget,
    };
    use rvoip_core::capability::{CapabilityDescriptor, CodecInfo, NegotiatedCodecs};
    use rvoip_core::connection::{
        Connection, ConnectionState, Direction, Transport, TransportHandle,
    };
    use rvoip_core::identity::IdentityAssurance;
    use rvoip_core::ids::{ParticipantId, SessionId, StreamId};
    use rvoip_core::message::Message;
    use rvoip_core::stream::{MediaFrame, MediaStream, QualitySnapshot, StreamKind};
    use rvoip_core::{Config, Result as RvoipResult, RvoipError};
    use std::collections::BTreeMap;
    use tokio::sync::mpsc;

    use crate::context::{ContextEnvelope, ContextPolicy};

    #[test]
    fn direct_uctp_limit_is_release_bounded() {
        assert_eq!(MAX_DIRECT_UCTP_SUBSCRIBERS, 1_000);
    }

    #[test]
    fn uctp_endpoint_is_one_exact_credential_free_authority() {
        let valid = Url::parse("uctp+quic://gateway.example:4446").unwrap();
        assert!(validate_uctp_endpoint(&valid).is_ok());
        assert_eq!(valid.to_string(), "uctp+quic://gateway.example:4446");

        for invalid in [
            "uctp://gateway.example:4446",
            "uctp+quic://gateway.example",
            "uctp+quic://user@gateway.example:4446",
            "uctp+quic://gateway.example:4446/path",
            "uctp+quic://gateway.example:4446?token=secret",
            "uctp+quic://gateway.example:4446#fragment",
        ] {
            let endpoint = Url::parse(invalid).unwrap();
            assert!(validate_uctp_endpoint(&endpoint).is_err(), "{invalid}");
        }
    }

    #[test]
    fn relay_target_debug_omits_credentials_and_host() {
        // Userinfo is invalid for the production wire client, but Debug must
        // remain safe even before that validation boundary is reached.
        let endpoint = Url::parse("moqt://user:secret@relay.example/live").unwrap();
        let rendered = format!(
            "{:?}",
            DebugRelayTargetEndpoint {
                endpoint: &endpoint
            }
        );
        assert!(!rendered.contains("user"));
        assert!(!rendered.contains("secret"));
        assert!(!rendered.contains("relay.example"));
    }

    #[test]
    fn sanitized_event_binding_debug_omits_call_and_leg_identifiers() {
        const CANARY: &str = "event-binding-canary\r\nAuthorization: exposed";
        let context_policy = ContextPolicy {
            allow_headers: BTreeMap::from([("X-Bridgefu-Event".into(), "broadcast_event".into())]),
            ..ContextPolicy::default()
        };
        let policy =
            SanitizedContextEventPolicy::new("broadcast_event", 1, 1, 1, &context_policy).unwrap();
        // Construct directly so this diagnostic test also covers values that
        // the public validation boundary would reject.
        let binding = ManagedSanitizedEventBinding {
            call_id: CANARY.into(),
            source_leg_id: CANARY.into(),
            policy,
        };
        let debug = format!("{binding:?}");
        assert!(!debug.contains(CANARY));
        assert!(!debug.contains("Authorization: exposed"));
    }

    struct DebugRelayTargetEndpoint<'a> {
        endpoint: &'a Url,
    }

    impl fmt::Debug for DebugRelayTargetEndpoint<'_> {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter
                .debug_struct("MoqRelayTarget")
                .field("endpoint_scheme", &self.endpoint.scheme())
                .field("endpoint_has_host", &self.endpoint.host_str().is_some())
                .finish()
        }
    }

    fn opus() -> CodecInfo {
        CodecInfo {
            name: "opus".into(),
            clock_rate_hz: 48_000,
            channels: 1,
            fmtp: None,
        }
    }

    fn g711(name: &str) -> CodecInfo {
        CodecInfo {
            name: name.to_owned(),
            clock_rate_hz: 8_000,
            channels: 1,
            fmtp: None,
        }
    }

    struct TestMediaStream {
        id: StreamId,
        codec: CodecInfo,
        inbound: StdMutex<Option<mpsc::Receiver<MediaFrame>>>,
        outbound: mpsc::Sender<MediaFrame>,
    }

    impl TestMediaStream {
        fn source() -> (Arc<Self>, mpsc::Sender<MediaFrame>) {
            Self::source_with_codec(opus())
        }

        fn source_with_codec(codec: CodecInfo) -> (Arc<Self>, mpsc::Sender<MediaFrame>) {
            let (source, inbound) = mpsc::channel(32);
            let (outbound, _) = mpsc::channel(1);
            (
                Arc::new(Self {
                    id: StreamId::new(),
                    codec,
                    inbound: StdMutex::new(Some(inbound)),
                    outbound,
                }),
                source,
            )
        }

        fn sink() -> (Arc<Self>, mpsc::Receiver<MediaFrame>) {
            let (_, inbound) = mpsc::channel(1);
            let (outbound, receiver) = mpsc::channel(32);
            (
                Arc::new(Self {
                    id: StreamId::new(),
                    codec: opus(),
                    inbound: StdMutex::new(Some(inbound)),
                    outbound,
                }),
                receiver,
            )
        }
    }

    #[async_trait]
    impl MediaStream for TestMediaStream {
        fn id(&self) -> StreamId {
            self.id.clone()
        }

        fn kind(&self) -> StreamKind {
            StreamKind::Audio
        }

        fn codec(&self) -> CodecInfo {
            self.codec.clone()
        }

        fn direction(&self) -> Direction {
            Direction::Inbound
        }

        fn frames_in(&self) -> mpsc::Receiver<MediaFrame> {
            self.inbound
                .lock()
                .expect("inbound stream lock")
                .take()
                .unwrap_or_else(|| mpsc::channel(1).1)
        }

        fn try_frames_in(&self) -> RvoipResult<mpsc::Receiver<MediaFrame>> {
            self.inbound
                .lock()
                .expect("inbound stream lock")
                .take()
                .ok_or(RvoipError::InvalidState(
                    "test stream receiver already acquired",
                ))
        }

        fn frames_out(&self) -> mpsc::Sender<MediaFrame> {
            self.outbound.clone()
        }

        fn quality_snapshot(&self) -> QualitySnapshot {
            QualitySnapshot::default()
        }

        async fn close(self: Arc<Self>) -> RvoipResult<()> {
            Ok(())
        }
    }

    struct TestAdapter {
        streams: dashmap::DashMap<ConnectionId, Vec<Arc<dyn MediaStream>>>,
        events: StdMutex<Option<mpsc::Receiver<AdapterEvent>>>,
    }

    impl TestAdapter {
        fn new() -> (Arc<Self>, mpsc::Sender<AdapterEvent>) {
            let (sender, receiver) = mpsc::channel(32);
            (
                Arc::new(Self {
                    streams: dashmap::DashMap::new(),
                    events: StdMutex::new(Some(receiver)),
                }),
                sender,
            )
        }

        fn add_stream(&self, connection_id: ConnectionId, stream: Arc<dyn MediaStream>) {
            self.streams.insert(connection_id, vec![stream]);
        }
    }

    #[async_trait]
    impl ConnectionAdapter for TestAdapter {
        fn transport(&self) -> Transport {
            Transport::Sip
        }

        fn kind(&self) -> AdapterKind {
            AdapterKind::Substrate
        }

        async fn originate(&self, _: OriginateRequest) -> RvoipResult<ConnectionHandle> {
            Err(RvoipError::NotImplemented("test originate"))
        }

        async fn accept(&self, _: ConnectionId) -> RvoipResult<()> {
            Ok(())
        }

        async fn reject(&self, _: ConnectionId, _: RejectReason) -> RvoipResult<()> {
            Ok(())
        }

        async fn end(&self, _: ConnectionId, _: EndReason) -> RvoipResult<()> {
            Ok(())
        }

        async fn hold(&self, _: ConnectionId) -> RvoipResult<()> {
            Ok(())
        }

        async fn resume(&self, _: ConnectionId) -> RvoipResult<()> {
            Ok(())
        }

        async fn transfer(&self, _: ConnectionId, _: TransferTarget) -> RvoipResult<()> {
            Ok(())
        }

        async fn streams(
            &self,
            connection_id: ConnectionId,
        ) -> RvoipResult<Vec<Arc<dyn MediaStream>>> {
            Ok(self
                .streams
                .get(&connection_id)
                .map(|streams| streams.value().clone())
                .unwrap_or_default())
        }

        async fn send_message(&self, _: ConnectionId, _: Message) -> RvoipResult<()> {
            Ok(())
        }

        async fn send_dtmf(&self, _: ConnectionId, _: &str, _: u32) -> RvoipResult<()> {
            Ok(())
        }

        async fn renegotiate_media(
            &self,
            _: ConnectionId,
            _: CapabilityDescriptor,
        ) -> RvoipResult<NegotiatedCodecs> {
            Ok(NegotiatedCodecs::default())
        }

        fn subscribe_events(&self) -> mpsc::Receiver<AdapterEvent> {
            self.events
                .lock()
                .expect("adapter event lock")
                .take()
                .expect("adapter subscribed once")
        }

        fn capabilities(&self) -> CapabilityDescriptor {
            CapabilityDescriptor::default()
        }

        async fn verify_request_signature(
            &self,
            _: ConnectionId,
            _: SignatureHeaders,
        ) -> RvoipResult<IdentityAssurance> {
            Ok(IdentityAssurance::Anonymous)
        }
    }

    fn connection(id: ConnectionId) -> Connection {
        Connection {
            id,
            session_id: SessionId::new(),
            participant_id: ParticipantId::new(),
            transport: Transport::Sip,
            direction: Direction::Inbound,
            state: ConnectionState::Connecting,
            capabilities: CapabilityDescriptor::default(),
            negotiated_codecs: NegotiatedCodecs::default(),
            streams: Vec::new(),
            messaging_enabled: false,
            transport_handle: TransportHandle(Arc::new(())),
            opened_at: Utc::now(),
            closed_at: None,
        }
    }

    async fn register_connection(events: &mpsc::Sender<AdapterEvent>, id: ConnectionId) {
        events
            .send(AdapterEvent::InboundConnection {
                connection: connection(id),
            })
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(20)).await;
    }

    #[tokio::test]
    async fn uctp_and_moq_share_one_real_source_and_cleanup_exactly() {
        let orchestrator = Orchestrator::new(Config::default());
        let (adapter, events) = TestAdapter::new();
        orchestrator
            .register(adapter.clone() as Arc<dyn ConnectionAdapter>)
            .unwrap();

        let source_id = ConnectionId::new();
        let subscriber_id = ConnectionId::new();
        let (source, source_tx) = TestMediaStream::source();
        let (subscriber, mut subscriber_rx) = TestMediaStream::sink();
        adapter.add_stream(source_id.clone(), source);
        adapter.add_stream(subscriber_id.clone(), subscriber);
        register_connection(&events, source_id.clone()).await;
        register_connection(&events, subscriber_id.clone()).await;

        let grants = BroadcastGrantRegistry::new();
        let service = ManagedBroadcastService::new(
            Arc::clone(&orchestrator),
            grants.clone(),
            MAX_DIRECT_UCTP_SUBSCRIBERS,
        )
        .unwrap();
        let expires_at = Utc::now() + chrono::Duration::minutes(5);
        let uctp = service
            .start(
                "tenant-a",
                "broadcast-uctp",
                source_id.clone(),
                expires_at,
                ManagedBroadcastTransport::UctpQuic {
                    endpoint: Url::parse("uctp+quic://127.0.0.1:4444").unwrap(),
                },
            )
            .await
            .unwrap();
        let moq = service
            .start(
                "tenant-a",
                "broadcast-moq",
                source_id.clone(),
                expires_at,
                ManagedBroadcastTransport::Moqt {
                    publisher: MoqPublisherConfig {
                        tenant_id: "tenant-a".into(),
                        broadcast_id: "broadcast-moq".into(),
                        bitrate: 24_000,
                        language: None,
                        queue_frames: 10,
                    },
                    relay: None,
                    sanitized_events: None,
                },
            )
            .await
            .unwrap();
        assert_eq!(grants.active_count(), 2);
        assert_eq!(
            uctp.endpoint().uri.as_deref(),
            Some("uctp+quic://127.0.0.1:4444")
        );
        assert_eq!(uctp.diagnostics().graph_id, moq.diagnostics().graph_id);
        assert!(!moq.diagnostics().sanitized_events.enabled);
        assert!(!moq.diagnostics().sanitized_events.route_registered);
        assert_eq!(service.sanitized_event_route_count(), 0);
        assert!(matches!(
            moq.endpoint().resource,
            BroadcastResource::Moqt {
                events_track: None,
                ..
            }
        ));

        orchestrator.add_subscription(
            SessionId::from_string("broadcast-uctp"),
            subscriber_id,
            source_id,
            StreamId::from_string(UCTP_STREAM_ID),
        );
        source_tx
            .send(MediaFrame {
                stream_id: StreamId::new(),
                kind: StreamKind::Audio,
                payload: vec![0x78, 0x00].into(),
                timestamp_rtp: 960,
                captured_at: Utc::now(),
                payload_type: Some(111),
            })
            .await
            .unwrap();
        let received = tokio::time::timeout(Duration::from_secs(1), subscriber_rx.recv())
            .await
            .expect("UCTP fanout deadline")
            .expect("UCTP subscriber frame");
        assert_eq!(received.payload.as_ref(), &[0x78, 0x00]);
        assert_eq!(received.stream_id, StreamId::from_string(UCTP_STREAM_ID));

        let (first, second) = tokio::join!(
            uctp.close(BroadcastDrainReason::OperatorRequest),
            uctp.close(BroadcastDrainReason::OperatorRequest)
        );
        first.unwrap();
        second.unwrap();
        moq.close(BroadcastDrainReason::OperatorRequest)
            .await
            .unwrap();
        assert_eq!(grants.active_count(), 0);
        assert_eq!(uctp.lifecycle().state, BroadcastLifecycleState::Closed);
        assert_eq!(moq.lifecycle().state, BroadcastLifecycleState::Closed);
        assert!(orchestrator
            .publisher_registry()
            .entry(&SessionId::from_string("broadcast-uctp"), UCTP_STREAM_ID)
            .is_none());
        assert!(matches!(
            uctp.diagnostics().route_state,
            MediaGraphRouteState::Terminal(_)
        ));
        assert!(matches!(
            moq.diagnostics().route_state,
            MediaGraphRouteState::Terminal(_)
        ));
    }

    async fn assert_managed_g711_source_publishes_opus(
        source_codec: CodecInfo,
        source_payload_type: u8,
        samples: [u8; 2],
    ) {
        let orchestrator = Orchestrator::new(Config::default());
        let (adapter, events) = TestAdapter::new();
        orchestrator
            .register(adapter.clone() as Arc<dyn ConnectionAdapter>)
            .unwrap();

        let source_id = ConnectionId::new();
        let subscriber_id = ConnectionId::new();
        let (source, source_tx) = TestMediaStream::source_with_codec(source_codec);
        let source_stream_id = source.id();
        let (subscriber, mut subscriber_rx) = TestMediaStream::sink();
        adapter.add_stream(source_id.clone(), source);
        adapter.add_stream(subscriber_id.clone(), subscriber);
        register_connection(&events, source_id.clone()).await;
        register_connection(&events, subscriber_id.clone()).await;

        let service = ManagedBroadcastService::new(
            Arc::clone(&orchestrator),
            BroadcastGrantRegistry::new(),
            MAX_DIRECT_UCTP_SUBSCRIBERS,
        )
        .unwrap();
        let broadcast_id = format!("broadcast-g711-{source_payload_type}");
        let broadcast = service
            .start(
                "tenant-a",
                broadcast_id.clone(),
                source_id.clone(),
                Utc::now() + chrono::Duration::minutes(5),
                ManagedBroadcastTransport::UctpQuic {
                    endpoint: Url::parse("uctp+quic://gateway.example:4446").unwrap(),
                },
            )
            .await
            .expect("start managed UCTP broadcast");
        orchestrator.add_subscription(
            SessionId::from_string(&broadcast_id),
            subscriber_id,
            source_id.clone(),
            StreamId::from_string(UCTP_STREAM_ID),
        );

        for (sample, timestamp_rtp) in [(samples[0], u32::MAX - 159), (samples[1], 0_u32)] {
            source_tx
                .send(MediaFrame {
                    stream_id: source_stream_id.clone(),
                    kind: StreamKind::Audio,
                    payload: vec![sample; 160].into(),
                    timestamp_rtp,
                    captured_at: Utc::now(),
                    payload_type: Some(source_payload_type),
                })
                .await
                .expect("send G.711 source frame");
        }

        let first = tokio::time::timeout(Duration::from_secs(2), subscriber_rx.recv())
            .await
            .expect("first Opus frame deadline")
            .expect("first Opus frame");
        let second = tokio::time::timeout(Duration::from_secs(2), subscriber_rx.recv())
            .await
            .expect("second Opus frame deadline")
            .expect("second Opus frame");
        assert_eq!(first.payload_type, Some(111));
        assert_eq!(second.payload_type, Some(111));
        assert!(!first.payload.is_empty());
        assert!(!second.payload.is_empty());
        assert_eq!(first.stream_id, StreamId::from_string(UCTP_STREAM_ID));
        assert_eq!(second.stream_id, StreamId::from_string(UCTP_STREAM_ID));
        assert_eq!(second.timestamp_rtp.wrapping_sub(first.timestamp_rtp), 960);

        let registry = orchestrator
            .publisher_registry()
            .entry(&SessionId::from_string(&broadcast_id), UCTP_STREAM_ID)
            .expect("canonical publisher registry row");
        assert_eq!(registry.codec, Some(opus()));
        let snapshot = orchestrator
            .media_graph_for_connection(source_id)
            .await
            .unwrap()
            .snapshot()
            .await;
        assert_eq!(snapshot.source_frames, 2);
        assert_eq!(snapshot.transcode_operations, 2);
        assert_eq!(snapshot.codec_groups.len(), 1);
        assert_eq!(snapshot.codec_groups[0].target_payload_type, 111);

        broadcast
            .close(BroadcastDrainReason::OperatorRequest)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn managed_pcmu_source_is_published_as_canonical_opus() {
        assert_managed_g711_source_publishes_opus(g711("pcmu"), 0, [0xff, 0x7f]).await;
    }

    #[tokio::test]
    async fn managed_pcma_source_is_published_as_canonical_opus() {
        assert_managed_g711_source_publishes_opus(g711("pcma"), 8, [0xd5, 0x55]).await;
    }

    #[tokio::test]
    async fn managed_expiry_revokes_grant_and_closes_route() {
        let orchestrator = Orchestrator::new(Config::default());
        let (adapter, events) = TestAdapter::new();
        orchestrator
            .register(adapter.clone() as Arc<dyn ConnectionAdapter>)
            .unwrap();
        let source_id = ConnectionId::new();
        let (source, _source_tx) = TestMediaStream::source();
        adapter.add_stream(source_id.clone(), source);
        register_connection(&events, source_id.clone()).await;

        let grants = BroadcastGrantRegistry::new();
        let service = ManagedBroadcastService::new(
            Arc::clone(&orchestrator),
            grants.clone(),
            MAX_DIRECT_UCTP_SUBSCRIBERS,
        )
        .unwrap();
        let broadcast = service
            .start(
                "tenant-a",
                "expiring-broadcast",
                source_id,
                Utc::now() + chrono::Duration::milliseconds(75),
                ManagedBroadcastTransport::UctpQuic {
                    endpoint: Url::parse("uctp+quic://127.0.0.1:4444").unwrap(),
                },
            )
            .await
            .unwrap();
        assert_eq!(grants.active_count(), 1);

        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                if broadcast.lifecycle().state == BroadcastLifecycleState::Closed {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("managed expiry deadline");
        assert_eq!(grants.active_count(), 0);
        assert!(matches!(
            broadcast.diagnostics().route_state,
            MediaGraphRouteState::Terminal(_)
        ));
    }

    #[tokio::test]
    async fn opt_in_context_events_require_exact_source_and_binding_then_cleanup() {
        let orchestrator = Orchestrator::new(Config::default());
        let (adapter, events) = TestAdapter::new();
        orchestrator
            .register(adapter.clone() as Arc<dyn ConnectionAdapter>)
            .unwrap();
        let source_id = ConnectionId::new();
        let foreign_connection_id = ConnectionId::new();
        let (source, _source_tx) = TestMediaStream::source();
        let (foreign, _foreign_tx) = TestMediaStream::source();
        adapter.add_stream(source_id.clone(), source);
        adapter.add_stream(foreign_connection_id.clone(), foreign);
        register_connection(&events, source_id.clone()).await;
        register_connection(&events, foreign_connection_id.clone()).await;

        let context_policy = ContextPolicy {
            allow_headers: BTreeMap::from([("X-Bridgefu-Event".into(), "broadcast_event".into())]),
            ..ContextPolicy::default()
        };
        let policy =
            SanitizedContextEventPolicy::new("broadcast_event", 8, 8, 1, &context_policy).unwrap();
        let binding = ManagedSanitizedEventBinding::new("call-a", "leg-a", policy).unwrap();
        let service = ManagedBroadcastService::new(
            Arc::clone(&orchestrator),
            BroadcastGrantRegistry::new(),
            MAX_DIRECT_UCTP_SUBSCRIBERS,
        )
        .unwrap();
        let broadcast = service
            .start(
                "tenant-a",
                "events-broadcast",
                source_id.clone(),
                Utc::now() + chrono::Duration::minutes(5),
                ManagedBroadcastTransport::Moqt {
                    publisher: MoqPublisherConfig {
                        tenant_id: "tenant-a".into(),
                        broadcast_id: "events-broadcast".into(),
                        bitrate: 24_000,
                        language: None,
                        queue_frames: 10,
                    },
                    relay: None,
                    sanitized_events: Some(binding),
                },
            )
            .await
            .unwrap();
        assert_eq!(service.sanitized_event_route_count(), 1);
        assert!(matches!(
            broadcast.endpoint().resource,
            BroadcastResource::Moqt {
                events_track: Some(ref track),
                ..
            } if track == rvoip_moq::EVENTS_TRACK
        ));

        let context_message = |tenant: &str, call: &str, leg: &str, kind: &str| {
            let mut envelope = ContextEnvelope::new("private-correlation", tenant, call, leg);
            envelope
                .metadata
                .insert("broadcast_event".into(), kind.into());
            envelope
                .metadata
                .insert("sip_authorization".into(), "must-not-leak".into());
            envelope.to_data_message().unwrap()
        };
        // An otherwise valid envelope from a different authenticated
        // connection is invisible to this broadcast route.
        events
            .send(AdapterEvent::DataMessage {
                connection_id: foreign_connection_id,
                message: context_message("tenant-a", "call-a", "leg-a", "call-connected"),
            })
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert_eq!(broadcast.diagnostics().sanitized_events.received, 0);

        let accepted = context_message("tenant-a", "call-a", "leg-a", "call-connected");
        events
            .send(AdapterEvent::DataMessage {
                connection_id: source_id.clone(),
                message: accepted.clone(),
            })
            .await
            .unwrap();
        // Same ID is a replay. A second distinct valid event exceeds this
        // test policy's one-event-per-second admission limit. A forged tenant
        // is rejected before either limiter can be poisoned.
        events
            .send(AdapterEvent::DataMessage {
                connection_id: source_id.clone(),
                message: accepted,
            })
            .await
            .unwrap();
        events
            .send(AdapterEvent::DataMessage {
                connection_id: source_id.clone(),
                message: context_message("tenant-a", "call-a", "leg-a", "call-held"),
            })
            .await
            .unwrap();
        events
            .send(AdapterEvent::DataMessage {
                connection_id: source_id,
                message: context_message("tenant-b", "call-a", "leg-a", "call-ended"),
            })
            .await
            .unwrap();

        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                let events = broadcast.diagnostics().sanitized_events;
                if events.received == 4
                    && events.published == 1
                    && events.rejected_replay == 1
                    && events.rejected_rate_limited == 1
                    && events.rejected_invalid_or_unauthorized == 1
                {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("sanitized event diagnostics deadline");

        broadcast
            .close(BroadcastDrainReason::OperatorRequest)
            .await
            .unwrap();
        assert_eq!(service.sanitized_event_route_count(), 0);
        let diagnostics = broadcast.diagnostics().sanitized_events;
        assert!(diagnostics.enabled);
        assert!(!diagnostics.route_registered);
        assert_eq!(diagnostics.published, 1);
        let rendered = serde_json::to_string(&diagnostics).unwrap();
        for secret in [
            "tenant-a",
            "call-a",
            "leg-a",
            "private-correlation",
            "must-not-leak",
            "X-Bridgefu-Event",
        ] {
            assert!(!rendered.contains(secret), "diagnostics leaked {secret}");
        }
    }
}
