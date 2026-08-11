//! Generic SIP/RTP ↔ WebRTC/RTP runtime built from rvoip's first-party
//! server and adapter implementations.
//!
//! The durable call execution supervisor is installed before public signaling
//! sockets or adapters. It owns both the admission boundary and the
//! authoritative operational stream; the lossy compatibility broadcast is
//! never used for authorization or call-state correctness.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use bridgefu::call_service::{
    CallExecutionSupervisor, CallServiceRuntime, OutboundProfileResolver, ProviderLegExecutor,
};
use bridgefu::reference_tenant_canary::ReferenceTenantCanaryPolicy;
use rvoip_amazon_connect::AmazonConnectAdapter;
use rvoip_auth_core::BearerValidator;
use rvoip_core::adapter::ConnectionAdapter;
use rvoip_core::config::Config as CoreConfig;
use rvoip_core::Orchestrator;
use rvoip_sip::{
    ProfiledSipAdapter, SipAdapter, SipEgressProfileRegistration, SipInboundContextPolicy,
    SipListenerAuthPolicy, SipNatConfig, UnifiedCoordinator,
};
use rvoip_webrtc::signaling::auth::{AuthCoreHook, WsBearerSessionBinding};
use rvoip_webrtc::tls::TlsConfig as WebRtcTlsConfig;
use rvoip_webrtc::{WebRtcServer, WebRtcServerBuilder};
use tokio::sync::Mutex;

use bridgefu::gateway_native_ingress::SipEgressProfileConfig;
use bridgefu::recipe_admission::RecipeSipAdmissionCatalog;
use bridgefu::sip_security_evidence::{SipSecurityEvidenceMonitor, SipSecurityEvidencePolicy};

use crate::config::{GenericBridgeCfg, RuntimeCfg};
use crate::context::ContextPolicy;

const WEBSOCKET_ATTACHMENT_PREFIX: &str = "bridgefu.attach.";

pub struct GenericBridgeRuntime {
    orchestrator: Arc<Orchestrator>,
    sip: Arc<ProfiledSipAdapter>,
    sip_security_evidence: Mutex<Option<SipSecurityEvidenceMonitor>>,
    webrtc: Mutex<Option<WebRtcServer>>,
    execution: Mutex<Option<CallExecutionSupervisor>>,
    amazon_connect: Arc<AmazonConnectAdapter>,
    pub sip_addr: SocketAddr,
    pub ws_addr: SocketAddr,
    pub whip_addr: SocketAddr,
}

/// File-backed TLS material shared by the generic WSS and WHIP/WHEP HTTPS
/// listeners. Bridgefu deliberately reuses the already validated public API
/// certificate in all-in-one mode so a route cannot advertise WSS while the
/// process only serves cleartext signaling.
#[derive(Clone, Copy, Debug)]
pub struct GenericBridgeTls<'a> {
    pub certificate_chain: &'a str,
    pub private_key: &'a str,
}

/// Validated construction inputs for the generic media runtime.
///
/// Keeping the related policy and dependency handles in one value makes it
/// difficult for a caller to accidentally swap positional arguments as the
/// runtime grows new transport-owned dependencies.
pub struct GenericBridgeStart<'a> {
    pub config: &'a GenericBridgeCfg,
    pub runtime: &'a RuntimeCfg,
    pub call_runtime: Arc<CallServiceRuntime>,
    pub sip_stack: (rvoip_sip::Config, SipNatConfig),
    pub sip_egress_profiles: Vec<SipEgressProfileConfig>,
    pub sip_listener_auth: SipListenerAuthPolicy,
    pub webrtc_bearer_validator: Arc<dyn BearerValidator>,
    pub webrtc_session_binding: Arc<dyn WsBearerSessionBinding>,
    pub context_policy: &'a ContextPolicy,
    pub reference_tenant_canary: Option<Arc<ReferenceTenantCanaryPolicy>>,
    pub recipe_sip_admissions: Option<Arc<RecipeSipAdmissionCatalog>>,
    pub provider_executor: Arc<dyn ProviderLegExecutor>,
    pub outbound_profiles: Arc<dyn OutboundProfileResolver>,
    pub amazon_connect: Arc<AmazonConnectAdapter>,
    pub signaling_tls: Option<GenericBridgeTls<'a>>,
}

impl GenericBridgeRuntime {
    /// Exact orchestrator that owns every generic SIP/WebRTC connection and
    /// its reusable media graph. Broadcast integration must use this handle;
    /// constructing a second orchestrator would make durable bindings stale.
    pub(crate) fn orchestrator(&self) -> Arc<Orchestrator> {
        Arc::clone(&self.orchestrator)
    }

    pub async fn start(input: GenericBridgeStart<'_>) -> Result<Arc<Self>> {
        let GenericBridgeStart {
            config,
            runtime,
            call_runtime,
            sip_stack,
            sip_egress_profiles,
            sip_listener_auth,
            webrtc_bearer_validator,
            webrtc_session_binding,
            context_policy,
            reference_tenant_canary,
            recipe_sip_admissions,
            provider_executor,
            outbound_profiles,
            amazon_connect,
            signaling_tls,
        } = input;
        let sip_addr: SocketAddr = config.sip_bind.parse().context("generic_bridge.sip_bind")?;
        let setup_timeout = Duration::from_secs(runtime.setup_timeout_secs);
        let admission_capacity = runtime
            .max_concurrent_calls
            .checked_mul(2)
            .ok_or_else(|| anyhow!("generic bridge admission capacity overflow"))?;

        let mut rtc_config = config
            .webrtc_stack_config()
            .context("configuring generic WebRTC ICE/DTLS networking")?;
        rtc_config.max_concurrent_sessions = admission_capacity;
        let (mut sip_stack_config, sip_nat_config) = sip_stack;
        let mut correlation_headers = context_policy
            .allow_headers
            .iter()
            .filter_map(|(header, key)| (key == "correlation_id").then_some(header.as_str()));
        let correlation_header = correlation_headers
            .next()
            .filter(|_| correlation_headers.next().is_none());
        let sip_security_evidence_policy =
            if sip_stack_config.offer_srtp && sip_stack_config.tls_bind_addr.is_some() {
                correlation_header
                    .map(|correlation_header| {
                        SipSecurityEvidencePolicy::install(
                            &mut sip_stack_config,
                            correlation_header,
                            admission_capacity.saturating_mul(4),
                        )
                        .context("configuring redacted SIPS media-security evidence")
                    })
                    .transpose()?
            } else {
                None
            };
        let inbound_context_policy = sip_inbound_context_policy(context_policy)?;
        let webrtc_auth = Arc::new(
            AuthCoreHook::new(webrtc_bearer_validator)
                .try_with_session_hint_subprotocol_prefix(WEBSOCKET_ATTACHMENT_PREFIX)
                .context("configuring WebRTC attachment subprotocol")?
                .with_session_binding(webrtc_session_binding),
        );

        // Load both PEM files before installing the execution owner or
        // opening either signaling listener. A bad certificate therefore
        // leaves no partially started call runtime behind.
        let webrtc_tls = match signaling_tls {
            Some(tls) => Some(
                WebRtcTlsConfig::from_pem_files(tls.certificate_chain, tls.private_key)
                    .await
                    .context("loading generic WebRTC signaling TLS")?,
            ),
            None => None,
        };

        // Complete every fallible configuration/secret validation before
        // installing task owners. The supervisor must still precede all
        // coordinator/server construction and adapter registration so an
        // immediate lifecycle event always has an authoritative consumer.
        let orchestrator = Orchestrator::new(CoreConfig::default());
        let execution =
            CallExecutionSupervisor::install_with_leg_executors_context_canary_recipe_broadcast_profiles_and_private_egress(
                Arc::clone(&orchestrator),
                call_runtime,
                provider_executor,
                Some(Arc::clone(&amazon_connect)),
                Arc::new(context_policy.clone()),
                reference_tenant_canary,
                recipe_sip_admissions,
                None,
                outbound_profiles,
                None,
                admission_capacity,
                setup_timeout,
            )
            .await
            .context("installing generic call execution supervisor")?;

        let coordinator = match UnifiedCoordinator::new_with_listener_auth_and_nat(
            sip_stack_config,
            sip_listener_auth,
            sip_nat_config,
        )
        .await
        {
            Ok(coordinator) => coordinator,
            Err(error) => {
                rollback_failed_startup(
                    execution,
                    None,
                    None,
                    None,
                    Arc::clone(&orchestrator),
                    Arc::clone(&amazon_connect),
                    setup_timeout,
                )
                .await;
                return Err(error).context("starting authenticated generic SIP coordinator");
            }
        };
        let sip_security_evidence = match sip_security_evidence_policy {
            Some(policy) => {
                match SipSecurityEvidenceMonitor::start(coordinator.as_ref(), policy).await {
                    Ok(observer) => Some(observer),
                    Err(error) => {
                        rollback_failed_startup(
                            execution,
                            Some(Arc::clone(&coordinator)),
                            None,
                            None,
                            Arc::clone(&orchestrator),
                            Arc::clone(&amazon_connect),
                            setup_timeout,
                        )
                        .await;
                        return Err(error)
                            .context("starting redacted SIPS media-security evidence observer");
                    }
                }
            }
            None => None,
        };
        let sip_adapter = match SipAdapter::new_with_inbound_context_policy(
            Arc::clone(&coordinator),
            inbound_context_policy,
        )
        .await
        {
            Ok(adapter) => adapter,
            Err(error) => {
                rollback_failed_startup(
                    execution,
                    Some(Arc::clone(&coordinator)),
                    None,
                    None,
                    Arc::clone(&orchestrator),
                    Arc::clone(&amazon_connect),
                    setup_timeout,
                )
                .await;
                return Err(error).context("starting generic SIP adapter");
            }
        };
        let sip = match build_profiled_sip_adapter(sip_adapter, sip_egress_profiles, setup_timeout)
            .await
        {
            Ok(adapter) => adapter,
            Err(error) => {
                rollback_failed_startup(
                    execution,
                    Some(Arc::clone(&coordinator)),
                    None,
                    None,
                    Arc::clone(&orchestrator),
                    Arc::clone(&amazon_connect),
                    setup_timeout,
                )
                .await;
                return Err(error).context("starting isolated named SIP egress profiles");
            }
        };

        let mut webrtc_builder = WebRtcServerBuilder::new(rtc_config)
            .with_ws_auth(webrtc_auth.clone())
            .with_whip_auth(webrtc_auth)
            .with_inbound_admission_confirmation(setup_timeout);
        webrtc_builder = match webrtc_tls {
            Some(tls) => webrtc_builder
                .with_wss(config.webrtc_ws_bind.clone(), tls.clone())
                .with_whips(config.webrtc_whip_bind.clone(), tls),
            None => webrtc_builder
                .with_ws(config.webrtc_ws_bind.clone())
                .with_whip(config.webrtc_whip_bind.clone()),
        };
        let webrtc = match webrtc_builder.build().await {
            Ok(server) => server,
            Err(error) => {
                rollback_failed_startup(
                    execution,
                    None,
                    Some(Arc::clone(&sip)),
                    None,
                    Arc::clone(&orchestrator),
                    Arc::clone(&amazon_connect),
                    setup_timeout,
                )
                .await;
                return Err(error).context("starting authenticated generic WebRTC server");
            }
        };
        let secure_signaling = signaling_tls.is_some();
        let ws_addr = match webrtc.ws_addr().or_else(|| webrtc.wss_addr()) {
            Some(address) => address,
            None => {
                rollback_failed_startup(
                    execution,
                    None,
                    Some(Arc::clone(&sip)),
                    Some(webrtc),
                    Arc::clone(&orchestrator),
                    Arc::clone(&amazon_connect),
                    setup_timeout,
                )
                .await;
                return Err(anyhow!("WebRTC WS listener missing"));
            }
        };
        let whip_addr = match webrtc.whip_addr().or_else(|| webrtc.whips_addr()) {
            Some(address) => address,
            None => {
                rollback_failed_startup(
                    execution,
                    None,
                    Some(Arc::clone(&sip)),
                    Some(webrtc),
                    Arc::clone(&orchestrator),
                    Arc::clone(&amazon_connect),
                    setup_timeout,
                )
                .await;
                return Err(anyhow!("WebRTC WHIP listener missing"));
            }
        };

        if let Err(error) = orchestrator.register(Arc::clone(&sip) as Arc<dyn ConnectionAdapter>) {
            rollback_failed_startup(
                execution,
                None,
                Some(Arc::clone(&sip)),
                Some(webrtc),
                Arc::clone(&orchestrator),
                Arc::clone(&amazon_connect),
                setup_timeout,
            )
            .await;
            return Err(error).context("registering generic SIP adapter");
        }
        if let Err(error) = orchestrator.register(webrtc.adapter() as Arc<dyn ConnectionAdapter>) {
            rollback_failed_startup(
                execution,
                None,
                Some(Arc::clone(&sip)),
                Some(webrtc),
                Arc::clone(&orchestrator),
                Arc::clone(&amazon_connect),
                setup_timeout,
            )
            .await;
            return Err(error).context("registering generic WebRTC adapter");
        }
        if let Err(error) =
            orchestrator.register(Arc::clone(&amazon_connect) as Arc<dyn ConnectionAdapter>)
        {
            rollback_failed_startup(
                execution,
                None,
                Some(Arc::clone(&sip)),
                Some(webrtc),
                Arc::clone(&orchestrator),
                Arc::clone(&amazon_connect),
                setup_timeout,
            )
            .await;
            return Err(error).context("registering generic Amazon Connect adapter");
        }

        tracing::info!(
            %sip_addr,
            %ws_addr,
            %whip_addr,
            secure_signaling,
            admission_capacity,
            "authenticated generic SIP/WebRTC call execution runtime started"
        );
        Ok(Arc::new(Self {
            orchestrator,
            sip,
            sip_security_evidence: Mutex::new(sip_security_evidence),
            webrtc: Mutex::new(Some(webrtc)),
            execution: Mutex::new(Some(execution)),
            amazon_connect,
            sip_addr,
            ws_addr,
            whip_addr,
        }))
    }

    pub async fn shutdown(&self, deadline: Duration) {
        let deadline_at = tokio::time::Instant::now() + deadline;
        // Stop policy admission first but keep the operational consumer alive
        // while listeners and their live routes emit terminal events.
        if let Some(supervisor) = self.execution.lock().await.as_ref() {
            supervisor.begin_drain();
        }
        self.amazon_connect.begin_drain();
        let webrtc = self.webrtc.lock().await.take();
        let listener_budget = shutdown_budget(deadline_at);
        if tokio::time::timeout(listener_budget, async {
            let webrtc_shutdown = async {
                if let Some(server) = webrtc {
                    server.shutdown_with_deadline(listener_budget).await;
                }
            };
            let sip_shutdown = async {
                if let Err(error) = self.sip.drain(listener_budget).await {
                    tracing::warn!(%error, "generic SIP profile pool did not drain cleanly");
                }
            };
            tokio::join!(webrtc_shutdown, sip_shutdown);
        })
        .await
        .is_err()
        {
            tracing::warn!("public signaling listeners exceeded the shutdown deadline");
        }
        if let Some(observer) = self.sip_security_evidence.lock().await.take() {
            observer.shutdown(shutdown_budget(deadline_at)).await;
        }
        // Keep the correctness receiver alive through listener teardown, then
        // stop its actors before aborting rvoip normalization tasks. Reversing
        // these two waits can deadlock shutdown when an actor is blocked on a
        // durable store while a lifecycle task is backpressured on that
        // actor's full operational mailbox.
        if let Some(supervisor) = self.execution.lock().await.take() {
            supervisor.shutdown(shutdown_budget(deadline_at)).await;
        }
        let _ = self
            .amazon_connect
            .drain_until(
                std::time::Instant::now()
                    .checked_add(shutdown_budget(deadline_at))
                    .unwrap_or_else(std::time::Instant::now),
            )
            .await;
        if tokio::time::timeout(
            shutdown_budget(deadline_at),
            self.orchestrator.drain_prepared_outbound_connections(),
        )
        .await
        .is_err()
        {
            tracing::warn!("prepared outbound drain exceeded the shutdown deadline");
        }
        if tokio::time::timeout(
            shutdown_budget(deadline_at),
            self.orchestrator.drain_connection_lifecycle_tasks(),
        )
        .await
        .is_err()
        {
            tracing::warn!("rvoip lifecycle drain exceeded the shutdown deadline");
        }
    }
}

async fn build_profiled_sip_adapter(
    default: Arc<SipAdapter>,
    profiles: Vec<SipEgressProfileConfig>,
    timeout: Duration,
) -> Result<Arc<ProfiledSipAdapter>> {
    let mut registrations = Vec::with_capacity(profiles.len());
    for profile in profiles {
        match SipEgressProfileRegistration::from_config_and_nat(
            profile.revision,
            profile.stack,
            profile.nat,
            profile.allowed_initial_headers,
            profile.sip_message,
        )
        .await
        {
            Ok(registration) => registrations.push(registration),
            Err(error) => {
                for registration in registrations {
                    let _ = registration.shutdown(timeout).await;
                }
                return Err(anyhow!(error));
            }
        }
    }
    ProfiledSipAdapter::new(default, registrations).map_err(|error| anyhow!(error))
}

async fn rollback_failed_startup(
    execution: CallExecutionSupervisor,
    coordinator: Option<Arc<UnifiedCoordinator>>,
    sip: Option<Arc<ProfiledSipAdapter>>,
    webrtc: Option<WebRtcServer>,
    orchestrator: Arc<Orchestrator>,
    amazon_connect: Arc<AmazonConnectAdapter>,
    timeout: Duration,
) {
    let deadline_at = tokio::time::Instant::now() + timeout;
    execution.begin_drain();
    amazon_connect.begin_drain();

    let listener_budget = shutdown_budget(deadline_at);
    let webrtc_shutdown = async move {
        if let Some(server) = webrtc {
            server.shutdown_with_deadline(listener_budget).await;
        }
    };
    let sip_shutdown = async move {
        if let Some(sip) = sip {
            if sip.drain(listener_budget).await.is_err() {
                tracing::warn!("generic SIP profile-pool startup rollback did not drain cleanly");
            }
        } else if let Some(coordinator) = coordinator {
            if coordinator
                .shutdown_gracefully(Some(listener_budget))
                .await
                .is_err()
            {
                tracing::warn!("generic SIP startup rollback did not drain cleanly");
            }
        }
    };
    if tokio::time::timeout(listener_budget, async {
        tokio::join!(webrtc_shutdown, sip_shutdown);
    })
    .await
    .is_err()
    {
        tracing::warn!("generic signaling startup rollback exceeded its deadline");
    }

    execution.shutdown(shutdown_budget(deadline_at)).await;
    let _ = amazon_connect
        .drain_until(
            std::time::Instant::now()
                .checked_add(shutdown_budget(deadline_at))
                .unwrap_or_else(std::time::Instant::now),
        )
        .await;
    let _ = tokio::time::timeout(
        shutdown_budget(deadline_at),
        orchestrator.drain_prepared_outbound_connections(),
    )
    .await;
    let _ = tokio::time::timeout(
        shutdown_budget(deadline_at),
        orchestrator.drain_connection_lifecycle_tasks(),
    )
    .await;
}

fn shutdown_budget(deadline: tokio::time::Instant) -> Duration {
    deadline.saturating_duration_since(tokio::time::Instant::now())
}

fn sip_inbound_context_policy(context: &ContextPolicy) -> Result<SipInboundContextPolicy> {
    context
        .validate()
        .context("validating Bridgefu context policy for SIP admission")?;
    // The rvoip SIP boundary reserves its own and Bridgefu's internal
    // namespaces. Those names may still be configured for outbound context or
    // sanitized broadcast policy, but an untrusted inbound INVITE can never
    // assert them. Ordinary allowlisted X-* application headers remain
    // duplicate-preserving signaling metadata on the principal-bound context.
    let inbound_names = context.allow_headers.keys().filter(|name| {
        let normalized = name.to_ascii_lowercase();
        normalized != "x-bridgefu"
            && normalized != "x-rvoip"
            && !normalized.starts_with("x-bridgefu-")
            && !normalized.starts_with("x-rvoip-")
    });
    SipInboundContextPolicy::new(inbound_names)
        .map_err(|error| anyhow!(error))
        .context("constructing SIP inbound context allowlist")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    #[test]
    fn inbound_sip_context_captures_only_safe_application_headers() {
        let context = ContextPolicy {
            allow_headers: BTreeMap::from([
                ("X-Correlation-Id".into(), "correlation_id".into()),
                ("X-Account-Tier".into(), "account_tier".into()),
                ("X-Bridgefu-Event".into(), "broadcast_event".into()),
            ]),
            ..ContextPolicy::default()
        };
        let policy = sip_inbound_context_policy(&context).unwrap();
        assert_eq!(policy.allowed_header_count(), 2);
    }

    #[test]
    fn invalid_bridgefu_context_policy_never_reaches_sip_listener_startup() {
        let context = ContextPolicy {
            allow_headers: BTreeMap::from([("Authorization".into(), "credential".into())]),
            ..ContextPolicy::default()
        };
        assert!(sip_inbound_context_policy(&context).is_err());
    }
}
