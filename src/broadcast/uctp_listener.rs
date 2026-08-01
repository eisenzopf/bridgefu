//! Public receive-only UCTP broadcast listener installation.
//!
//! TLS certificates, UDP binding, and ALPN dispatch are deployment concerns,
//! so callers provide a fully constructed [`UctpQuicConfig`]. This installer
//! always replaces its authentication, Session authorization, subscription,
//! and Orchestrator fields with Bridgefu's shared broadcast authorities. A
//! caller therefore cannot accidentally publish an advertised endpoint that
//! bypasses token, tenant, replay, or broadcast ownership checks.

use std::fmt;
use std::fs::File;
use std::io::{BufReader, Read};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use rvoip_auth_core::BearerValidator;
use rvoip_core::adapter::ConnectionAdapter;
use rvoip_core::{Orchestrator, RvoipError};
use rvoip_quic::{UctpQuicAdapter, UctpQuicConfig, UctpQuicError};
use rvoip_uctp::state::{
    OrchestratorSubscriptionHandler, SessionBindingResolver, SubscriptionHandler,
};

use super::{BroadcastSessionResolver, BroadcastTokenService};

/// Installed public raw-QUIC listener. The caller retains ownership of the
/// prebuilt endpoint and ALPN dispatcher; this value owns only admission into
/// the shared Orchestrator.
pub struct PublicUctpBroadcastListener {
    adapter: Arc<UctpQuicAdapter>,
    owned_endpoint: Option<Arc<quinn::Endpoint>>,
}

#[derive(Clone)]
pub struct PublicUctpBindConfig {
    pub bind: SocketAddr,
    pub certificate_chain: Vec<PathBuf>,
    pub private_key: PathBuf,
    pub max_concurrent_connections: usize,
}

impl fmt::Debug for PublicUctpBindConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PublicUctpBindConfig")
            .field("bind", &self.bind)
            .field("certificate_chain_files", &self.certificate_chain.len())
            .field(
                "private_key_configured",
                &!self.private_key.as_os_str().is_empty(),
            )
            .field(
                "max_concurrent_connections",
                &self.max_concurrent_connections,
            )
            .finish()
    }
}

impl fmt::Debug for PublicUctpBroadcastListener {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PublicUctpBroadcastListener")
            .field("local_addr", &self.adapter.local_addr())
            .field("draining", &self.adapter.is_draining())
            .finish_non_exhaustive()
    }
}

impl PublicUctpBroadcastListener {
    /// Install Bridgefu's mandatory public-listener authorities into an
    /// ALPN-filtered raw-QUIC receiver and register the resulting adapter with
    /// the supplied Orchestrator.
    pub async fn install(
        orchestrator: Arc<Orchestrator>,
        tokens: Arc<BroadcastTokenService>,
        config: UctpQuicConfig,
    ) -> Result<Arc<Self>, PublicUctpListenerError> {
        Self::install_inner(orchestrator, tokens, config, None).await
    }

    /// Bind a dedicated production-shaped UDP/QUIC endpoint from PEM TLS
    /// material, install the mandatory Bridgefu authorities, and retain
    /// ownership so shutdown closes the socket and active peers.
    pub async fn bind(
        orchestrator: Arc<Orchestrator>,
        tokens: Arc<BroadcastTokenService>,
        bind: PublicUctpBindConfig,
    ) -> Result<Arc<Self>, PublicUctpListenerError> {
        if bind.max_concurrent_connections == 0 || bind.certificate_chain.is_empty() {
            return Err(PublicUctpListenerError::InvalidConfiguration);
        }
        let _ = rustls::crypto::ring::default_provider().install_default();
        let mut tls = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(
                load_certificate_chain(&bind.certificate_chain)?,
                load_private_key(&bind.private_key)?,
            )
            .map_err(|_| PublicUctpListenerError::TlsConfiguration)?;
        tls.alpn_protocols = vec![rvoip_uctp::UCTP_RAW_QUIC_ALPN_BYTES.to_vec()];
        let endpoint = Arc::new(rvoip_uctp::substrate::make_server_endpoint(
            bind.bind,
            Arc::new(tls),
            quinn::TransportConfig::default(),
        )?);
        let mut routes = rvoip_uctp::substrate::dispatch_by_alpn(
            Arc::clone(&endpoint),
            &[rvoip_uctp::UCTP_RAW_QUIC_ALPN_BYTES],
        )?;
        let accept_rx = routes
            .take(rvoip_uctp::UCTP_RAW_QUIC_ALPN_BYTES)
            .ok_or(PublicUctpListenerError::InvalidConfiguration)?;
        let validator: Arc<dyn BearerValidator> = tokens.clone();
        let mut config = UctpQuicConfig::new(Arc::clone(&endpoint), accept_rx, validator);
        config.max_concurrent_connections = bind.max_concurrent_connections;
        Self::install_inner(orchestrator, tokens, config, Some(endpoint)).await
    }

    async fn install_inner(
        orchestrator: Arc<Orchestrator>,
        tokens: Arc<BroadcastTokenService>,
        mut config: UctpQuicConfig,
        owned_endpoint: Option<Arc<quinn::Endpoint>>,
    ) -> Result<Arc<Self>, PublicUctpListenerError> {
        let validator: Arc<dyn BearerValidator> = tokens.clone();
        let subscriptions: Arc<dyn SubscriptionHandler> = OrchestratorSubscriptionHandler::new(
            Arc::clone(&orchestrator),
            orchestrator.publisher_registry(),
        );
        let resolver: Arc<dyn SessionBindingResolver> =
            BroadcastSessionResolver::new(tokens.grants());

        // These fields are intentionally overwritten rather than filled only
        // when absent. Public admission must never inherit a permissive test
        // validator, peer-scoped resolver, or handler from the endpoint owner.
        config.bearer_validator = validator;
        config.subscription_handler = Some(subscriptions);
        config.session_binding_resolver = Some(resolver);
        config.orchestrator = Some(Arc::clone(&orchestrator));

        let adapter = UctpQuicAdapter::new(config).await?;
        if let Err(error) =
            orchestrator.register(Arc::clone(&adapter) as Arc<dyn ConnectionAdapter>)
        {
            adapter.begin_drain();
            return Err(error.into());
        }
        Ok(Arc::new(Self {
            adapter,
            owned_endpoint,
        }))
    }

    pub fn local_addr(&self) -> SocketAddr {
        self.adapter.local_addr()
    }

    pub fn adapter(&self) -> Arc<UctpQuicAdapter> {
        Arc::clone(&self.adapter)
    }

    /// Stop admitting new peers. Existing authenticated listeners retain
    /// their routes until they close, expire, or lose broadcast authority.
    pub fn begin_drain(&self) {
        self.adapter.begin_drain();
    }

    pub fn is_draining(&self) -> bool {
        self.adapter.is_draining()
    }

    pub async fn shutdown(&self) {
        self.begin_drain();
        if let Some(endpoint) = &self.owned_endpoint {
            endpoint.close(0u32.into(), b"bridgefu public UCTP listener shutdown");
            endpoint.wait_idle().await;
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum PublicUctpListenerError {
    #[error("public UCTP listener configuration is invalid")]
    InvalidConfiguration,
    #[error("public UCTP listener TLS configuration is invalid")]
    TlsConfiguration,
    #[error("failed to bind or dispatch the public UCTP endpoint")]
    Substrate(#[from] rvoip_uctp::errors::SubstrateError),
    #[error("failed to create the public UCTP adapter")]
    Adapter(#[from] UctpQuicError),
    #[error("failed to register the public UCTP adapter")]
    Orchestrator(#[from] RvoipError),
}

fn load_certificate_chain(
    paths: &[PathBuf],
) -> Result<Vec<rustls::pki_types::CertificateDer<'static>>, PublicUctpListenerError> {
    let mut certificates = Vec::new();
    for path in paths {
        let file = File::open(path).map_err(|_| PublicUctpListenerError::TlsConfiguration)?;
        let mut reader = BufReader::new(file);
        certificates.extend(
            rustls_pemfile::certs(&mut reader)
                .collect::<Result<Vec<_>, _>>()
                .map_err(|_| PublicUctpListenerError::TlsConfiguration)?,
        );
    }
    if certificates.is_empty() {
        return Err(PublicUctpListenerError::TlsConfiguration);
    }
    Ok(certificates)
}

fn load_private_key(
    path: &Path,
) -> Result<rustls::pki_types::PrivateKeyDer<'static>, PublicUctpListenerError> {
    let mut bytes = Vec::new();
    File::open(path)
        .and_then(|mut file| file.read_to_end(&mut bytes))
        .map_err(|_| PublicUctpListenerError::TlsConfiguration)?;
    rustls_pemfile::private_key(&mut bytes.as_slice())
        .map_err(|_| PublicUctpListenerError::TlsConfiguration)?
        .ok_or(PublicUctpListenerError::TlsConfiguration)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    use base64::engine::general_purpose::STANDARD;
    use base64::Engine;
    use chrono::Utc;
    use rvoip_core::events::Event;
    use rvoip_quic::UctpQuicClient;
    use rvoip_uctp::envelope::UctpEnvelope;
    use rvoip_uctp::payloads::{auth, session};
    use rvoip_uctp::substrate::{
        dev_client_config_trusting, dispatch_by_alpn, make_client_endpoint, make_server_endpoint,
        self_signed_for_dev,
    };
    use rvoip_uctp::types::MessageType;
    use rvoip_uctp::UCTP_RAW_QUIC_ALPN_BYTES;
    use uuid::Uuid;

    fn pem(label: &str, bytes: &[u8]) -> String {
        let encoded = STANDARD.encode(bytes);
        let mut output = format!("-----BEGIN {label}-----\n");
        for line in encoded.as_bytes().chunks(64) {
            output.push_str(std::str::from_utf8(line).unwrap());
            output.push('\n');
        }
        output.push_str(&format!("-----END {label}-----\n"));
        output
    }

    fn envelope(msg_type: MessageType, payload: serde_json::Value) -> UctpEnvelope {
        UctpEnvelope {
            v: 1,
            msg_type,
            id: format!("env-{}", Uuid::new_v4()),
            ts: Utc::now(),
            cid: None,
            sid: None,
            connid: None,
            in_reply_to: None,
            payload,
            signature: None,
        }
    }

    async fn authenticate(
        client: &UctpQuicClient,
        inbound: &mut tokio::sync::mpsc::Receiver<UctpEnvelope>,
        credential: &str,
    ) -> MessageType {
        client
            .send(envelope(
                MessageType::AuthHello,
                serde_json::to_value(auth::AuthHello {
                    device: auth::Device {
                        id: "bridgefu-listener-test".into(),
                        kind: "service".into(),
                        platform: "test".into(),
                        sdk_version: "bridgefu-test/1".into(),
                    },
                    auth_methods: vec!["bearer".into()],
                    capabilities: serde_json::Value::Object(Default::default()),
                })
                .unwrap(),
            ))
            .await
            .unwrap();
        let challenge = tokio::time::timeout(Duration::from_secs(2), inbound.recv())
            .await
            .expect("auth challenge timeout")
            .expect("auth channel closed");
        assert_eq!(challenge.msg_type, MessageType::AuthChallenge);
        let mut response = envelope(
            MessageType::AuthResponse,
            serde_json::to_value(auth::AuthResponse {
                method: "bearer".into(),
                credential: credential.into(),
                actor_token: None,
            })
            .unwrap(),
        );
        response.in_reply_to = Some(challenge.id);
        client.send(response).await.unwrap();
        tokio::time::timeout(Duration::from_secs(2), inbound.recv())
            .await
            .expect("auth result timeout")
            .expect("auth channel closed")
            .msg_type
    }

    async fn connect(
        endpoint: &quinn::Endpoint,
        server: SocketAddr,
        certificate: &rustls::pki_types::CertificateDer<'static>,
    ) -> (
        Arc<UctpQuicClient>,
        tokio::sync::mpsc::Receiver<UctpEnvelope>,
    ) {
        let tls = dev_client_config_trusting(certificate).unwrap();
        let client = UctpQuicClient::connect(endpoint, server, "localhost", Arc::new(tls))
            .await
            .unwrap();
        let inbound = client.take_inbound().unwrap();
        (client, inbound)
    }

    #[tokio::test]
    async fn public_listener_overwrites_permissive_authority_and_enforces_replay_and_revocation() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let (certificate, private_key) = self_signed_for_dev(&["localhost".into()]).unwrap();
        let mut server_tls = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![certificate.clone()], private_key)
            .unwrap();
        server_tls.alpn_protocols = vec![UCTP_RAW_QUIC_ALPN_BYTES.to_vec()];
        let server_endpoint = Arc::new(
            make_server_endpoint(
                "127.0.0.1:0".parse().unwrap(),
                Arc::new(server_tls),
                quinn::TransportConfig::default(),
            )
            .unwrap(),
        );
        let mut alpn =
            dispatch_by_alpn(Arc::clone(&server_endpoint), &[UCTP_RAW_QUIC_ALPN_BYTES]).unwrap();
        let accept_rx = alpn.take(UCTP_RAW_QUIC_ALPN_BYTES).unwrap();

        let grants = super::super::BroadcastGrantRegistry::new();
        let lease = grants
            .register(
                "tenant-a",
                "broadcast-a",
                super::super::BroadcastGrantTransport::UctpQuic,
                Utc::now() + chrono::Duration::minutes(2),
            )
            .unwrap();
        let tokens = Arc::new(
            BroadcastTokenService::new(
                b"0123456789abcdef0123456789abcdef".to_vec(),
                grants,
                Duration::from_secs(120),
            )
            .unwrap(),
        );
        let issued = tokens
            .issue("tenant-a", "broadcast-a", Duration::from_secs(60))
            .unwrap();
        let orchestrator = Orchestrator::new(rvoip_core::Config::default());
        let mut events = orchestrator.subscribe_events();
        let config = UctpQuicConfig::new(
            Arc::clone(&server_endpoint),
            accept_rx,
            rvoip_auth_core::bearer_stub(),
        );
        let listener = PublicUctpBroadcastListener::install(
            Arc::clone(&orchestrator),
            Arc::clone(&tokens),
            config,
        )
        .await
        .unwrap();

        let client_tls =
            Arc::new(dev_client_config_trusting(&certificate).expect("client trust configuration"));
        let client_endpoint =
            make_client_endpoint("127.0.0.1:0".parse().unwrap(), client_tls).unwrap();

        // The caller supplied bearer_stub(), which accepts any non-empty
        // credential. Rejection here proves the installer replaced it.
        let (invalid, mut invalid_inbound) =
            connect(&client_endpoint, listener.local_addr(), &certificate).await;
        assert_eq!(
            authenticate(&invalid, &mut invalid_inbound, "permissive-stub-token").await,
            MessageType::Error
        );
        invalid
            .connection
            .close(0u32.into(), b"invalid test complete");

        let (first, mut first_inbound) =
            connect(&client_endpoint, listener.local_addr(), &certificate).await;
        assert_eq!(
            authenticate(&first, &mut first_inbound, &issued.token).await,
            MessageType::AuthSession
        );
        let (replay, mut replay_inbound) =
            connect(&client_endpoint, listener.local_addr(), &certificate).await;
        assert_eq!(
            authenticate(&replay, &mut replay_inbound, &issued.token).await,
            MessageType::AuthSession
        );

        let invite = |id: &str| {
            let mut envelope = envelope(
                MessageType::SessionInvite,
                serde_json::to_value(session::SessionInvite {
                    from: "listener".into(),
                    to: vec!["broadcast".into()],
                    medium: "voice".into(),
                    intent: "broadcast-subscribe".into(),
                    capabilities_offer: serde_json::Value::Object(Default::default()),
                })
                .unwrap(),
            );
            envelope.id = id.to_string();
            envelope.sid = Some("broadcast-a".into());
            envelope
        };
        first.send(invite("first-invite")).await.unwrap();
        loop {
            let event = tokio::time::timeout(Duration::from_secs(2), events.recv())
                .await
                .expect("inbound event timeout")
                .expect("event stream closed");
            if matches!(event, Event::ConnectionInbound { .. }) {
                break;
            }
        }

        replay.send(invite("replayed-invite")).await.unwrap();
        let replay_error = tokio::time::timeout(Duration::from_secs(2), replay_inbound.recv())
            .await
            .expect("replay rejection timeout")
            .expect("replay peer closed before protocol error");
        assert_eq!(replay_error.msg_type, MessageType::Error);

        assert!(lease.revoke());
        tokio::time::timeout(Duration::from_secs(2), first.connection.closed())
            .await
            .expect("revoked bound listener must be closed by the authority guard");

        listener.begin_drain();
        assert!(listener.is_draining());
        replay.connection.close(0u32.into(), b"test complete");
        server_endpoint.close(0u32.into(), b"test complete");
    }

    #[tokio::test]
    async fn dedicated_listener_binds_pem_tls_and_owns_clean_shutdown() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let (certificate, private_key) = self_signed_for_dev(&["localhost".into()]).unwrap();
        let root = std::env::temp_dir().join(format!("bridgefu-uctp-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&root).unwrap();
        let certificate_path = root.join("server.pem");
        let private_key_path = root.join("server.key");
        std::fs::write(&certificate_path, pem("CERTIFICATE", certificate.as_ref())).unwrap();
        std::fs::write(
            &private_key_path,
            pem("PRIVATE KEY", private_key.secret_der()),
        )
        .unwrap();

        let grants = super::super::BroadcastGrantRegistry::new();
        let tokens = Arc::new(
            BroadcastTokenService::new(
                b"0123456789abcdef0123456789abcdef".to_vec(),
                grants,
                Duration::from_secs(60),
            )
            .unwrap(),
        );
        let listener = PublicUctpBroadcastListener::bind(
            Orchestrator::new(rvoip_core::Config::default()),
            tokens,
            PublicUctpBindConfig {
                bind: "127.0.0.1:0".parse().unwrap(),
                certificate_chain: vec![certificate_path],
                private_key: private_key_path,
                max_concurrent_connections: 4,
            },
        )
        .await
        .unwrap();
        assert_ne!(listener.local_addr().port(), 0);
        listener.shutdown().await;
        assert!(listener.is_draining());
        std::fs::remove_dir_all(root).unwrap();
    }
}
