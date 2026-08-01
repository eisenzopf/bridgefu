//! Runtime-only outbound profile material.
//!
//! Durable call plans retain only a profile ID and non-secret revision. This
//! module joins that identity to configured secret references immediately
//! before an adapter context is prepared. No credential is serialized into a
//! call, command, log, metric, or repository row.

use std::collections::BTreeMap;
use std::fmt;
use std::sync::Arc;

use rvoip_sip::{SipClientAuth, SipOriginateContext, SipProfileRevision};
use rvoip_webrtc::{
    IceServerConfig, StaticWebRtcBearerCredentialProvider, WebRtcAudioCodec,
    WebRtcBearerCredential, WebRtcBearerCredentialProvider, WebRtcOriginateContext,
    WebRtcTlsClientTrust,
};
use thiserror::Error;
use zeroize::{Zeroize, Zeroizing};

use super::{NamedProfileKind, NamedProfileRole, NamedRouteBinding};
use crate::secret_ref::SecretRef;

/// Fixed, credential-free failure returned at the execution boundary.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum OutboundProfileError {
    /// A durable named-profile identity is unavailable in this process.
    #[error("the named outbound profile is not installed")]
    NotInstalled,
    /// Resolved SIP material failed the rvoip context boundary.
    #[error("the named SIP profile is invalid")]
    InvalidSipProfile,
    /// Resolved WebRTC material failed the rvoip context boundary.
    #[error("the named WebRTC profile is invalid")]
    InvalidWebRtcProfile,
    /// A secret reference or file-backed trust bundle was unavailable at the
    /// moment an owned signaling effect tried to use it.
    #[error("the named outbound profile material is unavailable")]
    MaterialUnavailable,
}

/// Applies execution-resolved, non-durable profile material to adapter contexts.
pub trait OutboundProfileResolver: Send + Sync {
    fn apply_sip(
        &self,
        route: Option<&NamedRouteBinding>,
        context: SipOriginateContext,
    ) -> Result<SipOriginateContext, OutboundProfileError>;

    fn apply_webrtc(
        &self,
        route: Option<&NamedRouteBinding>,
        context: WebRtcOriginateContext,
    ) -> Result<WebRtcOriginateContext, OutboundProfileError>;
}

/// Compatibility resolver for advanced calls and historical routes. A route
/// that explicitly retained a SIP/WebRTC destination profile fails closed.
#[derive(Default)]
pub struct DisabledOutboundProfileResolver;

impl OutboundProfileResolver for DisabledOutboundProfileResolver {
    fn apply_sip(
        &self,
        route: Option<&NamedRouteBinding>,
        context: SipOriginateContext,
    ) -> Result<SipOriginateContext, OutboundProfileError> {
        if destination_profile(route, NamedProfileKind::Sip).is_some() {
            Err(OutboundProfileError::NotInstalled)
        } else {
            Ok(context)
        }
    }

    fn apply_webrtc(
        &self,
        route: Option<&NamedRouteBinding>,
        context: WebRtcOriginateContext,
    ) -> Result<WebRtcOriginateContext, OutboundProfileError> {
        if destination_profile(route, NamedProfileKind::WebRtc).is_some() {
            Err(OutboundProfileError::NotInstalled)
        } else {
            Ok(context)
        }
    }
}

#[derive(Clone)]
#[doc(hidden)]
pub enum ConfiguredSipProfileAuth {
    Digest {
        realm: Option<String>,
        username: String,
        password: SecretRef,
    },
    Bearer {
        token: SecretRef,
    },
}

impl fmt::Debug for ConfiguredSipProfileAuth {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Digest { realm, .. } => formatter
                .debug_struct("Digest")
                .field("realm_present", &realm.is_some())
                .field("credentials", &"[redacted]")
                .finish(),
            Self::Bearer { .. } => formatter.write_str("Bearer([redacted])"),
        }
    }
}

#[derive(Clone)]
#[doc(hidden)]
pub struct ConfiguredSipOutboundProfile {
    pub from_uri: String,
    pub outbound_proxy: Option<String>,
    pub auth: Option<ConfiguredSipProfileAuth>,
}

impl fmt::Debug for ConfiguredSipOutboundProfile {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ConfiguredSipOutboundProfile")
            .field("from_uri", &"[redacted]")
            .field("outbound_proxy_present", &self.outbound_proxy.is_some())
            .field("auth", &self.auth)
            .finish()
    }
}

#[derive(Clone)]
#[doc(hidden)]
pub struct ConfiguredIceServer {
    pub urls: Vec<String>,
    pub username: Option<String>,
    pub credential: Option<SecretRef>,
}

#[derive(Clone)]
#[doc(hidden)]
pub struct ConfiguredWebRtcOutboundProfile {
    pub bearer_token: Option<SecretRef>,
    pub tls_roots: Vec<String>,
    pub ice_servers: Vec<ConfiguredIceServer>,
    pub audio_codecs: Vec<WebRtcAudioCodec>,
    pub data_channels: bool,
}

impl fmt::Debug for ConfiguredWebRtcOutboundProfile {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ConfiguredWebRtcOutboundProfile")
            .field("bearer_present", &self.bearer_token.is_some())
            .field("ice_server_count", &self.ice_servers.len())
            .field("tls_root_count", &self.tls_roots.len())
            .field("audio_codec_count", &self.audio_codecs.len())
            .field("data_channels", &self.data_channels)
            .finish()
    }
}

/// Immutable catalog built once from validated configuration.
#[derive(Default)]
#[doc(hidden)]
pub struct StaticOutboundProfileResolver {
    sip: BTreeMap<(String, String), ConfiguredSipOutboundProfile>,
    webrtc: BTreeMap<(String, String), ConfiguredWebRtcOutboundProfile>,
}

impl StaticOutboundProfileResolver {
    pub fn insert_sip(
        &mut self,
        profile_id: String,
        revision: String,
        profile: ConfiguredSipOutboundProfile,
    ) {
        self.sip.entry((profile_id, revision)).or_insert(profile);
    }

    pub fn insert_webrtc(
        &mut self,
        profile_id: String,
        revision: String,
        profile: ConfiguredWebRtcOutboundProfile,
    ) {
        self.webrtc.entry((profile_id, revision)).or_insert(profile);
    }

    #[cfg(test)]
    fn counts(&self) -> (usize, usize) {
        (self.sip.len(), self.webrtc.len())
    }
}

impl OutboundProfileResolver for StaticOutboundProfileResolver {
    fn apply_sip(
        &self,
        route: Option<&NamedRouteBinding>,
        mut context: SipOriginateContext,
    ) -> Result<SipOriginateContext, OutboundProfileError> {
        let Some(binding) = destination_profile(route, NamedProfileKind::Sip) else {
            return Ok(context);
        };
        let profile = self
            .sip
            .get(&(
                binding.profile_id().to_owned(),
                binding.revision().to_owned(),
            ))
            .ok_or(OutboundProfileError::NotInstalled)?;
        let revision = SipProfileRevision::new(binding.revision().to_owned())
            .map_err(|_| OutboundProfileError::InvalidSipProfile)?;
        context = context.with_profile_revision(revision);
        context = context
            .with_from_uri(profile.from_uri.clone())
            .map_err(|_| OutboundProfileError::InvalidSipProfile)?;
        if let Some(proxy) = &profile.outbound_proxy {
            context = context
                .with_outbound_proxy(proxy.clone())
                .map_err(|_| OutboundProfileError::InvalidSipProfile)?;
        }
        if let Some(auth) = &profile.auth {
            let auth = match auth {
                ConfiguredSipProfileAuth::Digest {
                    realm,
                    username,
                    password,
                } => {
                    let password = Zeroizing::new(
                        password
                            .resolve()
                            .map_err(|_| OutboundProfileError::MaterialUnavailable)?,
                    );
                    let credentials =
                        rvoip_sip::types::Credentials::new(username.as_str(), password.as_str());
                    let credentials = match realm {
                        Some(realm) => credentials.with_realm(realm.clone()),
                        None => credentials,
                    };
                    SipClientAuth::Digest(credentials)
                }
                ConfiguredSipProfileAuth::Bearer { token } => {
                    let token = Zeroizing::new(
                        token
                            .resolve()
                            .map_err(|_| OutboundProfileError::MaterialUnavailable)?,
                    );
                    SipClientAuth::bearer_token(token.as_str())
                }
            };
            context = context
                .with_auth(auth)
                .map_err(|_| OutboundProfileError::InvalidSipProfile)?;
        }
        Ok(context)
    }

    fn apply_webrtc(
        &self,
        route: Option<&NamedRouteBinding>,
        mut context: WebRtcOriginateContext,
    ) -> Result<WebRtcOriginateContext, OutboundProfileError> {
        let Some(binding) = destination_profile(route, NamedProfileKind::WebRtc) else {
            return Ok(context);
        };
        let profile = self
            .webrtc
            .get(&(
                binding.profile_id().to_owned(),
                binding.revision().to_owned(),
            ))
            .ok_or(OutboundProfileError::NotInstalled)?;
        if let Some(token) = &profile.bearer_token {
            let token = Zeroizing::new(
                token
                    .resolve()
                    .map_err(|_| OutboundProfileError::MaterialUnavailable)?,
            );
            let credential = WebRtcBearerCredential::new(token.as_str())
                .map_err(|_| OutboundProfileError::InvalidWebRtcProfile)?;
            let provider: Arc<dyn WebRtcBearerCredentialProvider> =
                Arc::new(StaticWebRtcBearerCredentialProvider::new(credential));
            context = context.with_bearer_provider(provider);
        }
        if !profile.tls_roots.is_empty() {
            let mut pem = Vec::new();
            for path in &profile.tls_roots {
                let mut part =
                    std::fs::read(path).map_err(|_| OutboundProfileError::MaterialUnavailable)?;
                pem.append(&mut part);
                pem.push(b'\n');
            }
            let trust = WebRtcTlsClientTrust::from_pem(&pem);
            pem.zeroize();
            let trust = trust.map_err(|_| OutboundProfileError::InvalidWebRtcProfile)?;
            context = context.with_tls_trust(Arc::new(trust));
        }
        let mut ice_servers = Vec::with_capacity(profile.ice_servers.len());
        for configured in &profile.ice_servers {
            let credential = configured
                .credential
                .as_ref()
                .map(SecretRef::resolve)
                .transpose()
                .map_err(|_| OutboundProfileError::MaterialUnavailable)?;
            ice_servers.push(IceServerConfig {
                urls: configured.urls.clone(),
                username: configured.username.clone(),
                credential,
            });
        }
        context = context
            .with_ice_servers(ice_servers)
            .map_err(|_| OutboundProfileError::InvalidWebRtcProfile)?;
        context = context
            .with_audio_codecs(profile.audio_codecs.iter().copied())
            .map_err(|_| OutboundProfileError::InvalidWebRtcProfile)?;
        Ok(context.with_data_channels(profile.data_channels))
    }
}

fn destination_profile(
    route: Option<&NamedRouteBinding>,
    kind: NamedProfileKind,
) -> Option<&super::NamedProfileBinding> {
    route?
        .profiles()
        .iter()
        .find(|profile| profile.role() == NamedProfileRole::Destination && profile.kind() == kind)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::call_service::{NamedProfileBinding, NamedRouteCallContext};

    fn route(kind: NamedProfileKind, revision: &str) -> NamedRouteBinding {
        NamedRouteBinding::new_with_profiles(
            "support",
            None::<NamedRouteCallContext>,
            vec![NamedProfileBinding::new(
                NamedProfileRole::Destination,
                kind,
                "primary",
                revision,
            )
            .unwrap()],
        )
        .unwrap()
    }

    #[test]
    fn disabled_resolver_fails_closed_only_for_explicit_profiles() {
        let resolver = DisabledOutboundProfileResolver;
        assert!(resolver.apply_sip(None, SipOriginateContext::new()).is_ok());
        assert_eq!(
            resolver
                .apply_sip(
                    Some(&route(NamedProfileKind::Sip, &"a".repeat(64))),
                    SipOriginateContext::new(),
                )
                .unwrap_err(),
            OutboundProfileError::NotInstalled
        );
    }

    #[test]
    fn static_sip_profile_requires_exact_revision_and_applies_policy() {
        let revision = "b".repeat(64);
        let mut resolver = StaticOutboundProfileResolver::default();
        resolver.insert_sip(
            "primary".into(),
            revision.clone(),
            ConfiguredSipOutboundProfile {
                from_uri: "sips:bridge@example.test".into(),
                outbound_proxy: Some("sips:proxy.example.test;lr".into()),
                auth: Some(ConfiguredSipProfileAuth::Digest {
                    realm: Some("example.test".into()),
                    username: "bridge".into(),
                    password: serde_yaml::from_str("secret").unwrap(),
                }),
            },
        );
        assert_eq!(resolver.counts(), (1, 0));
        let context = resolver
            .apply_sip(
                Some(&route(NamedProfileKind::Sip, &revision)),
                SipOriginateContext::new(),
            )
            .unwrap();
        assert_eq!(context.from_uri(), Some("sips:bridge@example.test"));
        assert_eq!(
            context
                .profile_revision()
                .map(SipProfileRevision::expose_opaque),
            Some(revision.as_str())
        );
        assert_eq!(
            context.outbound_proxy_uri(),
            Some("sips:proxy.example.test;lr")
        );
        assert!(context.auth().is_some());
        assert_eq!(
            resolver
                .apply_sip(
                    Some(&route(NamedProfileKind::Sip, &"c".repeat(64))),
                    SipOriginateContext::new(),
                )
                .unwrap_err(),
            OutboundProfileError::NotInstalled
        );
    }

    #[test]
    fn static_webrtc_profile_carries_codec_and_data_channel_policy() {
        let revision = "d".repeat(64);
        let mut resolver = StaticOutboundProfileResolver::default();
        resolver.insert_webrtc(
            "primary".into(),
            revision.clone(),
            ConfiguredWebRtcOutboundProfile {
                bearer_token: None,
                tls_roots: Vec::new(),
                ice_servers: Vec::new(),
                audio_codecs: vec![WebRtcAudioCodec::Opus],
                data_channels: false,
            },
        );
        let context = WebRtcOriginateContext::websocket(
            "wss://agent.example.test/call",
            rvoip_webrtc::WebRtcTargetPolicy::default(),
        )
        .expect("context");
        let context = resolver
            .apply_webrtc(Some(&route(NamedProfileKind::WebRtc, &revision)), context)
            .expect("profile applied");
        assert_eq!(
            context.audio_codecs_override(),
            Some([WebRtcAudioCodec::Opus].as_slice())
        );
        assert!(!context.data_channels_allowed());
    }
}
