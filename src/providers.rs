//! Native programmable-voice control adapters.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::future::Future;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

#[cfg(test)]
use std::time::{SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
#[cfg(test)]
use base64::Engine;
use dashmap::DashMap;
#[cfg(test)]
use hmac::{Hmac, Mac};
#[cfg(test)]
use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};
use serde::{Deserialize, Serialize};
#[cfg(test)]
use serde_json::json;
use serde_json::Value;
#[cfg(test)]
use sha1::Sha1;
#[cfg(test)]
use sha2::{Digest, Sha256};

use bridgefu::call_engine::ProviderAccountKey;
use bridgefu::call_engine::ProviderCallId;
#[cfg(test)]
use bridgefu::call_service::ProviderTransferCorrelation;
use bridgefu::call_service::{
    ConfiguredAttachmentPrincipalResolver, ProviderConnectDestinationRequest,
    ProviderDialClientState, ProviderDtmfRequest, ProviderEndpointConfig, ProviderExecutionContext,
    ProviderExecutionError, ProviderExecutionReference, ProviderHangupRequest, ProviderKind,
    ProviderLegExecutor, ProviderStartMediaRequest, ProviderTransferRequest, TransferTarget,
    MAX_PROVIDER_DIAL_CLIENT_STATE_BYTES,
};
use rvoip_auth_core::{AuthenticatedPrincipal, AuthenticationMethod};
use rvoip_core::{CredentialKind, IdentityAssurance};
use zeroize::Zeroize;

#[cfg(test)]
type HmacSha1 = Hmac<Sha1>;

const MAX_PROVIDER_EVENT_ID_BYTES: usize = 512;
const MAX_PROVIDER_EVENT_KIND_BYTES: usize = 128;
const MAX_PROVIDER_DESTINATION_BYTES: usize = 2_048;
#[cfg(test)]
const MAX_TWILIO_SEQUENCE_DIGITS: usize = 20;
const MAX_TELNYX_REQUEST_TIMEOUT_MS: u64 = 120_000;
const MAX_TELNYX_RETRIES: u32 = 5;
const TELNYX_CIRCUIT_FAILURE_THRESHOLD: u32 = 5;
const TELNYX_CIRCUIT_OPEN_DURATION: Duration = Duration::from_secs(30);

pub type SecretRef = bridgefu::secret_ref::SecretRef;

// Retain the historical tuple-like test helper without making the reusable
// secret wrapper's representation public.
#[cfg(test)]
#[allow(non_snake_case)]
fn SecretRef(value: String) -> SecretRef {
    SecretRef::new(value)
}

#[derive(Clone, Debug, Default, Deserialize)]
pub struct ProviderConfigs {
    #[serde(default)]
    pub twilio: Option<TwilioConfig>,
    #[serde(default)]
    pub telnyx: Option<TelnyxConfig>,
    #[serde(default)]
    pub vonage: Option<VonageConfig>,
}

#[derive(Clone, Debug, Deserialize)]
#[cfg_attr(not(test), allow(dead_code))]
pub struct TwilioConfig {
    #[serde(default = "default_twilio_account_profile")]
    pub account_profile: String,
    pub account_sid: String,
    pub auth_token: SecretRef,
    #[serde(default = "twilio_base_url")]
    pub base_url: String,
}

#[derive(Clone, Debug, Deserialize)]
pub struct TelnyxConfig {
    #[serde(default = "default_telnyx_account_profile")]
    pub account_profile: String,
    pub api_key: SecretRef,
    pub connection_id: String,
    pub webhook_public_key: SecretRef,
    /// E.164 or SIP caller identity used for both Telnyx Dial operations.
    pub from: String,
    /// Public Bridgefu SIP authority, without scheme, user info, or URI params.
    pub media_sip_authority: String,
    /// Digest username Telnyx presents to the Bridgefu SIP listener.
    pub media_sip_username: String,
    /// Digest password shared only with Telnyx and the Bridgefu listener.
    pub media_sip_password: SecretRef,
    /// Digest challenge realm emitted by the Bridgefu SIP listener.
    #[serde(default = "default_telnyx_media_sip_realm")]
    pub media_sip_realm: String,
    /// UDP, TCP, or TLS for the provider-to-Bridgefu SIP media call.
    #[serde(default = "default_telnyx_media_sip_transport")]
    pub media_sip_transport: String,
    /// Optional per-call webhook override; the connection profile remains the fallback.
    #[serde(default)]
    pub webhook_url: Option<String>,
    #[serde(default = "telnyx_base_url")]
    pub base_url: String,
    #[serde(default = "default_telnyx_request_timeout_ms")]
    pub request_timeout_ms: u64,
    #[serde(default = "default_telnyx_max_retries")]
    pub max_retries: u32,
}

#[derive(Clone, Debug, Deserialize)]
#[cfg_attr(not(test), allow(dead_code))]
pub struct VonageConfig {
    #[serde(default = "default_vonage_account_profile")]
    pub account_profile: String,
    pub application_id: String,
    /// PEM-encoded RSA private key or `env:VARIABLE` containing it.
    pub private_key: SecretRef,
    pub signature_secret: SecretRef,
    #[serde(default = "vonage_base_url")]
    pub base_url: String,
}

fn twilio_base_url() -> String {
    "https://api.twilio.com/2010-04-01".into()
}
fn default_twilio_account_profile() -> String {
    "twilio".into()
}
fn default_telnyx_account_profile() -> String {
    "telnyx".into()
}
fn default_vonage_account_profile() -> String {
    "vonage".into()
}
fn telnyx_base_url() -> String {
    "https://api.telnyx.com/v2".into()
}
fn default_telnyx_request_timeout_ms() -> u64 {
    15_000
}
fn default_telnyx_max_retries() -> u32 {
    2
}
fn default_telnyx_media_sip_transport() -> String {
    "UDP".into()
}
fn default_telnyx_media_sip_realm() -> String {
    "bridgefu".into()
}
fn vonage_base_url() -> String {
    "https://api.nexmo.com/v1".into()
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProviderCapabilities {
    pub originate: bool,
    pub transfer: bool,
    pub hangup: bool,
    pub dtmf: bool,
    pub bridge: bool,
    pub media: String,
}

impl Default for ProviderCapabilities {
    fn default() -> Self {
        Self {
            originate: true,
            transfer: true,
            hangup: true,
            dtmf: true,
            bridge: false,
            media: "sip-rtp".into(),
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct OriginateCommand {
    pub from: String,
    pub to: String,
    pub answer_url: Option<String>,
    pub event_url: Option<String>,
    /// Durable Bridgefu effect identifier. The Telnyx SDK is configured not
    /// to synthesize command IDs, so every retry reuses this exact value.
    pub command_id: String,
    /// Typed Bridgefu-owned state. Only adapters with a signed opaque-state
    /// callback contract may encode this at their SDK boundary.
    #[serde(default)]
    pub client_state: Option<ProviderDialClientState>,
    #[serde(default)]
    pub metadata: BTreeMap<String, String>,
    #[serde(default)]
    pub sip_auth_username: Option<String>,
    #[serde(default)]
    pub sip_auth_password: Option<String>,
    #[serde(default)]
    pub sip_transport_protocol: Option<String>,
    #[serde(default)]
    pub link_to: Option<String>,
    #[serde(default)]
    pub bridge_on_answer: Option<bool>,
}

impl fmt::Debug for OriginateCommand {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OriginateCommand")
            .field("from_bytes", &self.from.len())
            .field("to_bytes", &self.to.len())
            .field("answer_url_present", &self.answer_url.is_some())
            .field("event_url_present", &self.event_url.is_some())
            .field("command_id_bytes", &self.command_id.len())
            .field("client_state", &self.client_state)
            .field("metadata_entries", &self.metadata.len())
            .field("sip_auth_present", &self.sip_auth_username.is_some())
            .field(
                "sip_transport_present",
                &self.sip_transport_protocol.is_some(),
            )
            .field("link_present", &self.link_to.is_some())
            .field("bridge_on_answer", &self.bridge_on_answer)
            .finish()
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[cfg_attr(not(test), allow(dead_code))]
pub struct BridgeCommand {
    pub call_id: String,
    pub other_call_id: String,
    pub command_id: String,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct TransferCommand {
    pub call_id: String,
    pub target: String,
    pub command_id: String,
    /// Base64 provider state echoed on callbacks for the existing leg.
    #[serde(default)]
    pub client_state: Option<String>,
    /// The same correlation copied to callbacks for the newly created leg.
    #[serde(default)]
    pub target_leg_client_state: Option<String>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct HangupCommand {
    pub call_id: String,
    pub command_id: String,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct DtmfCommand {
    pub call_id: String,
    pub digits: String,
    pub command_id: String,
}

macro_rules! redacted_provider_command_debug {
    ($type:ty, $name:literal, $($field:ident),+ $(,)?) => {
        impl fmt::Debug for $type {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                let mut debug = formatter.debug_struct($name);
                $(debug.field(concat!(stringify!($field), "_bytes"), &self.$field.len());)+
                debug.finish()
            }
        }
    };
}

redacted_provider_command_debug!(
    BridgeCommand,
    "BridgeCommand",
    call_id,
    other_call_id,
    command_id
);
redacted_provider_command_debug!(
    TransferCommand,
    "TransferCommand",
    call_id,
    target,
    command_id
);
redacted_provider_command_debug!(HangupCommand, "HangupCommand", call_id, command_id);
redacted_provider_command_debug!(DtmfCommand, "DtmfCommand", call_id, digits, command_id);

#[derive(Clone, Serialize, Deserialize)]
pub struct ProviderCall {
    pub provider: String,
    pub provider_call_id: String,
    pub state: String,
}

impl fmt::Debug for ProviderCall {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProviderCall")
            .field("provider", &self.provider)
            .field("provider_call_id_bytes", &self.provider_call_id.len())
            .field("state_bytes", &self.state.len())
            .finish()
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct NormalizedProviderEvent {
    pub provider: String,
    pub event_id: String,
    pub provider_call_id: Option<String>,
    pub event_type: String,
    pub occurred_at: Option<String>,
    pub raw: Value,
}

impl fmt::Debug for NormalizedProviderEvent {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NormalizedProviderEvent")
            .field("provider", &self.provider)
            .field("event_id_bytes", &self.event_id.len())
            .field(
                "provider_call_id_bytes",
                &self.provider_call_id.as_ref().map(String::len),
            )
            .field("event_type_bytes", &self.event_type.len())
            .field("occurred_at_present", &self.occurred_at.is_some())
            .finish_non_exhaustive()
    }
}

#[derive(Clone)]
pub struct WebhookRequest {
    pub url: String,
    pub headers: BTreeMap<String, String>,
    pub content_type: String,
    pub body: Vec<u8>,
}

impl fmt::Debug for WebhookRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WebhookRequest")
            .field("url_bytes", &self.url.len())
            .field("header_count", &self.headers.len())
            .field("content_type_bytes", &self.content_type.len())
            .field("body_bytes", &self.body.len())
            .finish()
    }
}

impl WebhookRequest {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }

    fn json(&self) -> Result<Value, ProviderError> {
        serde_json::from_slice(&self.body).map_err(ProviderError::Json)
    }
}

#[async_trait]
pub trait ProviderControl: Send + Sync {
    fn name(&self) -> &'static str;
    fn kind(&self) -> ProviderKind;
    /// Exact configured account-profile key used by durable webhook and call
    /// reference reconciliation. It is deliberately distinct from provider
    /// credential identifiers and its `Debug` representation is redacted.
    fn account_key(&self) -> ProviderAccountKey;
    fn capabilities(&self) -> ProviderCapabilities;
    async fn originate(&self, command: OriginateCommand) -> Result<ProviderCall, ProviderError>;
    #[allow(dead_code)]
    async fn bridge(&self, command: BridgeCommand) -> Result<(), ProviderError>;
    async fn transfer(&self, command: TransferCommand) -> Result<(), ProviderError>;
    async fn hangup(&self, command: HangupCommand) -> Result<(), ProviderError>;
    async fn send_dtmf(&self, command: DtmfCommand) -> Result<(), ProviderError>;
    fn verify_webhook(
        &self,
        request: &WebhookRequest,
    ) -> Result<NormalizedProviderEvent, ProviderError>;
}

#[derive(Clone, Default)]
pub struct ProviderRegistry {
    providers: Arc<DashMap<String, Arc<dyn ProviderControl>>>,
    configs: Arc<ProviderConfigs>,
}

impl ProviderRegistry {
    pub fn from_config(config: &ProviderConfigs) -> Result<Self, ProviderError> {
        config.validate_account_profiles()?;
        if config.twilio.is_some() || config.vonage.is_some() {
            return Err(ProviderError::Configuration(
                "Twilio and Vonage provider control are deferred beyond Bridgefu 1.0".into(),
            ));
        }
        let registry = Self {
            providers: Arc::new(DashMap::new()),
            configs: Arc::new(config.clone()),
        };
        if let Some(config) = &config.telnyx {
            registry.insert(Arc::new(TelnyxProvider::new(config.clone())?))?;
        }
        Ok(registry)
    }

    pub fn insert(&self, provider: Arc<dyn ProviderControl>) -> Result<(), ProviderError> {
        if provider.name() != provider_kind_name(provider.kind())
            || self.providers.contains_key(provider.name())
        {
            return Err(ProviderError::Configuration(
                "provider registry identity is inconsistent".into(),
            ));
        }
        let account = provider.account_key();
        if self.providers.iter().any(|configured| {
            configured.value().account_key() == account
                && configured.value().name() != provider.name()
        }) {
            return Err(ProviderError::Configuration(
                "provider account profiles must be globally unique".into(),
            ));
        }
        self.providers.insert(provider.name().to_string(), provider);
        Ok(())
    }

    pub fn get(&self, name: &str) -> Option<Arc<dyn ProviderControl>> {
        self.providers
            .get(name)
            .map(|entry| Arc::clone(entry.value()))
    }

    pub fn names(&self) -> Vec<String> {
        let mut names: Vec<_> = self
            .providers
            .iter()
            .map(|entry| entry.key().clone())
            .collect();
        names.sort();
        names
    }

    pub fn resolve_endpoint(
        &self,
        endpoint: &ProviderEndpointConfig,
    ) -> Result<Arc<dyn ProviderControl>, ProviderError> {
        let provider = self
            .get(provider_kind_name(endpoint.provider))
            .ok_or(ProviderError::AccountProfileMismatch)?;
        if provider.kind() != endpoint.provider
            || provider.account_key().as_str() != endpoint.account_profile
        {
            return Err(ProviderError::AccountProfileMismatch);
        }
        Ok(provider)
    }

    async fn start_telnyx_media_with_token(
        &self,
        context: ProviderExecutionContext,
        client_state: ProviderDialClientState,
        endpoint: ProviderEndpointConfig,
        attachment_token: &str,
    ) -> Result<ProviderExecutionReference, ProviderExecutionError> {
        let provider = self
            .resolve_endpoint(&endpoint)
            .map_err(map_provider_execution_error)?;
        let config = self
            .configs
            .telnyx
            .as_ref()
            .filter(|config| {
                endpoint.provider == ProviderKind::Telnyx
                    && config.account_profile == endpoint.account_profile
            })
            .ok_or(ProviderExecutionError::AccountProfileMismatch)?;
        let password = config
            .media_sip_password
            .resolve()
            .map_err(|error| map_provider_execution_error(error.into()))?;
        let transport = config.media_sip_transport.to_ascii_uppercase();
        let to = format!(
            "sip:{attachment_token}@{};transport={}",
            config.media_sip_authority,
            transport.to_ascii_lowercase()
        );
        let call = provider
            .originate(OriginateCommand {
                from: config.from.clone(),
                to,
                answer_url: None,
                event_url: config.webhook_url.clone(),
                command_id: context.command_id(),
                client_state: Some(client_state),
                metadata: BTreeMap::new(),
                sip_auth_username: Some(config.media_sip_username.clone()),
                sip_auth_password: Some(password),
                sip_transport_protocol: Some(transport),
                link_to: None,
                bridge_on_answer: None,
            })
            .await
            .map_err(map_provider_execution_error)?;
        provider_execution_reference(&endpoint, call)
    }
}

#[async_trait]
impl ProviderLegExecutor for ProviderRegistry {
    #[tracing::instrument(
        name = "bridgefu.provider.start_media",
        skip_all,
        fields(
            tenant_id = %request.context.tenant_id,
            call_id = %request.context.call_id,
            leg_id = %request.context.leg_id,
            provider = ?request.endpoint.provider
        )
    )]
    async fn start_media(
        &self,
        request: ProviderStartMediaRequest,
    ) -> Result<ProviderExecutionReference, ProviderExecutionError> {
        let ProviderStartMediaRequest {
            context,
            client_state,
            endpoint,
            attachment_token,
        } = request;
        self.start_telnyx_media_with_token(
            context,
            client_state,
            endpoint,
            attachment_token.expose_secret(),
        )
        .await
    }

    #[tracing::instrument(
        name = "bridgefu.provider.connect_destination",
        skip_all,
        fields(
            tenant_id = %request.context.tenant_id,
            call_id = %request.context.call_id,
            leg_id = %request.context.leg_id,
            provider = ?request.endpoint.provider
        )
    )]
    async fn connect_destination(
        &self,
        request: ProviderConnectDestinationRequest,
    ) -> Result<ProviderExecutionReference, ProviderExecutionError> {
        let provider = self
            .resolve_endpoint(&request.endpoint)
            .map_err(map_provider_execution_error)?;
        let config = self
            .configs
            .telnyx
            .as_ref()
            .filter(|config| {
                request.endpoint.provider == ProviderKind::Telnyx
                    && config.account_profile == request.endpoint.account_profile
                    && request.media_call.account.as_str() == config.account_profile
            })
            .ok_or(ProviderExecutionError::AccountProfileMismatch)?;
        let destination = request
            .endpoint
            .destination
            .clone()
            .ok_or(ProviderExecutionError::InvalidRequest)?;
        let call = provider
            .originate(OriginateCommand {
                from: config.from.clone(),
                to: destination,
                answer_url: None,
                event_url: config.webhook_url.clone(),
                command_id: request.context.destination_command_id(),
                client_state: Some(request.client_state),
                metadata: BTreeMap::new(),
                sip_auth_username: None,
                sip_auth_password: None,
                sip_transport_protocol: None,
                link_to: Some(
                    request
                        .media_call
                        .provider_call_id
                        .expose_secret()
                        .to_owned(),
                ),
                bridge_on_answer: Some(true),
            })
            .await
            .map_err(map_provider_execution_error)?;
        provider_execution_reference(&request.endpoint, call)
    }

    #[tracing::instrument(
        name = "bridgefu.provider.transfer",
        skip_all,
        fields(
            tenant_id = %request.context.tenant_id,
            call_id = %request.context.call_id,
            leg_id = %request.context.leg_id,
            provider = ?request.endpoint.provider
        )
    )]
    async fn transfer(
        &self,
        request: ProviderTransferRequest,
    ) -> Result<(), ProviderExecutionError> {
        let provider = self
            .resolve_endpoint(&request.endpoint)
            .map_err(map_provider_execution_error)?;
        ensure_media_reference(&request.endpoint, &request.media_call)?;
        let target = match request.target {
            TransferTarget::Provider {
                provider: ProviderKind::Telnyx,
                account_profile,
                destination,
            } if account_profile == request.endpoint.account_profile => destination,
            TransferTarget::Sip { uri } => uri,
            _ => return Err(ProviderExecutionError::Unsupported),
        };
        let client_state = telnyx::calls::client_state::encode_json(&request.correlation)
            .map_err(|_| ProviderExecutionError::InvalidRequest)?;
        provider
            .transfer(TransferCommand {
                call_id: request
                    .media_call
                    .provider_call_id
                    .expose_secret()
                    .to_owned(),
                target,
                command_id: request.context.command_id(),
                client_state: Some(client_state.clone()),
                target_leg_client_state: Some(client_state),
            })
            .await
            .map_err(map_provider_execution_error)
    }

    #[tracing::instrument(
        name = "bridgefu.provider.hangup",
        skip_all,
        fields(
            tenant_id = %request.context.tenant_id,
            call_id = %request.context.call_id,
            leg_id = %request.context.leg_id,
            provider = ?request.endpoint.provider
        )
    )]
    async fn hangup(&self, request: ProviderHangupRequest) -> Result<(), ProviderExecutionError> {
        let provider = self
            .resolve_endpoint(&request.endpoint)
            .map_err(map_provider_execution_error)?;
        ensure_media_reference(&request.endpoint, &request.media_call)?;
        provider
            .hangup(HangupCommand {
                call_id: request
                    .media_call
                    .provider_call_id
                    .expose_secret()
                    .to_owned(),
                command_id: request.context.command_id(),
            })
            .await
            .map_err(map_provider_execution_error)
    }

    #[tracing::instrument(
        name = "bridgefu.provider.dtmf",
        skip_all,
        fields(
            tenant_id = %request.context.tenant_id,
            call_id = %request.context.call_id,
            leg_id = %request.context.leg_id,
            provider = ?request.endpoint.provider
        )
    )]
    async fn send_dtmf(&self, request: ProviderDtmfRequest) -> Result<(), ProviderExecutionError> {
        let provider = self
            .resolve_endpoint(&request.endpoint)
            .map_err(map_provider_execution_error)?;
        ensure_media_reference(&request.endpoint, &request.media_call)?;
        provider
            .send_dtmf(DtmfCommand {
                call_id: request
                    .media_call
                    .provider_call_id
                    .expose_secret()
                    .to_owned(),
                digits: request.sequence.digits,
                command_id: request.context.command_id(),
            })
            .await
            .map_err(map_provider_execution_error)
    }
}

fn provider_execution_reference(
    endpoint: &ProviderEndpointConfig,
    call: ProviderCall,
) -> Result<ProviderExecutionReference, ProviderExecutionError> {
    if call.provider != provider_kind_name(endpoint.provider) {
        return Err(ProviderExecutionError::AccountProfileMismatch);
    }
    Ok(ProviderExecutionReference {
        account: ProviderAccountKey::parse(endpoint.account_profile.clone())
            .map_err(|_| ProviderExecutionError::InvalidRequest)?,
        provider_call_id: ProviderCallId::parse(call.provider_call_id)
            .map_err(|_| ProviderExecutionError::InvalidRequest)?,
    })
}

fn ensure_media_reference(
    endpoint: &ProviderEndpointConfig,
    reference: &ProviderExecutionReference,
) -> Result<(), ProviderExecutionError> {
    if reference.account.as_str() == endpoint.account_profile {
        Ok(())
    } else {
        Err(ProviderExecutionError::AccountProfileMismatch)
    }
}

fn map_provider_execution_error(error: ProviderError) -> ProviderExecutionError {
    match error {
        ProviderError::AccountProfileMismatch => ProviderExecutionError::AccountProfileMismatch,
        ProviderError::Unsupported => ProviderExecutionError::Unsupported,
        ProviderError::InvalidCommand(_)
        | ProviderError::MissingField(_)
        | ProviderError::Configuration(_)
        | ProviderError::Json(_)
        | ProviderError::InvalidSignature
        | ProviderError::InvalidWebhookField(_) => ProviderExecutionError::InvalidRequest,
        ProviderError::Telnyx { retryable, .. } => ProviderExecutionError::Remote { retryable },
        ProviderError::CircuitOpen => ProviderExecutionError::Remote { retryable: true },
        ProviderError::Http(error) => ProviderExecutionError::Remote {
            retryable: error.is_timeout() || error.is_connect(),
        },
        ProviderError::Remote { status, .. } => ProviderExecutionError::Remote {
            retryable: status == 429 || status >= 500,
        },
    }
}

impl ProviderConfigs {
    pub fn validate_account_profiles(&self) -> Result<(), ProviderError> {
        let mut profiles = BTreeSet::new();
        for profile in [
            self.twilio
                .as_ref()
                .map(|config| config.account_profile.as_str()),
            self.telnyx
                .as_ref()
                .map(|config| config.account_profile.as_str()),
            self.vonage
                .as_ref()
                .map(|config| config.account_profile.as_str()),
        ]
        .into_iter()
        .flatten()
        {
            validate_account_profile(profile)?;
            if !profiles.insert(profile) {
                return Err(ProviderError::Configuration(
                    "provider account profiles must be globally unique".into(),
                ));
            }
        }
        Ok(())
    }

    pub fn attachment_principal_resolver(
        &self,
        tenants: &[String],
    ) -> ConfiguredAttachmentPrincipalResolver {
        let mut resolver = ConfiguredAttachmentPrincipalResolver::new();
        if let Some(config) = &self.telnyx {
            for tenant in tenants {
                resolver = resolver.with_provider(
                    ProviderKind::Telnyx,
                    config.account_profile.clone(),
                    AuthenticatedPrincipal {
                        subject: config.media_sip_username.clone(),
                        tenant: Some(tenant.clone()),
                        scopes: Vec::new(),
                        issuer: Some(format!("sip-digest:{}", config.media_sip_realm)),
                        expires_at: None,
                        method: AuthenticationMethod::SipDigest,
                        assurance: IdentityAssurance::Identified {
                            credential_kind: CredentialKind::SipDigest,
                        },
                    },
                );
            }
        }
        resolver
    }
}

#[cfg(test)]
struct TwilioProvider {
    config: TwilioConfig,
    account_key: ProviderAccountKey,
    auth_token: String,
    http: reqwest::Client,
}

#[cfg(test)]
impl TwilioProvider {
    fn new(config: TwilioConfig) -> Result<Self, ProviderError> {
        validate_account_profile(&config.account_profile)?;
        let account_key = ProviderAccountKey::parse(config.account_profile.clone())
            .map_err(|_| ProviderError::Configuration("invalid provider account profile".into()))?;
        Ok(Self {
            auth_token: config.auth_token.resolve()?,
            config,
            account_key,
            http: reqwest::Client::new(),
        })
    }

    fn call_url(&self, call_id: Option<&str>) -> String {
        match call_id {
            Some(id) => format!(
                "{}/Accounts/{}/Calls/{id}.json",
                self.config.base_url, self.config.account_sid
            ),
            None => format!(
                "{}/Accounts/{}/Calls.json",
                self.config.base_url, self.config.account_sid
            ),
        }
    }
}

#[async_trait]
#[cfg(test)]
impl ProviderControl for TwilioProvider {
    fn name(&self) -> &'static str {
        "twilio"
    }
    fn kind(&self) -> ProviderKind {
        ProviderKind::Twilio
    }
    fn account_key(&self) -> ProviderAccountKey {
        self.account_key.clone()
    }
    fn capabilities(&self) -> ProviderCapabilities {
        ProviderCapabilities::default()
    }

    async fn originate(&self, command: OriginateCommand) -> Result<ProviderCall, ProviderError> {
        let mut form = vec![("From", command.from), ("To", command.to)];
        if let Some(url) = command.answer_url {
            form.push(("Url", url));
        }
        if let Some(url) = command.event_url {
            form.push(("StatusCallback", url));
        }
        let value = send_json(
            self.http
                .post(self.call_url(None))
                .basic_auth(&self.config.account_sid, Some(&self.auth_token))
                .form(&form),
        )
        .await?;
        Ok(ProviderCall {
            provider: self.name().into(),
            provider_call_id: required_string(&value, "sid")?,
            state: value
                .get("status")
                .and_then(Value::as_str)
                .unwrap_or("queued")
                .into(),
        })
    }

    async fn bridge(&self, _command: BridgeCommand) -> Result<(), ProviderError> {
        Err(ProviderError::Unsupported)
    }

    async fn transfer(&self, command: TransferCommand) -> Result<(), ProviderError> {
        let twiml = format!(
            "<Response><Dial><Sip>{}</Sip></Dial></Response>",
            xml_escape(&command.target)
        );
        send_empty(
            self.http
                .post(self.call_url(Some(&command.call_id)))
                .basic_auth(&self.config.account_sid, Some(&self.auth_token))
                .form(&[("Twiml", twiml)]),
        )
        .await
    }

    async fn hangup(&self, command: HangupCommand) -> Result<(), ProviderError> {
        send_empty(
            self.http
                .post(self.call_url(Some(&command.call_id)))
                .basic_auth(&self.config.account_sid, Some(&self.auth_token))
                .form(&[("Status", "completed")]),
        )
        .await
    }

    async fn send_dtmf(&self, command: DtmfCommand) -> Result<(), ProviderError> {
        let twiml = format!(
            "<Response><Play digits=\"{}\"/></Response>",
            xml_escape(&command.digits)
        );
        send_empty(
            self.http
                .post(self.call_url(Some(&command.call_id)))
                .basic_auth(&self.config.account_sid, Some(&self.auth_token))
                .form(&[("Twiml", twiml)]),
        )
        .await
    }

    fn verify_webhook(
        &self,
        request: &WebhookRequest,
    ) -> Result<NormalizedProviderEvent, ProviderError> {
        let supplied = request
            .header("X-Twilio-Signature")
            .ok_or(ProviderError::InvalidSignature)?;
        let mut signed = request.url.clone();
        if request
            .content_type
            .starts_with("application/x-www-form-urlencoded")
        {
            let mut params: Vec<(String, String)> = url::form_urlencoded::parse(&request.body)
                .into_owned()
                .collect();
            params.sort_by(|a, b| a.0.cmp(&b.0));
            for (key, value) in params {
                signed.push_str(&key);
                signed.push_str(&value);
            }
        } else if request.content_type.starts_with("application/json") {
            if let Some(expected) = url::Url::parse(&request.url).ok().and_then(|url| {
                url.query_pairs()
                    .find(|(key, _)| key == "bodySHA256")
                    .map(|(_, value)| value.into_owned())
            }) {
                let actual = format!("{:x}", Sha256::digest(&request.body));
                if actual != expected {
                    return Err(ProviderError::InvalidSignature);
                }
            }
        }
        let mut mac = HmacSha1::new_from_slice(self.auth_token.as_bytes())
            .map_err(|_| ProviderError::Configuration("invalid Twilio auth token".into()))?;
        mac.update(signed.as_bytes());
        let supplied = base64::engine::general_purpose::STANDARD
            .decode(supplied)
            .map_err(|_| ProviderError::InvalidSignature)?;
        mac.verify_slice(&supplied)
            .map_err(|_| ProviderError::InvalidSignature)?;

        let raw = if request.content_type.starts_with("application/json") {
            request.json()?
        } else {
            Value::Object(
                url::form_urlencoded::parse(&request.body)
                    .into_owned()
                    .map(|(key, value)| (key, Value::String(value)))
                    .collect(),
            )
        };
        validate_payload_credential(
            &raw,
            &["AccountSid", "account_sid"],
            &self.config.account_sid,
        )?;
        let call_id = required_webhook_string(
            &raw,
            &["CallSid", "call_sid"],
            "CallSid",
            MAX_PROVIDER_EVENT_ID_BYTES,
        )?;
        let event_type = required_webhook_string(
            &raw,
            &["CallStatus", "call_status"],
            "CallStatus",
            MAX_PROVIDER_EVENT_KIND_BYTES,
        )?;
        if event_type.eq_ignore_ascii_case("callback") {
            return Err(ProviderError::InvalidWebhookField("CallStatus"));
        }
        let sequence = optional_twilio_sequence(&raw)?;
        // Twilio documents SequenceNumber for status callbacks, but older or
        // customized callback producers can omit it. The explicit fallback is
        // deterministic: repeated sequence-less delivery of one call/status
        // deduplicates, while different statuses remain distinct.
        let event_id = match sequence {
            Some(sequence) => {
                format!("twilio-status-v1:{call_id}:sequence:{sequence}:{event_type}")
            }
            None => format!("twilio-status-v1:{call_id}:no-sequence:{event_type}"),
        };
        let event_id =
            validated_webhook_string(&event_id, "durable event ID", MAX_PROVIDER_EVENT_ID_BYTES)?;
        Ok(NormalizedProviderEvent {
            provider: self.name().into(),
            event_id,
            provider_call_id: Some(call_id),
            event_type,
            occurred_at: raw
                .get("Timestamp")
                .and_then(Value::as_str)
                .map(str::to_string),
            raw,
        })
    }
}

#[derive(Clone, Copy, Debug)]
struct ProviderCircuitBreakerPolicy {
    failure_threshold: u32,
    open_duration: Duration,
}

impl ProviderCircuitBreakerPolicy {
    fn telnyx_default() -> Self {
        Self {
            failure_threshold: TELNYX_CIRCUIT_FAILURE_THRESHOLD,
            open_duration: TELNYX_CIRCUIT_OPEN_DURATION,
        }
    }

    fn validate(self) -> Result<Self, ProviderError> {
        if self.failure_threshold == 0 || self.open_duration.is_zero() {
            return Err(ProviderError::Configuration(
                "invalid provider circuit-breaker policy".into(),
            ));
        }
        Ok(self)
    }
}

#[derive(Clone, Copy, Debug)]
enum ProviderCircuitPhase {
    Closed { retryable_failures: u32 },
    Open { retry_at: Instant },
    HalfOpen,
}

#[derive(Debug)]
struct ProviderCircuitState {
    generation: u64,
    phase: ProviderCircuitPhase,
}

#[derive(Debug)]
struct ProviderCircuitBreaker {
    provider: &'static str,
    policy: ProviderCircuitBreakerPolicy,
    state: Mutex<ProviderCircuitState>,
}

impl ProviderCircuitBreaker {
    fn new(
        provider: &'static str,
        policy: ProviderCircuitBreakerPolicy,
    ) -> Result<Arc<Self>, ProviderError> {
        Ok(Arc::new(Self {
            provider,
            policy: policy.validate()?,
            state: Mutex::new(ProviderCircuitState {
                generation: 0,
                phase: ProviderCircuitPhase::Closed {
                    retryable_failures: 0,
                },
            }),
        }))
    }

    fn acquire(self: &Arc<Self>) -> Result<ProviderCircuitPermit, ProviderError> {
        self.acquire_at(Instant::now())
    }

    fn acquire_at(self: &Arc<Self>, now: Instant) -> Result<ProviderCircuitPermit, ProviderError> {
        let mut state = self.lock_state();
        let half_open = match state.phase {
            ProviderCircuitPhase::Closed { .. } => false,
            ProviderCircuitPhase::Open { retry_at } if retry_at <= now => {
                state.phase = ProviderCircuitPhase::HalfOpen;
                true
            }
            ProviderCircuitPhase::Open { .. } | ProviderCircuitPhase::HalfOpen => {
                metrics::counter!(
                    "bridgefu_provider_circuit_rejections_total",
                    "provider" => self.provider
                )
                .increment(1);
                return Err(ProviderError::CircuitOpen);
            }
        };
        Ok(ProviderCircuitPermit {
            breaker: Arc::clone(self),
            generation: state.generation,
            half_open,
            completed: false,
        })
    }

    fn complete_at<T>(
        &self,
        generation: u64,
        half_open: bool,
        result: &Result<T, ProviderError>,
        now: Instant,
    ) {
        let mut state = self.lock_state();
        if state.generation != generation {
            return;
        }
        let retryable_failure = result
            .as_ref()
            .err()
            .is_some_and(provider_error_is_retryable);
        match (state.phase, half_open, retryable_failure) {
            (ProviderCircuitPhase::Closed { .. }, true, _)
            | (ProviderCircuitPhase::HalfOpen, false, _) => {}
            (ProviderCircuitPhase::Closed { .. }, false, false)
            | (ProviderCircuitPhase::HalfOpen, true, false) => {
                self.close_locked(&mut state);
            }
            (ProviderCircuitPhase::Closed { retryable_failures }, false, true) => {
                let failures = retryable_failures.saturating_add(1);
                if failures >= self.policy.failure_threshold {
                    self.open_locked(&mut state, now);
                } else {
                    state.phase = ProviderCircuitPhase::Closed {
                        retryable_failures: failures,
                    };
                }
            }
            (ProviderCircuitPhase::HalfOpen, true, true) => self.open_locked(&mut state, now),
            (ProviderCircuitPhase::Open { .. }, _, _) => {}
        }
    }

    fn abandon_half_open(&self, generation: u64) {
        let mut state = self.lock_state();
        if state.generation == generation && matches!(state.phase, ProviderCircuitPhase::HalfOpen) {
            self.open_locked(&mut state, Instant::now());
        }
    }

    fn open_locked(&self, state: &mut ProviderCircuitState, now: Instant) {
        state.generation = state.generation.wrapping_add(1);
        state.phase = ProviderCircuitPhase::Open {
            retry_at: now + self.policy.open_duration,
        };
        metrics::gauge!(
            "bridgefu_provider_circuit_open",
            "provider" => self.provider
        )
        .set(1.0);
        metrics::counter!(
            "bridgefu_provider_circuit_transitions_total",
            "provider" => self.provider,
            "state" => "open"
        )
        .increment(1);
    }

    fn close_locked(&self, state: &mut ProviderCircuitState) {
        let transitioned = matches!(state.phase, ProviderCircuitPhase::HalfOpen);
        if transitioned {
            state.generation = state.generation.wrapping_add(1);
        }
        state.phase = ProviderCircuitPhase::Closed {
            retryable_failures: 0,
        };
        if transitioned {
            metrics::gauge!(
                "bridgefu_provider_circuit_open",
                "provider" => self.provider
            )
            .set(0.0);
            metrics::counter!(
                "bridgefu_provider_circuit_transitions_total",
                "provider" => self.provider,
                "state" => "closed"
            )
            .increment(1);
        }
    }

    fn lock_state(&self) -> std::sync::MutexGuard<'_, ProviderCircuitState> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

struct ProviderCircuitPermit {
    breaker: Arc<ProviderCircuitBreaker>,
    generation: u64,
    half_open: bool,
    completed: bool,
}

impl ProviderCircuitPermit {
    fn complete<T>(mut self, result: &Result<T, ProviderError>) {
        self.breaker
            .complete_at(self.generation, self.half_open, result, Instant::now());
        self.completed = true;
    }
}

impl Drop for ProviderCircuitPermit {
    fn drop(&mut self) {
        if !self.completed && self.half_open {
            self.breaker.abandon_half_open(self.generation);
        }
    }
}

struct TelnyxProvider {
    config: TelnyxConfig,
    account_key: ProviderAccountKey,
    client: telnyx::Client,
    webhook_verifier: telnyx::webhooks::Verifier,
    circuit_breaker: Arc<ProviderCircuitBreaker>,
}

impl TelnyxProvider {
    fn new(config: TelnyxConfig) -> Result<Self, ProviderError> {
        validate_account_profile(&config.account_profile)?;
        if config.request_timeout_ms == 0
            || config.request_timeout_ms > MAX_TELNYX_REQUEST_TIMEOUT_MS
        {
            return Err(ProviderError::Configuration(
                "invalid Telnyx request timeout".into(),
            ));
        }
        if config.max_retries > MAX_TELNYX_RETRIES {
            return Err(ProviderError::Configuration(
                "invalid Telnyx retry budget".into(),
            ));
        }
        validate_telnyx_base_url(&config.base_url)?;
        let account_key = ProviderAccountKey::parse(config.account_profile.clone())
            .map_err(|_| ProviderError::Configuration("invalid provider account profile".into()))?;
        let api_key = config.api_key.resolve()?;
        if api_key.is_empty() || api_key.trim() != api_key {
            return Err(ProviderError::Configuration(
                "invalid Telnyx API key".into(),
            ));
        }
        validate_telnyx_connection_id(&config.connection_id)?;
        validate_provider_destination(&config.from, "from")?;
        validate_telnyx_sip_authority(&config.media_sip_authority)?;
        validate_telnyx_sip_username(&config.media_sip_username)?;
        validate_telnyx_sip_realm(&config.media_sip_realm)?;
        validate_telnyx_sip_transport(&config.media_sip_transport)?;
        if let Some(webhook_url) = &config.webhook_url {
            validate_provider_webhook_url(webhook_url)?;
        }
        let mut media_sip_password = config.media_sip_password.resolve()?;
        if media_sip_password.is_empty()
            || media_sip_password.len() > 1_024
            || media_sip_password
                .bytes()
                .any(|byte| byte.is_ascii_control())
        {
            media_sip_password.zeroize();
            return Err(ProviderError::Configuration(
                "invalid Telnyx media SIP password".into(),
            ));
        }
        media_sip_password.zeroize();
        let webhook_public_key = config.webhook_public_key.resolve()?;
        let webhook_verifier =
            telnyx::webhooks::Verifier::new(&webhook_public_key).map_err(|_| {
                ProviderError::Configuration("invalid Telnyx webhook public key".into())
            })?;
        ensure_telnyx_rustls_provider()?;
        let client = telnyx::Client::builder()
            .api_key(api_key)
            .base_url(config.base_url.clone())
            .timeout(Duration::from_millis(config.request_timeout_ms))
            .max_retries(config.max_retries)
            .public_key(webhook_public_key)
            .auto_command_id(false)
            .user_agent_suffix(format!("bridgefu/{}", env!("CARGO_PKG_VERSION")))
            .build()
            .map_err(|_| {
                ProviderError::Configuration("invalid Telnyx client configuration".into())
            })?;
        let circuit_breaker =
            ProviderCircuitBreaker::new("telnyx", ProviderCircuitBreakerPolicy::telnyx_default())?;
        Ok(Self {
            config,
            account_key,
            client,
            webhook_verifier,
            circuit_breaker,
        })
    }

    async fn execute<T, F, Fut>(&self, operation: F) -> Result<T, ProviderError>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = Result<T, ProviderError>>,
    {
        let permit = self.circuit_breaker.acquire()?;
        let result = operation().await;
        permit.complete(&result);
        result
    }
}

#[async_trait]
impl ProviderControl for TelnyxProvider {
    fn name(&self) -> &'static str {
        "telnyx"
    }
    fn kind(&self) -> ProviderKind {
        ProviderKind::Telnyx
    }
    fn account_key(&self) -> ProviderAccountKey {
        self.account_key.clone()
    }
    fn capabilities(&self) -> ProviderCapabilities {
        ProviderCapabilities {
            bridge: true,
            ..ProviderCapabilities::default()
        }
    }

    async fn originate(&self, command: OriginateCommand) -> Result<ProviderCall, ProviderError> {
        validate_telnyx_command_id(&command.command_id)?;
        validate_provider_destination(&command.from, "from")?;
        validate_provider_destination(&command.to, "to")?;
        let mut params = telnyx::calls::DialParams::new(
            command.to,
            command.from,
            self.config.connection_id.clone(),
        );
        params.command_id = Some(command.command_id);
        params.client_state = match command.client_state.as_ref() {
            Some(client_state) => {
                client_state
                    .validate()
                    .map_err(|_| ProviderError::InvalidCommand("client_state"))?;
                let encoded = telnyx::calls::client_state::encode_json(client_state)
                    .map_err(|_| ProviderError::InvalidCommand("client_state"))?;
                if encoded.len() > MAX_PROVIDER_DIAL_CLIENT_STATE_BYTES {
                    return Err(ProviderError::InvalidCommand("client_state"));
                }
                Some(encoded)
            }
            None => None,
        };
        params.webhook_url = command.event_url;
        params.sip_auth_username = command.sip_auth_username;
        params.sip_auth_password = command.sip_auth_password;
        params.sip_transport_protocol = command.sip_transport_protocol;
        params.link_to = command.link_to;
        params.bridge_on_answer = command.bridge_on_answer;
        let call = self
            .execute(|| async {
                self.client
                    .calls()
                    .dial(params)
                    .await
                    .map_err(map_telnyx_error)
            })
            .await?;
        Ok(ProviderCall {
            provider: self.name().into(),
            provider_call_id: call
                .call_control_id
                .filter(|value| !value.trim().is_empty())
                .ok_or(ProviderError::MissingField("call_control_id"))?,
            state: "queued".into(),
        })
    }

    async fn bridge(&self, command: BridgeCommand) -> Result<(), ProviderError> {
        validate_telnyx_command_id(&command.command_id)?;
        validate_provider_call_id(&command.call_id)?;
        validate_provider_call_id(&command.other_call_id)?;
        let mut params = telnyx::calls::BridgeParams::with(command.other_call_id);
        params.command_id = Some(command.command_id);
        self.execute(|| async {
            self.client
                .calls()
                .control(command.call_id)
                .bridge(params)
                .await
                .map_err(map_telnyx_error)
        })
        .await?;
        Ok(())
    }

    async fn transfer(&self, command: TransferCommand) -> Result<(), ProviderError> {
        validate_telnyx_command_id(&command.command_id)?;
        validate_provider_call_id(&command.call_id)?;
        validate_provider_destination(&command.target, "target")?;
        let mut params = telnyx::calls::TransferParams::to(command.target);
        params.command_id = Some(command.command_id);
        params.client_state = command.client_state;
        params.target_leg_client_state = command.target_leg_client_state;
        self.execute(|| async {
            self.client
                .calls()
                .control(command.call_id)
                .transfer(params)
                .await
                .map_err(map_telnyx_error)
        })
        .await?;
        Ok(())
    }

    async fn hangup(&self, command: HangupCommand) -> Result<(), ProviderError> {
        validate_telnyx_command_id(&command.command_id)?;
        validate_provider_call_id(&command.call_id)?;
        let params = telnyx::calls::HangupParams {
            command_id: Some(command.command_id),
            ..Default::default()
        };
        self.execute(|| async {
            self.client
                .calls()
                .control(command.call_id)
                .hangup(params)
                .await
                .map_err(map_telnyx_error)
        })
        .await?;
        Ok(())
    }

    async fn send_dtmf(&self, command: DtmfCommand) -> Result<(), ProviderError> {
        validate_telnyx_command_id(&command.command_id)?;
        validate_provider_call_id(&command.call_id)?;
        if command.digits.is_empty()
            || command.digits.len() > 128
            || !command
                .digits
                .bytes()
                .all(|byte| byte.is_ascii_digit() || b"ABCD*#wW".contains(&byte))
        {
            return Err(ProviderError::InvalidCommand("digits"));
        }
        let params = telnyx::calls::SendDtmfParams {
            digits: Some(command.digits),
            command_id: Some(command.command_id),
            ..Default::default()
        };
        self.execute(|| async {
            self.client
                .calls()
                .control(command.call_id)
                .send_dtmf(params)
                .await
                .map_err(map_telnyx_error)
        })
        .await?;
        Ok(())
    }

    fn verify_webhook(
        &self,
        request: &WebhookRequest,
    ) -> Result<NormalizedProviderEvent, ProviderError> {
        if !request.content_type.starts_with("application/json") {
            return Err(ProviderError::InvalidWebhookField("Content-Type"));
        }
        let signature = request
            .header(telnyx::webhooks::SIGNATURE_HEADER)
            .ok_or(ProviderError::InvalidSignature)?;
        let timestamp = request
            .header(telnyx::webhooks::TIMESTAMP_HEADER)
            .ok_or(ProviderError::InvalidSignature)?;
        self.webhook_verifier
            .verify(signature, timestamp, &request.body)
            .map_err(|_| ProviderError::InvalidSignature)?;
        let raw = request.json()?;
        let data = raw
            .get("data")
            .ok_or(ProviderError::InvalidWebhookField("data"))?;
        let payload = data
            .get("payload")
            .ok_or(ProviderError::InvalidWebhookField("data.payload"))?;
        validate_required_payload_credential(
            payload,
            &["connection_id"],
            &self.config.connection_id,
        )?;
        let event_id =
            required_webhook_string(data, &["id"], "data.id", MAX_PROVIDER_EVENT_ID_BYTES)?;
        let provider_call_id = required_webhook_string(
            payload,
            &["call_control_id"],
            "data.payload.call_control_id",
            MAX_PROVIDER_EVENT_ID_BYTES,
        )?;
        let event =
            telnyx::webhooks::Event::from_json(&request.body).map_err(|error| match error {
                telnyx::webhooks::WebhookError::Parse(source) => ProviderError::Json(source),
                _ => ProviderError::InvalidWebhookField("event envelope"),
            })?;
        let event_type = validated_webhook_string(
            event.event_type.as_str(),
            "data.event_type",
            MAX_PROVIDER_EVENT_KIND_BYTES,
        )?;
        Ok(NormalizedProviderEvent {
            provider: self.name().into(),
            event_id,
            provider_call_id: Some(provider_call_id),
            event_type,
            occurred_at: Some(event.occurred_at.to_rfc3339()),
            raw,
        })
    }
}

#[cfg(test)]
struct VonageProvider {
    config: VonageConfig,
    account_key: ProviderAccountKey,
    private_key: Vec<u8>,
    signature_secret: String,
    http: reqwest::Client,
}

#[derive(Serialize)]
#[cfg(test)]
struct VonageApiClaims<'a> {
    application_id: &'a str,
    iat: u64,
    exp: u64,
    jti: String,
}

#[derive(Debug, Deserialize)]
#[cfg(test)]
struct VonageWebhookClaims {
    iat: u64,
    jti: String,
    iss: String,
    payload_hash: Option<String>,
}

#[cfg(test)]
impl VonageProvider {
    fn new(config: VonageConfig) -> Result<Self, ProviderError> {
        validate_account_profile(&config.account_profile)?;
        let account_key = ProviderAccountKey::parse(config.account_profile.clone())
            .map_err(|_| ProviderError::Configuration("invalid provider account profile".into()))?;
        Ok(Self {
            private_key: config.private_key.resolve()?.into_bytes(),
            signature_secret: config.signature_secret.resolve()?,
            config,
            account_key,
            http: reqwest::Client::new(),
        })
    }

    fn token(&self) -> Result<String, ProviderError> {
        let now = unix_seconds();
        jsonwebtoken::encode(
            &jsonwebtoken::Header::new(Algorithm::RS256),
            &VonageApiClaims {
                application_id: &self.config.application_id,
                iat: now,
                exp: now + 300,
                jti: uuid::Uuid::new_v4().to_string(),
            },
            &jsonwebtoken::EncodingKey::from_rsa_pem(&self.private_key)
                .map_err(|error| ProviderError::Configuration(error.to_string()))?,
        )
        .map_err(|error| ProviderError::Configuration(error.to_string()))
    }

    async fn put_action(&self, call_id: &str, body: Value) -> Result<(), ProviderError> {
        send_empty(
            self.http
                .put(format!("{}/calls/{call_id}", self.config.base_url))
                .bearer_auth(self.token()?)
                .json(&body),
        )
        .await
    }
}

#[async_trait]
#[cfg(test)]
impl ProviderControl for VonageProvider {
    fn name(&self) -> &'static str {
        "vonage"
    }
    fn kind(&self) -> ProviderKind {
        ProviderKind::Vonage
    }
    fn account_key(&self) -> ProviderAccountKey {
        self.account_key.clone()
    }
    fn capabilities(&self) -> ProviderCapabilities {
        ProviderCapabilities::default()
    }

    async fn originate(&self, command: OriginateCommand) -> Result<ProviderCall, ProviderError> {
        let mut body = json!({
            "to": [vonage_endpoint(&command.to)],
            "from": vonage_endpoint(&command.from),
        });
        if let Some(url) = command.answer_url {
            body["answer_url"] = json!([url]);
        }
        if let Some(url) = command.event_url {
            body["event_url"] = json!([url]);
        }
        let value = send_json(
            self.http
                .post(format!("{}/calls", self.config.base_url))
                .bearer_auth(self.token()?)
                .json(&body),
        )
        .await?;
        Ok(ProviderCall {
            provider: self.name().into(),
            provider_call_id: required_string(&value, "uuid")?,
            state: value
                .get("status")
                .and_then(Value::as_str)
                .unwrap_or("started")
                .into(),
        })
    }

    async fn bridge(&self, _command: BridgeCommand) -> Result<(), ProviderError> {
        Err(ProviderError::Unsupported)
    }

    async fn transfer(&self, command: TransferCommand) -> Result<(), ProviderError> {
        self.put_action(&command.call_id, json!({"action":"transfer", "destination": {"type":"ncco", "ncco":[{"action":"connect", "endpoint":[vonage_endpoint(&command.target)]}]}})).await
    }

    async fn hangup(&self, command: HangupCommand) -> Result<(), ProviderError> {
        self.put_action(&command.call_id, json!({"action":"hangup"}))
            .await
    }

    async fn send_dtmf(&self, command: DtmfCommand) -> Result<(), ProviderError> {
        self.put_action(
            &command.call_id,
            json!({"action":"dtmf", "digits": command.digits}),
        )
        .await
    }

    fn verify_webhook(
        &self,
        request: &WebhookRequest,
    ) -> Result<NormalizedProviderEvent, ProviderError> {
        let token = request
            .header("Authorization")
            .and_then(|value| value.strip_prefix("Bearer "))
            .ok_or(ProviderError::InvalidSignature)?;
        let mut validation = Validation::new(Algorithm::HS256);
        validation.required_spec_claims.clear();
        validation.validate_exp = false;
        validation.set_issuer(&["Vonage"]);
        let claims = decode::<VonageWebhookClaims>(
            token,
            &DecodingKey::from_secret(self.signature_secret.as_bytes()),
            &validation,
        )
        .map_err(|_| ProviderError::InvalidSignature)?
        .claims;
        if claims.iss != "Vonage" || unix_seconds().abs_diff(claims.iat) > 300 {
            return Err(ProviderError::InvalidSignature);
        }
        if let Some(expected) = claims.payload_hash {
            let actual = format!("{:x}", Sha256::digest(&request.body));
            if actual != expected {
                return Err(ProviderError::InvalidSignature);
            }
        }
        let raw = request.json()?;
        validate_payload_credential(&raw, &["application_id"], &self.config.application_id)?;
        let event_id =
            validated_webhook_string(&claims.jti, "JWT jti", MAX_PROVIDER_EVENT_ID_BYTES)?;
        let call_id =
            required_webhook_string(&raw, &["uuid"], "uuid", MAX_PROVIDER_EVENT_ID_BYTES)?;
        let event_type =
            required_webhook_string(&raw, &["status"], "status", MAX_PROVIDER_EVENT_KIND_BYTES)?;
        Ok(NormalizedProviderEvent {
            provider: self.name().into(),
            event_id,
            provider_call_id: Some(call_id),
            event_type,
            occurred_at: raw
                .get("timestamp")
                .and_then(Value::as_str)
                .map(str::to_string),
            raw,
        })
    }
}

#[cfg(test)]
fn vonage_endpoint(value: &str) -> Value {
    if value.to_ascii_lowercase().starts_with("sip:") {
        json!({"type":"sip", "uri": value})
    } else {
        json!({"type":"phone", "number": value})
    }
}

#[cfg(test)]
async fn send_json(request: reqwest::RequestBuilder) -> Result<Value, ProviderError> {
    let response = request.send().await.map_err(ProviderError::Http)?;
    let status = response.status();
    let body = response.bytes().await.map_err(ProviderError::Http)?;
    if !status.is_success() {
        return Err(ProviderError::Remote {
            status: status.as_u16(),
            body_bytes: body.len(),
        });
    }
    serde_json::from_slice(&body).map_err(ProviderError::Json)
}

#[cfg(test)]
async fn send_empty(request: reqwest::RequestBuilder) -> Result<(), ProviderError> {
    let response = request.send().await.map_err(ProviderError::Http)?;
    let status = response.status();
    if status.is_success() {
        return Ok(());
    }
    let body_bytes = response.bytes().await.map(|body| body.len()).unwrap_or(0);
    Err(ProviderError::Remote {
        status: status.as_u16(),
        body_bytes,
    })
}

fn map_telnyx_error(error: telnyx::Error) -> ProviderError {
    let status = error.status().map(|status| status.as_u16());
    let retryable = error.is_timeout()
        || matches!(&error, telnyx::Error::Transport(_))
        || error.is_rate_limit()
        || matches!(status, Some(408 | 409 | 429 | 500..=599));
    ProviderError::Telnyx { status, retryable }
}

fn provider_error_is_retryable(error: &ProviderError) -> bool {
    match error {
        ProviderError::CircuitOpen => true,
        ProviderError::Telnyx { retryable, .. } => *retryable,
        ProviderError::Http(error) => error.is_timeout() || error.is_connect(),
        ProviderError::Remote { status, .. } => *status == 429 || *status >= 500,
        ProviderError::Configuration(_)
        | ProviderError::Json(_)
        | ProviderError::MissingField(_)
        | ProviderError::InvalidCommand(_)
        | ProviderError::InvalidSignature
        | ProviderError::InvalidWebhookField(_)
        | ProviderError::AccountProfileMismatch
        | ProviderError::Unsupported => false,
    }
}

fn ensure_telnyx_rustls_provider() -> Result<(), ProviderError> {
    if rustls::crypto::CryptoProvider::get_default().is_none() {
        // telnyx 0.1's `rustls-ring` feature selects reqwest's no-provider
        // mode, so the embedding process owns this one-time choice. A
        // concurrent installer may win; the second check handles that race.
        let _ = rustls::crypto::ring::default_provider().install_default();
    }
    if rustls::crypto::CryptoProvider::get_default().is_none() {
        return Err(ProviderError::Configuration(
            "Telnyx TLS crypto provider is unavailable".into(),
        ));
    }
    Ok(())
}

fn validate_telnyx_command_id(value: &str) -> Result<(), ProviderError> {
    let value =
        uuid::Uuid::parse_str(value).map_err(|_| ProviderError::InvalidCommand("command_id"))?;
    if value.is_nil() {
        return Err(ProviderError::InvalidCommand("command_id"));
    }
    Ok(())
}

fn validate_telnyx_connection_id(value: &str) -> Result<(), ProviderError> {
    if value.is_empty()
        || value.len() > MAX_PROVIDER_EVENT_ID_BYTES
        || value.trim() != value
        || value.chars().any(char::is_control)
    {
        return Err(ProviderError::Configuration(
            "invalid Telnyx connection ID".into(),
        ));
    }
    Ok(())
}

fn validate_telnyx_base_url(value: &str) -> Result<(), ProviderError> {
    let valid = url::Url::parse(value).ok().is_some_and(|url| {
        let host = url.host();
        let loopback = match host {
            Some(url::Host::Domain(host)) => host.eq_ignore_ascii_case("localhost"),
            Some(url::Host::Ipv4(address)) => address.is_loopback(),
            Some(url::Host::Ipv6(address)) => address.is_loopback(),
            None => false,
        };
        let secure_transport = url.scheme() == "https" || (url.scheme() == "http" && loopback);
        secure_transport
            && host.is_some()
            && url.username().is_empty()
            && url.password().is_none()
            && url.query().is_none()
            && url.fragment().is_none()
    });
    if !valid {
        return Err(ProviderError::Configuration(
            "invalid Telnyx base URL".into(),
        ));
    }
    Ok(())
}

fn validate_telnyx_sip_authority(value: &str) -> Result<(), ProviderError> {
    let parsed = url::Url::parse(&format!("sip://{value}"));
    let valid = parsed.ok().is_some_and(|url| {
        url.host().is_some()
            && url.username().is_empty()
            && url.password().is_none()
            && url.path().is_empty()
            && url.query().is_none()
            && url.fragment().is_none()
    }) && !value.chars().any(char::is_control)
        && !value
            .chars()
            .any(|character| matches!(character, '@' | ';' | '?' | '#'));
    if valid {
        Ok(())
    } else {
        Err(ProviderError::Configuration(
            "invalid Telnyx media SIP authority".into(),
        ))
    }
}

fn validate_telnyx_sip_username(value: &str) -> Result<(), ProviderError> {
    if value.is_empty()
        || value.len() > 256
        || value.trim() != value
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        Err(ProviderError::Configuration(
            "invalid Telnyx media SIP username".into(),
        ))
    } else {
        Ok(())
    }
}

fn validate_telnyx_sip_realm(value: &str) -> Result<(), ProviderError> {
    if value.is_empty()
        || value.len() > 256
        || value.trim() != value
        || value.chars().any(char::is_control)
    {
        Err(ProviderError::Configuration(
            "invalid Telnyx media SIP realm".into(),
        ))
    } else {
        Ok(())
    }
}

fn validate_telnyx_sip_transport(value: &str) -> Result<(), ProviderError> {
    if matches!(value.to_ascii_uppercase().as_str(), "UDP" | "TCP" | "TLS") {
        Ok(())
    } else {
        Err(ProviderError::Configuration(
            "invalid Telnyx media SIP transport".into(),
        ))
    }
}

fn validate_provider_webhook_url(value: &str) -> Result<(), ProviderError> {
    let valid = url::Url::parse(value).ok().is_some_and(|url| {
        url.scheme() == "https"
            && url.host().is_some()
            && url.username().is_empty()
            && url.password().is_none()
            && url.fragment().is_none()
    });
    if valid {
        Ok(())
    } else {
        Err(ProviderError::Configuration(
            "invalid provider webhook URL".into(),
        ))
    }
}

fn validate_provider_call_id(value: &str) -> Result<(), ProviderError> {
    if value.is_empty()
        || value.len() > MAX_PROVIDER_EVENT_ID_BYTES
        || value.bytes().any(|byte| byte.is_ascii_control())
    {
        return Err(ProviderError::InvalidCommand("provider_call_id"));
    }
    Ok(())
}

fn validate_provider_destination(value: &str, field: &'static str) -> Result<(), ProviderError> {
    if value.is_empty()
        || value.len() > MAX_PROVIDER_DESTINATION_BYTES
        || value.bytes().any(|byte| byte.is_ascii_control())
    {
        return Err(ProviderError::InvalidCommand(field));
    }
    Ok(())
}

#[cfg(test)]
fn required_string(value: &Value, field: &'static str) -> Result<String, ProviderError> {
    value
        .get(field)
        .and_then(Value::as_str)
        .map(str::to_string)
        .ok_or(ProviderError::MissingField(field))
}

#[cfg(test)]
fn unix_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn validate_account_profile(profile: &str) -> Result<(), ProviderError> {
    let mut bytes = profile.bytes();
    if profile.len() > 256
        || !bytes
            .next()
            .is_some_and(|byte| byte.is_ascii_alphanumeric())
        || !bytes.all(|byte| byte.is_ascii_alphanumeric() || b"._:-".contains(&byte))
    {
        return Err(ProviderError::Configuration(
            "invalid provider account profile".into(),
        ));
    }
    Ok(())
}

const fn provider_kind_name(provider: ProviderKind) -> &'static str {
    match provider {
        ProviderKind::Twilio => "twilio",
        ProviderKind::Telnyx => "telnyx",
        ProviderKind::Vonage => "vonage",
    }
}

#[cfg(test)]
fn validate_payload_credential(
    payload: &Value,
    fields: &[&str],
    expected: &str,
) -> Result<(), ProviderError> {
    for field in fields {
        if let Some(value) = payload.get(field) {
            if value.as_str() != Some(expected) {
                return Err(ProviderError::InvalidSignature);
            }
        }
    }
    Ok(())
}

fn validate_required_payload_credential(
    payload: &Value,
    fields: &[&str],
    expected: &str,
) -> Result<(), ProviderError> {
    let mut found = false;
    for field in fields {
        if let Some(value) = payload.get(field) {
            found = true;
            if value.as_str() != Some(expected) {
                return Err(ProviderError::InvalidSignature);
            }
        }
    }
    if !found {
        return Err(ProviderError::InvalidSignature);
    }
    Ok(())
}

fn required_webhook_string(
    payload: &Value,
    fields: &[&str],
    label: &'static str,
    max_bytes: usize,
) -> Result<String, ProviderError> {
    let value = fields
        .iter()
        .find_map(|field| payload.get(field))
        .and_then(Value::as_str)
        .ok_or(ProviderError::InvalidWebhookField(label))?;
    validated_webhook_string(value, label, max_bytes)
}

fn validated_webhook_string(
    value: &str,
    label: &'static str,
    max_bytes: usize,
) -> Result<String, ProviderError> {
    if value.is_empty()
        || value.len() > max_bytes
        || value.trim() != value
        || value.chars().any(char::is_control)
    {
        Err(ProviderError::InvalidWebhookField(label))
    } else {
        Ok(value.to_owned())
    }
}

#[cfg(test)]
fn optional_twilio_sequence(payload: &Value) -> Result<Option<String>, ProviderError> {
    let Some(value) = payload
        .get("SequenceNumber")
        .or_else(|| payload.get("sequence_number"))
    else {
        return Ok(None);
    };
    let digits = match value {
        Value::String(value) => value.clone(),
        Value::Number(value) => value
            .as_u64()
            .map(|value| value.to_string())
            .ok_or(ProviderError::InvalidWebhookField("SequenceNumber"))?,
        _ => return Err(ProviderError::InvalidWebhookField("SequenceNumber")),
    };
    if digits.is_empty()
        || digits.len() > MAX_TWILIO_SEQUENCE_DIGITS
        || !digits.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(ProviderError::InvalidWebhookField("SequenceNumber"));
    }
    let canonical = digits.trim_start_matches('0');
    Ok(Some(if canonical.is_empty() {
        "0".into()
    } else {
        canonical.into()
    }))
}

#[cfg(test)]
fn xml_escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

#[derive(Debug, thiserror::Error)]
pub enum ProviderError {
    #[error("provider configuration error: {0}")]
    Configuration(String),
    #[error("provider HTTP error: {0}")]
    #[cfg_attr(not(test), allow(dead_code))]
    Http(reqwest::Error),
    #[error("provider returned HTTP {status}")]
    #[cfg_attr(not(test), allow(dead_code))]
    Remote { status: u16, body_bytes: usize },
    #[error("Telnyx operation failed (status {status:?}, retryable: {retryable})")]
    Telnyx {
        status: Option<u16>,
        retryable: bool,
    },
    #[error("provider circuit breaker is open")]
    CircuitOpen,
    #[error("provider response JSON error: {0}")]
    Json(serde_json::Error),
    #[error("provider response missing field {0}")]
    MissingField(&'static str),
    #[error("provider command field {0} is invalid")]
    InvalidCommand(&'static str),
    #[error("invalid provider webhook signature")]
    InvalidSignature,
    #[error("provider webhook field {0} is missing or invalid")]
    InvalidWebhookField(&'static str),
    #[error("provider account profile does not match the requested provider leg")]
    AccountProfileMismatch,
    #[error("provider operation is not supported")]
    #[cfg_attr(not(test), allow(dead_code))]
    Unsupported,
}

impl From<bridgefu::secret_ref::SecretRefError> for ProviderError {
    fn from(error: bridgefu::secret_ref::SecretRefError) -> Self {
        Self::Configuration(error.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Bytes;
    use axum::extract::{Path, State};
    use axum::http::{HeaderValue, StatusCode};
    use axum::response::{IntoResponse, Response};
    use axum::routing::post;
    use axum::{Json, Router};
    use bridgefu::call_engine::{BindingGeneration, CallId, EffectId, LegId, TenantId};
    use bridgefu::context::{ContextEnvelope, ContextPolicy};
    use ring::signature::KeyPair;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[derive(Clone, Default)]
    struct TelnyxMockState {
        requests: Arc<std::sync::Mutex<Vec<(String, Value)>>>,
    }

    #[derive(Clone)]
    enum TelnyxMockReply {
        Status(StatusCode),
        DelayedSuccess(Duration),
        Success,
    }

    type CapturedTelnyxRequests = Arc<std::sync::Mutex<Vec<(String, Vec<u8>)>>>;

    #[derive(Clone)]
    struct TelnyxRetryMockState {
        attempts: Arc<AtomicUsize>,
        requests: CapturedTelnyxRequests,
        replies: Arc<Vec<TelnyxMockReply>>,
    }

    impl TelnyxRetryMockState {
        fn new(replies: Vec<TelnyxMockReply>) -> Self {
            Self {
                attempts: Arc::new(AtomicUsize::new(0)),
                requests: Arc::new(std::sync::Mutex::new(Vec::new())),
                replies: Arc::new(replies),
            }
        }
    }

    async fn telnyx_mock_dial(
        State(state): State<TelnyxMockState>,
        Json(body): Json<Value>,
    ) -> Json<Value> {
        state
            .requests
            .lock()
            .expect("Telnyx mock requests")
            .push(("calls".into(), body));
        Json(json!({"data": {"call_control_id": "call-control-created"}}))
    }

    async fn telnyx_mock_action(
        State(state): State<TelnyxMockState>,
        Path((call_id, action)): Path<(String, String)>,
        Json(body): Json<Value>,
    ) -> Json<Value> {
        state
            .requests
            .lock()
            .expect("Telnyx mock requests")
            .push((format!("{call_id}/{action}"), body));
        Json(json!({"data": {"result": "ok"}}))
    }

    fn telnyx_mock_response(status: StatusCode) -> Response {
        let mut response = (
            status,
            Json(json!({
                "errors": [{
                    "code": "mock",
                    "title": "mock failure",
                    "detail": "diagnostic-secret-body diagnostic-secret-call-id diagnostic-secret-api-key"
                }]
            })),
        )
            .into_response();
        if status == StatusCode::TOO_MANY_REQUESTS {
            response
                .headers_mut()
                .insert("x-ratelimit-reset", HeaderValue::from_static("0"));
        }
        response
    }

    async fn telnyx_retry_mock_action(
        State(state): State<TelnyxRetryMockState>,
        Path((call_id, action)): Path<(String, String)>,
        body: Bytes,
    ) -> Response {
        let attempt = state.attempts.fetch_add(1, Ordering::SeqCst);
        state
            .requests
            .lock()
            .expect("Telnyx retry mock requests")
            .push((format!("{call_id}/{action}"), body.to_vec()));
        match state
            .replies
            .get(attempt)
            .cloned()
            .unwrap_or(TelnyxMockReply::Status(StatusCode::INTERNAL_SERVER_ERROR))
        {
            TelnyxMockReply::Status(status) => telnyx_mock_response(status),
            TelnyxMockReply::DelayedSuccess(delay) => {
                tokio::time::sleep(delay).await;
                Json(json!({"data": {"result": "ok"}})).into_response()
            }
            TelnyxMockReply::Success => Json(json!({"data": {"result": "ok"}})).into_response(),
        }
    }

    async fn telnyx_retry_mock_dial(
        State(state): State<TelnyxRetryMockState>,
        body: Bytes,
    ) -> Response {
        let attempt = state.attempts.fetch_add(1, Ordering::SeqCst);
        state
            .requests
            .lock()
            .expect("Telnyx retry mock requests")
            .push(("calls".into(), body.to_vec()));
        match state
            .replies
            .get(attempt)
            .cloned()
            .unwrap_or(TelnyxMockReply::Status(StatusCode::INTERNAL_SERVER_ERROR))
        {
            TelnyxMockReply::Status(status) => telnyx_mock_response(status),
            TelnyxMockReply::DelayedSuccess(delay) => {
                tokio::time::sleep(delay).await;
                Json(json!({"data": {"call_control_id": "call-retry"}})).into_response()
            }
            TelnyxMockReply::Success => {
                Json(json!({"data": {"call_control_id": "call-retry"}})).into_response()
            }
        }
    }

    fn telnyx_test_provider(
        base_url: String,
        api_key: &str,
        request_timeout_ms: u64,
        max_retries: u32,
    ) -> TelnyxProvider {
        TelnyxProvider::new(TelnyxConfig {
            account_profile: "telnyx-mock".into(),
            api_key: SecretRef(api_key.into()),
            connection_id: "connection-mock".into(),
            webhook_public_key: SecretRef(
                base64::engine::general_purpose::STANDARD.encode([0_u8; 32]),
            ),
            from: "+12065550100".into(),
            media_sip_authority: "bridgefu.test:5060".into(),
            media_sip_username: "telnyx-media".into(),
            media_sip_password: SecretRef("media-secret".into()),
            media_sip_realm: default_telnyx_media_sip_realm(),
            media_sip_transport: default_telnyx_media_sip_transport(),
            webhook_url: None,
            base_url,
            request_timeout_ms,
            max_retries,
        })
        .expect("Telnyx SDK provider")
    }

    async fn spawn_telnyx_retry_mock(
        replies: Vec<TelnyxMockReply>,
        api_key: &str,
        request_timeout_ms: u64,
        max_retries: u32,
    ) -> (
        TelnyxProvider,
        TelnyxRetryMockState,
        tokio::task::JoinHandle<()>,
    ) {
        let state = TelnyxRetryMockState::new(replies);
        let app = Router::new()
            .route("/v2/calls", post(telnyx_retry_mock_dial))
            .route(
                "/v2/calls/:call_id/actions/:action",
                post(telnyx_retry_mock_action),
            )
            .with_state(state.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind Telnyx retry mock");
        let address = listener.local_addr().expect("Telnyx retry mock address");
        let server = tokio::spawn(async move {
            axum::serve(listener, app)
                .await
                .expect("serve Telnyx retry mock");
        });
        let provider = telnyx_test_provider(
            format!("http://{address}/v2"),
            api_key,
            request_timeout_ms,
            max_retries,
        );
        (provider, state, server)
    }

    fn twilio_config(account_profile: &str) -> TwilioConfig {
        TwilioConfig {
            account_profile: account_profile.into(),
            account_sid: "AC-account".into(),
            auth_token: SecretRef("secret".into()),
            base_url: twilio_base_url(),
        }
    }

    fn signed_twilio_webhook(
        account_sid: &str,
        status: Option<&str>,
        sequence: Option<&str>,
    ) -> WebhookRequest {
        let url = "https://bridgefu.test/v1/providers/twilio/webhooks";
        let mut body = url::form_urlencoded::Serializer::new(String::new());
        body.append_pair("AccountSid", account_sid);
        body.append_pair("CallSid", "CA-call");
        if let Some(status) = status {
            body.append_pair("CallStatus", status);
        }
        if let Some(sequence) = sequence {
            body.append_pair("SequenceNumber", sequence);
        }
        let body = body.finish();
        let mut params: Vec<(String, String)> = url::form_urlencoded::parse(body.as_bytes())
            .into_owned()
            .collect();
        params.sort_by(|left, right| left.0.cmp(&right.0));
        let mut signed = url.to_owned();
        for (key, value) in params {
            signed.push_str(&key);
            signed.push_str(&value);
        }
        let mut mac = HmacSha1::new_from_slice(b"secret").unwrap();
        mac.update(signed.as_bytes());
        let signature =
            base64::engine::general_purpose::STANDARD.encode(mac.finalize().into_bytes());
        WebhookRequest {
            url: url.into(),
            headers: BTreeMap::from([("X-Twilio-Signature".into(), signature)]),
            content_type: "application/x-www-form-urlencoded".into(),
            body: body.into_bytes(),
        }
    }

    fn signed_telnyx_webhook(mut data: Value) -> (TelnyxProvider, WebhookRequest) {
        if data.get("occurred_at").is_none() {
            data["occurred_at"] = Value::String("2026-07-13T00:00:00Z".into());
        }
        let random = ring::rand::SystemRandom::new();
        let encoded = ring::signature::Ed25519KeyPair::generate_pkcs8(&random).unwrap();
        let key_pair = ring::signature::Ed25519KeyPair::from_pkcs8(encoded.as_ref()).unwrap();
        let provider = TelnyxProvider::new(TelnyxConfig {
            account_profile: "telnyx-sandbox".into(),
            api_key: SecretRef("secret".into()),
            connection_id: "connection-a".into(),
            webhook_public_key: SecretRef(
                base64::engine::general_purpose::STANDARD.encode(key_pair.public_key().as_ref()),
            ),
            from: "+12065550100".into(),
            media_sip_authority: "bridgefu.test:5060".into(),
            media_sip_username: "telnyx-media".into(),
            media_sip_password: SecretRef("media-secret".into()),
            media_sip_realm: default_telnyx_media_sip_realm(),
            media_sip_transport: default_telnyx_media_sip_transport(),
            webhook_url: None,
            base_url: telnyx_base_url(),
            request_timeout_ms: default_telnyx_request_timeout_ms(),
            max_retries: default_telnyx_max_retries(),
        })
        .unwrap();
        let body = serde_json::to_vec(&json!({"data": data})).unwrap();
        let timestamp = unix_seconds().to_string();
        let mut signed = timestamp.as_bytes().to_vec();
        signed.push(b'|');
        signed.extend_from_slice(&body);
        let signature = base64::engine::general_purpose::STANDARD.encode(key_pair.sign(&signed));
        let request = WebhookRequest {
            url: "https://bridgefu.test/v1/providers/telnyx/webhooks".into(),
            headers: BTreeMap::from([
                ("Telnyx-Signature-Ed25519".into(), signature),
                ("Telnyx-Timestamp".into(), timestamp),
            ]),
            content_type: "application/json".into(),
            body,
        };
        (provider, request)
    }

    #[tokio::test]
    async fn telnyx_sdk_uses_bridgefu_owned_command_ids_for_every_mutation() {
        let state = TelnyxMockState::default();
        let app = Router::new()
            .route("/v2/calls", post(telnyx_mock_dial))
            .route(
                "/v2/calls/:call_id/actions/:action",
                post(telnyx_mock_action),
            )
            .with_state(state.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind Telnyx mock");
        let address = listener.local_addr().expect("Telnyx mock address");
        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.expect("serve Telnyx mock");
        });

        let random = ring::rand::SystemRandom::new();
        let encoded = ring::signature::Ed25519KeyPair::generate_pkcs8(&random).unwrap();
        let key_pair = ring::signature::Ed25519KeyPair::from_pkcs8(encoded.as_ref()).unwrap();
        let provider = TelnyxProvider::new(TelnyxConfig {
            account_profile: "telnyx-mock".into(),
            api_key: SecretRef("mock-secret".into()),
            connection_id: "connection-mock".into(),
            webhook_public_key: SecretRef(
                base64::engine::general_purpose::STANDARD.encode(key_pair.public_key().as_ref()),
            ),
            from: "+12065550100".into(),
            media_sip_authority: "bridgefu.test:5060".into(),
            media_sip_username: "telnyx-media".into(),
            media_sip_password: SecretRef("media-secret".into()),
            media_sip_realm: default_telnyx_media_sip_realm(),
            media_sip_transport: default_telnyx_media_sip_transport(),
            webhook_url: None,
            base_url: format!("http://{address}/v2"),
            request_timeout_ms: 2_000,
            max_retries: 0,
        })
        .expect("Telnyx SDK provider");

        for command_id in [
            "sdk-generated-or-malformed",
            "00000000-0000-0000-0000-000000000000",
        ] {
            assert!(matches!(
                provider
                    .hangup(HangupCommand {
                        call_id: "call-a".into(),
                        command_id: command_id.into(),
                    })
                    .await,
                Err(ProviderError::InvalidCommand("command_id"))
            ));
        }
        assert!(state
            .requests
            .lock()
            .expect("Telnyx mock requests")
            .is_empty());

        let originated = provider
            .originate(OriginateCommand {
                from: "+12065550100".into(),
                to: "sip:attach-token@bridgefu.test".into(),
                answer_url: None,
                event_url: Some("https://bridgefu.test/v1/providers/telnyx/webhooks".into()),
                command_id: "00000000-0000-0000-0000-000000000001".into(),
                client_state: None,
                metadata: BTreeMap::new(),
                sip_auth_username: None,
                sip_auth_password: None,
                sip_transport_protocol: None,
                link_to: None,
                bridge_on_answer: None,
            })
            .await
            .expect("originate");
        assert_eq!(
            originated.provider_call_id,
            "call-control-created".to_string()
        );
        provider
            .bridge(BridgeCommand {
                call_id: "call-a".into(),
                other_call_id: "call-b".into(),
                command_id: "00000000-0000-0000-0000-000000000002".into(),
            })
            .await
            .expect("bridge");
        let transfer = TransferCommand {
            call_id: "call-a".into(),
            target: "sip:replacement@bridgefu.test".into(),
            command_id: "00000000-0000-0000-0000-000000000003".into(),
            client_state: None,
            target_leg_client_state: None,
        };
        provider.transfer(transfer.clone()).await.expect("transfer");
        provider.transfer(transfer).await.expect("transfer replay");
        provider
            .hangup(HangupCommand {
                call_id: "call-a".into(),
                command_id: "00000000-0000-0000-0000-000000000004".into(),
            })
            .await
            .expect("hangup");
        provider
            .send_dtmf(DtmfCommand {
                call_id: "call-a".into(),
                digits: "12#".into(),
                command_id: "00000000-0000-0000-0000-000000000005".into(),
            })
            .await
            .expect("DTMF");

        let observed: Vec<_> = state
            .requests
            .lock()
            .expect("Telnyx mock requests")
            .iter()
            .map(|(path, body)| {
                (
                    path.clone(),
                    body.get("command_id")
                        .and_then(Value::as_str)
                        .map(str::to_owned),
                )
            })
            .collect();
        assert_eq!(
            observed,
            vec![
                (
                    "calls".to_owned(),
                    Some("00000000-0000-0000-0000-000000000001".to_owned())
                ),
                (
                    "call-a/bridge".to_owned(),
                    Some("00000000-0000-0000-0000-000000000002".to_owned())
                ),
                (
                    "call-a/transfer".to_owned(),
                    Some("00000000-0000-0000-0000-000000000003".to_owned())
                ),
                (
                    "call-a/transfer".to_owned(),
                    Some("00000000-0000-0000-0000-000000000003".to_owned())
                ),
                (
                    "call-a/hangup".to_owned(),
                    Some("00000000-0000-0000-0000-000000000004".to_owned())
                ),
                (
                    "call-a/send_dtmf".to_owned(),
                    Some("00000000-0000-0000-0000-000000000005".to_owned())
                ),
            ]
        );
        server.abort();
        let _ = server.await;
    }

    #[tokio::test]
    async fn telnyx_executor_uses_two_dials_with_distinct_effect_ids_and_linking() {
        use bridgefu::call_engine::{
            BindingGeneration, CallId, DeadlineGeneration, EffectId, LegId, TenantId,
        };

        let state = TelnyxMockState::default();
        let app = Router::new()
            .route("/v2/calls", post(telnyx_mock_dial))
            .route(
                "/v2/calls/:call_id/actions/:action",
                post(telnyx_mock_action),
            )
            .with_state(state.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind Telnyx executor mock");
        let address = listener.local_addr().expect("Telnyx executor mock address");
        let server = tokio::spawn(async move {
            axum::serve(listener, app)
                .await
                .expect("serve Telnyx executor mock");
        });
        let random = ring::rand::SystemRandom::new();
        let encoded = ring::signature::Ed25519KeyPair::generate_pkcs8(&random).unwrap();
        let key_pair = ring::signature::Ed25519KeyPair::from_pkcs8(encoded.as_ref()).unwrap();
        let configs = ProviderConfigs {
            twilio: None,
            telnyx: Some(TelnyxConfig {
                account_profile: "telnyx-mock".into(),
                api_key: SecretRef("mock-secret".into()),
                connection_id: "connection-mock".into(),
                webhook_public_key: SecretRef(
                    base64::engine::general_purpose::STANDARD
                        .encode(key_pair.public_key().as_ref()),
                ),
                from: "+12065550100".into(),
                media_sip_authority: "bridgefu.test:5061".into(),
                media_sip_username: "telnyx-media".into(),
                media_sip_password: SecretRef("media-secret".into()),
                media_sip_realm: "bridgefu".into(),
                media_sip_transport: "TLS".into(),
                webhook_url: Some("https://bridgefu.test/v1/providers/telnyx/webhooks".into()),
                base_url: format!("http://{address}/v2"),
                request_timeout_ms: 2_000,
                max_retries: 0,
            }),
            vonage: None,
        };
        let registry = ProviderRegistry::from_config(&configs).unwrap();
        let tenant_id = TenantId::parse("tenant-a").unwrap();
        let call_id = CallId::from_uuid(uuid::Uuid::from_u128(1)).unwrap();
        let leg_id = LegId::from_uuid(uuid::Uuid::from_u128(2)).unwrap();
        let endpoint = ProviderEndpointConfig {
            provider: ProviderKind::Telnyx,
            account_profile: "telnyx-mock".into(),
            destination: Some("+12065550123".into()),
        };
        let start_effect =
            EffectId::from_uuid(uuid::Uuid::from_u128(3)).expect("valid start effect ID");
        let start_context = ProviderExecutionContext {
            tenant_id: tenant_id.clone(),
            call_id,
            leg_id,
            binding_generation: BindingGeneration::INITIAL,
            effect_id: start_effect,
        };
        let mut envelope = ContextEnvelope::new(
            "controlled-correlation",
            tenant_id.as_str(),
            call_id.to_string(),
            uuid::Uuid::from_u128(9).to_string(),
        );
        envelope
            .metadata
            .insert("account_tier".into(), "gold".into());
        envelope
            .metadata
            .insert("must_not_forward".into(), "private".into());
        let policy = ContextPolicy {
            allow_headers: BTreeMap::from([
                ("X-Correlation-Id".into(), "correlation_id".into()),
                ("X-Account-Tier".into(), "account_tier".into()),
            ]),
            ..ContextPolicy::default()
        };
        let media_client_state = ProviderDialClientState::new(
            &start_context,
            bridgefu::call_service::ProviderDialRole::Media,
            Some(&envelope),
            &policy,
        )
        .unwrap();
        let media_call = registry
            .start_telnyx_media_with_token(
                start_context.clone(),
                media_client_state.clone(),
                endpoint.clone(),
                "opaque-attachment-token",
            )
            .await
            .expect("start Telnyx media call");
        let connect_effect =
            EffectId::from_uuid(uuid::Uuid::from_u128(4)).expect("valid connect effect ID");
        let destination_context = ProviderExecutionContext {
            tenant_id: tenant_id.clone(),
            call_id,
            leg_id,
            binding_generation: BindingGeneration::INITIAL,
            effect_id: connect_effect,
        };
        let destination_command_id = destination_context.destination_command_id();
        let destination_client_state = ProviderDialClientState::new(
            &destination_context,
            bridgefu::call_service::ProviderDialRole::Destination,
            Some(&envelope),
            &policy,
        )
        .unwrap();
        registry
            .connect_destination(ProviderConnectDestinationRequest {
                context: destination_context.clone(),
                client_state: destination_client_state.clone(),
                endpoint: endpoint.clone(),
                media_call: media_call.clone(),
            })
            .await
            .expect("connect Telnyx destination");

        let transfer_context = ProviderExecutionContext {
            tenant_id,
            call_id,
            leg_id,
            binding_generation: BindingGeneration::INITIAL,
            effect_id: EffectId::from_uuid(uuid::Uuid::from_u128(5))
                .expect("valid transfer effect ID"),
        };
        let deadline_generation: DeadlineGeneration = serde_json::from_str("7").unwrap();
        let transfer_correlation =
            ProviderTransferCorrelation::new(&transfer_context, deadline_generation);
        let transfer_command_id = transfer_context.command_id();
        registry
            .transfer(ProviderTransferRequest {
                context: transfer_context,
                endpoint,
                media_call: media_call.clone(),
                target: TransferTarget::Sip {
                    uri: "sip:replacement@bridgefu.test".into(),
                },
                correlation: transfer_correlation.clone(),
            })
            .await
            .expect("submit Telnyx transfer");

        {
            let requests = state.requests.lock().expect("Telnyx executor requests");
            assert_eq!(requests.len(), 3);
            assert_eq!(requests[0].0, "calls");
            assert_eq!(requests[1].0, "calls");
            let media = &requests[0].1;
            assert_eq!(
                media["to"],
                "sip:opaque-attachment-token@bridgefu.test:5061;transport=tls"
            );
            assert_eq!(media["from"], "+12065550100");
            assert_eq!(media["connection_id"], "connection-mock");
            assert_eq!(media["command_id"], start_effect.to_string());
            assert_eq!(media["sip_auth_username"], "telnyx-media");
            assert_eq!(media["sip_auth_password"], "media-secret");
            assert_eq!(media["sip_transport_protocol"], "TLS");
            assert_eq!(
                media["webhook_url"],
                "https://bridgefu.test/v1/providers/telnyx/webhooks"
            );
            assert!(media.get("link_to").is_none());
            assert!(media.get("bridge_on_answer").is_none());
            let encoded = media["client_state"].as_str().unwrap();
            assert!(encoded.len() <= MAX_PROVIDER_DIAL_CLIENT_STATE_BYTES);
            let decoded =
                telnyx::calls::client_state::decode_json::<ProviderDialClientState>(encoded)
                    .unwrap();
            assert_eq!(decoded, media_client_state);
            assert!(decoded.matches(
                &start_context,
                bridgefu::call_service::ProviderDialRole::Media
            ));
            assert_eq!(decoded.correlation_id(), Some("controlled-correlation"));
            assert_eq!(
                decoded.metadata().get("account_tier").map(String::as_str),
                Some("gold")
            );
            assert!(!decoded.metadata().contains_key("must_not_forward"));

            let destination = &requests[1].1;
            assert_eq!(destination["to"], "+12065550123");
            assert_eq!(destination["from"], "+12065550100");
            assert_eq!(destination["connection_id"], "connection-mock");
            assert_eq!(destination["command_id"], destination_command_id);
            assert_ne!(destination["command_id"], media["command_id"]);
            assert_eq!(
                destination["link_to"],
                media_call.provider_call_id.expose_secret()
            );
            assert_eq!(destination["bridge_on_answer"], true);
            assert!(destination.get("sip_auth_username").is_none());
            assert!(destination.get("sip_auth_password").is_none());
            let encoded = destination["client_state"].as_str().unwrap();
            let decoded =
                telnyx::calls::client_state::decode_json::<ProviderDialClientState>(encoded)
                    .unwrap();
            assert_eq!(decoded, destination_client_state);
            assert!(decoded.matches(
                &destination_context,
                bridgefu::call_service::ProviderDialRole::Destination
            ));
            assert_eq!(decoded.correlation_id(), Some("controlled-correlation"));
            assert_eq!(
                decoded.metadata().get("account_tier").map(String::as_str),
                Some("gold")
            );
            assert!(!decoded.metadata().contains_key("must_not_forward"));
            let transfer = &requests[2];
            assert_eq!(transfer.0, "call-control-created/transfer");
            assert_eq!(transfer.1["to"], "sip:replacement@bridgefu.test");
            assert_eq!(transfer.1["command_id"], transfer_command_id);
            let current_state = transfer.1["client_state"].as_str().unwrap();
            let target_state = transfer.1["target_leg_client_state"].as_str().unwrap();
            assert_eq!(current_state, target_state);
            assert_eq!(
                telnyx::calls::client_state::decode_json::<ProviderTransferCorrelation>(
                    current_state
                )
                .unwrap(),
                transfer_correlation
            );
        }
        server.abort();
        let _ = server.await;
    }

    #[tokio::test]
    async fn telnyx_sdk_retries_429_and_5xx_with_the_exact_request_body() {
        for status in [
            StatusCode::TOO_MANY_REQUESTS,
            StatusCode::SERVICE_UNAVAILABLE,
        ] {
            let (provider, state, server) = spawn_telnyx_retry_mock(
                vec![TelnyxMockReply::Status(status), TelnyxMockReply::Success],
                "mock-secret",
                2_000,
                1,
            )
            .await;
            let context = ProviderExecutionContext {
                tenant_id: TenantId::parse("retry-tenant").unwrap(),
                call_id: CallId::from_uuid(uuid::Uuid::from_u128(81)).unwrap(),
                leg_id: LegId::from_uuid(uuid::Uuid::from_u128(82)).unwrap(),
                binding_generation: BindingGeneration::INITIAL,
                effect_id: EffectId::from_uuid(uuid::Uuid::from_u128(83)).unwrap(),
            };
            let client_state = ProviderDialClientState::new(
                &context,
                bridgefu::call_service::ProviderDialRole::Media,
                None,
                &ContextPolicy::default(),
            )
            .unwrap();
            provider
                .originate(OriginateCommand {
                    from: "+12065550100".into(),
                    to: "sip:retry@bridgefu.test".into(),
                    answer_url: None,
                    event_url: None,
                    command_id: "00000000-0000-0000-0000-000000000011".into(),
                    client_state: Some(client_state.clone()),
                    metadata: BTreeMap::new(),
                    sip_auth_username: None,
                    sip_auth_password: None,
                    sip_transport_protocol: None,
                    link_to: None,
                    bridge_on_answer: None,
                })
                .await
                .expect("retryable Telnyx response succeeds on retry");

            let requests = state
                .requests
                .lock()
                .expect("Telnyx retry requests")
                .clone();
            assert_eq!(requests.len(), 2, "status {status} retry count");
            assert_eq!(requests[0].0, "calls");
            assert_eq!(requests[0].1, requests[1].1, "status {status} body");
            let body: Value = serde_json::from_slice(&requests[0].1).unwrap();
            assert_eq!(
                body.get("command_id").and_then(Value::as_str),
                Some("00000000-0000-0000-0000-000000000011")
            );
            let encoded = body.get("client_state").and_then(Value::as_str).unwrap();
            assert_eq!(
                telnyx::calls::client_state::decode_json::<ProviderDialClientState>(encoded)
                    .unwrap(),
                client_state
            );
            server.abort();
            let _ = server.await;
        }
    }

    #[tokio::test]
    async fn telnyx_sdk_retries_a_timeout_with_the_exact_request_body() {
        let (provider, state, server) = spawn_telnyx_retry_mock(
            vec![
                TelnyxMockReply::DelayedSuccess(Duration::from_millis(100)),
                TelnyxMockReply::Success,
            ],
            "mock-secret",
            20,
            1,
        )
        .await;
        provider
            .send_dtmf(DtmfCommand {
                call_id: "call-timeout".into(),
                digits: "12#".into(),
                command_id: "00000000-0000-0000-0000-000000000012".into(),
            })
            .await
            .expect("timed-out Telnyx command succeeds on retry");

        let requests = state
            .requests
            .lock()
            .expect("Telnyx timeout requests")
            .clone();
        assert_eq!(requests.len(), 2);
        assert_eq!(requests[0].1, requests[1].1);
        server.abort();
        let _ = server.await;
    }

    #[tokio::test]
    async fn telnyx_exhausted_errors_have_safe_retry_classification() {
        for (status, max_retries, expected_retryable, expected_attempts) in [
            (StatusCode::BAD_REQUEST, 2, false, 1),
            (StatusCode::CONFLICT, 1, true, 2),
            (StatusCode::TOO_MANY_REQUESTS, 1, true, 2),
            (StatusCode::BAD_GATEWAY, 1, true, 2),
        ] {
            let replies = (0..expected_attempts)
                .map(|_| TelnyxMockReply::Status(status))
                .collect();
            let (provider, state, server) =
                spawn_telnyx_retry_mock(replies, "mock-secret", 2_000, max_retries).await;
            let error = provider
                .transfer(TransferCommand {
                    call_id: "call-classification".into(),
                    target: "sip:target@bridgefu.test".into(),
                    command_id: "00000000-0000-0000-0000-000000000013".into(),
                    client_state: None,
                    target_leg_client_state: None,
                })
                .await
                .expect_err("mock status must fail after its retry budget");
            assert!(matches!(
                error,
                ProviderError::Telnyx {
                    status: Some(observed),
                    retryable
                } if observed == status.as_u16() && retryable == expected_retryable
            ));
            assert_eq!(
                state.attempts.load(Ordering::SeqCst),
                expected_attempts,
                "status {status} attempt count"
            );
            server.abort();
            let _ = server.await;
        }

        let (provider, state, server) = spawn_telnyx_retry_mock(
            vec![
                TelnyxMockReply::DelayedSuccess(Duration::from_millis(100)),
                TelnyxMockReply::DelayedSuccess(Duration::from_millis(100)),
            ],
            "mock-secret",
            20,
            1,
        )
        .await;
        let error = provider
            .hangup(HangupCommand {
                call_id: "call-timeout-exhausted".into(),
                command_id: "00000000-0000-0000-0000-000000000014".into(),
            })
            .await
            .expect_err("timeout budget must be exhausted");
        assert!(matches!(
            error,
            ProviderError::Telnyx {
                status: None,
                retryable: true
            }
        ));
        assert_eq!(state.attempts.load(Ordering::SeqCst), 2);
        server.abort();
        let _ = server.await;
    }

    #[tokio::test]
    async fn telnyx_circuit_breaker_opens_rejects_and_recovers_with_one_probe() {
        let (mut provider, state, server) = spawn_telnyx_retry_mock(
            vec![
                TelnyxMockReply::Status(StatusCode::SERVICE_UNAVAILABLE),
                TelnyxMockReply::Status(StatusCode::SERVICE_UNAVAILABLE),
                TelnyxMockReply::DelayedSuccess(Duration::from_millis(50)),
                TelnyxMockReply::Success,
            ],
            "mock-secret",
            2_000,
            0,
        )
        .await;
        provider.circuit_breaker = ProviderCircuitBreaker::new(
            "telnyx",
            ProviderCircuitBreakerPolicy {
                failure_threshold: 2,
                open_duration: Duration::from_millis(20),
            },
        )
        .unwrap();

        for command_id in [
            "00000000-0000-0000-0000-000000000021",
            "00000000-0000-0000-0000-000000000022",
        ] {
            assert!(matches!(
                provider
                    .hangup(HangupCommand {
                        call_id: "call-circuit".into(),
                        command_id: command_id.into(),
                    })
                    .await,
                Err(ProviderError::Telnyx {
                    status: Some(503),
                    retryable: true
                })
            ));
        }

        assert!(matches!(
            provider
                .hangup(HangupCommand {
                    call_id: "call-circuit".into(),
                    command_id: "00000000-0000-0000-0000-000000000023".into(),
                })
                .await,
            Err(ProviderError::CircuitOpen)
        ));
        assert_eq!(state.attempts.load(Ordering::SeqCst), 2);

        tokio::time::sleep(Duration::from_millis(30)).await;
        let (probe, concurrent) = tokio::join!(
            provider.hangup(HangupCommand {
                call_id: "call-circuit".into(),
                command_id: "00000000-0000-0000-0000-000000000024".into(),
            }),
            provider.hangup(HangupCommand {
                call_id: "call-circuit".into(),
                command_id: "00000000-0000-0000-0000-000000000025".into(),
            })
        );
        probe.expect("half-open probe closes the circuit");
        assert!(matches!(concurrent, Err(ProviderError::CircuitOpen)));
        assert_eq!(state.attempts.load(Ordering::SeqCst), 3);

        provider
            .hangup(HangupCommand {
                call_id: "call-circuit".into(),
                command_id: "00000000-0000-0000-0000-000000000026".into(),
            })
            .await
            .expect("closed circuit admits the next command");
        assert_eq!(state.attempts.load(Ordering::SeqCst), 4);

        server.abort();
        let _ = server.await;
    }

    #[tokio::test]
    async fn telnyx_sdk_and_bridgefu_error_diagnostics_are_payload_free() {
        const API_KEY: &str = "diagnostic-secret-api-key";
        const CALL_ID: &str = "diagnostic-secret-call-id";
        let (provider, _state, server) = spawn_telnyx_retry_mock(
            vec![TelnyxMockReply::Status(StatusCode::INTERNAL_SERVER_ERROR)],
            API_KEY,
            2_000,
            0,
        )
        .await;
        let client_diagnostics = format!("{:?}", provider.client);
        assert!(!client_diagnostics.contains(API_KEY));

        let command = HangupCommand {
            call_id: CALL_ID.into(),
            command_id: "00000000-0000-0000-0000-000000000015".into(),
        };
        assert!(!format!("{command:?}").contains(CALL_ID));
        let error = provider
            .hangup(command)
            .await
            .expect_err("mock Telnyx error");
        let diagnostics = format!("{error:?} {error}");
        for secret in [API_KEY, CALL_ID, "diagnostic-secret-body"] {
            assert!(!diagnostics.contains(secret), "diagnostic leaked {secret}");
        }
        server.abort();
        let _ = server.await;
    }

    #[test]
    fn secret_ref_reads_environment() {
        std::env::set_var("BRIDGEFU_TEST_SECRET", "value");
        assert_eq!(
            SecretRef("env:BRIDGEFU_TEST_SECRET".into())
                .resolve()
                .unwrap(),
            "value"
        );
        std::env::remove_var("BRIDGEFU_TEST_SECRET");
    }

    #[test]
    fn provider_command_and_webhook_diagnostics_are_payload_free() {
        let command = OriginateCommand {
            from: "sip:diagnostic-secret-from@example.test".into(),
            to: "sip:diagnostic-secret-to@example.test".into(),
            answer_url: Some("https://diagnostic-secret-answer.example.test".into()),
            event_url: Some("https://diagnostic-secret-event.example.test".into()),
            command_id: "00000000-0000-0000-0000-000000000001".into(),
            client_state: None,
            metadata: BTreeMap::from([("secret-key".into(), "secret-value".into())]),
            sip_auth_username: Some("diagnostic-secret-user".into()),
            sip_auth_password: Some("diagnostic-secret-password".into()),
            sip_transport_protocol: Some("TLS".into()),
            link_to: Some("diagnostic-secret-link".into()),
            bridge_on_answer: Some(true),
        };
        let request = WebhookRequest {
            url: "https://diagnostic-secret-webhook.example.test".into(),
            headers: BTreeMap::from([(
                "Telnyx-Signature-Ed25519".into(),
                "diagnostic-secret-signature".into(),
            )]),
            content_type: "application/json".into(),
            body: br#"{"diagnostic-secret-body":true}"#.to_vec(),
        };
        let event = NormalizedProviderEvent {
            provider: "telnyx".into(),
            event_id: "diagnostic-secret-event-id".into(),
            provider_call_id: Some("diagnostic-secret-call-id".into()),
            event_type: "diagnostic-secret-event-type".into(),
            occurred_at: Some("diagnostic-secret-time".into()),
            raw: json!({"diagnostic-secret-raw": true}),
        };

        let diagnostics = format!("{command:?} {request:?} {event:?}");
        for secret in [
            "diagnostic-secret-from",
            "diagnostic-secret-to",
            "diagnostic-secret-answer",
            "diagnostic-secret-event.example",
            "secret-key",
            "secret-value",
            "diagnostic-secret-webhook",
            "diagnostic-secret-signature",
            "diagnostic-secret-body",
            "diagnostic-secret-event-id",
            "diagnostic-secret-call-id",
            "diagnostic-secret-event-type",
            "diagnostic-secret-raw",
        ] {
            assert!(!diagnostics.contains(secret), "diagnostic leaked {secret}");
        }
    }

    #[test]
    fn vonage_endpoints_distinguish_sip_and_phone() {
        assert_eq!(vonage_endpoint("sip:a@example.com")["type"], "sip");
        assert_eq!(vonage_endpoint("+12065550100")["type"], "phone");
    }

    #[test]
    fn provider_account_keys_are_exact_configured_profiles() {
        let twilio = TwilioProvider::new(twilio_config("twilio-sandbox")).unwrap();
        assert_eq!(twilio.account_key().as_str(), "twilio-sandbox");

        let telnyx = TelnyxProvider::new(TelnyxConfig {
            account_profile: "telnyx-sandbox".into(),
            api_key: SecretRef("secret".into()),
            connection_id: "connection-a".into(),
            webhook_public_key: SecretRef(
                base64::engine::general_purpose::STANDARD.encode([0_u8; 32]),
            ),
            from: "+12065550100".into(),
            media_sip_authority: "bridgefu.test:5060".into(),
            media_sip_username: "telnyx-media".into(),
            media_sip_password: SecretRef("media-secret".into()),
            media_sip_realm: default_telnyx_media_sip_realm(),
            media_sip_transport: default_telnyx_media_sip_transport(),
            webhook_url: None,
            base_url: telnyx_base_url(),
            request_timeout_ms: default_telnyx_request_timeout_ms(),
            max_retries: default_telnyx_max_retries(),
        })
        .unwrap();
        assert_eq!(telnyx.account_key().as_str(), "telnyx-sandbox");

        let vonage = VonageProvider::new(VonageConfig {
            account_profile: "vonage-sandbox".into(),
            application_id: "application-a".into(),
            private_key: SecretRef("not-used-by-this-test".into()),
            signature_secret: SecretRef("secret".into()),
            base_url: vonage_base_url(),
        })
        .unwrap();
        assert_eq!(vonage.account_key().as_str(), "vonage-sandbox");
    }

    #[test]
    fn provider_account_keys_reject_empty_profiles() {
        let error = TwilioProvider::new(twilio_config(""))
            .err()
            .expect("empty account is rejected");
        assert_eq!(
            error.to_string(),
            "provider configuration error: invalid provider account profile"
        );
    }

    #[test]
    fn provider_profiles_default_validate_and_remain_globally_unique() {
        let defaults: ProviderConfigs = serde_yaml::from_str(
            r#"
twilio:
  account_sid: AC-account
  auth_token: secret
telnyx:
  api_key: secret
  connection_id: connection-a
  webhook_public_key: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
  from: "+12065550100"
  media_sip_authority: bridgefu.test:5060
  media_sip_username: telnyx-media
  media_sip_password: media-secret
vonage:
  application_id: application-a
  private_key: private
  signature_secret: secret
"#,
        )
        .unwrap();
        assert_eq!(defaults.twilio.as_ref().unwrap().account_profile, "twilio");
        let telnyx_defaults = defaults.telnyx.as_ref().unwrap();
        assert_eq!(telnyx_defaults.account_profile, "telnyx");
        assert_eq!(telnyx_defaults.request_timeout_ms, 15_000);
        assert_eq!(telnyx_defaults.max_retries, 2);
        assert_eq!(defaults.vonage.as_ref().unwrap().account_profile, "vonage");
        defaults.validate_account_profiles().unwrap();

        let duplicate = ProviderConfigs {
            twilio: Some(twilio_config("shared-profile")),
            telnyx: Some(TelnyxConfig {
                account_profile: "shared-profile".into(),
                api_key: SecretRef("secret".into()),
                connection_id: "connection-a".into(),
                webhook_public_key: SecretRef(
                    base64::engine::general_purpose::STANDARD.encode([0_u8; 32]),
                ),
                from: "+12065550100".into(),
                media_sip_authority: "bridgefu.test:5060".into(),
                media_sip_username: "telnyx-media".into(),
                media_sip_password: SecretRef("media-secret".into()),
                media_sip_realm: default_telnyx_media_sip_realm(),
                media_sip_transport: default_telnyx_media_sip_transport(),
                webhook_url: None,
                base_url: telnyx_base_url(),
                request_timeout_ms: default_telnyx_request_timeout_ms(),
                max_retries: default_telnyx_max_retries(),
            }),
            vonage: None,
        };
        assert!(duplicate
            .validate_account_profiles()
            .unwrap_err()
            .to_string()
            .contains("globally unique"));
    }

    #[test]
    fn telnyx_timeout_retry_and_connection_configuration_is_bounded() {
        let schema: Value =
            serde_json::from_str(include_str!("../config/schema.json")).expect("config schema");
        let telnyx = &schema["properties"]["providers"]["properties"]["telnyx"];
        assert_eq!(
            telnyx["properties"]["request_timeout_ms"]["default"],
            15_000
        );
        assert_eq!(
            telnyx["properties"]["request_timeout_ms"]["maximum"],
            120_000
        );
        assert_eq!(telnyx["properties"]["max_retries"]["default"], 2);
        assert_eq!(telnyx["properties"]["max_retries"]["maximum"], 5);
        assert_eq!(telnyx["properties"]["connection_id"]["maxLength"], 512);

        for (timeout, retries, connection_id) in [
            (0, 0, "connection-a"),
            (MAX_TELNYX_REQUEST_TIMEOUT_MS + 1, 0, "connection-a"),
            (1, MAX_TELNYX_RETRIES + 1, "connection-a"),
            (1, 0, ""),
            (1, 0, " connection-a"),
        ] {
            let error = TelnyxProvider::new(TelnyxConfig {
                account_profile: "telnyx-invalid".into(),
                api_key: SecretRef("secret".into()),
                connection_id: connection_id.into(),
                webhook_public_key: SecretRef(
                    base64::engine::general_purpose::STANDARD.encode([0_u8; 32]),
                ),
                from: "+12065550100".into(),
                media_sip_authority: "bridgefu.test:5060".into(),
                media_sip_username: "telnyx-media".into(),
                media_sip_password: SecretRef("media-secret".into()),
                media_sip_realm: default_telnyx_media_sip_realm(),
                media_sip_transport: default_telnyx_media_sip_transport(),
                webhook_url: None,
                base_url: telnyx_base_url(),
                request_timeout_ms: timeout,
                max_retries: retries,
            })
            .err()
            .expect("invalid Telnyx config must fail");
            assert!(matches!(error, ProviderError::Configuration(_)));
        }

        for (api_key, base_url) in [
            ("", "https://api.telnyx.com/v2"),
            ("secret", "ftp://api.telnyx.test/v2"),
            ("secret", "http://api.telnyx.test/v2"),
            ("secret", "http://[2001:db8::1]:8080/v2"),
            ("secret", "https://user:password@api.telnyx.test/v2"),
        ] {
            let error = TelnyxProvider::new(TelnyxConfig {
                account_profile: "telnyx-invalid".into(),
                api_key: SecretRef(api_key.into()),
                connection_id: "connection-a".into(),
                webhook_public_key: SecretRef(
                    base64::engine::general_purpose::STANDARD.encode([0_u8; 32]),
                ),
                from: "+12065550100".into(),
                media_sip_authority: "bridgefu.test:5060".into(),
                media_sip_username: "telnyx-media".into(),
                media_sip_password: SecretRef("media-secret".into()),
                media_sip_realm: default_telnyx_media_sip_realm(),
                media_sip_transport: default_telnyx_media_sip_transport(),
                webhook_url: None,
                base_url: base_url.into(),
                request_timeout_ms: 1,
                max_retries: 0,
            })
            .err()
            .expect("unsafe Telnyx client config must fail");
            assert!(matches!(error, ProviderError::Configuration(_)));
            assert!(!error.to_string().contains("password"));
        }

        for base_url in [
            "http://127.0.0.1:8080/v2",
            "http://[::1]:8080/v2",
            "http://localhost:8080/v2",
            "https://api.telnyx.com/v2",
        ] {
            assert!(
                validate_telnyx_base_url(base_url).is_ok(),
                "safe Telnyx test/production URL was rejected: {base_url}"
            );
        }

        assert!(validate_provider_webhook_url(
            "https://bridgefu.test/v1/providers/telnyx/webhooks"
        )
        .is_ok());
        for webhook_url in [
            "http://bridgefu.test/v1/providers/telnyx/webhooks",
            "https://user@bridgefu.test/v1/providers/telnyx/webhooks",
            "https://bridgefu.test/v1/providers/telnyx/webhooks#fragment",
        ] {
            assert!(
                validate_provider_webhook_url(webhook_url).is_err(),
                "unsafe provider webhook URL was accepted: {webhook_url}"
            );
        }
    }

    #[test]
    fn configured_twilio_and_vonage_adapters_are_explicitly_deferred() {
        for configs in [
            ProviderConfigs {
                twilio: Some(twilio_config("twilio-deferred")),
                telnyx: None,
                vonage: None,
            },
            ProviderConfigs {
                twilio: None,
                telnyx: None,
                vonage: Some(VonageConfig {
                    account_profile: "vonage-deferred".into(),
                    application_id: "application-a".into(),
                    private_key: SecretRef("unused".into()),
                    signature_secret: SecretRef("unused".into()),
                    base_url: vonage_base_url(),
                }),
            },
        ] {
            let error = ProviderRegistry::from_config(&configs)
                .err()
                .expect("deferred provider config must fail");
            assert!(error.to_string().contains("deferred beyond Bridgefu 1.0"));
        }
    }

    #[test]
    fn provider_registry_resolves_only_the_matching_kind_and_profile() {
        let registry = ProviderRegistry::default();
        registry
            .insert(Arc::new(
                TwilioProvider::new(twilio_config("twilio-sandbox")).unwrap(),
            ))
            .unwrap();
        let matching = ProviderEndpointConfig {
            provider: ProviderKind::Twilio,
            account_profile: "twilio-sandbox".into(),
            destination: Some("+12065550100".into()),
        };
        assert_eq!(
            registry.resolve_endpoint(&matching).unwrap().account_key(),
            ProviderAccountKey::parse("twilio-sandbox").unwrap()
        );

        for endpoint in [
            ProviderEndpointConfig {
                account_profile: "twilio-production".into(),
                ..matching.clone()
            },
            ProviderEndpointConfig {
                provider: ProviderKind::Telnyx,
                ..matching.clone()
            },
        ] {
            assert!(matches!(
                registry.resolve_endpoint(&endpoint),
                Err(ProviderError::AccountProfileMismatch)
            ));
        }
    }

    #[test]
    fn signed_twilio_webhook_rejects_a_credential_account_mismatch() {
        let provider = TwilioProvider::new(twilio_config("twilio-sandbox")).unwrap();
        let accepted = provider
            .verify_webhook(&signed_twilio_webhook(
                "AC-account",
                Some("completed"),
                Some("7"),
            ))
            .unwrap();
        assert_eq!(accepted.provider_call_id.as_deref(), Some("CA-call"));

        assert!(matches!(
            provider.verify_webhook(&signed_twilio_webhook(
                "AC-other-account",
                Some("completed"),
                Some("7"),
            )),
            Err(ProviderError::InvalidSignature)
        ));
    }

    #[test]
    fn twilio_status_event_ids_dedupe_exact_replays_and_separate_sequences() {
        let provider = TwilioProvider::new(twilio_config("twilio-sandbox")).unwrap();
        let sequence_seven = provider
            .verify_webhook(&signed_twilio_webhook(
                "AC-account",
                Some("in-progress"),
                Some("7"),
            ))
            .unwrap();
        let exact_replay = provider
            .verify_webhook(&signed_twilio_webhook(
                "AC-account",
                Some("in-progress"),
                Some("7"),
            ))
            .unwrap();
        let sequence_eight = provider
            .verify_webhook(&signed_twilio_webhook(
                "AC-account",
                Some("in-progress"),
                Some("8"),
            ))
            .unwrap();
        assert_eq!(sequence_seven.event_id, exact_replay.event_id);
        assert_ne!(sequence_seven.event_id, sequence_eight.event_id);
        assert!(sequence_seven.event_id.contains(":sequence:7:"));

        let fallback = provider
            .verify_webhook(&signed_twilio_webhook(
                "AC-account",
                Some("completed"),
                None,
            ))
            .unwrap();
        let fallback_replay = provider
            .verify_webhook(&signed_twilio_webhook(
                "AC-account",
                Some("completed"),
                None,
            ))
            .unwrap();
        assert_eq!(fallback.event_id, fallback_replay.event_id);
        assert!(fallback.event_id.contains(":no-sequence:completed"));
    }

    #[test]
    fn twilio_status_callbacks_require_status_and_bounded_digit_sequences() {
        let provider = TwilioProvider::new(twilio_config("twilio-sandbox")).unwrap();
        assert!(matches!(
            provider.verify_webhook(&signed_twilio_webhook("AC-account", None, Some("1"),)),
            Err(ProviderError::InvalidWebhookField("CallStatus"))
        ));
        assert!(matches!(
            provider.verify_webhook(&signed_twilio_webhook(
                "AC-account",
                Some("callback"),
                Some("1"),
            )),
            Err(ProviderError::InvalidWebhookField("CallStatus"))
        ));
        for sequence in ["", "not-digits", "123456789012345678901"] {
            assert!(matches!(
                provider.verify_webhook(&signed_twilio_webhook(
                    "AC-account",
                    Some("completed"),
                    Some(sequence),
                )),
                Err(ProviderError::InvalidWebhookField("SequenceNumber"))
            ));
        }
    }

    #[test]
    fn telnyx_verified_callbacks_reject_missing_or_blank_event_ids() {
        let valid_data = json!({
            "id": "event-a",
            "event_type": "call.answered",
            "payload": {
                "call_control_id": "call-control-a",
                "connection_id": "connection-a"
            }
        });
        let (provider, request) = signed_telnyx_webhook(valid_data.clone());
        assert_eq!(
            provider.verify_webhook(&request).unwrap().event_id,
            "event-a"
        );

        for invalid in [
            Value::Null,
            Value::String(String::new()),
            Value::String("  ".into()),
        ] {
            let mut data = valid_data.clone();
            if invalid.is_null() {
                data.as_object_mut().unwrap().remove("id");
            } else {
                data["id"] = invalid;
            }
            let (provider, request) = signed_telnyx_webhook(data);
            assert!(matches!(
                provider.verify_webhook(&request),
                Err(ProviderError::InvalidWebhookField("data.id"))
            ));
        }
    }

    #[test]
    fn telnyx_verified_callbacks_require_the_configured_connection() {
        let valid_data = json!({
            "id": "event-a",
            "event_type": "call.answered",
            "payload": {
                "call_control_id": "call-control-a",
                "connection_id": "connection-a"
            }
        });
        let (provider, request) = signed_telnyx_webhook(valid_data.clone());
        assert!(provider.verify_webhook(&request).is_ok());

        let (provider, mut altered_raw_body) = signed_telnyx_webhook(valid_data.clone());
        // Whitespace would leave the parsed JSON equivalent, but the SDK must
        // verify the untouched wire bytes rather than a reserialized value.
        altered_raw_body.body.push(b' ');
        assert!(matches!(
            provider.verify_webhook(&altered_raw_body),
            Err(ProviderError::InvalidSignature)
        ));

        for connection_id in [None, Some("connection-b")] {
            let mut data = valid_data.clone();
            match connection_id {
                Some(connection_id) => {
                    data["payload"]["connection_id"] = Value::String(connection_id.into())
                }
                None => {
                    data["payload"]
                        .as_object_mut()
                        .unwrap()
                        .remove("connection_id");
                }
            }
            let (provider, request) = signed_telnyx_webhook(data);
            assert!(matches!(
                provider.verify_webhook(&request),
                Err(ProviderError::InvalidSignature)
            ));
        }
    }
}
