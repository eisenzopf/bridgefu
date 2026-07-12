//! Native programmable-voice control adapters.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use base64::Engine;
use dashmap::DashMap;
use hmac::{Hmac, Mac};
use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};
use ring::signature::{UnparsedPublicKey, ED25519};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha1::Sha1;
use sha2::{Digest, Sha256};

use bridgefu::call_engine::ProviderAccountKey;
use bridgefu::call_service::{ProviderEndpointConfig, ProviderKind};

type HmacSha1 = Hmac<Sha1>;

const MAX_PROVIDER_EVENT_ID_BYTES: usize = 512;
const MAX_PROVIDER_EVENT_KIND_BYTES: usize = 128;
const MAX_TWILIO_SEQUENCE_DIGITS: usize = 20;

#[derive(Clone, Deserialize)]
#[serde(transparent)]
pub struct SecretRef(String);

impl SecretRef {
    pub fn resolve(&self) -> Result<String, ProviderError> {
        if let Some(name) = self.0.strip_prefix("env:") {
            std::env::var(name).map_err(|_| {
                ProviderError::Configuration(format!("environment variable {name} is not set"))
            })
        } else {
            Ok(self.0.clone())
        }
    }
}

impl fmt::Debug for SecretRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretRef([redacted])")
    }
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
    #[serde(default = "telnyx_base_url")]
    pub base_url: String,
}

#[derive(Clone, Debug, Deserialize)]
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

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OriginateCommand {
    pub from: String,
    pub to: String,
    pub answer_url: Option<String>,
    pub event_url: Option<String>,
    pub idempotency_key: String,
    #[serde(default)]
    pub metadata: BTreeMap<String, String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProviderCall {
    pub provider: String,
    pub provider_call_id: String,
    pub state: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NormalizedProviderEvent {
    pub provider: String,
    pub event_id: String,
    pub provider_call_id: Option<String>,
    pub event_type: String,
    pub occurred_at: Option<String>,
    pub raw: Value,
}

#[derive(Clone, Debug)]
pub struct WebhookRequest {
    pub url: String,
    pub headers: BTreeMap<String, String>,
    pub content_type: String,
    pub body: Vec<u8>,
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
    async fn transfer(&self, call_id: &str, target: &str) -> Result<(), ProviderError>;
    async fn hangup(&self, call_id: &str) -> Result<(), ProviderError>;
    async fn send_dtmf(&self, call_id: &str, digits: &str) -> Result<(), ProviderError>;
    fn verify_webhook(
        &self,
        request: &WebhookRequest,
    ) -> Result<NormalizedProviderEvent, ProviderError>;
}

#[derive(Clone, Default)]
pub struct ProviderRegistry {
    providers: Arc<DashMap<String, Arc<dyn ProviderControl>>>,
}

impl ProviderRegistry {
    pub fn from_config(config: &ProviderConfigs) -> Result<Self, ProviderError> {
        config.validate_account_profiles()?;
        let registry = Self::default();
        if let Some(config) = &config.twilio {
            registry.insert(Arc::new(TwilioProvider::new(config.clone())?))?;
        }
        if let Some(config) = &config.telnyx {
            registry.insert(Arc::new(TelnyxProvider::new(config.clone())?))?;
        }
        if let Some(config) = &config.vonage {
            registry.insert(Arc::new(VonageProvider::new(config.clone())?))?;
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
}

struct TwilioProvider {
    config: TwilioConfig,
    account_key: ProviderAccountKey,
    auth_token: String,
    http: reqwest::Client,
}

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

    async fn transfer(&self, call_id: &str, target: &str) -> Result<(), ProviderError> {
        let twiml = format!(
            "<Response><Dial><Sip>{}</Sip></Dial></Response>",
            xml_escape(target)
        );
        send_empty(
            self.http
                .post(self.call_url(Some(call_id)))
                .basic_auth(&self.config.account_sid, Some(&self.auth_token))
                .form(&[("Twiml", twiml)]),
        )
        .await
    }

    async fn hangup(&self, call_id: &str) -> Result<(), ProviderError> {
        send_empty(
            self.http
                .post(self.call_url(Some(call_id)))
                .basic_auth(&self.config.account_sid, Some(&self.auth_token))
                .form(&[("Status", "completed")]),
        )
        .await
    }

    async fn send_dtmf(&self, call_id: &str, digits: &str) -> Result<(), ProviderError> {
        let twiml = format!(
            "<Response><Play digits=\"{}\"/></Response>",
            xml_escape(digits)
        );
        send_empty(
            self.http
                .post(self.call_url(Some(call_id)))
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

struct TelnyxProvider {
    config: TelnyxConfig,
    account_key: ProviderAccountKey,
    api_key: String,
    webhook_key: Vec<u8>,
    http: reqwest::Client,
}

impl TelnyxProvider {
    fn new(config: TelnyxConfig) -> Result<Self, ProviderError> {
        validate_account_profile(&config.account_profile)?;
        let account_key = ProviderAccountKey::parse(config.account_profile.clone())
            .map_err(|_| ProviderError::Configuration("invalid provider account profile".into()))?;
        let webhook_key = base64::engine::general_purpose::STANDARD
            .decode(config.webhook_public_key.resolve()?)
            .map_err(|_| {
                ProviderError::Configuration("invalid Telnyx webhook public key".into())
            })?;
        Ok(Self {
            api_key: config.api_key.resolve()?,
            config,
            account_key,
            webhook_key,
            http: reqwest::Client::new(),
        })
    }

    fn action_url(&self, call_id: &str, action: &str) -> String {
        format!("{}/calls/{call_id}/actions/{action}", self.config.base_url)
    }

    fn request(&self, request: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        request.bearer_auth(&self.api_key)
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
        let mut body = json!({
            "connection_id": self.config.connection_id,
            "from": command.from,
            "to": command.to,
            "command_id": command.idempotency_key,
        });
        if let Some(url) = command.event_url {
            body["webhook_url"] = Value::String(url);
        }
        let value = send_json(
            self.request(self.http.post(format!("{}/calls", self.config.base_url)))
                .json(&body),
        )
        .await?;
        let data = value.get("data").unwrap_or(&value);
        Ok(ProviderCall {
            provider: self.name().into(),
            provider_call_id: required_string(data, "call_control_id")?,
            state: "queued".into(),
        })
    }

    async fn transfer(&self, call_id: &str, target: &str) -> Result<(), ProviderError> {
        send_empty(
            self.request(self.http.post(self.action_url(call_id, "transfer")))
                .json(&json!({"to": target})),
        )
        .await
    }
    async fn hangup(&self, call_id: &str) -> Result<(), ProviderError> {
        send_empty(
            self.request(self.http.post(self.action_url(call_id, "hangup")))
                .json(&json!({})),
        )
        .await
    }
    async fn send_dtmf(&self, call_id: &str, digits: &str) -> Result<(), ProviderError> {
        send_empty(
            self.request(self.http.post(self.action_url(call_id, "send_dtmf")))
                .json(&json!({"digits": digits})),
        )
        .await
    }

    fn verify_webhook(
        &self,
        request: &WebhookRequest,
    ) -> Result<NormalizedProviderEvent, ProviderError> {
        let signature = base64::engine::general_purpose::STANDARD
            .decode(
                request
                    .header("Telnyx-Signature-Ed25519")
                    .ok_or(ProviderError::InvalidSignature)?,
            )
            .map_err(|_| ProviderError::InvalidSignature)?;
        let timestamp = request
            .header("Telnyx-Timestamp")
            .ok_or(ProviderError::InvalidSignature)?;
        require_fresh_timestamp(timestamp, 300)?;
        let mut signed = timestamp.as_bytes().to_vec();
        signed.push(b'|');
        signed.extend_from_slice(&request.body);
        UnparsedPublicKey::new(&ED25519, &self.webhook_key)
            .verify(&signed, &signature)
            .map_err(|_| ProviderError::InvalidSignature)?;
        let raw = request.json()?;
        let data = raw.get("data").unwrap_or(&raw);
        let payload = data.get("payload").unwrap_or(data);
        validate_payload_credential(payload, &["connection_id"], &self.config.connection_id)?;
        let event_id =
            required_webhook_string(data, &["id"], "data.id", MAX_PROVIDER_EVENT_ID_BYTES)?;
        let provider_call_id = required_webhook_string(
            payload,
            &["call_control_id"],
            "data.payload.call_control_id",
            MAX_PROVIDER_EVENT_ID_BYTES,
        )?;
        let event_type = required_webhook_string(
            data,
            &["event_type"],
            "data.event_type",
            MAX_PROVIDER_EVENT_KIND_BYTES,
        )?;
        Ok(NormalizedProviderEvent {
            provider: self.name().into(),
            event_id,
            provider_call_id: Some(provider_call_id),
            event_type,
            occurred_at: data
                .get("occurred_at")
                .and_then(Value::as_str)
                .map(str::to_string),
            raw,
        })
    }
}

struct VonageProvider {
    config: VonageConfig,
    account_key: ProviderAccountKey,
    private_key: Vec<u8>,
    signature_secret: String,
    http: reqwest::Client,
}

#[derive(Serialize)]
struct VonageApiClaims<'a> {
    application_id: &'a str,
    iat: u64,
    exp: u64,
    jti: String,
}

#[derive(Debug, Deserialize)]
struct VonageWebhookClaims {
    iat: u64,
    jti: String,
    iss: String,
    payload_hash: Option<String>,
    api_key: Option<String>,
}

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

    async fn transfer(&self, call_id: &str, target: &str) -> Result<(), ProviderError> {
        self.put_action(call_id, json!({"action":"transfer", "destination": {"type":"ncco", "ncco":[{"action":"connect", "endpoint":[vonage_endpoint(target)]}]}})).await
    }
    async fn hangup(&self, call_id: &str) -> Result<(), ProviderError> {
        self.put_action(call_id, json!({"action":"hangup"})).await
    }
    async fn send_dtmf(&self, call_id: &str, digits: &str) -> Result<(), ProviderError> {
        self.put_action(call_id, json!({"action":"dtmf", "digits": digits}))
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

fn vonage_endpoint(value: &str) -> Value {
    if value.to_ascii_lowercase().starts_with("sip:") {
        json!({"type":"sip", "uri": value})
    } else {
        json!({"type":"phone", "number": value})
    }
}

async fn send_json(request: reqwest::RequestBuilder) -> Result<Value, ProviderError> {
    let response = request.send().await.map_err(ProviderError::Http)?;
    let status = response.status();
    let body = response.bytes().await.map_err(ProviderError::Http)?;
    if !status.is_success() {
        return Err(ProviderError::Remote {
            status: status.as_u16(),
            body: String::from_utf8_lossy(&body).into_owned(),
        });
    }
    serde_json::from_slice(&body).map_err(ProviderError::Json)
}

async fn send_empty(request: reqwest::RequestBuilder) -> Result<(), ProviderError> {
    let response = request.send().await.map_err(ProviderError::Http)?;
    let status = response.status();
    if status.is_success() {
        return Ok(());
    }
    let body = response.text().await.unwrap_or_default();
    Err(ProviderError::Remote {
        status: status.as_u16(),
        body,
    })
}

fn required_string(value: &Value, field: &'static str) -> Result<String, ProviderError> {
    value
        .get(field)
        .and_then(Value::as_str)
        .map(str::to_string)
        .ok_or(ProviderError::MissingField(field))
}

fn require_fresh_timestamp(timestamp: &str, tolerance_secs: u64) -> Result<(), ProviderError> {
    let timestamp: u64 = timestamp
        .parse()
        .map_err(|_| ProviderError::InvalidSignature)?;
    if unix_seconds().abs_diff(timestamp) > tolerance_secs {
        Err(ProviderError::InvalidSignature)
    } else {
        Ok(())
    }
}

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
    Http(reqwest::Error),
    #[error("provider returned HTTP {status}: {body}")]
    Remote { status: u16, body: String },
    #[error("provider response JSON error: {0}")]
    Json(serde_json::Error),
    #[error("provider response missing field {0}")]
    MissingField(&'static str),
    #[error("invalid provider webhook signature")]
    InvalidSignature,
    #[error("provider webhook field {0} is missing or invalid")]
    InvalidWebhookField(&'static str),
    #[error("provider account profile does not match the requested provider leg")]
    AccountProfileMismatch,
    #[error("provider operation is not supported")]
    Unsupported,
}

#[cfg(test)]
mod tests {
    use super::*;
    use ring::signature::KeyPair;

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

    fn signed_telnyx_webhook(data: Value) -> (TelnyxProvider, WebhookRequest) {
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
            base_url: telnyx_base_url(),
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
            base_url: telnyx_base_url(),
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
vonage:
  application_id: application-a
  private_key: private
  signature_secret: secret
"#,
        )
        .unwrap();
        assert_eq!(defaults.twilio.as_ref().unwrap().account_profile, "twilio");
        assert_eq!(defaults.telnyx.as_ref().unwrap().account_profile, "telnyx");
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
                base_url: telnyx_base_url(),
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
}
