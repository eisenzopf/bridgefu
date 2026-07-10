//! Native programmable-voice control adapters.

use std::collections::BTreeMap;
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

type HmacSha1 = Hmac<Sha1>;

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
    pub account_sid: String,
    pub auth_token: SecretRef,
    #[serde(default = "twilio_base_url")]
    pub base_url: String,
}

#[derive(Clone, Debug, Deserialize)]
pub struct TelnyxConfig {
    pub api_key: SecretRef,
    pub connection_id: String,
    pub webhook_public_key: SecretRef,
    #[serde(default = "telnyx_base_url")]
    pub base_url: String,
}

#[derive(Clone, Debug, Deserialize)]
pub struct VonageConfig {
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
        let registry = Self::default();
        if let Some(config) = &config.twilio {
            registry.insert(Arc::new(TwilioProvider::new(config.clone())?));
        }
        if let Some(config) = &config.telnyx {
            registry.insert(Arc::new(TelnyxProvider::new(config.clone())?));
        }
        if let Some(config) = &config.vonage {
            registry.insert(Arc::new(VonageProvider::new(config.clone())?));
        }
        Ok(registry)
    }

    pub fn insert(&self, provider: Arc<dyn ProviderControl>) {
        self.providers.insert(provider.name().to_string(), provider);
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
}

struct TwilioProvider {
    config: TwilioConfig,
    auth_token: String,
    http: reqwest::Client,
}

impl TwilioProvider {
    fn new(config: TwilioConfig) -> Result<Self, ProviderError> {
        Ok(Self {
            auth_token: config.auth_token.resolve()?,
            config,
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
        let call_id = raw
            .get("CallSid")
            .or_else(|| raw.get("call_sid"))
            .and_then(Value::as_str)
            .map(str::to_string);
        let event_type = raw
            .get("CallStatus")
            .or_else(|| raw.get("call_status"))
            .and_then(Value::as_str)
            .unwrap_or("callback")
            .to_string();
        Ok(NormalizedProviderEvent {
            provider: self.name().into(),
            event_id: format!("{}:{}", call_id.as_deref().unwrap_or("unknown"), event_type),
            provider_call_id: call_id,
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
    api_key: String,
    webhook_key: Vec<u8>,
    http: reqwest::Client,
}

impl TelnyxProvider {
    fn new(config: TelnyxConfig) -> Result<Self, ProviderError> {
        let webhook_key = base64::engine::general_purpose::STANDARD
            .decode(config.webhook_public_key.resolve()?)
            .map_err(|_| {
                ProviderError::Configuration("invalid Telnyx webhook public key".into())
            })?;
        Ok(Self {
            api_key: config.api_key.resolve()?,
            config,
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
        Ok(NormalizedProviderEvent {
            provider: self.name().into(),
            event_id: data
                .get("id")
                .and_then(Value::as_str)
                .unwrap_or("unknown")
                .into(),
            provider_call_id: payload
                .get("call_control_id")
                .and_then(Value::as_str)
                .map(str::to_string),
            event_type: data
                .get("event_type")
                .and_then(Value::as_str)
                .unwrap_or("unknown")
                .into(),
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
        Ok(Self {
            private_key: config.private_key.resolve()?.into_bytes(),
            signature_secret: config.signature_secret.resolve()?,
            config,
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
        let call_id = raw.get("uuid").and_then(Value::as_str).map(str::to_string);
        let event_type = raw
            .get("status")
            .and_then(Value::as_str)
            .unwrap_or("callback")
            .to_string();
        Ok(NormalizedProviderEvent {
            provider: self.name().into(),
            event_id: claims.jti,
            provider_call_id: call_id,
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
    #[error("provider operation is not supported")]
    Unsupported,
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
