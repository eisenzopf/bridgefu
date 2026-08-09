use anyhow::{bail, Context, Result};
use async_trait::async_trait;
use reqwest::{Client, Method};
use serde_json::Value;
use std::time::Duration;
use url::Url;
use zeroize::Zeroizing;

#[async_trait]
pub trait VapiApi: Send + Sync {
    async fn get(&self, resource: &str, id: &str) -> Result<Option<Value>>;
    async fn create(&self, resource: &str, body: &Value) -> Result<Value>;
    async fn update(&self, resource: &str, id: &str, body: &Value) -> Result<Value>;
    async fn delete(&self, resource: &str, id: &str) -> Result<()>;
}

#[derive(Clone)]
pub struct HttpVapiApi {
    client: Client,
    base: Url,
    api_key: Zeroizing<String>,
}

impl HttpVapiApi {
    pub fn new(api_base: &str, api_key: String) -> Result<Self> {
        let base = Url::parse(api_base).context("invalid Vapi API base URL")?;
        if base.scheme() != "https"
            || base.host_str().is_none()
            || base.username() != ""
            || base.password().is_some()
            || base.query().is_some()
            || base.fragment().is_some()
        {
            bail!("Vapi API base URL must be a plain HTTPS origin");
        }
        if api_key.len() < 24 {
            bail!("Vapi API key is invalid");
        }
        Ok(Self {
            client: Client::builder()
                .timeout(Duration::from_secs(30))
                .redirect(reqwest::redirect::Policy::none())
                .user_agent(concat!("vapire-iac/", env!("CARGO_PKG_VERSION")))
                .build()?,
            base,
            api_key: Zeroizing::new(api_key),
        })
    }

    async fn request(
        &self,
        method: Method,
        resource: &str,
        id: Option<&str>,
        body: Option<&Value>,
    ) -> Result<Option<Value>> {
        validate_segment(resource)?;
        if let Some(value) = id {
            validate_segment(value)?;
        }
        let path = match id {
            Some(value) => format!("{resource}/{value}"),
            None => resource.to_string(),
        };
        let url = self.base.join(&path)?;
        let mut request = self
            .client
            .request(method.clone(), url)
            .bearer_auth(self.api_key.as_str())
            .header("accept", "application/json");
        if let Some(value) = body {
            request = request.json(value);
        }
        let response = request.send().await.context("Vapi request failed")?;
        let status = response.status();
        let bytes = response.bytes().await.context("reading Vapi response")?;
        if status == reqwest::StatusCode::NOT_FOUND && method == Method::GET {
            return Ok(None);
        }
        if !status.is_success() {
            let code = match status.as_u16() {
                401 | 403 => "vapi_unauthorized",
                404 => "vapi_resource_missing",
                409 => "vapi_conflict",
                429 => "vapi_throttled",
                _ => "vapi_request_failed",
            };
            bail!(code);
        }
        if bytes.is_empty() {
            return Ok(None);
        }
        let value = serde_json::from_slice(&bytes).context("invalid Vapi response")?;
        Ok(Some(value))
    }
}

fn validate_segment(value: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        bail!("invalid Vapi resource identifier");
    }
    Ok(())
}

#[async_trait]
impl VapiApi for HttpVapiApi {
    async fn get(&self, resource: &str, id: &str) -> Result<Option<Value>> {
        self.request(Method::GET, resource, Some(id), None).await
    }

    async fn create(&self, resource: &str, body: &Value) -> Result<Value> {
        self.request(Method::POST, resource, None, Some(body))
            .await?
            .context("empty Vapi create response")
    }

    async fn update(&self, resource: &str, id: &str, body: &Value) -> Result<Value> {
        self.request(Method::PATCH, resource, Some(id), Some(body))
            .await?
            .context("empty Vapi update response")
    }

    async fn delete(&self, resource: &str, id: &str) -> Result<()> {
        self.request(Method::DELETE, resource, Some(id), None)
            .await?;
        Ok(())
    }
}
