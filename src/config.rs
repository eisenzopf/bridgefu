//! YAML configuration for bridgefu and the mapping onto the
//! `rvoip-amazon-connect` server types.

use std::collections::BTreeMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use serde::Deserialize;

use rvoip_amazon_connect::{
    AttributeMapping, AwsConnectStarter, ConnectConfig, ConnectContactStarter,
    ScreenPopServerConfig, SipConfig, UnmappedPolicy,
};

/// Top-level config (see `config/bridgefu.example.yaml`).
#[derive(Debug, Deserialize)]
pub struct Config {
    pub aws: AwsCfg,
    pub sip: SipCfg,
    #[serde(default)]
    pub contact: ContactCfg,
    #[serde(default)]
    pub mapping: MappingCfg,
    #[serde(default)]
    pub observability: ObsCfg,
}

#[derive(Debug, Deserialize)]
pub struct AwsCfg {
    pub region: String,
    pub instance_id: String,
    pub contact_flow_id: String,
}

#[derive(Debug, Deserialize)]
pub struct SipCfg {
    #[serde(default = "default_bind_ip")]
    pub bind_ip: String,
    #[serde(default = "default_port")]
    pub port: u16,
    /// Public IP for SIP Via/Contact. `"auto"` → IMDSv2 public-ipv4.
    #[serde(default = "default_auto")]
    pub advertised_ip: String,
    /// Public IP for SDP media (`c=`/`m=`). `"auto"` → IMDSv2 public-ipv4.
    #[serde(default = "default_auto")]
    pub media_public_ip: String,
}

#[derive(Debug, Deserialize)]
pub struct ContactCfg {
    #[serde(default = "default_display_name")]
    pub default_display_name: String,
    #[serde(default = "default_signaling_timeout")]
    pub signaling_timeout_secs: u64,
    #[serde(default = "default_media_timeout")]
    pub media_connect_timeout_secs: u64,
    #[serde(default = "default_keepalive")]
    pub keepalive_interval_secs: u64,
    #[serde(default = "default_idle_ttl")]
    pub session_idle_ttl_secs: u64,
}

#[derive(Debug, Deserialize)]
pub struct MappingCfg {
    /// `drop` | `pass_prefixed`
    #[serde(default = "default_unmapped")]
    pub unmapped: String,
    #[serde(default = "default_prefix")]
    pub passthrough_prefix: String,
    /// inbound SIP header name → Connect attribute key
    #[serde(default)]
    pub rename: BTreeMap<String, String>,
}

#[derive(Debug, Deserialize)]
pub struct ObsCfg {
    #[serde(default = "default_log_level")]
    pub log_level: String,
    #[serde(default = "default_log_format")]
    pub log_format: String,
    #[serde(default = "default_http_bind")]
    pub http_bind: String,
}

impl Config {
    /// Parse a YAML config file.
    pub fn load(path: &std::path::Path) -> Result<Self> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("reading config file {}", path.display()))?;
        serde_yaml::from_str(&text).with_context(|| format!("parsing {}", path.display()))
    }

    /// Build the `rvoip-amazon-connect` server config from this YAML. Async
    /// because it resolves AWS credentials and may query IMDS for `auto` IPs.
    pub async fn into_server_config(&self) -> Result<ScreenPopServerConfig> {
        // --- mapping ---
        let unmapped = match self.mapping.unmapped.as_str() {
            "drop" => UnmappedPolicy::Drop,
            "pass_prefixed" => UnmappedPolicy::PassPrefixed,
            other => return Err(anyhow!("invalid mapping.unmapped: {other} (drop|pass_prefixed)")),
        };
        let mapping = AttributeMapping {
            rename: self.mapping.rename.clone(),
            passthrough_prefix: self.mapping.passthrough_prefix.clone(),
            unmapped,
        };

        // --- connect ---
        let mut connect = ConnectConfig::new(&self.aws.instance_id, &self.aws.contact_flow_id)
            .with_region(self.aws.region.clone())
            .with_attribute_mapping(mapping);
        connect.default_display_name = self.contact.default_display_name.clone();
        connect.signaling_timeout = Duration::from_secs(self.contact.signaling_timeout_secs);
        connect.media_connect_timeout = Duration::from_secs(self.contact.media_connect_timeout_secs);
        connect.keepalive_interval = Duration::from_secs(self.contact.keepalive_interval_secs);
        connect.session_idle_ttl = Duration::from_secs(self.contact.session_idle_ttl_secs);

        // --- sip ---
        let bind_ip: IpAddr = self
            .sip
            .bind_ip
            .parse()
            .with_context(|| format!("invalid sip.bind_ip: {}", self.sip.bind_ip))?;
        let mut sip = SipConfig::on("bridgefu", bind_ip, self.sip.port);

        let advertised_ip = resolve_public_ip(&self.sip.advertised_ip)
            .await
            .context("resolving sip.advertised_ip")?;
        sip.sip_advertised_addr = Some(SocketAddr::new(advertised_ip, self.sip.port));

        let media_ip = resolve_public_ip(&self.sip.media_public_ip)
            .await
            .context("resolving sip.media_public_ip")?;
        // Port 0 → keep the dynamically-allocated RTP port, swap in the public IP.
        sip.media_public_addr = Some(SocketAddr::new(media_ip, 0));

        // --- control-plane starter (AWS creds via the default chain / instance role) ---
        let starter: Arc<dyn ConnectContactStarter> =
            Arc::new(AwsConnectStarter::from_env(Some(self.aws.region.clone())).await);

        Ok(ScreenPopServerConfig::new(sip, connect, starter))
    }
}

/// Resolve a configured IP value: a literal IP, or `"auto"` → IMDSv2 public-ipv4.
async fn resolve_public_ip(value: &str) -> Result<IpAddr> {
    if value.eq_ignore_ascii_case("auto") {
        let ip = crate::imds::public_ipv4()
            .await
            .context("IMDSv2 public-ipv4 lookup (set a literal IP if not on EC2)")?;
        ip.parse()
            .with_context(|| format!("IMDS returned an unparseable IP: {ip:?}"))
    } else {
        value
            .parse()
            .with_context(|| format!("invalid IP {value:?} (use a literal IP or \"auto\")"))
    }
}

fn default_bind_ip() -> String { "0.0.0.0".into() }
fn default_port() -> u16 { 5060 }
fn default_auto() -> String { "auto".into() }
fn default_display_name() -> String { "bridgefu".into() }
fn default_signaling_timeout() -> u64 { 15 }
fn default_media_timeout() -> u64 { 30 }
fn default_keepalive() -> u64 { 10 }
fn default_idle_ttl() -> u64 { 120 }
fn default_unmapped() -> String { "drop".into() }
fn default_prefix() -> String { "X-".into() }
fn default_log_level() -> String { "info".into() }
fn default_log_format() -> String { "json".into() }
fn default_http_bind() -> String { "0.0.0.0:9090".into() }

impl Default for ContactCfg {
    fn default() -> Self {
        Self {
            default_display_name: default_display_name(),
            signaling_timeout_secs: default_signaling_timeout(),
            media_connect_timeout_secs: default_media_timeout(),
            keepalive_interval_secs: default_keepalive(),
            session_idle_ttl_secs: default_idle_ttl(),
        }
    }
}
impl Default for MappingCfg {
    fn default() -> Self {
        Self {
            unmapped: default_unmapped(),
            passthrough_prefix: default_prefix(),
            rename: BTreeMap::new(),
        }
    }
}
impl Default for ObsCfg {
    fn default() -> Self {
        Self {
            log_level: default_log_level(),
            log_format: default_log_format(),
            http_bind: default_http_bind(),
        }
    }
}
