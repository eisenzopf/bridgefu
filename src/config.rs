//! YAML configuration for bridgefu and the mapping onto the
//! `rvoip-amazon-connect` server types.
//!
//! Multi-tenant SIP-URI routing (CONTRACTS.md B.4): a `tenants:` map keyed by
//! SIP user part routes each INVITE to per-tenant `{instance_id,
//! contact_flow_id, mapping, default_display_name}`. Match order: Request-URI
//! user part → `To:` user part → `default_tenant` → reject `404 Not Found`
//! (+ `bridgefu_unknown_tenant_total`). The legacy single-tenant schema
//! (top-level `aws.instance_id`/`aws.contact_flow_id`) is still accepted and
//! becomes one catch-all tenant named `default`.

use std::collections::BTreeMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use serde::Deserialize;

use rvoip_amazon_connect::{
    request_uri_user, to_uri_user, AttributeMapping, AwsConnectStarter, ConnectConfig,
    ConnectContactStarter, ContactRoute, IncomingCall, RouteDecision, ScreenPopServerConfig,
    SipConfig, UnmappedPolicy,
};

/// Top-level config (see `config/bridgefu.example.yaml`).
#[derive(Debug, Deserialize)]
pub struct Config {
    pub aws: AwsCfg,
    pub sip: SipCfg,
    #[serde(default)]
    pub contact: ContactCfg,
    /// Global header→attribute mapping: the per-tenant default, and the
    /// mapping of the legacy single-tenant schema.
    #[serde(default)]
    pub mapping: MappingCfg,
    #[serde(default)]
    pub observability: ObsCfg,
    /// Tenant to route to when neither the R-URI nor the To user part
    /// matches. `null`/absent → reject unmatched INVITEs with 404.
    #[serde(default)]
    pub default_tenant: Option<String>,
    /// Routing table — key is the SIP user part (e.g. `banking` for
    /// `sip:banking@<eip>`).
    #[serde(default)]
    pub tenants: BTreeMap<String, TenantCfg>,
}

#[derive(Debug, Deserialize)]
pub struct AwsCfg {
    pub region: String,
    /// Legacy single-tenant Connect instance id. Ignored when `tenants:` is
    /// non-empty.
    #[serde(default)]
    pub instance_id: Option<String>,
    /// Legacy single-tenant contact-flow id. Ignored when `tenants:` is
    /// non-empty.
    #[serde(default)]
    pub contact_flow_id: Option<String>,
}

/// One tenant: the Connect target for a SIP user part (CONTRACTS.md B.4).
#[derive(Debug, Deserialize, Clone)]
pub struct TenantCfg {
    pub instance_id: String,
    pub contact_flow_id: String,
    /// Display name shown to the agent when the INVITE supplies none.
    /// Falls back to `contact.default_display_name`.
    #[serde(default)]
    pub default_display_name: Option<String>,
    /// Per-tenant header→attribute mapping. Falls back to the top-level
    /// `mapping:` block.
    #[serde(default)]
    pub mapping: Option<MappingCfg>,
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

#[derive(Debug, Deserialize, Clone)]
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
        let cfg: Self =
            serde_yaml::from_str(&text).with_context(|| format!("parsing {}", path.display()))?;
        cfg.resolved_tenants()
            .with_context(|| format!("validating {}", path.display()))?;
        Ok(cfg)
    }

    /// Resolve the effective routing table: `(user part → route, effective
    /// default tenant)`. Applies the legacy single-tenant fallback; an empty
    /// table means every INVITE is rejected 404.
    pub fn resolved_tenants(&self) -> Result<(BTreeMap<String, ContactRoute>, Option<String>)> {
        if !self.tenants.is_empty() {
            let mut table = BTreeMap::new();
            for (name, tenant) in &self.tenants {
                if name.is_empty() {
                    return Err(anyhow!("tenants: empty tenant name (SIP user part)"));
                }
                if tenant.instance_id.is_empty() || tenant.contact_flow_id.is_empty() {
                    return Err(anyhow!(
                        "tenants.{name}: instance_id and contact_flow_id must be non-empty"
                    ));
                }
                let mapping = tenant.mapping.as_ref().unwrap_or(&self.mapping);
                table.insert(
                    name.clone(),
                    ContactRoute {
                        label: name.clone(),
                        instance_id: Some(tenant.instance_id.clone()),
                        contact_flow_id: Some(tenant.contact_flow_id.clone()),
                        attribute_mapping: Some(attribute_mapping(mapping)?),
                        default_display_name: tenant.default_display_name.clone(),
                    },
                );
            }
            if let Some(d) = &self.default_tenant {
                if !table.contains_key(d) {
                    return Err(anyhow!("default_tenant {d:?} is not a key of tenants"));
                }
            }
            return Ok((table, self.default_tenant.clone()));
        }

        // Legacy single-tenant schema: one catch-all tenant named `default`.
        match (&self.aws.instance_id, &self.aws.contact_flow_id) {
            (Some(instance), Some(flow)) if !instance.is_empty() && !flow.is_empty() => {
                if self.default_tenant.is_some() {
                    return Err(anyhow!(
                        "default_tenant is set but tenants is empty (legacy single-tenant \
                         config routes everything already)"
                    ));
                }
                let route = ContactRoute {
                    label: LEGACY_TENANT.to_string(),
                    instance_id: Some(instance.clone()),
                    contact_flow_id: Some(flow.clone()),
                    attribute_mapping: Some(attribute_mapping(&self.mapping)?),
                    default_display_name: None,
                };
                Ok((
                    BTreeMap::from([(LEGACY_TENANT.to_string(), route)]),
                    Some(LEGACY_TENANT.to_string()),
                ))
            }
            (None, None) => {
                if self.default_tenant.is_some() {
                    return Err(anyhow!("default_tenant is set but tenants is empty"));
                }
                // 0 tenants: valid — serve and reject every INVITE with 404
                // until the reconciler renders a tenant.
                Ok((BTreeMap::new(), None))
            }
            _ => Err(anyhow!(
                "aws.instance_id and aws.contact_flow_id must be set together \
                 (legacy single-tenant schema), or use tenants:"
            )),
        }
    }

    /// The loaded tenant names (for `/healthz` and metric pre-seeding).
    pub fn tenant_names(&self) -> Result<Vec<String>> {
        Ok(self.resolved_tenants()?.0.into_keys().collect())
    }

    /// Build the `rvoip-amazon-connect` server config from this YAML. Async
    /// because it resolves AWS credentials and may query IMDS for `auto` IPs.
    pub async fn into_server_config(&self) -> Result<ScreenPopServerConfig> {
        let (table, default_tenant) = self.resolved_tenants()?;

        // --- connect defaults (every real call is routed, so the empty
        //     instance/flow placeholders are never used to place a contact) ---
        let mut connect = ConnectConfig::new(
            self.aws.instance_id.clone().unwrap_or_default(),
            self.aws.contact_flow_id.clone().unwrap_or_default(),
        )
        .with_region(self.aws.region.clone())
        .with_attribute_mapping(attribute_mapping(&self.mapping)?);
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

        // --- per-INVITE router (B.4 match order) ---
        let router = Arc::new(move |call: &IncomingCall| {
            let ruri_user = request_uri_user(call);
            let to_user = to_uri_user(call);
            match match_tenant(
                &table,
                default_tenant.as_deref(),
                ruri_user.as_deref(),
                to_user.as_deref(),
            ) {
                Some(route) => {
                    metrics::counter!(
                        "bridgefu_calls_routed_total",
                        "tenant" => route.label.clone()
                    )
                    .increment(1);
                    RouteDecision::Route(route.clone())
                }
                None => {
                    metrics::counter!("bridgefu_unknown_tenant_total").increment(1);
                    tracing::warn!(
                        ruri_user = ruri_user.as_deref().unwrap_or("-"),
                        to_user = to_user.as_deref().unwrap_or("-"),
                        "no tenant matches inbound INVITE — rejecting 404"
                    );
                    RouteDecision::Reject {
                        status: 404,
                        reason: "Not Found".into(),
                    }
                }
            }
        });

        Ok(ScreenPopServerConfig::new(sip, connect, starter).with_router(router))
    }
}

/// Tenant name used for the legacy single-tenant schema.
pub const LEGACY_TENANT: &str = "default";

/// B.4 match order: R-URI user part, else `To:` user part, else the default
/// tenant, else `None` (caller rejects 404).
fn match_tenant<'a>(
    table: &'a BTreeMap<String, ContactRoute>,
    default_tenant: Option<&str>,
    ruri_user: Option<&str>,
    to_user: Option<&str>,
) -> Option<&'a ContactRoute> {
    ruri_user
        .and_then(|u| table.get(u))
        .or_else(|| to_user.and_then(|u| table.get(u)))
        .or_else(|| default_tenant.and_then(|d| table.get(d)))
}

/// Translate a YAML mapping block into the crate's `AttributeMapping`.
fn attribute_mapping(cfg: &MappingCfg) -> Result<AttributeMapping> {
    let unmapped = match cfg.unmapped.as_str() {
        "drop" => UnmappedPolicy::Drop,
        "pass_prefixed" => UnmappedPolicy::PassPrefixed,
        other => return Err(anyhow!("invalid mapping.unmapped: {other} (drop|pass_prefixed)")),
    };
    Ok(AttributeMapping {
        rename: cfg.rename.clone(),
        passthrough_prefix: cfg.passthrough_prefix.clone(),
        unmapped,
    })
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

#[cfg(test)]
mod tests {
    use super::*;

    /// The B.4 render the reconciler produces for two tenants.
    const B4_TWO_TENANTS: &str = r#"
aws: {"region": "us-west-2"}
sip: {"advertised_ip": "1.2.3.4", "bind_ip": "0.0.0.0", "media_public_ip": "1.2.3.4", "port": 5060}
observability: {"http_bind": "0.0.0.0:9090", "log_format": "json"}
default_tenant: null
tenants:
  "banking": {"contact_flow_id": "flow-banking", "default_display_name": "Vapi caller", "instance_id": "inst-banking", "mapping": {"rename": {"X-Correlation-Id": "correlation_id"}, "unmapped": "drop"}}
  "retail": {"contact_flow_id": "flow-retail", "instance_id": "inst-retail"}
"#;

    /// Today's single-tenant schema (bridgefu.example.yaml shape).
    const LEGACY: &str = r#"
aws:
  region: us-west-2
  instance_id: inst-legacy
  contact_flow_id: flow-legacy
sip: {advertised_ip: 1.2.3.4, media_public_ip: 1.2.3.4}
mapping:
  unmapped: drop
  rename: {X-Correlation-Id: correlation_id}
"#;

    fn parse(yaml: &str) -> Config {
        serde_yaml::from_str(yaml).expect("yaml parses")
    }

    #[test]
    fn b4_schema_resolves_two_tenants_no_default() {
        let cfg = parse(B4_TWO_TENANTS);
        let (table, default) = cfg.resolved_tenants().unwrap();
        assert_eq!(
            table.keys().cloned().collect::<Vec<_>>(),
            vec!["banking", "retail"]
        );
        assert_eq!(default, None);

        let banking = &table["banking"];
        assert_eq!(banking.label, "banking");
        assert_eq!(banking.instance_id.as_deref(), Some("inst-banking"));
        assert_eq!(banking.contact_flow_id.as_deref(), Some("flow-banking"));
        assert_eq!(banking.default_display_name.as_deref(), Some("Vapi caller"));
        let mapping = banking.attribute_mapping.as_ref().unwrap();
        assert_eq!(mapping.rename.get("X-Correlation-Id").unwrap(), "correlation_id");
        assert_eq!(mapping.unmapped, UnmappedPolicy::Drop);

        // retail has no mapping block → inherits the (default) top-level one.
        let retail = &table["retail"];
        assert_eq!(retail.default_display_name, None);
        assert_eq!(
            retail.attribute_mapping.as_ref().unwrap().unmapped,
            UnmappedPolicy::Drop // top-level default is `drop`
        );
    }

    #[test]
    fn match_order_is_ruri_then_to_then_default() {
        let cfg = parse(B4_TWO_TENANTS);
        let (table, _) = cfg.resolved_tenants().unwrap();

        // R-URI wins over To.
        let hit = match_tenant(&table, None, Some("banking"), Some("retail")).unwrap();
        assert_eq!(hit.label, "banking");
        // Unknown R-URI user falls through to To.
        let hit = match_tenant(&table, None, Some("nope"), Some("retail")).unwrap();
        assert_eq!(hit.label, "retail");
        // Nothing matches, no default → None (→ 404).
        assert!(match_tenant(&table, None, Some("nope"), Some("also-nope")).is_none());
        assert!(match_tenant(&table, None, None, None).is_none());
        // default_tenant catches the rest.
        let hit = match_tenant(&table, Some("banking"), Some("nope"), None).unwrap();
        assert_eq!(hit.label, "banking");
    }

    #[test]
    fn legacy_schema_becomes_catch_all_default_tenant() {
        let cfg = parse(LEGACY);
        let (table, default) = cfg.resolved_tenants().unwrap();
        assert_eq!(table.len(), 1);
        assert_eq!(default.as_deref(), Some(LEGACY_TENANT));
        let route = &table[LEGACY_TENANT];
        assert_eq!(route.instance_id.as_deref(), Some("inst-legacy"));
        assert_eq!(route.contact_flow_id.as_deref(), Some("flow-legacy"));
        // Any user part routes to it via the default.
        let hit = match_tenant(&table, default.as_deref(), Some("bridgefu"), None).unwrap();
        assert_eq!(hit.label, LEGACY_TENANT);
    }

    #[test]
    fn single_tenant_b4_render_with_legacy_keys_prefers_tenants() {
        // The reconciler's single-tenant render carries BOTH the tenants map
        // and the legacy aws keys; the tenants map must win.
        let yaml = r#"
aws: {"region": "us-west-2", "instance_id": "inst-x", "contact_flow_id": "flow-x"}
sip: {advertised_ip: 1.2.3.4, media_public_ip: 1.2.3.4}
default_tenant: null
contact: {"default_display_name": "Vapi caller"}
mapping: {"rename": {"X-Correlation-Id": "correlation_id"}, "unmapped": "drop"}
tenants:
  "banking": {"contact_flow_id": "flow-x", "instance_id": "inst-x", "mapping": {"unmapped": "drop"}}
"#;
        let cfg = parse(yaml);
        let (table, default) = cfg.resolved_tenants().unwrap();
        assert_eq!(table.keys().cloned().collect::<Vec<_>>(), vec!["banking"]);
        assert_eq!(default, None); // explicit null → unmatched user parts get 404
    }

    #[test]
    fn zero_tenants_is_valid_and_rejects_everything() {
        let yaml = r#"
aws: {"region": "us-west-2"}
sip: {advertised_ip: 1.2.3.4, media_public_ip: 1.2.3.4}
default_tenant: null
tenants: {}
"#;
        let cfg = parse(yaml);
        let (table, default) = cfg.resolved_tenants().unwrap();
        assert!(table.is_empty());
        assert_eq!(default, None);
        assert!(match_tenant(&table, default.as_deref(), Some("any"), None).is_none());
    }

    #[test]
    fn bad_default_tenant_is_rejected() {
        let yaml = r#"
aws: {"region": "us-west-2"}
sip: {advertised_ip: 1.2.3.4, media_public_ip: 1.2.3.4}
default_tenant: missing
tenants:
  "banking": {"contact_flow_id": "f", "instance_id": "i"}
"#;
        let err = parse(yaml).resolved_tenants().unwrap_err().to_string();
        assert!(err.contains("default_tenant"), "unexpected error: {err}");
    }

    #[test]
    fn half_configured_legacy_aws_is_rejected() {
        let yaml = r#"
aws: {"region": "us-west-2", "instance_id": "inst-only"}
sip: {advertised_ip: 1.2.3.4, media_public_ip: 1.2.3.4}
"#;
        let err = parse(yaml).resolved_tenants().unwrap_err().to_string();
        assert!(err.contains("must be set together"), "unexpected error: {err}");
    }

    #[test]
    fn tenant_names_lists_loaded_tenants() {
        assert_eq!(
            parse(B4_TWO_TENANTS).tenant_names().unwrap(),
            vec!["banking".to_string(), "retail".to_string()]
        );
        assert_eq!(
            parse(LEGACY).tenant_names().unwrap(),
            vec![LEGACY_TENANT.to_string()]
        );
    }
}
