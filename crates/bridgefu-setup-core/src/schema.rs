use anyhow::{bail, Context, Result};
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use url::Url;

pub const SETUP_SCHEMA: &str = "bridgefu.amazon-connect.setup/v1";
pub const MIN_TTL_SECONDS: u32 = 300;
pub const MAX_TTL_SECONDS: u32 = 604_800;
pub const DEFAULT_TTL_SECONDS: u32 = 3_600;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SetupConfiguration {
    pub schema: String,
    pub deployment_id: String,
    pub stack_name: String,
    pub aws: AwsTarget,
    pub connect: ConnectTarget,
    pub dns: DnsTarget,
    pub vapi: VapiTemplateTarget,
    pub screen_pop_fields: Vec<ScreenPopField>,
    #[serde(default)]
    pub routing: Option<RoutingConfiguration>,
    #[serde(default = "default_ttl")]
    pub context_ttl_seconds: u32,
    pub release: ReleaseInputs,
}

const fn default_ttl() -> u32 {
    DEFAULT_TTL_SECONDS
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AwsTarget {
    pub profile: String,
    pub account_id: String,
    pub region: String,
    #[serde(default)]
    pub cloudformation_service_role_arn: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ConnectTarget {
    pub instance_arn: String,
    pub instance_alias: String,
    pub target_contact_flow_arn: String,
    pub target_contact_flow_name: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DnsTarget {
    pub public_hosted_zone_id: String,
    pub public_hosted_zone_name: String,
    pub sip_hostname: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct VapiTemplateTarget {
    pub template: TemplateAssistantConfig,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TemplateAssistantConfig {
    pub name: String,
    pub model_provider: String,
    pub model: String,
    pub voice_provider: String,
    pub voice_id: String,
    pub placeholder_prompt: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReleaseInputs {
    pub template_url: String,
    pub release_manifest_url: String,
    pub release_manifest_sha256: String,
    #[serde(default)]
    pub cloudformation_parameters: BTreeMap<String, String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ScreenPopField {
    Text(TextField),
    Choice(ChoiceField),
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TextField {
    pub key: String,
    pub label: String,
    pub description: String,
    pub required: bool,
    pub max_length: u16,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ChoiceField {
    pub key: String,
    pub label: String,
    pub description: String,
    pub required: bool,
    pub choices: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RoutingConfiguration {
    /// Must name one configured choice field. Its value is looked up in the
    /// reviewed route map; it is never interpreted as an AWS identifier.
    pub field_key: String,
    pub routes: Vec<RouteMapping>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RouteMapping {
    pub value: String,
    pub target_contact_flow_arn: String,
    pub target_contact_flow_name: String,
}

impl ScreenPopField {
    pub fn key(&self) -> &str {
        match self {
            Self::Text(field) => &field.key,
            Self::Choice(field) => &field.key,
        }
    }

    pub fn label(&self) -> &str {
        match self {
            Self::Text(field) => &field.label,
            Self::Choice(field) => &field.label,
        }
    }

    pub fn description(&self) -> &str {
        match self {
            Self::Text(field) => &field.description,
            Self::Choice(field) => &field.description,
        }
    }

    pub const fn required(&self) -> bool {
        match self {
            Self::Text(field) => field.required,
            Self::Choice(field) => field.required,
        }
    }

    pub fn cloudformation_value(&self) -> Value {
        match self {
            Self::Text(field) => serde_json::json!({
                "key": field.key,
                "label": field.label,
                "description": field.description,
                "type": "text",
                "required": field.required,
                "max_length": field.max_length,
            }),
            Self::Choice(field) => serde_json::json!({
                "key": field.key,
                "label": field.label,
                "description": field.description,
                "type": "choice",
                "required": field.required,
                "choices": field.choices,
            }),
        }
    }

    pub fn vapi_property(&self) -> Value {
        match self {
            Self::Text(field) => serde_json::json!({
                "type": "string",
                "maxLength": field.max_length,
                "description": field.description,
            }),
            Self::Choice(field) => serde_json::json!({
                "type": "string",
                "enum": field.choices,
                "description": field.description,
            }),
        }
    }
}

impl SetupConfiguration {
    pub fn validate(&self) -> Result<()> {
        if self.schema != SETUP_SCHEMA {
            bail!("unsupported setup schema");
        }
        validate_deployment_id(&self.deployment_id)?;
        validate_stack_name(&self.stack_name)?;
        if self.aws.profile.is_empty() || self.aws.profile.len() > 128 {
            bail!("invalid AWS profile");
        }
        if self.aws.account_id.len() != 12
            || !self
                .aws
                .account_id
                .bytes()
                .all(|byte| byte.is_ascii_digit())
        {
            bail!("AWS account ID must contain 12 digits");
        }
        let region = Regex::new(r"^[a-z]{2}(?:-gov)?-[a-z]+-\d$").unwrap();
        if !region.is_match(&self.aws.region) {
            bail!("invalid AWS region");
        }
        validate_arn_account_region(
            "Connect instance ARN",
            &self.connect.instance_arn,
            &self.aws.account_id,
            &self.aws.region,
        )?;
        validate_arn_account_region(
            "target contact-flow ARN",
            &self.connect.target_contact_flow_arn,
            &self.aws.account_id,
            &self.aws.region,
        )?;
        let instance_prefix = format!("{}/contact-flow/", self.connect.instance_arn);
        if !self
            .connect
            .target_contact_flow_arn
            .starts_with(&instance_prefix)
        {
            bail!("target contact flow does not belong to the selected Connect instance");
        }
        let zone_name = self.dns.public_hosted_zone_name.trim_end_matches('.');
        let hostname = self.dns.sip_hostname.trim_end_matches('.');
        if self.dns.public_hosted_zone_id.is_empty()
            || zone_name.is_empty()
            || (hostname != zone_name && !hostname.ends_with(&format!(".{zone_name}")))
        {
            bail!("SIP hostname must belong to the selected public hosted zone");
        }
        validate_template(&self.vapi.template)?;
        validate_fields(&self.screen_pop_fields)?;
        if let Some(routing) = &self.routing {
            validate_routing(self, routing)?;
        }
        if !(MIN_TTL_SECONDS..=MAX_TTL_SECONDS).contains(&self.context_ttl_seconds) {
            bail!("context TTL must be between 5 minutes and 7 days");
        }
        validate_https("CloudFormation template URL", &self.release.template_url)?;
        validate_https("release manifest URL", &self.release.release_manifest_url)?;
        if self.release.release_manifest_sha256.len() != 64
            || !self
                .release
                .release_manifest_sha256
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit())
        {
            bail!("release manifest SHA-256 is invalid");
        }
        const REQUIRED_RELEASE_PARAMETERS: &[&str] = &[
            "NestedTemplateBaseUrl",
            "ArtifactBucket",
            "PrepareArtifactKey",
            "PrepareArtifactVersion",
            "TransferArtifactKey",
            "TransferArtifactVersion",
            "LookupArtifactKey",
            "LookupArtifactVersion",
            "ProvisionerArtifactKey",
            "ProvisionerArtifactVersion",
            "RuntimeArtifactKey",
            "RuntimeArtifactVersion",
            "RuntimeArtifactSha256",
            "BridgefuImageUri",
            "BridgefuRegistryType",
        ];
        const ALLOWED_RELEASE_PARAMETERS: &[&str] = &[
            "NestedTemplateBaseUrl",
            "ArtifactBucket",
            "PrepareArtifactKey",
            "PrepareArtifactVersion",
            "TransferArtifactKey",
            "TransferArtifactVersion",
            "LookupArtifactKey",
            "LookupArtifactVersion",
            "ProvisionerArtifactKey",
            "ProvisionerArtifactVersion",
            "RuntimeArtifactKey",
            "RuntimeArtifactVersion",
            "RuntimeArtifactSha256",
            "BridgefuImageUri",
            "BridgefuRegistryType",
            "BridgefuImageRepositoryArn",
        ];
        for required in REQUIRED_RELEASE_PARAMETERS {
            if !self
                .release
                .cloudformation_parameters
                .contains_key(*required)
            {
                bail!("signed release descriptor is missing {required}");
            }
        }
        for (key, value) in &self.release.cloudformation_parameters {
            if !ALLOWED_RELEASE_PARAMETERS.contains(&key.as_str()) {
                bail!("signed release descriptor contains unsupported parameter {key}");
            }
            if value.len() > 4096
                || value.contains("AKIA")
                || value.contains("sk-ant-")
                || value.contains("-----BEGIN PRIVATE KEY-----")
            {
                bail!("release parameters cannot contain secret values");
            }
        }
        let registry = &self.release.cloudformation_parameters["BridgefuRegistryType"];
        if !matches!(registry.as_str(), "Anonymous" | "PrivateEcr") {
            bail!("signed release descriptor has an invalid registry type");
        }
        if registry == "PrivateEcr"
            && !self
                .release
                .cloudformation_parameters
                .contains_key("BridgefuImageRepositoryArn")
        {
            bail!("private ECR releases require BridgefuImageRepositoryArn");
        }
        Ok(())
    }
}

fn validate_routing(config: &SetupConfiguration, routing: &RoutingConfiguration) -> Result<()> {
    let choices = config
        .screen_pop_fields
        .iter()
        .find_map(|field| match field {
            ScreenPopField::Choice(choice) if choice.key == routing.field_key => {
                Some(&choice.choices)
            }
            _ => None,
        })
        .context("routing field must be a configured choice field")?;
    if routing.routes.is_empty() || routing.routes.len() > 8 {
        bail!("routing requires one through eight reviewed destinations");
    }
    let mut values = BTreeSet::new();
    for route in &routing.routes {
        if !choices.contains(&route.value) || !values.insert(route.value.as_str()) {
            bail!("route values must be unique choices from the routing field");
        }
        validate_plain_text("route flow name", &route.target_contact_flow_name, 128)?;
        validate_arn_account_region(
            "route contact-flow ARN",
            &route.target_contact_flow_arn,
            &config.aws.account_id,
            &config.aws.region,
        )?;
        if !route
            .target_contact_flow_arn
            .starts_with(&format!("{}/contact-flow/", config.connect.instance_arn))
        {
            bail!("route contact flow does not belong to the selected Connect instance");
        }
    }
    Ok(())
}

fn validate_template(value: &TemplateAssistantConfig) -> Result<()> {
    for (name, item, maximum) in [
        ("assistant name", value.name.as_str(), 80),
        ("model provider", value.model_provider.as_str(), 64),
        ("model", value.model.as_str(), 128),
        ("voice provider", value.voice_provider.as_str(), 64),
        ("voice ID", value.voice_id.as_str(), 128),
    ] {
        if item.is_empty() || item.len() > maximum || item.chars().any(char::is_control) {
            bail!("invalid {name}");
        }
    }
    if value.placeholder_prompt.is_empty()
        || value.placeholder_prompt.len() > 8_192
        || value.placeholder_prompt.contains("sk-")
    {
        bail!("invalid template prompt");
    }
    Ok(())
}

fn validate_fields(fields: &[ScreenPopField]) -> Result<()> {
    if fields.is_empty() || fields.len() > 8 {
        bail!("configure between one and eight screen-pop fields");
    }
    let key_pattern = Regex::new(r"^[a-z][a-z0-9_]{0,39}$").unwrap();
    let reserved = BTreeSet::from([
        "correlation_id",
        "schema_version",
        "content_hash",
        "expires_at",
        "screen_pop_schema_hash",
        "context_available",
    ]);
    let mut keys = BTreeSet::new();
    let mut labels = BTreeSet::new();
    let mut maximum_total = 0usize;
    for field in fields {
        if !key_pattern.is_match(field.key())
            || reserved.contains(field.key())
            || !keys.insert(field.key().to_string())
        {
            bail!("screen-pop field keys must be unique lowercase identifiers");
        }
        validate_plain_text("field label", field.label(), 64)?;
        if !labels.insert(field.label().to_ascii_lowercase()) {
            bail!("screen-pop field labels must be unique");
        }
        validate_plain_text("field description", field.description(), 256)?;
        match field {
            ScreenPopField::Text(text) => {
                if text.max_length == 0 || text.max_length > 1024 {
                    bail!("text field maximum length must be 1 through 1024");
                }
                maximum_total += usize::from(text.max_length);
            }
            ScreenPopField::Choice(choice) => {
                if !(2..=20).contains(&choice.choices.len()) {
                    bail!("choice fields require 2 through 20 choices");
                }
                let mut values = BTreeSet::new();
                let mut maximum_choice = 0usize;
                for item in &choice.choices {
                    validate_plain_text("choice", item, 128)?;
                    if !values.insert(item) {
                        bail!("choice values must be unique");
                    }
                    maximum_choice = maximum_choice.max(item.chars().count());
                }
                maximum_total += maximum_choice;
            }
        }
    }
    if maximum_total > 8192 {
        bail!("configured field values may not exceed 8 KiB");
    }
    let encoded = serde_json::to_vec(fields)?;
    if encoded.len() > 4096 {
        bail!("screen-pop schema may not exceed 4 KiB");
    }
    Ok(())
}

fn validate_deployment_id(value: &str) -> Result<()> {
    let pattern = Regex::new(r"^[a-z][a-z0-9-]{2,23}$").unwrap();
    if !pattern.is_match(value) {
        bail!("deployment ID must be 3–24 lowercase letters, digits, and hyphens");
    }
    Ok(())
}

fn validate_stack_name(value: &str) -> Result<()> {
    let pattern = Regex::new(r"^[A-Za-z][A-Za-z0-9-]{0,127}$").unwrap();
    if !pattern.is_match(value) {
        bail!("invalid CloudFormation stack name");
    }
    Ok(())
}

fn validate_plain_text(name: &str, value: &str, maximum: usize) -> Result<()> {
    if value.is_empty()
        || value.chars().count() > maximum
        || value.chars().any(char::is_control)
        || value.contains('<')
        || value.contains('>')
    {
        bail!("invalid {name}");
    }
    Ok(())
}

fn validate_arn_account_region(name: &str, value: &str, account: &str, region: &str) -> Result<()> {
    let parts: Vec<_> = value.split(':').collect();
    if parts.len() < 6
        || parts[0] != "arn"
        || parts[2] != "connect"
        || parts[3] != region
        || parts[4] != account
    {
        bail!("{name} must belong to the selected AWS account and region");
    }
    Ok(())
}

fn validate_https(name: &str, value: &str) -> Result<()> {
    let parsed = Url::parse(value).with_context(|| format!("invalid {name}"))?;
    if parsed.scheme() != "https"
        || parsed.host_str().is_none()
        || parsed.username() != ""
        || parsed.password().is_some()
        || parsed.query().is_some()
        || parsed.fragment().is_some()
    {
        bail!("{name} must be a plain HTTPS URL");
    }
    Ok(())
}

pub fn default_screen_pop_fields() -> Vec<ScreenPopField> {
    vec![
        ScreenPopField::Text(TextField {
            key: "customer_name".into(),
            label: "Customer".into(),
            description: "Caller name for the Amazon Connect agent.".into(),
            required: true,
            max_length: 256,
        }),
        ScreenPopField::Text(TextField {
            key: "issue_summary".into(),
            label: "Issue".into(),
            description: "Short summary of why the caller needs an agent.".into(),
            required: true,
            max_length: 1024,
        }),
        ScreenPopField::Text(TextField {
            key: "intent".into(),
            label: "Intent".into(),
            description: "Short routing or support intent.".into(),
            required: true,
            max_length: 128,
        }),
        ScreenPopField::Choice(ChoiceField {
            key: "verification_status".into(),
            label: "Verification".into(),
            description: "Verification completed before transfer.".into(),
            required: true,
            choices: vec![
                "verified".into(),
                "not_verified".into(),
                "not_required".into(),
            ],
        }),
    ]
}
