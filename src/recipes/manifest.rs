use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_yaml::Value;

pub const BUILTIN_RECIPE_API_VERSION: &str = "bridgefu.dev/recipe/v1";
pub const BUILTIN_RECIPE_KIND: &str = "bridge_recipe";

/// One immutable recipe package manifest.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RecipeManifest {
    pub api_version: String,
    pub kind: String,
    pub metadata: RecipeMetadata,
    #[serde(default)]
    pub inputs: BTreeMap<String, RecipeInputDefinition>,
    /// This remains a YAML value until whole-node input references have been
    /// resolved. The result is then deserialized into [`RecipeSpec`].
    pub spec: Value,
    #[serde(default)]
    pub deployments: BTreeMap<String, BTreeMap<String, String>>,
    #[serde(default)]
    pub assets: BTreeMap<String, String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RecipeMetadata {
    pub name: String,
    pub version: u32,
    pub title: String,
    pub support: RecipeSupport,
    #[serde(default)]
    pub description: Option<String>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RecipeSupport {
    Supported,
    Preview,
    Development,
    Custom,
    Experimental,
    Roadmap,
}

impl std::fmt::Display for RecipeSupport {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Supported => "supported",
            Self::Preview => "preview",
            Self::Development => "development",
            Self::Custom => "custom",
            Self::Experimental => "experimental",
            Self::Roadmap => "roadmap",
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RecipeInputDefinition {
    #[serde(rename = "type")]
    pub kind: RecipeInputType,
    #[serde(default)]
    pub required: bool,
    #[serde(default)]
    pub default: Option<Value>,
    #[serde(default)]
    pub values: Vec<String>,
    #[serde(default)]
    pub description: Option<String>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RecipeInputType {
    String,
    Boolean,
    Integer,
    Enum,
    CidrList,
    AwsArn,
    AwsConnectResourceId,
    SecretRef,
}

impl RecipeInputType {
    #[must_use]
    pub const fn is_secret(self) -> bool {
        matches!(self, Self::SecretRef)
    }
}

/// One configured recipe instance in `bridgefu.yaml`.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecipeSelection {
    #[serde(rename = "use")]
    pub selector: String,
    #[serde(default, rename = "with")]
    pub values: BTreeMap<String, Value>,
}

/// Fully resolved and typed recipe bridge specification.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RecipeSpec {
    pub bridges: BTreeMap<String, RecipeBridgeSpec>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RecipeBridgeSpec {
    pub source: RecipeEndpointSpec,
    pub destination: RecipeEndpointSpec,
    #[serde(default)]
    pub context: Option<RecipeContextSpec>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum RecipeEndpointSpec {
    Sip {
        security: SipSecurity,
        #[serde(default)]
        admission: Option<SipAdmissionSpec>,
        #[serde(default)]
        target_uri: Option<String>,
        #[serde(default)]
        from_uri: Option<String>,
        #[serde(default)]
        outbound_proxy: Option<String>,
        #[serde(default)]
        auth: Option<RecipeSipAuthSpec>,
        #[serde(default)]
        tls_roots: Vec<String>,
        #[serde(default = "default_recipe_audio_codecs")]
        codecs: BTreeSet<RecipeAudioCodec>,
        #[serde(default)]
        metadata_keys: BTreeSet<String>,
    },
    Webrtc {
        #[serde(default)]
        signaling_uri: Option<String>,
        #[serde(default)]
        bearer_token_ref: Option<String>,
        #[serde(default)]
        tls_roots: Vec<String>,
        #[serde(default = "default_recipe_audio_codecs")]
        codecs: BTreeSet<RecipeAudioCodec>,
        #[serde(default = "default_true")]
        data_channels: bool,
    },
    AmazonConnect {
        media: AmazonConnectMedia,
        instance_arn: String,
        contact_flow_id: String,
        #[serde(default)]
        context_metadata_keys: BTreeSet<String>,
    },
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum RecipeSipAuthSpec {
    Digest {
        #[serde(default)]
        realm: Option<String>,
        #[serde(default)]
        username: Option<String>,
        #[serde(default)]
        password_ref: Option<String>,
    },
    Bearer {
        #[serde(default)]
        token_ref: Option<String>,
    },
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum RecipeAudioCodec {
    Pcmu,
    Pcma,
    Opus,
}

fn default_recipe_audio_codecs() -> BTreeSet<RecipeAudioCodec> {
    BTreeSet::from([
        RecipeAudioCodec::Pcmu,
        RecipeAudioCodec::Pcma,
        RecipeAudioCodec::Opus,
    ])
}

const fn default_true() -> bool {
    true
}

impl RecipeEndpointSpec {
    #[must_use]
    pub const fn transport_name(&self) -> &'static str {
        match self {
            Self::Sip { .. } => "sip",
            Self::Webrtc { .. } => "webrtc",
            Self::AmazonConnect { .. } => "amazon_connect",
        }
    }

    #[must_use]
    pub const fn sip_security(&self) -> Option<SipSecurity> {
        match self {
            Self::Sip { security, .. } => Some(*security),
            _ => None,
        }
    }

    #[must_use]
    pub const fn sip_admission(&self) -> Option<&SipAdmissionSpec> {
        match self {
            Self::Sip { admission, .. } => admission.as_ref(),
            _ => None,
        }
    }

    #[must_use]
    pub fn amazon_connect_target(&self) -> Option<(&str, &str)> {
        match self {
            Self::AmazonConnect {
                instance_arn,
                contact_flow_id,
                ..
            } => Some((instance_arn, contact_flow_id)),
            _ => None,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SipAdmissionSpec {
    pub mode: SipAdmissionMode,
    #[serde(default)]
    pub trusted_cidrs: Vec<String>,
    #[serde(default)]
    pub uri_user: Option<String>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SipAdmissionMode {
    ManagedAttachment,
    StableUri,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SipSecurity {
    SipsSrtp,
    SipsOptionalSrtp,
    SipRtp,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AmazonConnectMedia {
    Webrtc,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RecipeContextSpec {
    pub correlation: RecipeCorrelationSpec,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RecipeCorrelationSpec {
    #[serde(default)]
    pub required: bool,
    pub from_sip_header: String,
    pub to_amazon_attribute: String,
    pub format: String,
}
