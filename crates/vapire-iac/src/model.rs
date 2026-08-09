use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CredentialArtifact {
    pub slug: String,
    pub name: String,
    pub bearer_secret_ref: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ToolArtifact {
    pub slug: String,
    pub spec: Value,
    pub endpoint_ref: String,
    pub credential_ref: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AssistantExtensionArtifact {
    pub slug: String,
    pub target_assistant_id: String,
    pub tool_ref: String,
    pub prompt_marker: String,
    pub prompt: String,
    #[serde(default = "default_true")]
    pub control_enabled: bool,
}

const fn default_true() -> bool {
    true
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BridgefuVapiBundle {
    pub schema: String,
    pub credential: CredentialArtifact,
    pub tool: ToolArtifact,
    pub assistant_extension: AssistantExtensionArtifact,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PlanAction {
    CreateCredential,
    CreateTool,
    UpdateCredential,
    UpdateTool,
    AttachAssistantExtension,
    UpdateAssistantExtension,
    Noop,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ExtensionState {
    pub schema: String,
    pub assistant_id: String,
    pub credential_id: String,
    pub tool_id: String,
    pub prompt_marker: String,
    pub prompt_hash: String,
    pub previous_control_enabled: Option<bool>,
    pub applied_owned_hash: String,
    pub credential_artifact_hash: String,
    pub tool_artifact_hash: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ExtensionPlan {
    pub schema: String,
    pub assistant_id: String,
    pub remote_digest: String,
    pub desired_owned_hash: String,
    pub actions: Vec<PlanAction>,
    pub masked_diff: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ApplyResult {
    pub state: ExtensionState,
    pub assistant: Value,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct UnapplyResult {
    pub assistant: Value,
    pub deleted_tool_id: String,
    pub deleted_credential_id: String,
}

/// A complete assistant created by Vapire. Unlike `AssistantExtensionArtifact`,
/// this resource never targets or mutates an existing assistant.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OwnedTemplateArtifact {
    pub slug: String,
    pub deployment_id: String,
    pub spec: Value,
    pub tool_ref: String,
    pub prompt_marker: String,
    pub prompt: String,
    /// Assistant-level webhook used only by this newly owned template.
    /// Existing-assistant overlays never set or replace a server URL.
    #[serde(default)]
    pub server_endpoint_ref: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OwnedTemplateBundle {
    pub schema: String,
    pub credential: CredentialArtifact,
    pub tool: ToolArtifact,
    pub assistant: OwnedTemplateArtifact,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TemplatePlanAction {
    CreateCredential,
    CreateTool,
    CreateAssistant,
    AlreadyCreated,
    RemoteDriftRetained,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OwnedTemplateState {
    pub schema: String,
    pub deployment_id: String,
    pub credential_id: String,
    pub tool_id: String,
    pub assistant_id: String,
    pub organization_id: String,
    pub owner_hash: String,
    pub desired_artifact_hash: String,
    pub created_assistant_hash: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OwnedTemplatePlan {
    pub schema: String,
    pub deployment_id: String,
    pub desired_artifact_hash: String,
    pub actions: Vec<TemplatePlanAction>,
    pub masked_diff: String,
    pub remote_assistant_hash: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OwnedTemplateResult {
    pub state: OwnedTemplateState,
    pub assistant: Value,
}
