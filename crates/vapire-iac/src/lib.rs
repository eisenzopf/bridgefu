//! Ownership-safe Vapi infrastructure-as-code primitives.
//!
//! The assistant extension API deliberately manages a very small overlay on
//! an existing assistant. It never treats the customer assistant as a fully
//! owned resource.

mod api;
mod extension;
mod model;
mod template;

pub use api::{HttpVapiApi, VapiApi};
pub use extension::{apply, plan, unapply, SecretResolver};
pub use model::{
    ApplyResult, AssistantExtensionArtifact, BridgefuVapiBundle, CredentialArtifact, ExtensionPlan,
    ExtensionState, OwnedTemplateArtifact, OwnedTemplateBundle, OwnedTemplatePlan,
    OwnedTemplateResult, OwnedTemplateState, PlanAction, TemplatePlanAction, ToolArtifact,
    UnapplyResult,
};
pub use template::{
    create_owned_template, delete_owned_template, plan_owned_template,
    rotate_owned_template_credential,
};
