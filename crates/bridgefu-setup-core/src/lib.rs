//! Shared, UI-independent setup engine for the Bridgefu Amazon Connect recipe.

mod artifact;
mod aws;
mod bundle;
mod journal;
mod schema;
mod vapi;

pub use artifact::{example_configuration, generate_artifacts, GeneratedArtifacts};
pub use aws::{
    AwsCallerIdentity, AwsCli, ConnectFlowSummary, ConnectInstanceSummary, HostedZoneSummary,
};
pub use bundle::{
    export_bundle, inspect_bundle, run_mocked_workflow_smoke, seal_bundle, state_journal_path,
    BundleInspection, BundleManifest, BundleManifestEntry,
};
pub use journal::{load_journal, save_journal, DeploymentJournal, ExecutionPhase, JOURNAL_SCHEMA};
pub use schema::{
    default_screen_pop_fields, AwsTarget, ChoiceField, ConnectTarget, DnsTarget, ReleaseInputs,
    RouteMapping, RoutingConfiguration, ScreenPopField, SetupConfiguration,
    TemplateAssistantConfig, TextField, VapiTemplateTarget,
};
pub use vapi::{
    apply_vapi_template, delete_vapi_template, plan_vapi_template, rotate_vapi_credential,
    VapiResolvedInputs,
};
pub use vapire_iac::{OwnedTemplatePlan, OwnedTemplateState};
