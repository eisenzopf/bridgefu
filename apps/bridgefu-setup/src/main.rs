#![cfg_attr(feature = "bundle", windows_subsystem = "windows")]

use anyhow::Context as _;
use bridgefu_setup_core::{
    default_screen_pop_fields, export_bundle, inspect_bundle, load_journal, seal_bundle, AwsCli,
    AwsTarget, ChoiceField, ConnectFlowSummary, ConnectInstanceSummary, ConnectTarget, DnsTarget,
    HostedZoneSummary, ReleaseInputs, RouteMapping, RoutingConfiguration, ScreenPopField,
    SetupConfiguration, TemplateAssistantConfig, TextField, VapiTemplateTarget,
};
use dioxus::prelude::*;
use std::collections::BTreeMap;
use std::path::PathBuf;

const CSS: Asset = asset!("/assets/main.css");

fn main() {
    if std::env::args_os().len() == 2
        && std::env::args_os().nth(1).as_deref()
            == Some(std::ffi::OsStr::new("--mock-workflow-smoke"))
    {
        if let Err(error) = bridgefu_setup_core::run_mocked_workflow_smoke() {
            eprintln!("Bridgefu Setup mocked workflow failed: {error:#}");
            std::process::exit(1);
        }
        println!(r#"{{"status":"ok","workflow":"reviewed-bundle"}}"#);
        return;
    }
    let window = dioxus::desktop::WindowBuilder::new()
        .with_title("Bridgefu Setup")
        .with_inner_size(dioxus::desktop::LogicalSize::new(1180.0, 780.0));
    let desktop = dioxus::desktop::Config::new()
        .with_window(window)
        .with_disable_context_menu(true)
        .with_menu(None)
        .with_navigation_handler(|_| false);
    dioxus::LaunchBuilder::desktop()
        .with_cfg(desktop)
        .launch(App);
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum WizardStep {
    Welcome,
    Aws,
    Connect,
    Vapi,
    Fields,
    Network,
    Review,
    Finish,
    Management,
}

impl WizardStep {
    const ALL: [Self; 9] = [
        Self::Welcome,
        Self::Aws,
        Self::Connect,
        Self::Vapi,
        Self::Fields,
        Self::Network,
        Self::Review,
        Self::Finish,
        Self::Management,
    ];

    const fn label(self) -> &'static str {
        match self {
            Self::Welcome => "Welcome",
            Self::Aws => "AWS account",
            Self::Connect => "Amazon Connect",
            Self::Vapi => "Vapi template",
            Self::Fields => "Screen-pop data",
            Self::Network => "Network & DNS",
            Self::Review => "Review",
            Self::Finish => "Save or execute",
            Self::Management => "Manage",
        }
    }

    fn index(self) -> usize {
        Self::ALL
            .iter()
            .position(|value| *value == self)
            .unwrap_or(0)
    }
}

#[derive(Clone, Debug)]
struct Draft {
    deployment_id: String,
    stack_name: String,
    aws_profile: String,
    account_id: String,
    region: String,
    service_role_arn: String,
    connect_instance_arn: String,
    connect_alias: String,
    contact_flow_arn: String,
    contact_flow_name: String,
    assistant_name: String,
    model_provider: String,
    model: String,
    voice_provider: String,
    voice_id: String,
    placeholder_prompt: String,
    vapi_api_key: String,
    fields: Vec<ScreenPopField>,
    routing_field_key: String,
    routing_routes: Vec<RouteMapping>,
    hosted_zone_id: String,
    hosted_zone_name: String,
    sip_hostname: String,
    ttl_seconds: String,
    template_url: String,
    release_manifest_url: String,
    release_manifest_sha256: String,
    release_parameters_json: String,
    connect_options: Vec<ConnectInstanceSummary>,
    flow_options: Vec<ConnectFlowSummary>,
    hosted_zone_options: Vec<HostedZoneSummary>,
    principal_arn: String,
}

impl Default for Draft {
    fn default() -> Self {
        let release = bundled_release().unwrap_or(ReleaseInputs {
            template_url: String::new(),
            release_manifest_url: String::new(),
            release_manifest_sha256: String::new(),
            cloudformation_parameters: BTreeMap::new(),
        });
        Self {
            deployment_id: "amazon-connect".into(),
            stack_name: "bridgefu-amazon-connect".into(),
            aws_profile: "default".into(),
            account_id: String::new(),
            region: String::new(),
            service_role_arn: String::new(),
            connect_instance_arn: String::new(),
            connect_alias: String::new(),
            contact_flow_arn: String::new(),
            contact_flow_name: String::new(),
            assistant_name: "Bridgefu Amazon Connect template".into(),
            model_provider: "openai".into(),
            model: "gpt-4.1-mini".into(),
            voice_provider: "vapi".into(),
            voice_id: "Elliot".into(),
            placeholder_prompt: "TODO: Add your business instructions. When the caller requests an agent, collect the configured fields, invoke prepare_bridgefu_amazon_connect_transfer exactly once, wait for prepared, then invoke the transferCall tool.".into(),
            vapi_api_key: String::new(),
            fields: default_screen_pop_fields(),
            routing_field_key: String::new(),
            routing_routes: Vec::new(),
            hosted_zone_id: String::new(),
            hosted_zone_name: String::new(),
            sip_hostname: String::new(),
            ttl_seconds: "3600".into(),
            template_url: release.template_url,
            release_manifest_url: release.release_manifest_url,
            release_manifest_sha256: release.release_manifest_sha256,
            release_parameters_json: serde_json::to_string_pretty(
                &release.cloudformation_parameters,
            )
            .unwrap_or_else(|_| "{}".into()),
            connect_options: Vec::new(),
            flow_options: Vec::new(),
            hosted_zone_options: Vec::new(),
            principal_arn: String::new(),
        }
    }
}

fn bundled_release() -> Option<ReleaseInputs> {
    let executable = std::env::current_exe().ok()?;
    let parent = executable.parent()?;
    let candidates = [
        parent.join("bridgefu-setup-release.json"),
        parent.join("../Resources/bridgefu-setup-release.json"),
        parent.join("../share/bridgefu/bridgefu-setup-release.json"),
    ];
    for path in candidates {
        let metadata = match path.metadata() {
            Ok(value) if value.is_file() && value.len() <= 256 * 1024 => value,
            _ => continue,
        };
        if metadata.len() == 0 {
            continue;
        }
        if let Ok(value) = serde_json::from_slice(&std::fs::read(path).ok()?) {
            return Some(value);
        }
    }
    None
}

impl Draft {
    fn from_configuration(config: SetupConfiguration) -> Self {
        let (routing_field_key, routing_routes) = config
            .routing
            .map(|routing| (routing.field_key, routing.routes))
            .unwrap_or_default();
        Self {
            deployment_id: config.deployment_id,
            stack_name: config.stack_name,
            aws_profile: config.aws.profile,
            account_id: config.aws.account_id,
            region: config.aws.region,
            service_role_arn: config
                .aws
                .cloudformation_service_role_arn
                .unwrap_or_default(),
            connect_instance_arn: config.connect.instance_arn,
            connect_alias: config.connect.instance_alias,
            contact_flow_arn: config.connect.target_contact_flow_arn,
            contact_flow_name: config.connect.target_contact_flow_name,
            assistant_name: config.vapi.template.name,
            model_provider: config.vapi.template.model_provider,
            model: config.vapi.template.model,
            voice_provider: config.vapi.template.voice_provider,
            voice_id: config.vapi.template.voice_id,
            placeholder_prompt: config.vapi.template.placeholder_prompt,
            vapi_api_key: String::new(),
            fields: config.screen_pop_fields,
            routing_field_key,
            routing_routes,
            hosted_zone_id: config.dns.public_hosted_zone_id,
            hosted_zone_name: config.dns.public_hosted_zone_name,
            sip_hostname: config.dns.sip_hostname,
            ttl_seconds: config.context_ttl_seconds.to_string(),
            template_url: config.release.template_url,
            release_manifest_url: config.release.release_manifest_url,
            release_manifest_sha256: config.release.release_manifest_sha256,
            release_parameters_json: serde_json::to_string_pretty(
                &config.release.cloudformation_parameters,
            )
            .unwrap_or_else(|_| "{}".into()),
            connect_options: Vec::new(),
            flow_options: Vec::new(),
            hosted_zone_options: Vec::new(),
            principal_arn: String::new(),
        }
    }

    fn configuration(&self) -> anyhow::Result<SetupConfiguration> {
        let release_parameters: BTreeMap<String, String> =
            serde_json::from_str(&self.release_parameters_json)?;
        let config = SetupConfiguration {
            schema: "bridgefu.amazon-connect.setup/v1".into(),
            deployment_id: self.deployment_id.clone(),
            stack_name: self.stack_name.clone(),
            aws: AwsTarget {
                profile: self.aws_profile.clone(),
                account_id: self.account_id.clone(),
                region: self.region.clone(),
                cloudformation_service_role_arn: (!self.service_role_arn.is_empty())
                    .then(|| self.service_role_arn.clone()),
            },
            connect: ConnectTarget {
                instance_arn: self.connect_instance_arn.clone(),
                instance_alias: self.connect_alias.clone(),
                target_contact_flow_arn: self.contact_flow_arn.clone(),
                target_contact_flow_name: self.contact_flow_name.clone(),
            },
            dns: DnsTarget {
                public_hosted_zone_id: self.hosted_zone_id.clone(),
                public_hosted_zone_name: self.hosted_zone_name.clone(),
                sip_hostname: self.sip_hostname.clone(),
            },
            vapi: VapiTemplateTarget {
                template: TemplateAssistantConfig {
                    name: self.assistant_name.clone(),
                    model_provider: self.model_provider.clone(),
                    model: self.model.clone(),
                    voice_provider: self.voice_provider.clone(),
                    voice_id: self.voice_id.clone(),
                    placeholder_prompt: self.placeholder_prompt.clone(),
                },
            },
            screen_pop_fields: self.fields.clone(),
            routing: (!self.routing_field_key.is_empty()).then(|| RoutingConfiguration {
                field_key: self.routing_field_key.clone(),
                routes: self.routing_routes.clone(),
            }),
            context_ttl_seconds: self.ttl_seconds.parse()?,
            release: ReleaseInputs {
                template_url: self.template_url.clone(),
                release_manifest_url: self.release_manifest_url.clone(),
                release_manifest_sha256: self.release_manifest_sha256.clone(),
                cloudformation_parameters: release_parameters,
            },
        };
        config.validate()?;
        Ok(config)
    }
}

#[allow(non_snake_case)]
fn App() -> Element {
    let step = use_signal(|| WizardStep::Welcome);
    let draft = use_signal(Draft::default);
    let message = use_signal(String::new);
    let saved_bundle = use_signal(|| None::<PathBuf>);
    let reviewed_change_set = use_signal(|| None::<String>);
    let stack_confirmation = use_signal(String::new);
    let assistant_confirmation = use_signal(String::new);
    let current = step();
    rsx! {
        document::Stylesheet { href: CSS }
        div { class: "shell",
            aside { class: "sidebar",
                div { class: "brand", "Bridgefu Setup" }
                for (index, item) in WizardStep::ALL.iter().enumerate() {
                    div {
                        class: if *item == current { "step active" } else if index < current.index() { "step done" } else { "step" },
                        span { class: "step-number", if index < current.index() { "✓" } else { "{index + 1}" } }
                        span { "{item.label()}" }
                    }
                }
                div { class: "privacy", "Credentials remain in memory. Saved deployment bundles contain configuration and resource IDs, never secret values." }
            }
            main { class: "main",
                if !message().is_empty() {
                    div { class: if message().starts_with("Saved") { "status ok" } else { "status error" }, "{message}" }
                }
                {render_step(current, draft, message, step, saved_bundle, reviewed_change_set, stack_confirmation, assistant_confirmation)}
                Nav { step }
            }
        }
    }
}

#[component]
fn Nav(mut step: Signal<WizardStep>) -> Element {
    let current = step();
    let index = current.index();
    rsx! {
        div { class: "button-row",
            button {
                class: "secondary",
                disabled: index == 0,
                onclick: move |_| if index > 0 { step.set(WizardStep::ALL[index - 1]); },
                "Back"
            }
            if index + 1 < WizardStep::ALL.len() {
                button {
                    class: "primary",
                    onclick: move |_| step.set(WizardStep::ALL[index + 1]),
                    "Continue"
                }
            }
        }
    }
}

fn render_step(
    step: WizardStep,
    mut draft: Signal<Draft>,
    mut message: Signal<String>,
    mut step_signal: Signal<WizardStep>,
    mut saved_bundle: Signal<Option<PathBuf>>,
    mut reviewed_change_set: Signal<Option<String>>,
    mut stack_confirmation: Signal<String>,
    mut assistant_confirmation: Signal<String>,
) -> Element {
    match step {
        WizardStep::Welcome => rsx! {
            div { class: "eyebrow", "Vapi → Amazon Connect" }
            h1 { "Deploy a safe Bridgefu call handoff" }
            p { class: "lede", "This app creates a new Vapi template assistant and a dedicated AWS deployment. It never changes any existing Vapi assistant or your selected Amazon Connect contact flow." }
            div { class: "safe", strong { "Safe default" } span { "The generated assistant is create-once. If you customize it later, Bridgefu reports the drift and leaves your changes alone." } }
            div { class: "card",
                h2 { "What happens during a call" }
                div { class: "diagram",
                    span { class: "node", "Vapi template" } span { class: "arrow", "→" }
                    span { class: "node", "Store context" } span { class: "arrow", "→" }
                    span { class: "node", "SIP transfer" } span { class: "arrow", "→" }
                    span { class: "node", "Amazon Connect" } span { class: "arrow", "→" }
                    span { class: "node", "Agent screen pop" }
                }
            }
            div { class: "button-row",
                button { class: "primary", onclick: move |_| step_signal.set(WizardStep::Aws), "New deployment" }
                button { class: "secondary", onclick: move |_| {
                    if let Some(path) = rfd::FileDialog::new().add_filter("Bridgefu deployment", &["bridgefu"]).pick_file() {
                        match inspect_bundle(&path) {
                            Ok(inspection) => {
                                draft.set(Draft::from_configuration(inspection.configuration));
                                saved_bundle.set(Some(path.clone()));
                                reviewed_change_set.set(None);
                                message.set(format!("Opened verified bundle {}", path.display()));
                                step_signal.set(WizardStep::Review);
                            }
                            Err(error) => message.set(format!("Could not open bundle: {error}")),
                        }
                    }
                }, "Open saved deployment" }
            }
        },
        WizardStep::Aws => rsx! {
            div { class: "eyebrow", "Step 2" } h1 { "Choose the AWS account" }
            p { class: "lede", "Use an existing AWS profile or SSO session. The final review shows every permission before anything is created." }
            div { class: "grid",
                TextInput { label: "AWS profile", value: draft().aws_profile, on_change: move |v| draft.write().aws_profile = v }
                TextInput { label: "AWS account ID", value: draft().account_id, on_change: move |v| draft.write().account_id = v }
                TextInput { label: "Region", value: draft().region, on_change: move |v| draft.write().region = v }
                TextInput { label: "CloudFormation service role ARN", value: draft().service_role_arn, on_change: move |v| draft.write().service_role_arn = v }
            }
            button { class: "secondary", onclick: move |_| {
                let snapshot = draft();
                let aws = AwsCli;
                let result = (|| -> anyhow::Result<_> {
                    let identity = aws.caller_identity(&snapshot.aws_profile)?;
                    let regions = if snapshot.region.is_empty() {
                        aws.enabled_regions(&snapshot.aws_profile)?
                    } else {
                        vec![snapshot.region.clone()]
                    };
                    let instances = aws.connect_instances(&snapshot.aws_profile, &regions)?;
                    Ok((identity, instances))
                })();
                match result {
                    Ok((identity, instances)) => {
                        let count = instances.len();
                        let mut value = draft.write();
                        value.account_id = identity.account_id;
                        value.principal_arn = identity.principal_arn;
                        value.connect_options = instances;
                        message.set(format!("AWS identity verified; found {count} active Connect instance(s)"));
                    }
                    Err(error) => message.set(format!("AWS discovery failed: {error}")),
                }
            }, "Discover with this profile" }
            if !draft().principal_arn.is_empty() {
                div { class: "safe", strong { "Signed in as" } span { "{draft().principal_arn}" } }
            }
        },
        WizardStep::Connect => rsx! {
            div { class: "eyebrow", "Step 3" } h1 { "Connect to Amazon Connect" }
            p { class: "lede", "Bridgefu creates its own wrapper and agent guide, then hands the call to this published customer flow. The selected flow is never edited." }
            TextInput { label: "Connect instance ARN", value: draft().connect_instance_arn, on_change: move |v| draft.write().connect_instance_arn = v }
            div { class: "grid",
                TextInput { label: "Instance alias", value: draft().connect_alias, on_change: move |v| draft.write().connect_alias = v }
                TextInput { label: "Published flow name", value: draft().contact_flow_name, on_change: move |v| draft.write().contact_flow_name = v }
            }
            TextInput { label: "Target contact-flow ARN", value: draft().contact_flow_arn, on_change: move |v| draft.write().contact_flow_arn = v }
            if !draft().connect_options.is_empty() {
                h2 { "Active instances" }
                for instance in draft().connect_options.clone() {
                    button { class: "choice-card", onclick: move |_| {
                        let mut value = draft.write();
                        value.region = instance.region.clone();
                        value.connect_instance_arn = instance.arn.clone();
                        value.connect_alias = instance.alias.clone();
                        value.contact_flow_arn.clear();
                        value.contact_flow_name.clear();
                        value.flow_options.clear();
                        value.routing_field_key.clear();
                        value.routing_routes.clear();
                    }, "{instance.alias} · {instance.region}" }
                }
            }
            button { class: "secondary", disabled: draft().connect_instance_arn.is_empty(), onclick: move |_| {
                let snapshot = draft();
                let instance_id = snapshot.connect_instance_arn.rsplit('/').next().unwrap_or_default().to_owned();
                match AwsCli.published_contact_flows(&snapshot.aws_profile, &snapshot.region, &instance_id) {
                    Ok(flows) => {
                        let count = flows.len();
                        draft.write().flow_options = flows;
                        message.set(format!("Found {count} published customer flow(s)"));
                    }
                    Err(error) => message.set(format!("Contact-flow discovery failed: {error}")),
                }
            }, "Find published flows" }
            if !draft().flow_options.is_empty() {
                for flow in draft().flow_options.clone() {
                    button { class: "choice-card", onclick: move |_| select_default_flow(&mut draft, flow.clone()), "{flow.name}" }
                }
            }
        },
        WizardStep::Vapi => rsx! {
            div { class: "eyebrow", "Step 4" } h1 { "Create a Vapi template assistant" }
            p { class: "lede", "Bridgefu creates a new assistant containing the handoff tool and a clearly marked placeholder prompt. Existing assistants are not listed, selected, or modified." }
            PasswordInput { label: "Vapi private API key", value: draft().vapi_api_key, on_change: move |v| draft.write().vapi_api_key = v }
            p { class: "hint", "The key is held only in native memory and is never written to the deployment bundle, logs, arguments, environment, or files." }
            TextInput { label: "Template assistant name", value: draft().assistant_name, on_change: move |v| draft.write().assistant_name = v }
            div { class: "grid",
                TextInput { label: "Model provider", value: draft().model_provider, on_change: move |v| draft.write().model_provider = v }
                TextInput { label: "Model", value: draft().model, on_change: move |v| draft.write().model = v }
                TextInput { label: "Voice provider", value: draft().voice_provider, on_change: move |v| draft.write().voice_provider = v }
                TextInput { label: "Voice ID", value: draft().voice_id, on_change: move |v| draft.write().voice_id = v }
            }
            div { class: "field", label { "Placeholder prompt" }
                textarea { value: "{draft().placeholder_prompt}", oninput: move |event| draft.write().placeholder_prompt = event.value() }
                span { class: "hint", "The developer can replace the business instructions while retaining the marked Bridgefu transfer rule." }
            }
        },
        WizardStep::Fields => rsx! {
            div { class: "eyebrow", "Step 5" } h1 { "Choose the agent screen-pop data" }
            p { class: "lede", "These definitions become the Vapi tool schema and the Amazon Connect agent labels. Caller values are stored only when the transfer tool runs." }
            for (index, field) in draft().fields.clone().into_iter().enumerate() {
                FieldEditor { index, field, draft }
            }
            div { class: "button-row",
                button { class: "secondary", disabled: draft().fields.len() >= 8, onclick: move |_| {
                    let index = draft().fields.len() + 1;
                    draft.write().fields.push(ScreenPopField::Text(TextField {
                        key: format!("field_{index}"),
                        label: format!("Field {index}"),
                        description: "Caller context for the Amazon Connect agent.".into(),
                        required: false,
                        max_length: 256,
                    }));
                }, "Add text field" }
                button { class: "secondary", disabled: draft().fields.len() >= 8, onclick: move |_| {
                    let index = draft().fields.len() + 1;
                    draft.write().fields.push(ScreenPopField::Choice(ChoiceField {
                        key: format!("choice_{index}"),
                        label: format!("Choice {index}"),
                        description: "Selected caller context for the Amazon Connect agent.".into(),
                        required: false,
                        choices: vec!["option_one".into(), "option_two".into()],
                    }));
                }, "Add choice field" }
            }
            p { class: "hint", "The initial release supports up to eight ordered text or choice fields. Artifact validation enforces all size and uniqueness limits." }
            div { class: "card",
                h2 { "Optional reviewed routing" }
                p { class: "hint", "Choose one choice field to route the call. Each allowed value maps to a published flow you reviewed; the caller and language model can never provide a flow ARN or SIP address." }
                button { class: if draft().routing_field_key.is_empty() { "choice-card selected" } else { "choice-card" }, onclick: move |_| {
                    let mut value = draft.write();
                    value.routing_field_key.clear();
                    value.routing_routes.clear();
                }, "Always use the default flow" }
                for choice in draft().fields.clone().into_iter().filter_map(|field| match field {
                    ScreenPopField::Choice(choice) => Some(choice),
                    ScreenPopField::Text(_) => None,
                }) {
                    button { class: if draft().routing_field_key == choice.key { "choice-card selected" } else { "choice-card" }, onclick: move |_| select_routing_field(&mut draft, choice.clone()),
                        "Route by {choice.label} · {choice.key}"
                    }
                }
                if !draft().routing_field_key.is_empty() {
                    p { class: "safe", "Missing or unmapped values use the default flow: {draft().contact_flow_name}." }
                    for (route_index, route) in draft().routing_routes.clone().into_iter().enumerate() {
                        RouteEditor { index: route_index, route, draft }
                    }
                    if draft().routing_routes.len() >= 8 {
                        p { class: "hint", "A deployment supports up to eight reviewed route mappings. Any additional choice values use the default flow." }
                    }
                }
            }
        },
        WizardStep::Network => rsx! {
            div { class: "eyebrow", "Step 6" } h1 { "Network, DNS, and retention" }
            p { class: "lede", "Bridgefu runs in a new dedicated VPC in the same region as the selected Connect instance. Amazon Connect itself is an AWS-managed regional service." }
            div { class: "grid",
                TextInput { label: "Public hosted-zone ID", value: draft().hosted_zone_id, on_change: move |v| draft.write().hosted_zone_id = v }
                TextInput { label: "Hosted-zone name", value: draft().hosted_zone_name, on_change: move |v| draft.write().hosted_zone_name = v }
                TextInput { label: "SIP hostname", value: draft().sip_hostname, on_change: move |v| draft.write().sip_hostname = v }
                TextInput { label: "Context TTL in seconds", value: draft().ttl_seconds, on_change: move |v| draft.write().ttl_seconds = v }
            }
            button { class: "secondary", onclick: move |_| {
                let snapshot = draft();
                match AwsCli.public_hosted_zones(&snapshot.aws_profile) {
                    Ok(zones) => {
                        let count = zones.len();
                        draft.write().hosted_zone_options = zones;
                        message.set(format!("Found {count} public Route 53 hosted zone(s)"));
                    }
                    Err(error) => message.set(format!("Route 53 discovery failed: {error}")),
                }
            }, "Find public hosted zones" }
            if !draft().hosted_zone_options.is_empty() {
                for zone in draft().hosted_zone_options.clone() {
                    button { class: "choice-card", onclick: move |_| {
                        let zone_name = zone.name.trim_end_matches('.').to_owned();
                        let mut value = draft.write();
                        value.hosted_zone_id = zone.id.clone();
                        value.hosted_zone_name = zone.name.clone();
                        value.sip_hostname = format!("bridgefu.{zone_name}");
                    }, "{zone.name}" }
                }
            }
            div { class: "card", h2 { "Signed release" }
                TextInput { label: "CloudFormation template URL", value: draft().template_url, on_change: move |v| draft.write().template_url = v }
                TextInput { label: "Release manifest URL", value: draft().release_manifest_url, on_change: move |v| draft.write().release_manifest_url = v }
                TextInput { label: "Release manifest SHA-256", value: draft().release_manifest_sha256, on_change: move |v| draft.write().release_manifest_sha256 = v }
                div { class: "field", label { "Advanced release parameters (JSON)" }
                    textarea { value: "{draft().release_parameters_json}", oninput: move |event| draft.write().release_parameters_json = event.value() }
                    span { class: "hint", "Signed release builds prefill these immutable artifact locations. Source builds can paste the release descriptor parameters here." }
                }
            }
        },
        WizardStep::Review => {
            let validation = draft().configuration();
            rsx! {
                div { class: "eyebrow", "Step 7" } h1 { "Review the complete plan" }
                p { class: "lede", "Saving creates an immutable, reviewable bundle. It does not call AWS or Vapi." }
                if let Err(error) = validation {
                    div { class: "status error", "Complete or correct the configuration: {error}" }
                } else {
                    div { class: "safe", strong { "Validated" } span { "The setup configuration and screen-pop schema are valid and contain no credentials." } }
                }
                div { class: "review",
                    div { class: "card", strong { "AWS" } span { "Dedicated Starter VPC and Bridgefu stack in {draft().region}." } }
                    div { class: "card", strong { "Amazon Connect" } span { if draft().routing_routes.is_empty() { "New wrapper and guide; selected flow remains unchanged." } else { "New wrapper and guide; reviewed routing selects among configured published flows." } } }
                    div { class: "card", strong { "Vapi" } span { "New template assistant, tool, and credential. No existing assistant changes." } }
                    div { class: "card", strong { "Data" } span { "{draft().fields.len()} configured fields; {draft().routing_routes.len()} optional route mapping(s); TTL {draft().ttl_seconds} seconds." } }
                    div { class: "card", strong { "Secrets" } span { "Vapi key stays in memory. Webhook bearer remains in Secrets Manager." } }
                    div { class: "card", strong { "Resume" } span { "The .bridgefu bundle can be opened and executed later." } }
                }
            }
        }
        WizardStep::Finish => rsx! {
            div { class: "eyebrow", "Step 8" } h1 { "Save the deployment bundle" }
            p { class: "lede", "The bundle contains human-readable CloudFormation and Vapire artifacts with a SHA-256 manifest. Execution remains a separate confirmed action." }
            div { class: "card",
                h2 { "No existing assistant will be changed" }
                p { class: "hint", "Bridgefu creates a new template assistant. Later customizations are reported as retained drift and are not overwritten." }
                button { class: "primary", onclick: move |_| {
                    match draft().configuration() {
                        Ok(config) => {
                            let path = rfd::FileDialog::new()
                                .add_filter("Bridgefu deployment", &["bridgefu"])
                                .set_file_name(format!("{}.bridgefu", config.deployment_id))
                                .save_file();
                            if let Some(path) = path {
                                match seal_bundle(&config, &path) {
                                    Ok(manifest) => {
                                        saved_bundle.set(Some(path.clone()));
                                        reviewed_change_set.set(None);
                                        message.set(format!("Saved {} — plan {}", path.display(), &manifest.bundle_sha256[..12]));
                                    }
                                    Err(error) => message.set(format!("Could not save bundle: {error}")),
                                }
                            }
                        }
                        Err(error) => message.set(format!("Configuration is incomplete: {error}")),
                    }
                }, "Save .bridgefu bundle" }
                if let Some(path) = saved_bundle() {
                    div { class: "button-row",
                        button { class: "secondary", onclick: {
                            let path = path.clone();
                            move |_| {
                            if let Some(folder) = rfd::FileDialog::new().pick_folder() {
                                match export_bundle(&path, &folder) {
                                    Ok(_) => message.set(format!("Exported reviewed artifacts to {}", folder.display())),
                                    Err(error) => message.set(format!("Could not export artifacts: {error}")),
                                }
                            }
                        }}, "Open artifact folder" }
                        button { class: "secondary", onclick: {
                            let path = path.clone();
                            move |_| {
                            let inspection = match inspect_bundle(&path) {
                                Ok(value) => value,
                                Err(error) => { message.set(format!("Could not verify bundle: {error}")); return; }
                            };
                            let name = format!("bridgefu-setup-{}", &inspection.manifest.bundle_sha256[..12]);
                            let review_path = path.clone();
                            message.set("Creating the non-executing AWS change set for review…".into());
                            spawn(async move {
                                let task_name = name.clone();
                                let result = tokio::task::spawn_blocking(move || {
                                    run_companion(&review_path, "apply", &["--change-set-name", &task_name], None)
                                }).await;
                                match result {
                                    Ok(Ok(summary)) => {
                                        reviewed_change_set.set(Some(name));
                                        message.set(format!("AWS change set reviewed. {summary}"));
                                    }
                                    Ok(Err(error)) => message.set(format!("AWS review failed: {error}")),
                                    Err(error) => message.set(format!("AWS review task failed: {error}")),
                                }
                            });
                        }}, "Review AWS change set" }
                    }
                    button { class: "primary", disabled: reviewed_change_set().is_none() || draft().vapi_api_key.len() < 24, onclick: {
                        let path = path.clone();
                        move |_| {
                        let Some(change_set) = reviewed_change_set() else { return; };
                        let key = zeroize::Zeroizing::new(draft().vapi_api_key.clone());
                        let stack_name = draft().stack_name.clone();
                        let execution_path = path.clone();
                        message.set("Deployment is running. The AWS stack is retained if Vapi setup fails, so this bundle can resume safely.".into());
                        spawn(async move {
                            let result = tokio::task::spawn_blocking(move || {
                                run_companion(
                                    &execution_path,
                                    "apply",
                                    &["--execute", "--confirm", &stack_name, "--vapi-key-stdin", "--change-set-name", &change_set],
                                    Some(key.as_str()),
                                )
                            }).await;
                            match result {
                                Ok(Ok(summary)) => message.set(format!("Deployment completed. {summary}")),
                                Ok(Err(error)) => message.set(format!("Deployment stopped safely: {error}")),
                                Err(error) => message.set(format!("Deployment task failed: {error}")),
                            }
                        });
                    }}, "Execute reviewed deployment" }
                }
            }
        },
        WizardStep::Management => rsx! {
            div { class: "eyebrow", "Step 9" } h1 { "Manage this deployment" }
            p { class: "lede", "All actions use the sealed bundle and its non-secret state journal to prove ownership before changing anything." }
            if let Some(path) = saved_bundle() {
                div { class: "card",
                    h2 { "Health and drift" }
                    button { class: "secondary", onclick: {
                        let path = path.clone();
                        move |_| {
                            match run_companion(&path, "status", &[], None) {
                                Ok(summary) => message.set(format!("Status checked. {summary}")),
                                Err(error) => message.set(format!("Status check failed: {error}")),
                            }
                        }
                    }, "Check deployment status" }
                }
                div { class: "card",
                    h2 { "Rotate webhook credential" }
                    p { class: "hint", "Creates a new AWS secret version and updates only the exact Bridgefu-owned Vapi credential. The assistant and its customizations are unchanged." }
                    button { class: "secondary", disabled: draft().vapi_api_key.len() < 24, onclick: {
                        let path = path.clone();
                        move |_| {
                            let inspection = match inspect_bundle(&path) { Ok(value) => value, Err(error) => { message.set(format!("Bundle verification failed: {error}")); return; } };
                            let journal = match load_journal(&path, &inspection.manifest) { Ok(Some(value)) => value, Ok(None) => { message.set("Deployment has no state journal".into()); return; }, Err(error) => { message.set(format!("State verification failed: {error}")); return; } };
                            let Some(state) = journal.vapi_template else { message.set("No Vapi template is recorded".into()); return; };
                            let key = zeroize::Zeroizing::new(draft().vapi_api_key.clone());
                            match run_companion(&path, "rotate-credential", &["--execute", "--confirm-assistant-id", &state.assistant_id, "--vapi-key-stdin"], Some(key.as_str())) {
                                Ok(summary) => message.set(format!("Credential rotated. {summary}")),
                                Err(error) => message.set(format!("Rotation stopped safely: {error}")),
                            }
                        }
                    }, "Rotate credential" }
                }
                div { class: "card",
                    h2 { "Uninstall AWS" }
                    p { class: "hint", "The customized Vapi template and retained DynamoDB/audit data are not deleted." }
                    TextInput { label: "Type the exact stack name to confirm", value: stack_confirmation(), on_change: move |v| stack_confirmation.set(v) }
                    button { class: "danger", disabled: stack_confirmation() != draft().stack_name, onclick: {
                        let path = path.clone();
                        move |_| {
                            let confirmation = stack_confirmation();
                            match run_companion(&path, "uninstall", &["--execute", "--confirm", &confirmation], None) {
                                Ok(summary) => message.set(format!("AWS uninstall completed. {summary}")),
                                Err(error) => message.set(format!("Uninstall stopped safely: {error}")),
                            }
                        }
                    }, "Uninstall AWS stack" }
                }
                div { class: "card",
                    h2 { "Delete generated Vapi template" }
                    p { class: "hint", "Destructive: deletes the exact Setup-created assistant, tool, and credential. Do this only if you do not need its customizations." }
                    TextInput { label: "Type the exact assistant ID to confirm", value: assistant_confirmation(), on_change: move |v| assistant_confirmation.set(v) }
                    button { class: "danger", disabled: assistant_confirmation().is_empty() || draft().vapi_api_key.len() < 24, onclick: {
                        let path = path.clone();
                        move |_| {
                            let confirmation = assistant_confirmation();
                            let key = zeroize::Zeroizing::new(draft().vapi_api_key.clone());
                            match run_companion(&path, "delete-template", &["--execute", "--confirm-assistant-id", &confirmation, "--vapi-key-stdin"], Some(key.as_str())) {
                                Ok(summary) => message.set(format!("Vapi template deleted. {summary}")),
                                Err(error) => message.set(format!("Vapi deletion stopped safely: {error}")),
                            }
                        }
                    }, "Delete Vapi template" }
                }
            } else {
                div { class: "status error", "Open or save a .bridgefu bundle first." }
            }
        },
    }
}

#[component]
fn TextInput(label: &'static str, value: String, on_change: EventHandler<String>) -> Element {
    rsx! {
        div { class: "field",
            label { "{label}" }
            input { value, oninput: move |event| on_change.call(event.value()) }
        }
    }
}

#[component]
fn PasswordInput(label: &'static str, value: String, on_change: EventHandler<String>) -> Element {
    rsx! {
        div { class: "field",
            label { "{label}" }
            input {
                r#type: "password",
                autocomplete: "off",
                spellcheck: "false",
                value,
                oninput: move |event| on_change.call(event.value())
            }
        }
    }
}

#[component]
fn FieldEditor(index: usize, field: ScreenPopField, mut draft: Signal<Draft>) -> Element {
    let (kind, key, label, description, required, detail) = match &field {
        ScreenPopField::Text(value) => (
            "Text",
            value.key.clone(),
            value.label.clone(),
            value.description.clone(),
            value.required,
            value.max_length.to_string(),
        ),
        ScreenPopField::Choice(value) => (
            "Choice",
            value.key.clone(),
            value.label.clone(),
            value.description.clone(),
            value.required,
            value.choices.join(", "),
        ),
    };
    let convert_label = if kind == "Text" {
        "Convert to choice"
    } else {
        "Convert to text"
    };
    rsx! {
        div { class: "card field-editor",
            div { class: "field-heading",
                strong { "Field {index + 1}" }
                span { class: "pill", "{kind}" }
            }
            div { class: "grid",
                div { class: "field", label { "Key" }
                    input { value: key, oninput: move |event| set_field_text(&mut draft, index, FieldPart::Key, event.value()) }
                }
                div { class: "field", label { "Agent label" }
                    input { value: label, oninput: move |event| set_field_text(&mut draft, index, FieldPart::Label, event.value()) }
                }
            }
            div { class: "field", label { "Description for the Vapi tool" }
                input { value: description, oninput: move |event| set_field_text(&mut draft, index, FieldPart::Description, event.value()) }
            }
            div { class: "field", label { if kind == "Text" { "Maximum length" } else { "Choices, comma separated" } }
                input { value: detail, oninput: move |event| set_field_detail(&mut draft, index, event.value()) }
            }
            label { class: "check",
                input { r#type: "checkbox", checked: required, onchange: move |event| set_field_required(&mut draft, index, event.checked()) }
                "Required before transfer"
            }
            div { class: "button-row compact",
                button { class: "secondary", disabled: index == 0, onclick: move |_| move_field(&mut draft, index, -1), "Move up" }
                button { class: "secondary", disabled: index + 1 >= draft().fields.len(), onclick: move |_| move_field(&mut draft, index, 1), "Move down" }
                button { class: "secondary", onclick: move |_| convert_field(&mut draft, index), "{convert_label}" }
                button { class: "danger", disabled: draft().fields.len() <= 1, onclick: move |_| remove_field(&mut draft, index), "Remove" }
            }
        }
    }
}

#[component]
fn RouteEditor(index: usize, route: RouteMapping, mut draft: Signal<Draft>) -> Element {
    let mut options = Vec::<ConnectFlowSummary>::new();
    if !route.target_contact_flow_arn.is_empty() {
        options.push(ConnectFlowSummary {
            id: route
                .target_contact_flow_arn
                .rsplit('/')
                .next()
                .unwrap_or_default()
                .to_owned(),
            arn: route.target_contact_flow_arn.clone(),
            name: route.target_contact_flow_name.clone(),
        });
    }
    let snapshot = draft();
    if !snapshot.contact_flow_arn.is_empty()
        && options
            .iter()
            .all(|flow| flow.arn != snapshot.contact_flow_arn)
    {
        options.push(ConnectFlowSummary {
            id: snapshot
                .contact_flow_arn
                .rsplit('/')
                .next()
                .unwrap_or_default()
                .to_owned(),
            arn: snapshot.contact_flow_arn.clone(),
            name: format!("Default — {}", snapshot.contact_flow_name),
        });
    }
    for flow in snapshot.flow_options {
        if options.iter().all(|known| known.arn != flow.arn) {
            options.push(flow);
        }
    }
    rsx! {
        div { class: "routing-row",
            div { strong { "{route.value}" } span { "Stored choice" } }
            div { class: "field",
                label { "Published Connect flow" }
                select {
                    value: route.target_contact_flow_arn.clone(),
                    onchange: move |event| set_route_flow(&mut draft, index, &event.value()),
                    for flow in options {
                        option { value: flow.arn.clone(), selected: flow.arn == route.target_contact_flow_arn, "{flow.name}" }
                    }
                }
            }
        }
    }
}

#[derive(Clone, Copy)]
enum FieldPart {
    Key,
    Label,
    Description,
}

fn set_field_text(draft: &mut Signal<Draft>, index: usize, part: FieldPart, value: String) {
    let mut draft = draft.write();
    let Some(previous_key) = draft.fields.get(index).map(|field| field.key().to_owned()) else {
        return;
    };
    if matches!(part, FieldPart::Key) && draft.routing_field_key == previous_key {
        draft.routing_field_key = value.clone();
    }
    let field = &mut draft.fields[index];
    match field {
        ScreenPopField::Text(field) => match part {
            FieldPart::Key => field.key = value,
            FieldPart::Label => field.label = value,
            FieldPart::Description => field.description = value,
        },
        ScreenPopField::Choice(field) => match part {
            FieldPart::Key => field.key = value,
            FieldPart::Label => field.label = value,
            FieldPart::Description => field.description = value,
        },
    }
}

fn set_field_detail(draft: &mut Signal<Draft>, index: usize, value: String) {
    let routing_choice = {
        let mut draft = draft.write();
        let routing_key = draft.routing_field_key.clone();
        let Some(field) = draft.fields.get_mut(index) else {
            return;
        };
        match field {
            ScreenPopField::Text(field) => {
                if let Ok(maximum) = value.parse() {
                    field.max_length = maximum;
                }
            }
            ScreenPopField::Choice(field) => {
                field.choices = value
                    .split(',')
                    .map(str::trim)
                    .filter(|item| !item.is_empty())
                    .map(str::to_owned)
                    .collect();
            }
        }
        match &draft.fields[index] {
            ScreenPopField::Choice(choice) if choice.key == routing_key => Some(choice.clone()),
            _ => None,
        }
    };
    if let Some(choice) = routing_choice {
        select_routing_field(draft, choice);
    }
}

fn select_default_flow(draft: &mut Signal<Draft>, flow: ConnectFlowSummary) {
    let mut draft = draft.write();
    let previous = draft.contact_flow_arn.clone();
    for route in &mut draft.routing_routes {
        if route.target_contact_flow_arn == previous {
            route.target_contact_flow_arn = flow.arn.clone();
            route.target_contact_flow_name = flow.name.clone();
        }
    }
    draft.contact_flow_arn = flow.arn;
    draft.contact_flow_name = flow.name;
}

fn select_routing_field(draft: &mut Signal<Draft>, choice: ChoiceField) {
    let mut draft = draft.write();
    let existing = draft.routing_routes.clone();
    draft.routing_field_key = choice.key;
    draft.routing_routes = choice
        .choices
        .into_iter()
        .take(8)
        .map(|value| {
            existing
                .iter()
                .find(|route| route.value == value)
                .cloned()
                .unwrap_or_else(|| RouteMapping {
                    value,
                    target_contact_flow_arn: draft.contact_flow_arn.clone(),
                    target_contact_flow_name: draft.contact_flow_name.clone(),
                })
        })
        .collect();
}

fn set_route_flow(draft: &mut Signal<Draft>, index: usize, arn: &str) {
    let mut draft = draft.write();
    let selected = if arn == draft.contact_flow_arn {
        Some((
            draft.contact_flow_arn.clone(),
            draft.contact_flow_name.clone(),
        ))
    } else {
        draft
            .flow_options
            .iter()
            .find(|flow| flow.arn == arn)
            .map(|flow| (flow.arn.clone(), flow.name.clone()))
    };
    let Some((arn, name)) = selected else {
        return;
    };
    if let Some(route) = draft.routing_routes.get_mut(index) {
        route.target_contact_flow_arn = arn;
        route.target_contact_flow_name = name;
    }
}

fn set_field_required(draft: &mut Signal<Draft>, index: usize, required: bool) {
    let mut draft = draft.write();
    let Some(field) = draft.fields.get_mut(index) else {
        return;
    };
    match field {
        ScreenPopField::Text(field) => field.required = required,
        ScreenPopField::Choice(field) => field.required = required,
    }
}

fn move_field(draft: &mut Signal<Draft>, index: usize, offset: isize) {
    let destination = index as isize + offset;
    if destination < 0 {
        return;
    }
    let mut draft = draft.write();
    if destination as usize >= draft.fields.len() {
        return;
    }
    draft.fields.swap(index, destination as usize);
}

fn convert_field(draft: &mut Signal<Draft>, index: usize) {
    let mut draft = draft.write();
    let Some(field) = draft.fields.get(index).cloned() else {
        return;
    };
    let selected_routing_key = draft.routing_field_key.clone();
    let field_key = field.key().to_owned();
    draft.fields[index] = match field {
        ScreenPopField::Text(value) => ScreenPopField::Choice(ChoiceField {
            key: value.key,
            label: value.label,
            description: value.description,
            required: value.required,
            choices: vec!["option_one".into(), "option_two".into()],
        }),
        ScreenPopField::Choice(value) => ScreenPopField::Text(TextField {
            key: value.key,
            label: value.label,
            description: value.description,
            required: value.required,
            max_length: 256,
        }),
    };
    if selected_routing_key == field_key {
        draft.routing_field_key.clear();
        draft.routing_routes.clear();
    }
}

fn remove_field(draft: &mut Signal<Draft>, index: usize) {
    let mut draft = draft.write();
    if index >= draft.fields.len() {
        return;
    }
    let key = draft.fields[index].key().to_owned();
    draft.fields.remove(index);
    if draft.routing_field_key == key {
        draft.routing_field_key.clear();
        draft.routing_routes.clear();
    }
}

fn run_companion(
    bundle: &std::path::Path,
    subcommand: &str,
    arguments: &[&str],
    vapi_key: Option<&str>,
) -> anyhow::Result<String> {
    use std::io::Write as _;
    use std::process::{Command, Stdio};

    let current = std::env::current_exe()?;
    let name = if cfg!(windows) {
        "bridgefu.exe"
    } else {
        "bridgefu"
    };
    let executable = current
        .parent()
        .unwrap_or_else(|| std::path::Path::new("."))
        .join(name);
    anyhow::ensure!(
        executable.is_file(),
        "the companion bridgefu CLI is not installed beside Bridgefu Setup"
    );
    let mut command = Command::new(executable);
    anyhow::ensure!(
        matches!(
            subcommand,
            "apply" | "status" | "rotate-credential" | "delete-template" | "uninstall"
        ),
        "invalid companion setup action"
    );
    command
        .arg("setup")
        .arg(subcommand)
        .arg(bundle)
        .args(arguments);
    command.stdout(Stdio::piped()).stderr(Stdio::piped());
    command.stdin(if vapi_key.is_some() {
        Stdio::piped()
    } else {
        Stdio::null()
    });
    let mut child = command.spawn()?;
    if let Some(key) = vapi_key {
        let mut stdin = child.stdin.take().context("open private setup input")?;
        stdin.write_all(key.as_bytes())?;
        stdin.write_all(b"\n")?;
    }
    let output = child.wait_with_output()?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    if !output.status.success() {
        let summary = stderr
            .lines()
            .last()
            .or_else(|| stdout.lines().last())
            .unwrap_or("companion CLI failed")
            .chars()
            .filter(|character| !character.is_control())
            .take(500)
            .collect::<String>();
        anyhow::bail!(summary);
    }
    Ok(stdout
        .lines()
        .last()
        .unwrap_or("completed")
        .chars()
        .filter(|character| !character.is_control())
        .take(500)
        .collect())
}
