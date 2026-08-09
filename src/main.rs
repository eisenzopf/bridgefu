//! bridgefu — programmable SIP/RTP, WebRTC/RTP, provider, and QUIC bridge.
//!
//! Loads a YAML config, stands up the `rvoip-amazon-connect`
//! `ConnectScreenPopServer` (SIP UAS → header→attribute mapping →
//! StartWebRTCContact → Chime media bridge), and serves `/healthz` + `/metrics`,
//! until SIGTERM/SIGINT triggers a graceful shutdown.

mod api;
mod api_rate_limit;
mod config;
mod imds;
mod moq_relay_role;
mod observability;
mod process_role;
mod recipe_admin;
mod runtime;
mod screen_pop_evidence;

pub(crate) use bridgefu::providers;

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use bridgefu::context;
use bridgefu::recipes::{
    AmazonConnectMedia, CompiledRecipe, RecipeCatalog, RecipeEndpointSpec, RecipeSource,
    SipAdmissionMode, SipSecurity,
};
use bridgefu_setup_core::{
    apply_vapi_template, delete_vapi_template, export_bundle, inspect_bundle, load_journal,
    plan_vapi_template, rotate_vapi_credential, save_journal, seal_bundle, AwsCli,
    DeploymentJournal, ExecutionPhase, SetupConfiguration, VapiResolvedInputs,
};
use clap::{Parser, Subcommand};
use metrics_exporter_prometheus::PrometheusHandle;
use rvoip_amazon_connect::ConnectScreenPopServer;

use crate::config::RuntimeMode;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ProcessRunner {
    AllInOne,
    Gateway,
    Worker,
    MoqRelay,
}

const fn process_runner(mode: RuntimeMode) -> ProcessRunner {
    match mode {
        RuntimeMode::AllInOne => ProcessRunner::AllInOne,
        RuntimeMode::Gateway => ProcessRunner::Gateway,
        RuntimeMode::Worker => ProcessRunner::Worker,
        RuntimeMode::MoqRelay => ProcessRunner::MoqRelay,
    }
}

#[derive(Parser, Debug)]
#[command(
    name = "bridgefu",
    version,
    about = "Programmable SIP, WebRTC, provider-control, and QUIC audio bridge"
)]
struct Args {
    /// Path to the YAML config file.
    #[arg(short, long, default_value = "/etc/bridgefu/bridgefu.yaml")]
    config: PathBuf,
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Clone, Debug, Subcommand)]
enum Command {
    /// Run the configured Bridgefu process (the default).
    Run,
    /// Parse configuration, apply environment overrides, and exit.
    Validate,
    /// Print the effective configuration with all secrets redacted.
    PrintEffectiveConfig,
    /// Inspect and validate immutable Bridgefu Recipe packages.
    Recipe {
        #[command(subcommand)]
        command: RecipeCommand,
    },
    /// Configure and administer the Vapi to Amazon Connect deployment.
    Setup {
        #[command(subcommand)]
        command: SetupCommand,
    },
    /// Probe the local liveness endpoint without loading configuration.
    Healthcheck {
        /// Local operations endpoint to probe.
        #[arg(long, default_value = "127.0.0.1:9090")]
        address: SocketAddr,
        /// HTTP liveness path to request.
        #[arg(long, default_value = "/livez")]
        path: String,
        /// Per-operation network timeout in milliseconds.
        #[arg(long, default_value_t = 2_500)]
        timeout_ms: u64,
    },
}

#[derive(Clone, Debug, Subcommand)]
enum SetupCommand {
    /// List AWS CLI and SSO profiles available on this workstation.
    Profiles,
    /// Discover the AWS identity, active Connect instances, and public zones.
    Discover {
        #[arg(long)]
        profile: String,
        /// Limit discovery to one or more regions. By default all enabled regions are checked.
        #[arg(long = "region")]
        regions: Vec<String>,
    },
    /// Validate a human-readable setup YAML file and seal a .bridgefu bundle.
    Generate {
        #[arg(long)]
        config: PathBuf,
        #[arg(long)]
        output: PathBuf,
    },
    /// Verify hashes and print a non-secret summary of a sealed bundle.
    Inspect { bundle: PathBuf },
    /// Export all reviewed source artifacts to a new or empty directory.
    Export {
        bundle: PathBuf,
        #[arg(long)]
        output: PathBuf,
    },
    /// Review a CloudFormation change set and optionally execute AWS then Vapi.
    Apply {
        bundle: PathBuf,
        /// Execute after printing both the Vapi and CloudFormation plans.
        #[arg(long)]
        execute: bool,
        /// Required with --execute; must equal the configured CloudFormation stack name.
        #[arg(long)]
        confirm: Option<String>,
        /// Read the Vapi private key from one line on stdin instead of a hidden terminal prompt.
        #[arg(long)]
        vapi_key_stdin: bool,
        /// Reuse a previously reviewed CloudFormation change set by exact name.
        #[arg(long)]
        change_set_name: Option<String>,
    },
    /// Show the local resume state and current AWS stack status.
    Status { bundle: PathBuf },
    /// Rotate the AWS/Vapi webhook credential without changing the assistant.
    RotateCredential {
        bundle: PathBuf,
        #[arg(long)]
        execute: bool,
        #[arg(long)]
        confirm_assistant_id: Option<String>,
        #[arg(long)]
        vapi_key_stdin: bool,
    },
    /// Delete the exact Setup-created Vapi template, tool, and credential.
    DeleteTemplate {
        bundle: PathBuf,
        #[arg(long)]
        execute: bool,
        #[arg(long)]
        confirm_assistant_id: Option<String>,
        #[arg(long)]
        vapi_key_stdin: bool,
    },
    /// Remove the AWS stack while retaining the customized Vapi template.
    Uninstall {
        bundle: PathBuf,
        #[arg(long)]
        execute: bool,
        #[arg(long)]
        confirm: Option<String>,
    },
}

#[derive(Clone, Debug, Subcommand)]
enum RecipeCommand {
    /// List recipe packages that can be selected on this installation.
    Available {
        /// External recipe package directory. Repeat for more than one.
        #[arg(long = "package", value_name = "DIRECTORY")]
        packages: Vec<PathBuf>,
    },
    /// List embedded recipes and any explicitly supplied external packages.
    List {
        /// External recipe package directory. Repeat for more than one.
        #[arg(long = "package", value_name = "DIRECTORY")]
        packages: Vec<PathBuf>,
        /// List configured instances from --config instead of available packages.
        #[arg(long)]
        configured: bool,
    },
    /// Print one unresolved, credential-free recipe manifest.
    Show {
        /// Exact builtin:name@version or external:name@version selector.
        selector: String,
        /// External recipe package directory. Repeat for more than one.
        #[arg(long = "package", value_name = "DIRECTORY")]
        packages: Vec<PathBuf>,
    },
    /// Compile one recipe with a YAML values file and print its fingerprint.
    Validate {
        /// Exact builtin:name@version or external:name@version selector.
        selector: String,
        /// YAML mapping containing the recipe's typed input values.
        #[arg(long, value_name = "FILE")]
        values: PathBuf,
        /// External recipe package directory. Repeat for more than one.
        #[arg(long = "package", value_name = "DIRECTORY")]
        packages: Vec<PathBuf>,
    },
    /// Create a safe, editable starter directory without overwriting files.
    Init {
        /// Exact builtin:name@version or external:name@version selector.
        selector: String,
        /// New directory to create.
        #[arg(long, value_name = "DIRECTORY")]
        output: PathBuf,
        /// External recipe package directory. Repeat for more than one.
        #[arg(long = "package", value_name = "DIRECTORY")]
        packages: Vec<PathBuf>,
    },
    /// Explain one configured recipe instance with credentials redacted.
    Explain {
        /// Instance name under the config's recipes mapping.
        instance: String,
    },
    /// Create and review an AWS CloudFormation change set; execution is opt-in.
    Deploy {
        /// Deployment descriptor created from a published recipe release.
        deployment: PathBuf,
        /// Starter Production or High Availability infrastructure profile.
        #[arg(long, value_enum, default_value_t = recipe_admin::DeploymentProfile::Starter)]
        profile: recipe_admin::DeploymentProfile,
        /// Execute the reviewed change set after it is printed.
        #[arg(long)]
        execute: bool,
        /// Required with --execute; must exactly equal the stack name.
        #[arg(long)]
        confirm: Option<String>,
        /// Explicit review name; with --execute, reuses that exact available review.
        #[arg(long)]
        change_set_name: Option<String>,
    },
    /// Verify identity, release, target, quotas, DNS, and account guardrails.
    Preflight {
        /// Deployment descriptor created from a published recipe release.
        deployment: PathBuf,
        /// Starter Production or High Availability infrastructure profile.
        #[arg(long, value_enum, default_value_t = recipe_admin::DeploymentProfile::Starter)]
        profile: recipe_admin::DeploymentProfile,
    },
    /// Print redacted CloudFormation deployment status and safe outputs.
    Status {
        deployment: PathBuf,
        #[arg(long, value_enum, default_value_t = recipe_admin::DeploymentProfile::Starter)]
        profile: recipe_admin::DeploymentProfile,
    },
    /// Check stack ownership, resources, required outputs, and active alarms.
    Doctor {
        deployment: PathBuf,
        #[arg(long, value_enum, default_value_t = recipe_admin::DeploymentProfile::Starter)]
        profile: recipe_admin::DeploymentProfile,
    },
    /// Run the nonbillable structural deployment qualification.
    Test {
        deployment: PathBuf,
        #[arg(long, value_enum, default_value_t = recipe_admin::DeploymentProfile::Starter)]
        profile: recipe_admin::DeploymentProfile,
    },
    /// Delete an exactly owned recipe stack after explicit confirmation.
    Destroy {
        deployment: PathBuf,
        #[arg(long, value_enum, default_value_t = recipe_admin::DeploymentProfile::Starter)]
        profile: recipe_admin::DeploymentProfile,
        /// Must exactly equal the stack name in the deployment descriptor.
        #[arg(long)]
        confirm: String,
    },
}

fn install_default_crypto_provider() -> Result<()> {
    if rustls::crypto::CryptoProvider::get_default().is_none() {
        let _ = rustls::crypto::ring::default_provider().install_default();
    }
    anyhow::ensure!(
        rustls::crypto::CryptoProvider::get_default().is_some(),
        "installing the process-level rustls crypto provider"
    );
    Ok(())
}

fn main() -> Result<()> {
    // Install before parsing or compiling configuration. Recipe-projected
    // WebRTC signaling may construct a TLS acceptor in the all-in-one path,
    // before the role-specific helpers that also defensively install one.
    install_default_crypto_provider()?;
    let args = Args::parse();
    let command = args.command.clone().unwrap_or(Command::Run);

    match command {
        // Printing must remain available before runtime secrets are
        // provisioned. The helper still parses the complete typed shape and
        // rejects unknown fields before redacting every credential-bearing
        // value.
        Command::PrintEffectiveConfig => {
            print!("{}", config::Config::redacted_effective_yaml(&args.config)?);
            Ok(())
        }
        Command::Recipe { command } => run_recipe_command(command, &args.config),
        Command::Setup { command } => run_setup_command(command),
        // Container liveness must work in a package-free runtime before a
        // config file or deployment secret is mounted. Dispatching before
        // constructing Tokio also keeps each frequent probe to one thread.
        Command::Healthcheck {
            address,
            path,
            timeout_ms,
        } => probe_liveness(address, &path, Duration::from_millis(timeout_ms)),
        Command::Validate => {
            let cfg = config::Config::load(&args.config)?;
            process_role::preflight(&cfg)?;
            println!("configuration is valid: {}", args.config.display());
            Ok(())
        }
        Command::Run => {
            let runtime = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
                .context("building the Bridgefu Tokio runtime")?;
            runtime.block_on(run(args))
        }
    }
}

fn run_setup_command(command: SetupCommand) -> Result<()> {
    match command {
        SetupCommand::Profiles => {
            for profile in AwsCli.list_profiles()? {
                println!("{profile}");
            }
            Ok(())
        }
        SetupCommand::Discover {
            profile,
            mut regions,
        } => {
            let aws = AwsCli;
            let identity = aws.caller_identity(&profile)?;
            if regions.is_empty() {
                regions = aws.enabled_regions(&profile)?;
            }
            let instances = aws.connect_instances(&profile, &regions)?;
            let zones = aws.public_hosted_zones(&profile)?;
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "identity": identity,
                    "connectInstances": instances,
                    "publicHostedZones": zones,
                }))?
            );
            Ok(())
        }
        SetupCommand::Generate { config, output } => {
            let metadata = config
                .metadata()
                .with_context(|| format!("read setup configuration {}", config.display()))?;
            anyhow::ensure!(
                metadata.is_file() && metadata.len() <= 512 * 1024,
                "setup configuration must be a bounded regular file"
            );
            let configuration: SetupConfiguration =
                serde_yaml::from_slice(&std::fs::read(&config)?)
                    .with_context(|| format!("parse setup configuration {}", config.display()))?;
            let manifest = seal_bundle(&configuration, &output)?;
            println!(
                "sealed {}\nplan hash: {}",
                output.display(),
                manifest.bundle_sha256
            );
            Ok(())
        }
        SetupCommand::Inspect { bundle } => {
            let inspection = inspect_bundle(&bundle)?;
            let journal = load_journal(&bundle, &inspection.manifest)?;
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "bundle": bundle,
                    "planHash": inspection.manifest.bundle_sha256,
                    "deploymentId": inspection.configuration.deployment_id,
                    "stackName": inspection.configuration.stack_name,
                    "awsAccount": inspection.configuration.aws.account_id,
                    "region": inspection.configuration.aws.region,
                    "connectInstance": inspection.configuration.connect.instance_arn,
                    "targetFlow": inspection.configuration.connect.target_contact_flow_arn,
                    "vapiAction": "create_new_template_assistant",
                    "existingAssistantsModified": false,
                    "screenPopFieldCount": inspection.configuration.screen_pop_fields.len(),
                    "routingField": inspection.configuration.routing.as_ref().map(|routing| &routing.field_key),
                    "reviewedRouteCount": inspection.configuration.routing.as_ref().map_or(0, |routing| routing.routes.len()),
                    "journalPhase": journal.map(|item| item.phase),
                    "containsSecrets": false,
                }))?
            );
            Ok(())
        }
        SetupCommand::Export { bundle, output } => {
            let manifest = export_bundle(&bundle, &output)?;
            println!(
                "exported plan {} to {}",
                manifest.bundle_sha256,
                output.display()
            );
            Ok(())
        }
        SetupCommand::Apply {
            bundle,
            execute,
            confirm,
            vapi_key_stdin,
            change_set_name,
        } => apply_setup_bundle(
            &bundle,
            execute,
            confirm.as_deref(),
            vapi_key_stdin,
            change_set_name.as_deref(),
        ),
        SetupCommand::Status { bundle } => {
            let inspection = inspect_bundle(&bundle)?;
            let journal = load_journal(&bundle, &inspection.manifest)?;
            if let Some(journal) = journal {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "planHash": journal.bundle_sha256,
                        "phase": journal.phase,
                        "updatedAt": journal.updated_at,
                        "vapiTemplateAssistantId": journal.vapi_template.map(|state| state.assistant_id),
                        "lastResultCategory": journal.last_result_category,
                    }))?
                );
            } else {
                println!("no execution has started for this sealed bundle");
            }
            let export = tempfile::tempdir()?;
            export_bundle(&bundle, export.path())?;
            let _profile = AwsProfileGuard::set(&inspection.configuration.aws.profile);
            recipe_admin::status(
                &export.path().join("aws/deployment-descriptor.yaml"),
                recipe_admin::DeploymentProfile::Starter,
            )
        }
        SetupCommand::RotateCredential {
            bundle,
            execute,
            confirm_assistant_id,
            vapi_key_stdin,
        } => rotate_setup_credential(
            &bundle,
            execute,
            confirm_assistant_id.as_deref(),
            vapi_key_stdin,
        ),
        SetupCommand::DeleteTemplate {
            bundle,
            execute,
            confirm_assistant_id,
            vapi_key_stdin,
        } => delete_setup_template(
            &bundle,
            execute,
            confirm_assistant_id.as_deref(),
            vapi_key_stdin,
        ),
        SetupCommand::Uninstall {
            bundle,
            execute,
            confirm,
        } => uninstall_setup_bundle(&bundle, execute, confirm.as_deref()),
    }
}

fn apply_setup_bundle(
    bundle: &std::path::Path,
    execute: bool,
    confirm: Option<&str>,
    vapi_key_stdin: bool,
    change_set_name: Option<&str>,
) -> Result<()> {
    let inspection = inspect_bundle(bundle)?;
    if execute {
        anyhow::ensure!(
            confirm == Some(inspection.configuration.stack_name.as_str()),
            "--confirm must exactly equal the configured stack name"
        );
    }
    let mut journal = load_journal(bundle, &inspection.manifest)?
        .unwrap_or_else(|| DeploymentJournal::reviewed(&inspection.manifest));
    save_journal(bundle, &mut journal)?;

    let vapi_key = if execute {
        Some(read_vapi_key(vapi_key_stdin)?)
    } else {
        None
    };
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("build setup runtime")?;
    let reviewed_vapi_plan = if let Some(key) = vapi_key.as_ref() {
        let plan = runtime.block_on(plan_vapi_template(
            &inspection.configuration,
            key.as_str().to_owned(),
            journal.vapi_template.as_ref(),
        ))?;
        println!("Vapi plan (masked):\n{}", plan.masked_diff);
        Some(plan)
    } else {
        println!(
            "Vapi plan: create one new Bridgefu template assistant; modify no existing assistant"
        );
        None
    };

    let export = tempfile::tempdir()?;
    export_bundle(bundle, export.path())?;
    let descriptor = export.path().join("aws/deployment-descriptor.yaml");
    let _profile = AwsProfileGuard::set(&inspection.configuration.aws.profile);
    recipe_admin::deploy(
        &descriptor,
        recipe_admin::DeploymentProfile::Starter,
        execute,
        confirm,
        change_set_name,
    )?;
    if !execute {
        return Ok(());
    }

    let outputs =
        recipe_admin::stack_outputs(&descriptor, recipe_admin::DeploymentProfile::Starter)?;
    let tool_url = outputs
        .get("VapiToolUrl")
        .context("deployed stack omitted VapiToolUrl")?
        .to_owned();
    let transfer_url = outputs
        .get("VapiTransferUrl")
        .context("deployed stack omitted VapiTransferUrl")?
        .to_owned();
    let webhook_reference = outputs
        .get("VapiWebhookReference")
        .context("deployed stack omitted VapiWebhookReference")?
        .to_owned();
    let identity_reference = outputs
        .get("VapiIdentityReference")
        .context("deployed stack omitted VapiIdentityReference")?
        .to_owned();
    journal.stack_outputs = outputs;
    journal.phase = ExecutionPhase::AwsDeployed;
    journal.last_result_category = Some("aws_deployed".into());
    save_journal(bundle, &mut journal)?;

    let webhook = AwsCli.secret_string(
        &inspection.configuration.aws.profile,
        &inspection.configuration.aws.region,
        &webhook_reference,
    )?;
    let resolved = VapiResolvedInputs::new(tool_url, transfer_url, webhook)?;
    let key = vapi_key.context("Vapi key was not available for execution")?;
    let plan = reviewed_vapi_plan.context("Vapi plan was not reviewed")?;
    let state = runtime.block_on(apply_vapi_template(
        &inspection.configuration,
        key.as_str().to_owned(),
        &resolved,
        &plan,
        journal.vapi_template.as_ref(),
    ))?;
    println!("created Vapi template assistant: {}", state.assistant_id);
    let assistant_id = state.assistant_id.clone();
    let organization_id = state.organization_id.clone();
    journal.vapi_template = Some(state);
    journal.phase = ExecutionPhase::VapiTemplateCreated;
    journal.last_result_category = Some("vapi_identity_binding_pending".into());
    save_journal(bundle, &mut journal)?;
    AwsCli.bind_vapi_identity(
        &inspection.configuration.aws.profile,
        &inspection.configuration.aws.region,
        &identity_reference,
        &organization_id,
        &assistant_id,
    )?;
    journal.phase = ExecutionPhase::VapiIdentityBound;
    journal.last_result_category = Some("vapi_identity_bound".into());
    save_journal(bundle, &mut journal)?;
    recipe_admin::doctor(&descriptor, recipe_admin::DeploymentProfile::Starter)?;
    journal.phase = ExecutionPhase::Verified;
    journal.last_result_category = Some("structural_verification_passed".into());
    save_journal(bundle, &mut journal)?;
    Ok(())
}

fn rotate_setup_credential(
    bundle: &std::path::Path,
    execute: bool,
    confirm_assistant_id: Option<&str>,
    vapi_key_stdin: bool,
) -> Result<()> {
    let inspection = inspect_bundle(bundle)?;
    let mut journal = load_journal(bundle, &inspection.manifest)?
        .context("this deployment has no execution journal")?;
    let state = journal
        .vapi_template
        .as_ref()
        .context("this deployment has no recorded Vapi template")?;
    println!(
        "plan: rotate only the Bridgefu webhook credential attached to assistant {}",
        state.assistant_id
    );
    println!("the assistant, prompt, model, voice, tools, and customer data will not be changed");
    if !execute {
        return Ok(());
    }
    anyhow::ensure!(
        confirm_assistant_id == Some(state.assistant_id.as_str()),
        "--confirm-assistant-id must exactly equal the recorded assistant ID"
    );
    let webhook_reference = journal
        .stack_outputs
        .get("VapiWebhookReference")
        .context("deployment journal omitted VapiWebhookReference")?
        .to_owned();
    let key = read_vapi_key(vapi_key_stdin)?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("build credential rotation runtime")?;
    let replacement = runtime.block_on(AwsCli.rotate_webhook_secret(
        &inspection.configuration.aws.profile,
        &inspection.configuration.aws.region,
        &webhook_reference,
    ))?;
    let result = runtime.block_on(rotate_vapi_credential(
        &inspection.configuration,
        key.as_str().to_owned(),
        state,
        replacement.as_str(),
    ));
    if result.is_err() {
        journal.last_result_category = Some("credential_rotation_vapi_pending".into());
        save_journal(bundle, &mut journal)?;
    }
    result?;
    journal.last_result_category = Some("credential_rotation_complete".into());
    save_journal(bundle, &mut journal)?;
    println!("webhook credential rotated and verified");
    Ok(())
}

fn delete_setup_template(
    bundle: &std::path::Path,
    execute: bool,
    confirm_assistant_id: Option<&str>,
    vapi_key_stdin: bool,
) -> Result<()> {
    let inspection = inspect_bundle(bundle)?;
    let mut journal = load_journal(bundle, &inspection.manifest)?
        .context("this deployment has no execution journal")?;
    let state = journal
        .vapi_template
        .as_ref()
        .context("this deployment has no recorded Vapi template")?;
    println!(
        "plan: delete the exact Setup-created Vapi assistant {}, its Bridgefu tool, and credential",
        state.assistant_id
    );
    println!("AWS resources and retained context will not be changed");
    if !execute {
        return Ok(());
    }
    let confirmation = confirm_assistant_id.context("--confirm-assistant-id is required")?;
    anyhow::ensure!(
        confirmation == state.assistant_id,
        "--confirm-assistant-id must exactly equal the recorded assistant ID"
    );
    let key = read_vapi_key(vapi_key_stdin)?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("build Vapi deletion runtime")?;
    runtime.block_on(delete_vapi_template(
        &inspection.configuration,
        key.as_str().to_owned(),
        state,
        confirmation,
    ))?;
    journal.phase = ExecutionPhase::VapiTemplateDeleted;
    journal.last_result_category = Some("vapi_template_deleted".into());
    save_journal(bundle, &mut journal)?;
    println!("owned Vapi template resources deleted");
    Ok(())
}

fn uninstall_setup_bundle(
    bundle: &std::path::Path,
    execute: bool,
    confirm: Option<&str>,
) -> Result<()> {
    let inspection = inspect_bundle(bundle)?;
    let mut journal = load_journal(bundle, &inspection.manifest)?
        .context("this deployment has no execution journal")?;
    println!(
        "plan: remove AWS stack {}",
        inspection.configuration.stack_name
    );
    println!("the generated Vapi template is retained by default so customer customizations are not destroyed");
    println!("DynamoDB and audit retention follow the reviewed production stack policies");
    if !execute {
        return Ok(());
    }
    anyhow::ensure!(
        confirm == Some(inspection.configuration.stack_name.as_str()),
        "--confirm must exactly equal the configured stack name"
    );
    let export = tempfile::tempdir()?;
    export_bundle(bundle, export.path())?;
    let descriptor = export.path().join("aws/deployment-descriptor.yaml");
    let _profile = AwsProfileGuard::set(&inspection.configuration.aws.profile);
    recipe_admin::uninstall_setup_production(
        &descriptor,
        recipe_admin::DeploymentProfile::Starter,
        confirm.context("--confirm is required")?,
    )?;
    journal.phase = ExecutionPhase::AwsRemoved;
    journal.last_result_category = Some("vapi_template_retained_aws_removed".into());
    save_journal(bundle, &mut journal)?;
    Ok(())
}

fn read_vapi_key(from_stdin: bool) -> Result<zeroize::Zeroizing<String>> {
    use std::io::{BufRead, Read};
    let value = if from_stdin {
        let mut value = String::new();
        std::io::stdin().lock().take(4_097).read_line(&mut value)?;
        while matches!(value.chars().last(), Some('\n' | '\r')) {
            value.pop();
        }
        value
    } else {
        rpassword::prompt_password("Vapi private API key (kept in memory only): ")?
    };
    anyhow::ensure!(
        (24..=4096).contains(&value.len()),
        "Vapi API key is invalid"
    );
    Ok(zeroize::Zeroizing::new(value))
}

struct AwsProfileGuard {
    previous: Option<std::ffi::OsString>,
}

impl AwsProfileGuard {
    fn set(profile: &str) -> Self {
        let previous = std::env::var_os("AWS_PROFILE");
        std::env::set_var("AWS_PROFILE", profile);
        Self { previous }
    }
}

impl Drop for AwsProfileGuard {
    fn drop(&mut self) {
        if let Some(value) = &self.previous {
            std::env::set_var("AWS_PROFILE", value);
        } else {
            std::env::remove_var("AWS_PROFILE");
        }
    }
}

fn run_recipe_command(command: RecipeCommand, config_path: &std::path::Path) -> Result<()> {
    match command {
        RecipeCommand::Available { packages }
        | RecipeCommand::List {
            packages,
            configured: false,
        } => {
            let catalog = RecipeCatalog::with_external_paths(&packages)?;
            for package in catalog.iter() {
                let source = match package.source() {
                    RecipeSource::Builtin => "builtin",
                    RecipeSource::External(_) => "external",
                };
                let manifest = package.manifest();
                println!(
                    "{source}:{}@{}\t{}\t{}",
                    manifest.metadata.name,
                    manifest.metadata.version,
                    package.effective_support(),
                    manifest.metadata.title
                );
            }
            Ok(())
        }
        RecipeCommand::List {
            configured: true, ..
        } => {
            let config = config::Config::load(config_path)?;
            for (instance, recipe) in &config.compiled_recipes {
                println!(
                    "{instance}\t{}@{}\t{}\t{}",
                    recipe.name, recipe.version, recipe.support, recipe.fingerprint
                );
            }
            Ok(())
        }
        RecipeCommand::Show { selector, packages } => {
            let catalog = RecipeCatalog::with_external_paths(&packages)?;
            let package = catalog.resolve(&selector)?;
            print!("{}", serde_yaml::to_string(package.manifest())?);
            Ok(())
        }
        RecipeCommand::Validate {
            selector,
            values,
            packages,
        } => {
            let catalog = RecipeCatalog::with_external_paths(&packages)?;
            let package = catalog.resolve(&selector)?;
            let metadata = std::fs::metadata(&values)
                .with_context(|| format!("reading recipe values file {}", values.display()))?;
            anyhow::ensure!(
                metadata.len() <= 256 * 1024,
                "recipe values file exceeds the size limit"
            );
            let raw = std::fs::read_to_string(&values)
                .with_context(|| format!("reading recipe values file {}", values.display()))?;
            let input_values = serde_yaml::from_str(&raw)
                .with_context(|| format!("parsing recipe values file {}", values.display()))?;
            let compiled = package.compile(&input_values)?;
            println!("recipe: {}@{}", compiled.name, compiled.version);
            println!("support: {}", compiled.support);
            println!("bridges: {}", compiled.spec.bridges.len());
            println!("fingerprint: {}", compiled.fingerprint);
            Ok(())
        }
        RecipeCommand::Init {
            selector,
            output,
            packages,
        } => {
            let catalog = RecipeCatalog::with_external_paths(&packages)?;
            let package = catalog.resolve(&selector)?;
            initialize_recipe_directory(&selector, package.manifest(), &output)?;
            println!("initialized {} in {}", selector, output.display());
            if selector == "builtin:vapi-amazon-connect-screen-pop@1" {
                println!(
                    "next: open {}/README.md for the AWS proof, production CloudFormation deployment, and operations path",
                    output.display()
                );
            } else {
                println!("next: edit values.yaml, then run bridgefu recipe validate {selector} --values {}/values.yaml", output.display());
            }
            Ok(())
        }
        RecipeCommand::Explain { instance } => {
            let config = config::Config::load_recipe_view(config_path)?;
            let recipe = config.compiled_recipes.get(&instance).with_context(|| {
                format!(
                    "configured recipe instance {instance:?} was not found in {}",
                    config_path.display()
                )
            })?;
            print!("{}", explain_compiled_recipe(&instance, recipe));
            Ok(())
        }
        RecipeCommand::Deploy {
            deployment,
            profile,
            execute,
            confirm,
            change_set_name,
        } => recipe_admin::deploy(
            &deployment,
            profile,
            execute,
            confirm.as_deref(),
            change_set_name.as_deref(),
        ),
        RecipeCommand::Preflight {
            deployment,
            profile,
        } => recipe_admin::preflight(&deployment, profile),
        RecipeCommand::Status {
            deployment,
            profile,
        } => recipe_admin::status(&deployment, profile),
        RecipeCommand::Doctor {
            deployment,
            profile,
        } => recipe_admin::doctor(&deployment, profile),
        RecipeCommand::Test {
            deployment,
            profile,
        } => recipe_admin::test(&deployment, profile),
        RecipeCommand::Destroy {
            deployment,
            profile,
            confirm,
        } => recipe_admin::destroy(&deployment, profile, &confirm),
    }
}

fn initialize_recipe_directory(
    selector: &str,
    manifest: &bridgefu::recipes::RecipeManifest,
    output: &std::path::Path,
) -> Result<()> {
    anyhow::ensure!(
        !output.exists(),
        "refusing to overwrite existing recipe directory {}",
        output.display()
    );
    std::fs::create_dir_all(output)
        .with_context(|| format!("creating recipe directory {}", output.display()))?;

    let canonical = selector == "builtin:vapi-amazon-connect-screen-pop@1";
    let values = if canonical {
        include_str!("../recipes/vapi-amazon-connect-screen-pop/values.example.yaml").to_owned()
    } else {
        serde_yaml::to_string(&initial_recipe_values(manifest))?
    };
    let selection_values: serde_yaml::Value = serde_yaml::from_str(&values)?;
    std::fs::write(output.join("values.yaml"), &values)
        .with_context(|| format!("writing {}/values.yaml", output.display()))?;

    let selection = serde_yaml::to_string(&serde_yaml::Value::Mapping(
        serde_yaml::Mapping::from_iter([(
            serde_yaml::Value::String("recipes".to_owned()),
            serde_yaml::Value::Mapping(serde_yaml::Mapping::from_iter([(
                serde_yaml::Value::String("support".to_owned()),
                serde_yaml::Value::Mapping(serde_yaml::Mapping::from_iter([
                    (
                        serde_yaml::Value::String("use".to_owned()),
                        serde_yaml::Value::String(selector.to_owned()),
                    ),
                    (
                        serde_yaml::Value::String("with".to_owned()),
                        selection_values,
                    ),
                ])),
            )])),
        )]),
    ))?;
    std::fs::write(output.join("recipe-selection.yaml"), selection)
        .with_context(|| format!("writing {}/recipe-selection.yaml", output.display()))?;

    let mut inputs = format!(
        "# {}\n\nSelector: `{selector}`\n\n| Input | Type | Required | Description |\n|---|---|---:|---|\n",
        manifest.metadata.title
    );
    for (name, definition) in &manifest.inputs {
        let description = definition
            .description
            .as_deref()
            .unwrap_or("")
            .replace('|', "\\|")
            .replace('\n', " ");
        inputs.push_str(&format!(
            "| `{name}` | `{:?}` | {} | {description} |\n",
            definition.kind,
            if definition.required { "yes" } else { "no" }
        ));
    }
    inputs.push_str("\nSecret values belong in env, absolute file, or Secrets Manager references; never write raw credentials here.\n");
    std::fs::write(output.join("INPUTS.md"), inputs)
        .with_context(|| format!("writing {}/INPUTS.md", output.display()))?;

    if canonical {
        std::fs::write(
            output.join("README.md"),
            include_str!("../recipes/vapi-amazon-connect-screen-pop/README.md"),
        )
        .with_context(|| format!("writing {}/README.md", output.display()))?;
        std::fs::write(
            output.join("bridgefu.yaml"),
            include_str!("../config/recipe-vapi-amazon-connect.example.yaml"),
        )
        .with_context(|| format!("writing {}/bridgefu.yaml", output.display()))?;
        std::fs::write(
            output.join("deployment.yaml"),
            include_str!("../recipes/vapi-amazon-connect-screen-pop/deployment.example.yaml"),
        )
        .with_context(|| format!("writing {}/deployment.yaml", output.display()))?;
        std::fs::write(
            output.join("deployment-nonproduction.yaml"),
            include_str!(
                "../recipes/vapi-amazon-connect-screen-pop/deployment.nonproduction.example.yaml"
            ),
        )
        .with_context(|| format!("writing {}/deployment-nonproduction.yaml", output.display()))?;
        std::fs::write(
            output.join("parameters-starter.json"),
            include_str!("../recipes/vapi-amazon-connect-screen-pop/parameters-starter.json"),
        )
        .with_context(|| format!("writing {}/parameters-starter.json", output.display()))?;
        std::fs::write(
            output.join("parameters-nonproduction-starter.json"),
            include_str!(
                "../recipes/vapi-amazon-connect-screen-pop/parameters-nonproduction-starter.json"
            ),
        )
        .with_context(|| {
            format!(
                "writing {}/parameters-nonproduction-starter.json",
                output.display()
            )
        })?;
        std::fs::write(
            output.join("parameters-ha.json"),
            include_str!("../recipes/vapi-amazon-connect-screen-pop/parameters-ha.json"),
        )
        .with_context(|| format!("writing {}/parameters-ha.json", output.display()))?;
        let cloudformation = output.join("cloudformation");
        std::fs::create_dir(&cloudformation)
            .with_context(|| format!("creating {}/cloudformation", output.display()))?;
        std::fs::write(
            cloudformation.join("production-stack-policy.json"),
            include_str!(
                "../recipes/vapi-amazon-connect-screen-pop/cloudformation/production-stack-policy.json"
            ),
        )
        .with_context(|| {
            format!(
                "writing {}/cloudformation/production-stack-policy.json",
                output.display()
            )
        })?;
    }
    Ok(())
}

fn initial_recipe_values(
    manifest: &bridgefu::recipes::RecipeManifest,
) -> std::collections::BTreeMap<String, serde_yaml::Value> {
    manifest
        .inputs
        .iter()
        .filter_map(|(name, definition)| {
            definition
                .default
                .clone()
                .or_else(|| definition.required.then_some(serde_yaml::Value::Null))
                .map(|value| (name.clone(), value))
        })
        .collect()
}

fn explain_compiled_recipe(instance: &str, recipe: &CompiledRecipe) -> String {
    use std::fmt::Write as _;

    let mut output = String::new();
    let _ = writeln!(output, "instance: {instance}");
    let _ = writeln!(output, "recipe: {}@{}", recipe.name, recipe.version);
    let _ = writeln!(output, "support: {}", recipe.support);
    let _ = writeln!(output, "fingerprint: {}", recipe.fingerprint);
    for (bridge_id, bridge) in &recipe.spec.bridges {
        let _ = writeln!(output, "bridge: {bridge_id}");
        let _ = writeln!(
            output,
            "  source: {}",
            explain_recipe_endpoint(&bridge.source, true)
        );
        let _ = writeln!(
            output,
            "  destination: {}",
            explain_recipe_endpoint(&bridge.destination, false)
        );
        if let Some(context) = &bridge.context {
            let correlation = &context.correlation;
            let _ = writeln!(
                output,
                "  context: {} -> Amazon attribute {} ({}, required={})",
                correlation.from_sip_header,
                correlation.to_amazon_attribute,
                correlation.format,
                correlation.required
            );
        } else {
            let _ = writeln!(output, "  context: none");
        }
    }
    output.push_str("secrets: redacted; recipe fingerprints never contain secret values\n");
    output
        .push_str("projection conflicts: none; run bridgefu validate for full runtime preflight\n");
    output
}

fn explain_recipe_endpoint(endpoint: &RecipeEndpointSpec, source: bool) -> String {
    match endpoint {
        RecipeEndpointSpec::Sip {
            security,
            admission,
            target_uri,
            ..
        } => {
            let posture = match security {
                SipSecurity::SipsSrtp => "SIPS/SRTP; TCP 5061; UDP 16384-32767",
                SipSecurity::SipRtp => "SIP/RTP; TCP+UDP 5060; UDP 16384-32767",
            };
            if source {
                let admission =
                    admission
                        .as_ref()
                        .map_or("missing", |admission| match admission.mode {
                            SipAdmissionMode::ManagedAttachment => "managed one-use attachment",
                            SipAdmissionMode::StableUri => "stable URI",
                        });
                format!("SIP ({posture}); admission={admission}")
            } else {
                format!(
                    "SIP ({posture}); target_uri={}",
                    if target_uri.is_some() {
                        "configured (redacted)"
                    } else {
                        "missing"
                    }
                )
            }
        }
        RecipeEndpointSpec::Webrtc { signaling_uri, .. } => format!(
            "WebRTC; signaling={}",
            if signaling_uri.is_some() {
                "configured (redacted)"
            } else {
                "runtime-managed"
            }
        ),
        RecipeEndpointSpec::AmazonConnect { media, .. } => {
            let media = match media {
                AmazonConnectMedia::Webrtc => "WebRTC",
            };
            format!("Amazon Connect {media}; instance and flow configured (redacted)")
        }
    }
}

async fn run(args: Args) -> Result<()> {
    let cfg = config::Config::load(&args.config)?;
    // Role prerequisites are checked before tracing, metrics, or any
    // listener/task is installed. Unsupported topologies never fall back to
    // the all-in-one compatibility process.
    process_role::preflight(&cfg)?;

    let tracing_guard = observability::init_tracing(&cfg.observability)?;
    let process_result = async {
        let prom = observability::install_metrics()?;
        tracing::info!(
            config = %args.config.display(),
            runtime_mode = %cfg.runtime.mode,
            "starting bridgefu process"
        );
        match process_runner(cfg.runtime.mode) {
            ProcessRunner::AllInOne => run_all_in_one(&cfg, &args.config, prom).await,
            ProcessRunner::Gateway => {
                process_role::run_gateway(&cfg, prom, shutdown_signal()).await
            }
            ProcessRunner::Worker => process_role::run_worker(&cfg, prom, shutdown_signal()).await,
            ProcessRunner::MoqRelay => {
                moq_relay_role::run_moq_relay(&cfg, prom, shutdown_signal()).await
            }
        }
    }
    .await;
    let tracing_shutdown = tracing_guard.shutdown();
    match (process_result, tracing_shutdown) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(process), Ok(())) => Err(process),
        (Ok(()), Err(shutdown)) => Err(shutdown),
        (Err(process), Err(shutdown)) => {
            Err(process.context(format!("OTLP trace shutdown also failed: {shutdown:#}")))
        }
    }
}

fn probe_liveness(address: SocketAddr, path: &str, timeout: Duration) -> Result<()> {
    use std::io::{BufRead, BufReader, Read, Write};
    use std::net::TcpStream;

    anyhow::ensure!(!timeout.is_zero(), "healthcheck timeout must be non-zero");
    anyhow::ensure!(
        path.starts_with('/')
            && path.len() <= 2_048
            && path.is_ascii()
            && !path.bytes().any(|byte| byte <= b' ' || byte == 0x7f),
        "healthcheck path must be a safe absolute ASCII HTTP path"
    );

    let mut stream = TcpStream::connect_timeout(&address, timeout)
        .with_context(|| format!("connecting to Bridgefu liveness endpoint at {address}"))?;
    stream
        .set_read_timeout(Some(timeout))
        .context("setting healthcheck read timeout")?;
    stream
        .set_write_timeout(Some(timeout))
        .context("setting healthcheck write timeout")?;
    write!(
        stream,
        "GET {path} HTTP/1.1\r\nHost: {address}\r\nConnection: close\r\n\r\n"
    )
    .context("sending Bridgefu liveness request")?;
    stream
        .flush()
        .context("flushing Bridgefu liveness request")?;

    let mut status_line = String::new();
    BufReader::new(stream)
        .take(1_025)
        .read_line(&mut status_line)
        .context("reading Bridgefu liveness response")?;
    anyhow::ensure!(
        status_line.ends_with('\n') && status_line.len() <= 1_024,
        "Bridgefu liveness endpoint returned an invalid HTTP status line"
    );
    let mut fields = status_line.split_whitespace();
    let protocol = fields.next().unwrap_or_default();
    anyhow::ensure!(
        matches!(protocol, "HTTP/1.0" | "HTTP/1.1"),
        "Bridgefu liveness endpoint returned an invalid HTTP status line"
    );
    let status = fields
        .next()
        .context("Bridgefu liveness response omitted its status code")?
        .parse::<u16>()
        .context("Bridgefu liveness response contained an invalid status code")?;
    anyhow::ensure!(
        (200..300).contains(&status),
        "Bridgefu liveness endpoint returned HTTP {status}"
    );
    Ok(())
}

/// Existing ReferenceTenant-compatible single-process lifecycle. This remains
/// the default and deliberately retains the original listener construction,
/// call-runtime sharing, and shutdown ordering.
async fn run_all_in_one(
    cfg: &config::Config,
    config_path: &std::path::Path,
    prom: PrometheusHandle,
) -> Result<()> {
    if !cfg.legacy_vapi_connect_enabled() {
        return run_recipe_all_in_one(cfg, config_path, prom).await;
    }
    let tenants = cfg.tenant_names()?;
    tracing::info!(
        config = %config_path.display(),
        region = %cfg.aws.region,
        tenants = ?tenants,
        "starting bridgefu"
    );

    let http_bind: SocketAddr = cfg.observability.http_bind.parse().with_context(|| {
        format!(
            "invalid observability.http_bind: {}",
            cfg.observability.http_bind
        )
    })?;

    // Build the gateway from config (resolves AWS creds + any `auto` IPs).
    let server_cfg = cfg.build_server_config().await?;
    let server = ConnectScreenPopServer::build(server_cfg)
        .await
        .map_err(|e| anyhow::anyhow!("building gateway: {e}"))?;
    // Subscribe before `serve()` can emit the first INVITE lifecycle event.
    // The broadcast channel intentionally has no replay buffer for late
    // subscribers.
    let lifecycle_events = server.subscribe_lifecycle();
    // The lifecycle and metrics loops remain live through the complete legacy
    // server drain. They are stopped and joined only after the final teardown
    // evidence and route counters have been emitted.
    let (owned_task_shutdown_tx, _) = tokio::sync::watch::channel(false);

    // Construct the durable authority before any generic signaling listener.
    // HTTP, SIP, and WebRTC must share this exact repository, worker fence,
    // validator, and cryptographic policy.
    let mut api_state =
        api::ApiState::from_config(cfg, server.clone(), prom, tenants.clone(), None).await?;
    let call_runtime_owner = api_state.call_runtime();
    let amazon_cleanup =
        bridgefu::amazon_cleanup::AmazonCleanupJournal::connect(cfg.call_repository_backend()?)
            .await
            .context("opening durable Amazon cleanup journal")?;
    let cleanup_observer: Arc<dyn rvoip_amazon_connect::AmazonConnectCleanupObserver> =
        amazon_cleanup.clone();
    server
        .adapter()
        .install_cleanup_observer(cleanup_observer)
        .map_err(|error| anyhow::anyhow!("installing Amazon cleanup journal: {error}"))?;
    let cleanup_reconcile = amazon_cleanup
        .reconcile(server.adapter())
        .await
        .context("reconciling retained Amazon cleanup authority")?;
    metrics::gauge!("bridgefu_amazon_durable_cleanups_pending")
        .set(cleanup_reconcile.remaining as f64);
    tracing::info!(
        attempted = cleanup_reconcile.attempted,
        resolved = cleanup_reconcile.resolved,
        remaining = cleanup_reconcile.remaining,
        "initial Amazon cleanup reconciliation completed"
    );
    let generic_runtime = if cfg.generic_bridge.enabled {
        let call_runtime = call_runtime_owner.as_ref().map(Arc::clone).ok_or_else(|| {
            anyhow::anyhow!("generic_bridge requires the authenticated transactional call runtime")
        })?;
        let bearer_validator = api_state.bearer_validator().ok_or_else(|| {
            anyhow::anyhow!("generic_bridge requires the shared API bearer validator")
        })?;
        let webrtc_bearer_validator =
            api_state
                .webrtc_signaling_bearer_validator()
                .ok_or_else(|| {
                    anyhow::anyhow!(
                        "generic_bridge requires the attachment-bound WebRTC bearer validator"
                    )
                })?;
        let webrtc_session_binding = api_state.webrtc_session_binding().ok_or_else(|| {
            anyhow::anyhow!("generic_bridge requires the WebRTC attachment binding authority")
        })?;
        let sip_tenant = cfg
            .api
            .static_tenant
            .as_deref()
            .or_else(|| (tenants.len() == 1).then(|| tenants[0].as_str()))
            .ok_or_else(|| {
                anyhow::anyhow!("generic_bridge requires one explicit signaling tenant")
            })?;
        let sip_listener_auth = cfg
            .sip_listener_auth_policy(sip_tenant, Arc::clone(&bearer_validator), "sip:connect")
            .context("configuring all-in-one SIP listener authentication")?;
        let generic_sip_bind = cfg
            .generic_bridge
            .sip_bind
            .parse::<SocketAddr>()
            .context("parsing generic_bridge.sip_bind")?;
        let sip_stack = cfg
            .generic_sip_stack_config("bridgefu-generic", generic_sip_bind)
            .context("configuring generic SIP/RTP networking")?;
        let sip_egress_profiles = cfg
            .sip_egress_profile_configs("bridgefu-generic", generic_sip_bind)
            .context("configuring isolated named SIP egress profiles")?;
        let outbound_profiles = cfg
            .outbound_profile_resolver()
            .context("configuring named outbound signaling profiles")?;
        let provider_executor: Arc<dyn bridgefu::call_service::ProviderLegExecutor> =
            Arc::new(api_state.provider_registry());
        // The legacy ReferenceTenant server keeps exclusive ownership of its
        // adapter event receiver and routes. Generic execution gets a fresh
        // adapter whose immutable profile catalog includes every projected
        // named/recipe Amazon destination; the legacy server exposes only its
        // default profile and therefore cannot be forked for recipe calls.
        let generic_amazon_connect = cfg
            .build_worker_amazon_connect_adapter()
            .await
            .context("building generic Amazon Connect profile catalog")?;
        let cleanup_observer: Arc<dyn rvoip_amazon_connect::AmazonConnectCleanupObserver> =
            amazon_cleanup.clone();
        generic_amazon_connect
            .install_cleanup_observer(cleanup_observer)
            .map_err(|error| {
                anyhow::anyhow!("installing generic Amazon cleanup journal: {error}")
            })?;
        let reference_tenant_canary = cfg.reference_tenant_canary_policy()?;
        let recipe_sip_admissions = cfg.recipe_sip_admission_catalog()?;
        let signaling_tls = cfg.api.tls.as_ref().map(|tls| runtime::GenericBridgeTls {
            certificate_chain: &tls.certificate_chain,
            private_key: &tls.private_key,
        });
        let runtime = runtime::GenericBridgeRuntime::start(runtime::GenericBridgeStart {
            config: &cfg.generic_bridge,
            runtime: &cfg.runtime,
            call_runtime,
            sip_stack,
            sip_egress_profiles,
            sip_listener_auth,
            webrtc_bearer_validator,
            webrtc_session_binding,
            context_policy: &cfg.context,
            reference_tenant_canary,
            recipe_sip_admissions,
            provider_executor,
            outbound_profiles,
            amazon_connect: generic_amazon_connect,
            signaling_tls,
        })
        .await?;
        if let Err(error) = api_state.set_generic_runtime(Arc::clone(&runtime)).await {
            runtime
                .shutdown(Duration::from_secs(cfg.runtime.drain_timeout_secs.max(1)))
                .await;
            return Err(error).context("publishing concrete all-in-one worker capabilities");
        }
        Some(runtime)
    } else {
        None
    };
    let public_uctp_listener_result: anyhow::Result<_> = async {
        match &cfg.broadcast.uctp_listener {
            Some(listener_config) => {
                let runtime = generic_runtime.as_ref().ok_or_else(|| {
                    anyhow::anyhow!(
                        "broadcast.uctp_listener requires the generic media Orchestrator"
                    )
                })?;
                let listener = bridgefu::broadcast::PublicUctpBroadcastListener::bind(
                    runtime.orchestrator(),
                    api_state.broadcast_token_service(),
                    listener_config.runtime()?,
                )
                .await
                .context("starting authenticated public UCTP broadcast listener")?;
                tracing::info!(
                    local_addr = %listener.local_addr(),
                    advertised_endpoint = cfg.broadcast.public_endpoint.as_deref().unwrap_or(""),
                    "authenticated public UCTP broadcast listener started"
                );
                Ok(Some(listener))
            }
            None => Ok(None),
        }
    }
    .await;
    let public_uctp_listener = match public_uctp_listener_result {
        Ok(listener) => listener,
        Err(error) => {
            if let Some(runtime) = &generic_runtime {
                runtime
                    .shutdown(std::time::Duration::from_secs(
                        cfg.runtime.drain_timeout_secs,
                    ))
                    .await;
            }
            return Err(error);
        }
    };
    // Start owned observers only after every fallible listener/runtime
    // construction above has succeeded. A startup error therefore cannot
    // strand detached metrics or cleanup tasks.
    let mut metrics_task = observability::spawn_metrics_updater(
        server.clone(),
        tenants.clone(),
        owned_task_shutdown_tx.subscribe(),
    );
    let mut cleanup_reconciler = amazon_cleanup.spawn_reconciler(
        server.adapter().clone(),
        owned_task_shutdown_tx.subscribe(),
        std::time::Duration::from_secs(30),
    );
    let (http_shutdown_tx, _) = tokio::sync::watch::channel(false);
    let mut lifecycle_task = screen_pop_evidence::spawn_lifecycle_ingest(
        lifecycle_events,
        api_state.screen_pop_evidence_store(),
        owned_task_shutdown_tx.subscribe(),
    );
    let api_shutdown_owner = api_state.clone();
    let app = api::router(api_state);

    // Control/health/metrics HTTP server, shut down on the same signal as the gateway.
    let mut http = tokio::spawn(api::serve(
        http_bind,
        app,
        wait_for_shutdown(http_shutdown_tx.subscribe()),
    ));

    // Retain the outer accept-loop owner. Dropping the `serve` future on a
    // process signal used to bypass the server's owned drain protocol.
    let mut legacy_serve = tokio::spawn(server.clone().serve());
    tokio::select! {
        res = &mut legacy_serve => {
            match res {
                Ok(Ok(())) => tracing::info!("gateway serve loop ended"),
                Ok(Err(error)) => tracing::error!(%error, "gateway serve loop ended with error"),
                Err(error) => tracing::error!(%error, "gateway serve task failed"),
            }
        }
        _ = shutdown_signal() => {
            tracing::info!("shutdown signal received; draining gateway");
        }
    }

    let shutdown_deadline = tokio::time::Instant::now()
        + std::time::Duration::from_secs(cfg.runtime.drain_timeout_secs);
    // Close public admission together. HTTP stops accepting mutations now,
    // while lifecycle/metrics consumers intentionally remain alive until the
    // legacy server has completed its exact teardown protocol.
    let _ = http_shutdown_tx.send(true);
    server.begin_drain();
    if let Some(listener) = &public_uctp_listener {
        listener.begin_drain();
    }

    let legacy_report = server
        .drain_until(
            std::time::Instant::now()
                .checked_add(shutdown_budget(shutdown_deadline))
                .unwrap_or_else(std::time::Instant::now),
        )
        .await;
    tracing::info!(
        attempted_tasks = legacy_report.attempted_tasks,
        joined_tasks = legacy_report.joined_tasks,
        failed_tasks = legacy_report.failed_tasks,
        detached_tasks = legacy_report.detached_tasks,
        remaining_setups = legacy_report.remaining_setups,
        remaining_active = legacy_report.remaining_active,
        remaining_connect_routes = legacy_report.remaining_connect_routes,
        pending_contact_cleanups = legacy_report.adapter.pending_contact_cleanups,
        serve_stopped = legacy_report.serve_stopped,
        coordinator_stopped = legacy_report.coordinator_stopped,
        "legacy screen-pop server drain completed"
    );
    metrics::gauge!("bridgefu_legacy_drain_incomplete").set(if legacy_report.is_complete() {
        0.0
    } else {
        1.0
    });
    metrics::gauge!("bridgefu_amazon_pending_contact_cleanups")
        .set(legacy_report.adapter.pending_contact_cleanups as f64);
    if !legacy_report.is_complete() {
        tracing::error!(
            detached_tasks = legacy_report.detached_tasks,
            remaining_setups = legacy_report.remaining_setups,
            remaining_active = legacy_report.remaining_active,
            remaining_connect_routes = legacy_report.remaining_connect_routes,
            pending_contact_cleanups = legacy_report.adapter.pending_contact_cleanups,
            "legacy screen-pop shutdown retained unfinished cleanup authority"
        );
    }
    if !legacy_serve.is_finished()
        && tokio::time::timeout(shutdown_budget(shutdown_deadline), &mut legacy_serve)
            .await
            .is_err()
    {
        // This is a bounded fallback only after `drain_until` has transferred
        // ambiguous contact cleanup to retained owners and stopped the SIP
        // coordinator. It is never the primary shutdown mechanism.
        tracing::error!("legacy serve owner remained live after completed drain; aborting task");
        legacy_serve.abort();
        let _ = legacy_serve.await;
    }

    let _ = owned_task_shutdown_tx.send(true);
    // The lifecycle consumer must stop before its store and API state are
    // dropped. Abort only as a bounded fallback for a runtime bug.
    if tokio::time::timeout(
        shutdown_budget(shutdown_deadline).min(std::time::Duration::from_secs(3)),
        &mut lifecycle_task,
    )
    .await
    .is_err()
    {
        tracing::warn!("screen-pop lifecycle consumer did not stop; aborting task");
        lifecycle_task.abort();
        let _ = lifecycle_task.await;
    }
    if tokio::time::timeout(
        shutdown_budget(shutdown_deadline).min(std::time::Duration::from_secs(3)),
        &mut metrics_task,
    )
    .await
    .is_err()
    {
        tracing::warn!("metrics updater did not stop; aborting task");
        metrics_task.abort();
        let _ = metrics_task.await;
    }
    if tokio::time::timeout(
        shutdown_budget(shutdown_deadline).min(std::time::Duration::from_secs(3)),
        &mut cleanup_reconciler,
    )
    .await
    .is_err()
    {
        tracing::warn!("Amazon cleanup reconciler did not stop; aborting task");
        cleanup_reconciler.abort();
        let _ = cleanup_reconciler.await;
    }

    // Give the HTTP server a moment to drain from the shared shutdown signal.
    if tokio::time::timeout(
        shutdown_budget(shutdown_deadline).min(std::time::Duration::from_secs(3)),
        &mut http,
    )
    .await
    .is_err()
    {
        tracing::warn!("HTTP API did not drain; aborting task");
        http.abort();
        let _ = http.await;
    }
    let closed_broadcasts = api_shutdown_owner.shutdown_local_broadcasts().await;
    tracing::info!(closed_broadcasts, "local broadcasts drained");
    // Release the retained API clone before CallServiceRuntime::try_unwrap.
    drop(api_shutdown_owner);
    if let Some(listener) = public_uctp_listener {
        if tokio::time::timeout(shutdown_budget(shutdown_deadline), listener.shutdown())
            .await
            .is_err()
        {
            tracing::warn!("public UCTP listener exceeded the shutdown deadline");
        }
    }
    if let Some(runtime) = generic_runtime {
        runtime.shutdown(shutdown_budget(shutdown_deadline)).await;
    }
    shutdown_call_runtime(call_runtime_owner, shutdown_deadline).await?;
    tracing::info!("bridgefu stopped");
    Ok(())
}

/// Recipe-only single-process lifecycle. The durable call service and generic
/// rvoip adapters remain identical to expert mode, but no legacy
/// `ConnectScreenPopServer` or clear ReferenceTenant listener is constructed.
async fn run_recipe_all_in_one(
    cfg: &config::Config,
    config_path: &std::path::Path,
    prom: PrometheusHandle,
) -> Result<()> {
    anyhow::ensure!(
        !cfg.compiled_recipes.is_empty(),
        "legacy_vapi_connect is disabled but no compiled recipe is configured"
    );
    anyhow::ensure!(
        cfg.generic_bridge.enabled,
        "recipe-only all-in-one mode requires the generic bridge runtime"
    );
    let tenants = cfg.tenant_names()?;
    tracing::info!(
        config = %config_path.display(),
        region = %cfg.aws.region,
        tenants = ?tenants,
        recipe_instances = cfg.compiled_recipes.len(),
        "starting recipe-only bridgefu"
    );
    let http_bind: SocketAddr = cfg.observability.http_bind.parse().with_context(|| {
        format!(
            "invalid observability.http_bind: {}",
            cfg.observability.http_bind
        )
    })?;
    let (owned_task_shutdown_tx, _) = tokio::sync::watch::channel(false);
    let mut api_state = api::ApiState::from_recipe_config(cfg, prom, tenants.clone()).await?;
    let call_runtime_owner = api_state.call_runtime();
    let call_runtime = call_runtime_owner.as_ref().map(Arc::clone).ok_or_else(|| {
        anyhow::anyhow!("recipe-only runtime requires the authenticated call service")
    })?;
    let bearer_validator = api_state.bearer_validator().ok_or_else(|| {
        anyhow::anyhow!("recipe-only runtime requires the shared API bearer validator")
    })?;
    let webrtc_bearer_validator =
        api_state
            .webrtc_signaling_bearer_validator()
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "recipe-only runtime requires the attachment-bound WebRTC bearer validator"
                )
            })?;
    let webrtc_session_binding = api_state.webrtc_session_binding().ok_or_else(|| {
        anyhow::anyhow!("recipe-only runtime requires WebRTC attachment binding authority")
    })?;
    let sip_tenant = cfg
        .api
        .static_tenant
        .as_deref()
        .or_else(|| (tenants.len() == 1).then(|| tenants[0].as_str()))
        .ok_or_else(|| anyhow::anyhow!("recipe-only runtime requires one SIP listener tenant"))?;
    let sip_listener_auth = cfg
        .sip_listener_auth_policy(sip_tenant, bearer_validator, "sip:connect")
        .context("configuring recipe SIP listener authentication")?;
    let generic_sip_bind = cfg
        .generic_bridge
        .sip_bind
        .parse::<SocketAddr>()
        .context("parsing generic_bridge.sip_bind")?;
    let sip_stack = cfg
        .generic_sip_stack_config("bridgefu-recipe", generic_sip_bind)
        .context("configuring recipe SIP/SRTP networking")?;
    let sip_egress_profiles = cfg
        .sip_egress_profile_configs("bridgefu-recipe", generic_sip_bind)
        .context("configuring recipe SIP egress profiles")?;
    let outbound_profiles = cfg
        .outbound_profile_resolver()
        .context("configuring recipe outbound profiles")?;
    let provider_executor: Arc<dyn bridgefu::call_service::ProviderLegExecutor> =
        Arc::new(api_state.provider_registry());
    let amazon_connect = cfg
        .build_worker_amazon_connect_adapter()
        .await
        .context("building recipe Amazon Connect adapter")?;
    let amazon_cleanup =
        bridgefu::amazon_cleanup::AmazonCleanupJournal::connect(cfg.call_repository_backend()?)
            .await
            .context("opening durable Amazon cleanup journal")?;
    let cleanup_observer: Arc<dyn rvoip_amazon_connect::AmazonConnectCleanupObserver> =
        amazon_cleanup.clone();
    amazon_connect
        .install_cleanup_observer(cleanup_observer)
        .map_err(|error| anyhow::anyhow!("installing Amazon cleanup journal: {error}"))?;
    let cleanup_reconcile = amazon_cleanup
        .reconcile(&amazon_connect)
        .await
        .context("reconciling retained Amazon cleanup authority")?;
    metrics::gauge!("bridgefu_amazon_durable_cleanups_pending")
        .set(cleanup_reconcile.remaining as f64);
    let signaling_tls = cfg.api.tls.as_ref().map(|tls| runtime::GenericBridgeTls {
        certificate_chain: &tls.certificate_chain,
        private_key: &tls.private_key,
    });
    let recipe_sip_admissions = cfg.recipe_sip_admission_catalog()?;
    let generic_runtime = runtime::GenericBridgeRuntime::start(runtime::GenericBridgeStart {
        config: &cfg.generic_bridge,
        runtime: &cfg.runtime,
        call_runtime,
        sip_stack,
        sip_egress_profiles,
        sip_listener_auth,
        webrtc_bearer_validator,
        webrtc_session_binding,
        context_policy: &cfg.context,
        reference_tenant_canary: None,
        recipe_sip_admissions,
        provider_executor,
        outbound_profiles,
        amazon_connect: Arc::clone(&amazon_connect),
        signaling_tls,
    })
    .await?;
    if let Err(error) = api_state
        .set_generic_runtime(Arc::clone(&generic_runtime))
        .await
    {
        generic_runtime
            .shutdown(Duration::from_secs(cfg.runtime.drain_timeout_secs.max(1)))
            .await;
        return Err(error).context("publishing recipe worker capabilities");
    }

    let public_uctp_listener = match &cfg.broadcast.uctp_listener {
        Some(listener_config) => Some(
            bridgefu::broadcast::PublicUctpBroadcastListener::bind(
                generic_runtime.orchestrator(),
                api_state.broadcast_token_service(),
                listener_config.runtime()?,
            )
            .await
            .context("starting authenticated public UCTP broadcast listener")?,
        ),
        None => None,
    };
    let mut cleanup_reconciler = amazon_cleanup.spawn_reconciler(
        Arc::clone(&amazon_connect),
        owned_task_shutdown_tx.subscribe(),
        Duration::from_secs(30),
    );
    let (http_shutdown_tx, _) = tokio::sync::watch::channel(false);
    let api_shutdown_owner = api_state.clone();
    let app = api::router(api_state);
    let mut http = tokio::spawn(api::serve(
        http_bind,
        app,
        wait_for_shutdown(http_shutdown_tx.subscribe()),
    ));

    tokio::select! {
        result = &mut http => {
            match result {
                Ok(Ok(())) => tracing::warn!("recipe HTTP server stopped before shutdown"),
                Ok(Err(error)) => tracing::error!(%error, "recipe HTTP server failed"),
                Err(error) => tracing::error!(%error, "recipe HTTP task failed"),
            }
        }
        _ = shutdown_signal() => {
            tracing::info!("shutdown signal received; draining recipe runtime");
        }
    }

    let shutdown_deadline =
        tokio::time::Instant::now() + Duration::from_secs(cfg.runtime.drain_timeout_secs);
    let _ = http_shutdown_tx.send(true);
    if let Some(listener) = &public_uctp_listener {
        listener.begin_drain();
    }
    let closed_broadcasts = api_shutdown_owner.shutdown_local_broadcasts().await;
    tracing::info!(closed_broadcasts, "local broadcasts drained");
    if let Some(listener) = public_uctp_listener {
        if tokio::time::timeout(shutdown_budget(shutdown_deadline), listener.shutdown())
            .await
            .is_err()
        {
            tracing::warn!("public UCTP listener exceeded the shutdown deadline");
        }
    }
    generic_runtime
        .shutdown(shutdown_budget(shutdown_deadline))
        .await;
    let _ = owned_task_shutdown_tx.send(true);
    if tokio::time::timeout(
        shutdown_budget(shutdown_deadline).min(Duration::from_secs(3)),
        &mut cleanup_reconciler,
    )
    .await
    .is_err()
    {
        tracing::warn!("Amazon cleanup reconciler did not stop; aborting task");
        cleanup_reconciler.abort();
        let _ = cleanup_reconciler.await;
    }
    if !http.is_finished()
        && tokio::time::timeout(
            shutdown_budget(shutdown_deadline).min(Duration::from_secs(3)),
            &mut http,
        )
        .await
        .is_err()
    {
        tracing::warn!("HTTP API did not drain; aborting task");
        http.abort();
        let _ = http.await;
    }
    drop(api_shutdown_owner);
    drop(amazon_connect);
    shutdown_call_runtime(call_runtime_owner, shutdown_deadline).await?;
    tracing::info!("recipe-only bridgefu stopped");
    Ok(())
}

async fn shutdown_call_runtime(
    runtime: Option<Arc<bridgefu::call_service::CallServiceRuntime>>,
    deadline: tokio::time::Instant,
) -> Result<()> {
    let Some(runtime) = runtime else {
        return Ok(());
    };
    let strong_count = Arc::strong_count(&runtime);
    let runtime = Arc::try_unwrap(runtime).map_err(|_| {
        anyhow::anyhow!(
            "call-service runtime still has {strong_count} owners after HTTP and media drain"
        )
    })?;
    runtime
        .shutdown(shutdown_budget(deadline))
        .await
        .context("shutting down durable call-service worker")
}

fn shutdown_budget(deadline: tokio::time::Instant) -> std::time::Duration {
    deadline.saturating_duration_since(tokio::time::Instant::now())
}

async fn wait_for_shutdown(mut shutdown: tokio::sync::watch::Receiver<bool>) {
    if *shutdown.borrow() {
        return;
    }
    while shutdown.changed().await.is_ok() {
        if *shutdown.borrow() {
            return;
        }
    }
}

/// Resolves when the process receives SIGINT (Ctrl-C) or SIGTERM (systemd/Docker stop).
async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };

    #[cfg(unix)]
    let term = async {
        use tokio::signal::unix::{signal, SignalKind};
        match signal(SignalKind::terminate()) {
            Ok(mut s) => {
                s.recv().await;
            }
            Err(_) => std::future::pending::<()>().await,
        }
    };
    #[cfg(not(unix))]
    let term = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {}
        _ = term => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;
    use std::io::{BufRead, BufReader, Write};
    use std::net::TcpListener;
    use std::thread;

    use bridgefu::call_engine::WorkerId;
    use bridgefu::call_service::{
        build_call_service_runtime, CallRepositoryBackendConfig, CallServiceCoordinationConfig,
        CallServiceRuntimeConfig, CallTimeoutPolicy, SamePrincipalAttachmentResolver,
        SystemCallServiceClock,
    };
    use bridgefu::coordination::DeploymentId;

    #[test]
    fn gateway_mode_dispatches_to_the_gateway_runner_without_fallback() {
        assert_eq!(
            process_runner(RuntimeMode::AllInOne),
            ProcessRunner::AllInOne
        );
        assert_eq!(process_runner(RuntimeMode::Gateway), ProcessRunner::Gateway);
        assert_ne!(
            process_runner(RuntimeMode::Gateway),
            ProcessRunner::AllInOne
        );
        assert_eq!(process_runner(RuntimeMode::Worker), ProcessRunner::Worker);
        assert_eq!(
            process_runner(RuntimeMode::MoqRelay),
            ProcessRunner::MoqRelay
        );
    }

    fn spawn_liveness_endpoint(status: &'static str) -> (SocketAddr, thread::JoinHandle<String>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let (mut connection, _) = listener.accept().unwrap();
            connection
                .set_read_timeout(Some(Duration::from_secs(10)))
                .unwrap();
            let mut request_line = String::new();
            let mut reader = BufReader::new(&mut connection);
            reader.read_line(&mut request_line).unwrap();
            loop {
                let mut header = String::new();
                reader.read_line(&mut header).unwrap();
                if header == "\r\n" || header.is_empty() {
                    break;
                }
            }
            drop(reader);
            write!(
                connection,
                "HTTP/1.1 {status}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
            )
            .unwrap();
            request_line
        });
        (address, server)
    }

    #[test]
    fn native_healthcheck_accepts_a_live_endpoint() {
        let (address, server) = spawn_liveness_endpoint("200 OK");
        probe_liveness(address, "/livez", Duration::from_secs(10)).unwrap();
        assert_eq!(server.join().unwrap(), "GET /livez HTTP/1.1\r\n");
    }

    #[test]
    fn native_healthcheck_rejects_an_unhealthy_endpoint() {
        let (address, server) = spawn_liveness_endpoint("503 Service Unavailable");
        let error = probe_liveness(address, "/livez", Duration::from_secs(10)).unwrap_err();
        assert!(
            error.to_string().contains("returned HTTP 503"),
            "unexpected healthcheck error: {error:#}"
        );
        assert_eq!(server.join().unwrap(), "GET /livez HTTP/1.1\r\n");
    }

    #[test]
    fn native_healthcheck_rejects_unsafe_inputs_before_connecting() {
        let address = "127.0.0.1:9".parse().unwrap();
        for path in ["livez", "/livez\r\nInjected: true", "/bad path"] {
            let error = probe_liveness(address, path, Duration::from_secs(1)).unwrap_err();
            assert!(error.to_string().contains("safe absolute ASCII HTTP path"));
        }
        let error = probe_liveness(address, "/livez", Duration::ZERO).unwrap_err();
        assert!(error.to_string().contains("timeout must be non-zero"));
    }

    #[test]
    fn healthcheck_cli_defaults_do_not_require_a_config_path() {
        let args = Args::try_parse_from(["bridgefu", "healthcheck"]).unwrap();
        let Some(Command::Healthcheck {
            address,
            path,
            timeout_ms,
        }) = args.command
        else {
            panic!("healthcheck command was not parsed");
        };
        assert_eq!(address, "127.0.0.1:9090".parse::<SocketAddr>().unwrap());
        assert_eq!(path, "/livez");
        assert_eq!(timeout_ms, 2_500);
    }

    #[test]
    fn recipe_cli_exposes_safe_administrator_commands() {
        let available = Args::try_parse_from(["bridgefu", "recipe", "available"]).unwrap();
        assert!(matches!(
            available.command,
            Some(Command::Recipe {
                command: RecipeCommand::Available { .. }
            })
        ));

        let init = Args::try_parse_from([
            "bridgefu",
            "recipe",
            "init",
            "builtin:vapi-amazon-connect-screen-pop@1",
            "--output",
            "starter",
        ])
        .unwrap();
        assert!(matches!(
            init.command,
            Some(Command::Recipe {
                command: RecipeCommand::Init { .. }
            })
        ));

        let explain = Args::try_parse_from([
            "bridgefu",
            "--config",
            "bridgefu.yaml",
            "recipe",
            "explain",
            "support",
        ])
        .unwrap();
        assert_eq!(explain.config, PathBuf::from("bridgefu.yaml"));
        assert!(matches!(
            explain.command,
            Some(Command::Recipe {
                command: RecipeCommand::Explain { .. }
            })
        ));

        let deploy = Args::try_parse_from([
            "bridgefu",
            "recipe",
            "deploy",
            "deployment.yaml",
            "--profile",
            "starter",
        ])
        .unwrap();
        assert!(matches!(
            deploy.command,
            Some(Command::Recipe {
                command: RecipeCommand::Deploy { execute: false, .. }
            })
        ));

        let preflight = Args::try_parse_from([
            "bridgefu",
            "recipe",
            "preflight",
            "deployment.yaml",
            "--profile",
            "starter",
        ])
        .unwrap();
        assert!(matches!(
            preflight.command,
            Some(Command::Recipe {
                command: RecipeCommand::Preflight { .. }
            })
        ));

        let destroy = Args::try_parse_from([
            "bridgefu",
            "recipe",
            "destroy",
            "deployment.yaml",
            "--confirm",
            "bridgefu",
        ])
        .unwrap();
        assert!(matches!(
            destroy.command,
            Some(Command::Recipe {
                command: RecipeCommand::Destroy { .. }
            })
        ));
    }

    #[test]
    fn flagship_recipe_guide_is_setup_first_and_keeps_disposable_proof_secondary() {
        let guide = include_str!("../recipes/vapi-amazon-connect-screen-pop/README.md");
        for required in [
            "## 1. Open Bridgefu Setup",
            "## 2. Select AWS and Amazon Connect",
            "## 3. Create the Vapi template",
            "Existing assistants are not read or modified",
            "**Reviewed routing**",
            "## Maintainer: disposable full proof",
            "release-maintainer test, not a prerequisite",
        ] {
            assert!(
                guide.contains(required),
                "flagship init guide is missing {required:?}"
            );
        }
    }

    #[test]
    fn recipe_explanation_is_useful_and_redacts_configured_targets() {
        let catalog = RecipeCatalog::builtin().unwrap();
        let package = catalog
            .resolve("builtin:vapi-amazon-connect-screen-pop@1")
            .unwrap();
        let values = serde_yaml::from_str(include_str!(
            "../recipes/vapi-amazon-connect-screen-pop/values.example.yaml"
        ))
        .unwrap();
        let compiled = package.compile(&values).unwrap();
        let explanation = explain_compiled_recipe("support", &compiled);
        assert!(explanation.contains("SIPS/SRTP; TCP 5061"));
        assert!(explanation.contains("managed one-use attachment"));
        assert!(explanation.contains("X-Correlation-Id -> Amazon attribute correlation_id"));
        assert!(explanation.contains("configured (redacted)"));
        assert!(!explanation.contains("123456789012"));
        assert!(!explanation.contains("11111111-1111"));
    }

    #[test]
    fn generic_recipe_initial_values_use_defaults_and_visible_nulls() {
        let catalog = RecipeCatalog::builtin().unwrap();
        let package = catalog
            .resolve("builtin:vapi-amazon-connect-screen-pop@1")
            .unwrap();
        let values = initial_recipe_values(package.manifest());
        assert_eq!(
            values
                .get("sip_security")
                .and_then(serde_yaml::Value::as_str),
            Some("sips_srtp")
        );
        assert!(matches!(
            values.get("connect_instance_arn"),
            Some(serde_yaml::Value::Null)
        ));
        assert!(matches!(
            values.get("vapi_signaling_cidrs"),
            Some(serde_yaml::Value::Null)
        ));
    }

    #[tokio::test]
    async fn owned_call_runtime_shutdown_marks_worker_draining_and_joins() {
        let mut coordination = CallServiceCoordinationConfig::new(
            DeploymentId::parse("main-runtime-shutdown-test").unwrap(),
        );
        coordination.worker_lease_ttl = std::time::Duration::from_secs(300);
        coordination.worker_renew_interval = std::time::Duration::from_secs(100);
        let runtime = build_call_service_runtime(
            CallServiceRuntimeConfig {
                backend: CallRepositoryBackendConfig::Memory,
                worker_id: WorkerId::new(),
                max_calls: 2,
                worker_capabilities: BTreeSet::from(["sip".into(), "webrtc".into()]),
                control_key: vec![0x38; 32],
                timeouts: CallTimeoutPolicy {
                    setup: std::time::Duration::from_secs(30),
                    media_idle: std::time::Duration::from_secs(30),
                    transfer: std::time::Duration::from_secs(30),
                    ending: std::time::Duration::from_secs(30),
                },
                coordination,
            },
            Arc::new(SamePrincipalAttachmentResolver),
            Arc::new(SystemCallServiceClock),
        )
        .await
        .unwrap();
        let repository = runtime.repository();
        let worker_id = runtime.worker().lease.worker_id;
        shutdown_call_runtime(
            Some(Arc::new(runtime)),
            tokio::time::Instant::now() + std::time::Duration::from_secs(2),
        )
        .await
        .unwrap();
        let worker = repository.worker_snapshot(worker_id).await.unwrap();
        assert!(worker.draining);
    }

    #[test]
    fn process_installs_a_rustls_crypto_provider_before_tls_construction() {
        install_default_crypto_provider().unwrap();
        assert!(rustls::crypto::CryptoProvider::get_default().is_some());
    }
}
