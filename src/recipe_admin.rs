//! Guarded AWS administrator lifecycle for released Bridgefu recipe stacks.
//!
//! The runtime intentionally uses the installed AWS CLI rather than embedding
//! a second AWS SDK graph. Arguments are passed directly without a shell, and
//! every destructive operation re-reads and verifies the stack's ownership
//! tags before it can run.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use clap::ValueEnum;
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use uuid::Uuid;

const MAX_DESCRIPTOR_BYTES: u64 = 256 * 1024;
const MAX_PARAMETER_BYTES: u64 = 256 * 1024;
const MAX_RELEASE_MANIFEST_BYTES: usize = 4 * 1024 * 1024;
const PROJECT_TAG: &str = "bridgefu-recipe";
const DRIFT_TIMEOUT: Duration = Duration::from_secs(15 * 60);

const ALLOWED_STACK_RESOURCE_TYPES: &[&str] = &[
    "AWS::ApiGatewayV2::Api",
    "AWS::ApiGatewayV2::Integration",
    "AWS::ApiGatewayV2::Route",
    "AWS::ApiGatewayV2::Stage",
    "AWS::AutoScaling::AutoScalingGroup",
    "AWS::AutoScaling::LifecycleHook",
    "AWS::Backup::BackupPlan",
    "AWS::Backup::BackupSelection",
    "AWS::Backup::BackupVault",
    "AWS::CertificateManager::Certificate",
    "AWS::CloudFormation::Stack",
    "AWS::CloudFront::CachePolicy",
    "AWS::CloudFront::Distribution",
    "AWS::CloudFront::OriginAccessControl",
    "AWS::CloudFront::ResponseHeadersPolicy",
    "AWS::CloudWatch::Alarm",
    "AWS::CloudWatch::Dashboard",
    "AWS::CodeBuild::Project",
    "AWS::Connect::ContactFlow",
    "AWS::Connect::HoursOfOperation",
    "AWS::Connect::IntegrationAssociation",
    "AWS::DynamoDB::Table",
    "AWS::EC2::EIP",
    "AWS::EC2::EIPAssociation",
    "AWS::EC2::Instance",
    "AWS::EC2::InternetGateway",
    "AWS::EC2::LaunchTemplate",
    "AWS::EC2::NatGateway",
    "AWS::EC2::NetworkInterface",
    "AWS::EC2::Route",
    "AWS::EC2::RouteTable",
    "AWS::EC2::SecurityGroup",
    "AWS::EC2::SecurityGroupEgress",
    "AWS::EC2::SecurityGroupIngress",
    "AWS::EC2::Subnet",
    "AWS::EC2::SubnetRouteTableAssociation",
    "AWS::EC2::VPC",
    "AWS::EC2::VPCEndpoint",
    "AWS::EC2::VPCGatewayAttachment",
    "AWS::EC2::Volume",
    "AWS::EC2::VolumeAttachment",
    "AWS::ECS::Cluster",
    "AWS::ECS::Service",
    "AWS::ECS::TaskDefinition",
    "AWS::ElastiCache::ReplicationGroup",
    "AWS::ElastiCache::SubnetGroup",
    "AWS::ElastiCache::User",
    "AWS::ElastiCache::UserGroup",
    "AWS::ElasticLoadBalancingV2::Listener",
    "AWS::ElasticLoadBalancingV2::LoadBalancer",
    "AWS::ElasticLoadBalancingV2::TargetGroup",
    "AWS::IAM::InstanceProfile",
    "AWS::IAM::Role",
    "AWS::Lambda::Function",
    "AWS::Lambda::Permission",
    "AWS::Logs::LogGroup",
    "AWS::Logs::MetricFilter",
    "AWS::RDS::DBInstance",
    "AWS::RDS::DBParameterGroup",
    "AWS::RDS::DBSubnetGroup",
    "AWS::Route53::HostedZone",
    "AWS::Route53::RecordSet",
    "AWS::S3::Bucket",
    "AWS::S3::BucketPolicy",
    "AWS::SecretsManager::Secret",
    "AWS::SNS::Subscription",
    "AWS::SNS::Topic",
    "Custom::BridgefuDemoSite",
    "Custom::BridgefuVapiResources",
];

const PROTECTED_NESTED_RESOURCE_TYPES: &[&str] = &[
    "AWS::Connect::ContactFlow",
    "AWS::Connect::IntegrationAssociation",
    "AWS::DynamoDB::Table",
    "AWS::EC2::EIP",
    "AWS::EC2::NetworkInterface",
    "AWS::EC2::SecurityGroup",
    "AWS::EC2::Subnet",
    "AWS::EC2::VPC",
    "AWS::EC2::Volume",
    "AWS::ElastiCache::ReplicationGroup",
    "AWS::RDS::DBInstance",
    "AWS::S3::Bucket",
    "AWS::SecretsManager::Secret",
    "Custom::BridgefuVapiResources",
];

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, ValueEnum)]
#[serde(rename_all = "snake_case")]
pub(crate) enum DeploymentProfile {
    Starter,
    HighAvailability,
}

impl DeploymentProfile {
    const fn label(self) -> &'static str {
        match self {
            Self::Starter => "starter",
            Self::HighAvailability => "high_availability",
        }
    }
}

impl std::fmt::Display for DeploymentProfile {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Starter => "starter",
            Self::HighAvailability => "high-availability",
        })
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
enum DeploymentEnvironment {
    Nonproduction,
    Production,
}

impl DeploymentEnvironment {
    const fn label(self) -> &'static str {
        match self {
            Self::Nonproduction => "nonproduction",
            Self::Production => "production",
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct DeploymentDescriptor {
    schema_version: u32,
    provider: DeploymentProvider,
    recipe: String,
    deployment_id: String,
    region: String,
    stack_name: String,
    #[serde(default)]
    environment: Option<DeploymentEnvironment>,
    #[serde(default)]
    expected_account_id: Option<String>,
    #[serde(default)]
    cloudformation_service_role_arn: Option<String>,
    #[serde(default)]
    release_manifest_url: Option<String>,
    #[serde(default)]
    release_manifest_sha256: Option<String>,
    #[serde(default)]
    stack_policy_file: Option<PathBuf>,
    #[serde(default)]
    termination_protection: Option<bool>,
    #[serde(default)]
    rollback_alarm_arns: Vec<String>,
    profiles: BTreeMap<DeploymentProfile, ProfileDescriptor>,
}

#[derive(Debug, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
enum DeploymentProvider {
    AwsCloudformation,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProfileDescriptor {
    template_url: String,
    parameters_file: PathBuf,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "PascalCase")]
struct StackParameter {
    parameter_key: String,
    parameter_value: String,
}

#[derive(Debug)]
struct LoadedDeployment {
    descriptor: DeploymentDescriptor,
    template_url: String,
    parameters_file: PathBuf,
    parameters: BTreeMap<String, String>,
    stack_policy_file: Option<PathBuf>,
}

pub(crate) fn preflight(descriptor_path: &Path, profile: DeploymentProfile) -> Result<()> {
    let deployment = load(descriptor_path, profile)?;
    let report = preflight_loaded(&deployment, profile)?;
    println!("{}", serde_json::to_string_pretty(&report)?);
    Ok(())
}

fn preflight_loaded(deployment: &LoadedDeployment, profile: DeploymentProfile) -> Result<Value> {
    let descriptor = &deployment.descriptor;
    anyhow::ensure!(
        descriptor.schema_version == 2,
        "deployment execution requires schema_version: 2; schema 1 is status-only"
    );
    let environment = descriptor
        .environment
        .context("missing deployment environment")?;
    let account_id = descriptor
        .expected_account_id
        .as_deref()
        .context("missing expected AWS account")?;
    let service_role = descriptor
        .cloudformation_service_role_arn
        .as_deref()
        .context("missing CloudFormation service role")?;

    let identity = aws_json(["sts", "get-caller-identity"])?;
    anyhow::ensure!(
        identity["Account"].as_str() == Some(account_id),
        "active AWS account does not match expected_account_id"
    );
    let caller_arn = required_string(&identity, "Arn")?;
    anyhow::ensure!(
        caller_arn != format!("arn:aws:iam::{account_id}:root"),
        "refusing to deploy from the AWS account root principal"
    );

    validate_environment_parameters(deployment, profile, environment)?;
    validate_release_manifest(deployment)?;
    validate_cloudformation_role(descriptor, service_role)?;
    validate_connect_target(deployment)?;
    let sip_prerequisites = validate_sip_prerequisites(deployment)?;
    let quota_report = validate_quotas(deployment, profile)?;
    let baseline_report = validate_account_baseline(descriptor, environment)?;
    validate_rollback_alarms(descriptor)?;

    Ok(json!({
        "preflight": "passed",
        "environment": environment.label(),
        "account_id": account_id,
        "region": descriptor.region,
        "caller_arn": caller_arn,
        "cloudformation_service_role_arn": service_role,
        "release_manifest": "verified",
        "connect_target": "verified",
        "sip_prerequisites": sip_prerequisites,
        "quotas": quota_report,
        "account_baseline": baseline_report,
    }))
}

fn validate_environment_parameters(
    deployment: &LoadedDeployment,
    profile: DeploymentProfile,
    environment: DeploymentEnvironment,
) -> Result<()> {
    let parameters = &deployment.parameters;
    for key in [
        "RuntimeProfile",
        "DataRetentionMode",
        "LambdaReservedConcurrencyPerFunction",
        "RetainVapiResourcesOnDelete",
        "EnableDemoSite",
        "SipSecurity",
        "NetworkMode",
        "VapiSignalingCidr1",
        "VapiSignalingCidr2",
        "MediaSourceCidr",
    ] {
        anyhow::ensure!(
            parameters.contains_key(key),
            "schema 2 parameters must explicitly set {key}"
        );
    }
    anyhow::ensure!(
        parameters.get("EnableDemoSite").map(String::as_str) == Some("false"),
        "administrator deployments keep EnableDemoSite=false"
    );
    anyhow::ensure!(
        parameters.get("VapiSignalingCidr1").map(String::as_str) == Some("44.229.228.186/32")
            && parameters.get("VapiSignalingCidr2").map(String::as_str)
                == Some("44.238.177.138/32"),
        "Vapi signaling allowlist must use the reviewed US /32 addresses"
    );
    anyhow::ensure!(
        parameters.get("MediaSourceCidr").map(String::as_str) == Some("0.0.0.0/0"),
        "Vapi US media uses dynamic source addresses; keep the reviewed media-source value"
    );
    let reserved = required_parameter(parameters, "LambdaReservedConcurrencyPerFunction")?
        .parse::<u64>()
        .context("LambdaReservedConcurrencyPerFunction must be an integer")?;
    match environment {
        DeploymentEnvironment::Nonproduction => {
            anyhow::ensure!(
                profile == DeploymentProfile::Starter,
                "IP-only nonproduction supports only the Starter profile"
            );
            anyhow::ensure!(
                parameters.get("SipSecurity").map(String::as_str) == Some("sip_rtp"),
                "nonproduction requires the explicit IP-only SipSecurity=sip_rtp posture"
            );
            anyhow::ensure!(
                parameters.get("DataRetentionMode").map(String::as_str) == Some("TestDelete"),
                "nonproduction requires DataRetentionMode=TestDelete"
            );
            anyhow::ensure!(
                parameters
                    .get("RetainVapiResourcesOnDelete")
                    .map(String::as_str)
                    == Some("false"),
                "nonproduction must delete recipe-owned Vapi resources"
            );
            anyhow::ensure!(
                reserved == 0,
                "nonproduction requires LambdaReservedConcurrencyPerFunction=0"
            );
        }
        DeploymentEnvironment::Production => {
            anyhow::ensure!(
                parameters.get("SipSecurity").map(String::as_str) == Some("sips_srtp"),
                "production requires SipSecurity=sips_srtp"
            );
            anyhow::ensure!(
                parameters.get("DataRetentionMode").map(String::as_str) == Some("ProductionRetain"),
                "production requires DataRetentionMode=ProductionRetain"
            );
            anyhow::ensure!(
                parameters
                    .get("RetainVapiResourcesOnDelete")
                    .map(String::as_str)
                    == Some("true"),
                "production requires RetainVapiResourcesOnDelete=true"
            );
            anyhow::ensure!(
                reserved == 20,
                "the initial production profile requires 20 reserved executions per function"
            );
            anyhow::ensure!(
                required_parameter(parameters, "AlarmEmail")?.contains('@'),
                "production requires a configured AlarmEmail"
            );
        }
    }
    if profile == DeploymentProfile::HighAvailability {
        anyhow::ensure!(
            parameters.contains_key("PrivateTlsSecretArn"),
            "HA requires an explicit PrivateTlsSecretArn"
        );
    }
    Ok(())
}

fn required_parameter<'a>(parameters: &'a BTreeMap<String, String>, key: &str) -> Result<&'a str> {
    parameters
        .get(key)
        .map(String::as_str)
        .with_context(|| format!("missing required CloudFormation parameter {key}"))
}

fn fetch_https(url: &str) -> Result<Vec<u8>> {
    let output = Command::new("curl")
        .args([
            "--fail",
            "--location",
            "--silent",
            "--show-error",
            "--max-time",
            "30",
            url,
        ])
        .output()
        .context("downloading the immutable release artifact with curl")?;
    anyhow::ensure!(output.status.success(), "release artifact download failed");
    anyhow::ensure!(
        !output.stdout.is_empty() && output.stdout.len() <= MAX_RELEASE_MANIFEST_BYTES,
        "release artifact is empty or exceeds the size limit"
    );
    Ok(output.stdout)
}

fn validate_release_manifest(deployment: &LoadedDeployment) -> Result<()> {
    let descriptor = &deployment.descriptor;
    let manifest_url = descriptor
        .release_manifest_url
        .as_deref()
        .context("missing release manifest URL")?;
    let expected_manifest_sha256 = descriptor
        .release_manifest_sha256
        .as_deref()
        .context("missing release manifest digest")?;
    let manifest_bytes = fetch_https(manifest_url)?;
    let observed_manifest_sha256 = format!("{:x}", Sha256::digest(&manifest_bytes));
    anyhow::ensure!(
        observed_manifest_sha256 == expected_manifest_sha256,
        "release manifest digest does not match the reviewed descriptor"
    );
    let manifest: Value =
        serde_json::from_slice(&manifest_bytes).context("release manifest is not valid JSON")?;
    anyhow::ensure!(
        manifest["schema_version"].as_u64() == Some(1),
        "unsupported release manifest"
    );
    anyhow::ensure!(
        manifest["recipe"]["id"].as_str() == Some("vapi-amazon-connect-screen-pop")
            && manifest["recipe"]["version"].as_u64() == Some(1),
        "release manifest selects a different recipe"
    );
    anyhow::ensure!(
        manifest["bridgefu"]["source_dirty"].as_bool() == Some(false),
        "release manifest was built from a dirty source tree"
    );
    anyhow::ensure!(
        manifest["signature"]["algorithm"].as_str() == Some("Ed25519")
            && manifest["signature"]["detached_file"].as_str().is_some()
            && manifest["signature"]["public_key_file"].as_str().is_some()
            && manifest["signature"]["public_key_sha256"]
                .as_str()
                .is_some_and(valid_sha256),
        "release manifest is not backed by the required detached Ed25519 signature"
    );
    verify_release_signature(manifest_url, &manifest_bytes, &manifest)?;
    let template_artifact = manifest["artifacts"]
        .as_array()
        .into_iter()
        .flatten()
        .find(|item| item["path"].as_str() == Some("recipe/cloudformation/template.yaml"))
        .context("release manifest does not inventory the root template")?;
    let expected_template_sha256 = template_artifact["sha256"]
        .as_str()
        .context("root template inventory entry has no digest")?;
    anyhow::ensure!(
        valid_sha256(expected_template_sha256),
        "invalid root template digest"
    );
    let base = url::Url::parse(manifest_url).context("invalid release manifest URL")?;
    let expected_template_url = base
        .join("recipe/cloudformation/template.yaml")
        .context("constructing the release template URL")?;
    anyhow::ensure!(
        deployment.template_url == expected_template_url.as_str(),
        "profile template_url is not bound to the release manifest"
    );
    let template_bytes = fetch_https(&deployment.template_url)?;
    anyhow::ensure!(
        format!("{:x}", Sha256::digest(&template_bytes)) == expected_template_sha256,
        "downloaded root template does not match the release manifest"
    );
    anyhow::ensure!(
        required_parameter(&deployment.parameters, "BridgefuImageUri")?
            == manifest["bridgefu"]["image_uri"]
                .as_str()
                .context("release manifest has no immutable image URI")?,
        "BridgefuImageUri does not match the release manifest"
    );
    let expected_nested_base = base
        .join("recipe/cloudformation")
        .context("constructing nested template base URL")?;
    anyhow::ensure!(
        required_parameter(&deployment.parameters, "NestedTemplateBaseUrl")?.trim_end_matches('/')
            == expected_nested_base.as_str().trim_end_matches('/'),
        "NestedTemplateBaseUrl is not bound to the release manifest"
    );
    Ok(())
}

fn verify_release_signature(
    manifest_url: &str,
    manifest_bytes: &[u8],
    manifest: &Value,
) -> Result<()> {
    let signature = &manifest["signature"];
    let detached_file = signature["detached_file"]
        .as_str()
        .context("release manifest has no detached signature file")?;
    let public_key_file = signature["public_key_file"]
        .as_str()
        .context("release manifest has no public key file")?;
    anyhow::ensure!(
        detached_file == "manifest.sig" && public_key_file == "manifest.pub",
        "release signature files must use the canonical manifest.sig and manifest.pub names"
    );
    let base = url::Url::parse(manifest_url).context("invalid release manifest URL")?;
    let signature_bytes = fetch_https(base.join(detached_file)?.as_str())?;
    let public_key_bytes = fetch_https(base.join(public_key_file)?.as_str())?;
    anyhow::ensure!(
        signature_bytes.len() == 64,
        "Ed25519 release signature must be exactly 64 bytes"
    );
    anyhow::ensure!(
        public_key_bytes.len() <= 16 * 1024,
        "release signing public key exceeds the size limit"
    );
    let expected_public_key_sha256 = signature["public_key_sha256"]
        .as_str()
        .context("release manifest has no public key digest")?;
    anyhow::ensure!(
        format!("{:x}", Sha256::digest(&public_key_bytes)) == expected_public_key_sha256,
        "release signing public key does not match the reviewed digest"
    );

    let directory = std::env::temp_dir().join(format!(
        "bridgefu-release-signature-{}",
        Uuid::new_v4().simple()
    ));
    std::fs::create_dir(&directory).context("creating release verification directory")?;
    let manifest_path = directory.join("manifest.json");
    let signature_path = directory.join("manifest.sig");
    let public_key_path = directory.join("manifest.pub");
    let verification = (|| -> Result<()> {
        std::fs::write(&manifest_path, manifest_bytes)
            .context("writing release manifest for signature verification")?;
        std::fs::write(&signature_path, &signature_bytes)
            .context("writing detached release signature")?;
        std::fs::write(&public_key_path, &public_key_bytes)
            .context("writing release signing public key")?;
        let output = Command::new("openssl")
            .args(["pkeyutl", "-verify", "-rawin", "-pubin", "-inkey"])
            .arg(&public_key_path)
            .arg("-in")
            .arg(&manifest_path)
            .arg("-sigfile")
            .arg(&signature_path)
            .output()
            .context("running OpenSSL release signature verification")?;
        anyhow::ensure!(
            output.status.success(),
            "release signature verification failed"
        );
        Ok(())
    })();
    let cleanup = std::fs::remove_dir_all(&directory)
        .context("removing release signature verification directory");
    verification?;
    cleanup?;
    Ok(())
}

fn validate_cloudformation_role(
    descriptor: &DeploymentDescriptor,
    service_role_arn: &str,
) -> Result<()> {
    let role_name = service_role_arn
        .rsplit('/')
        .next()
        .context("CloudFormation service role ARN has no role name")?;
    let role = aws_json(["iam", "get-role", "--role-name", role_name])?;
    anyhow::ensure!(
        role["Role"]["Arn"].as_str() == Some(service_role_arn),
        "CloudFormation service role ARN did not resolve exactly"
    );
    let statements = role["Role"]["AssumeRolePolicyDocument"]["Statement"]
        .as_array()
        .context("CloudFormation service role has no trust statements")?;
    let allow_statements = statements
        .iter()
        .filter(|statement| statement["Effect"].as_str() == Some("Allow"))
        .collect::<Vec<_>>();
    anyhow::ensure!(
        allow_statements.len() == 1
            && allow_statements[0]["Action"].as_str() == Some("sts:AssumeRole")
            && allow_statements[0]["Principal"]
                .as_object()
                .is_some_and(|principal| {
                    principal.len() == 1
                        && principal["Service"].as_str() == Some("cloudformation.amazonaws.com")
                }),
        "service role trust must allow only CloudFormation"
    );
    let account_id = descriptor
        .expected_account_id
        .as_deref()
        .unwrap_or_default();
    anyhow::ensure!(
        valid_role_arn(service_role_arn, account_id),
        "service role belongs to a different account"
    );
    Ok(())
}

fn connect_arn_parts<'a>(arn: &'a str, suffix: &str) -> Result<(&'a str, &'a str, &'a str)> {
    let parts = arn.splitn(6, ':').collect::<Vec<_>>();
    anyhow::ensure!(
        parts.len() == 6 && parts[0] == "arn" && parts[1] == "aws" && parts[2] == "connect",
        "invalid Amazon Connect ARN"
    );
    let resource = parts[5]
        .strip_prefix("instance/")
        .context("Connect ARN does not identify an instance")?;
    let (instance_id, resource_suffix) = resource
        .split_once('/')
        .map_or((resource, ""), |(instance, rest)| (instance, rest));
    anyhow::ensure!(
        suffix.is_empty() || resource_suffix.starts_with(suffix),
        "Connect ARN has the wrong resource type"
    );
    Ok((parts[3], parts[4], instance_id))
}

fn validate_connect_target(deployment: &LoadedDeployment) -> Result<()> {
    let descriptor = &deployment.descriptor;
    let account_id = descriptor
        .expected_account_id
        .as_deref()
        .unwrap_or_default();
    let instance_arn = required_parameter(&deployment.parameters, "ConnectInstanceArn")?;
    let target_arn = required_parameter(&deployment.parameters, "TargetContactFlowArn")?;
    let (region, account, instance_id) = connect_arn_parts(instance_arn, "")?;
    anyhow::ensure!(
        region == descriptor.region && account == account_id,
        "Connect instance belongs to a different account or region"
    );
    let (target_region, target_account, target_instance_id) =
        connect_arn_parts(target_arn, "contact-flow/")?;
    anyhow::ensure!(
        (target_region, target_account, target_instance_id) == (region, account, instance_id),
        "target flow does not belong to the configured Connect instance"
    );
    let flow_id = target_arn
        .rsplit('/')
        .next()
        .context("target flow ARN has no resource ID")?;
    let instance = aws_json([
        "connect",
        "describe-instance",
        "--region",
        &descriptor.region,
        "--instance-id",
        instance_id,
    ])?;
    anyhow::ensure!(
        instance["Instance"]["InstanceStatus"].as_str() == Some("ACTIVE"),
        "Amazon Connect instance is not ACTIVE"
    );
    let flow = aws_json([
        "connect",
        "describe-contact-flow",
        "--region",
        &descriptor.region,
        "--instance-id",
        instance_id,
        "--contact-flow-id",
        flow_id,
    ])?;
    anyhow::ensure!(
        flow["ContactFlow"]["Arn"].as_str() == Some(target_arn),
        "Amazon Connect returned a different target flow"
    );
    Ok(())
}

fn validate_sip_prerequisites(deployment: &LoadedDeployment) -> Result<&'static str> {
    let security = required_parameter(&deployment.parameters, "SipSecurity")?;
    let zone_id = required_parameter(&deployment.parameters, "PublicHostedZoneId")?;
    if security == "sip_rtp" {
        anyhow::ensure!(
            zone_id == "none",
            "IP-only SIP/RTP must set PublicHostedZoneId=none"
        );
        return Ok("ip_only_sip_rtp_no_dns_or_acm");
    }
    anyhow::ensure!(
        security == "sips_srtp",
        "SipSecurity must be sip_rtp or sips_srtp"
    );
    anyhow::ensure!(zone_id != "none", "SIPS/SRTP requires a public hosted zone");
    let zone = aws_json(["route53", "get-hosted-zone", "--id", zone_id])?;
    anyhow::ensure!(
        zone["HostedZone"]["Config"]["PrivateZone"].as_bool() == Some(false),
        "SIPS/SRTP hosted zone must be public"
    );
    let zone_name = zone["HostedZone"]["Name"]
        .as_str()
        .context("hosted zone has no name")?
        .trim_end_matches('.');
    let hostname = required_parameter(&deployment.parameters, "SipHostname")?;
    anyhow::ensure!(
        hostname == zone_name || hostname.ends_with(&format!(".{zone_name}")),
        "SipHostname is outside PublicHostedZoneId"
    );
    let delegated = Command::new("dig")
        .args(["+short", "NS", zone_name])
        .output()
        .context("checking public DNS delegation with dig")?;
    anyhow::ensure!(
        delegated.status.success() && !delegated.stdout.is_empty(),
        "public hosted zone is not delegated in DNS"
    );
    Ok("public_dns_and_sips_srtp_verified")
}

fn validate_quotas(deployment: &LoadedDeployment, profile: DeploymentProfile) -> Result<Value> {
    let descriptor = &deployment.descriptor;
    let reserved = required_parameter(
        &deployment.parameters,
        "LambdaReservedConcurrencyPerFunction",
    )?
    .parse::<u64>()
    .context("Lambda reserved concurrency must be an integer")?;
    let function_count = 4_u64;
    let required_concurrency = reserved.saturating_mul(function_count).saturating_add(10);
    let lambda = aws_json([
        "lambda",
        "get-account-settings",
        "--region",
        &descriptor.region,
    ])?;
    let concurrent = lambda["AccountLimit"]["ConcurrentExecutions"]
        .as_u64()
        .context("Lambda returned no concurrency quota")?;
    let unreserved = lambda["AccountLimit"]["UnreservedConcurrentExecutions"]
        .as_u64()
        .context("Lambda returned no unreserved concurrency quota")?;
    anyhow::ensure!(
        concurrent >= required_concurrency && unreserved >= 10,
        "Lambda concurrency quota is insufficient: need {required_concurrency} total and 10 unreserved"
    );

    let addresses = aws_json(["ec2", "describe-addresses", "--region", &descriptor.region])?;
    let address_count = addresses["Addresses"].as_array().map_or(0, Vec::len) as u64;
    let attributes = aws_json([
        "ec2",
        "describe-account-attributes",
        "--region",
        &descriptor.region,
        "--attribute-names",
        "vpc-max-elastic-ips",
    ])?;
    let address_limit = attributes["AccountAttributes"]
        .as_array()
        .and_then(|values| values.first())
        .and_then(|value| value["AttributeValues"].as_array())
        .and_then(|values| values.first())
        .and_then(|value| value["AttributeValue"].as_str())
        .and_then(|value| value.parse::<u64>().ok())
        .context("EC2 returned no Elastic IP quota")?;
    let required_addresses = match profile {
        DeploymentProfile::Starter => 1,
        DeploymentProfile::HighAvailability => 4,
    };
    if !stack_exists(&descriptor.region, &descriptor.stack_name)? {
        anyhow::ensure!(
            address_limit.saturating_sub(address_count) >= required_addresses,
            "Elastic IP quota has insufficient capacity for this profile"
        );
    }

    let cloudformation = aws_json([
        "cloudformation",
        "describe-account-limits",
        "--region",
        &descriptor.region,
    ])?;
    let stack_limit = cloudformation["AccountLimits"]
        .as_array()
        .into_iter()
        .flatten()
        .find(|item| item["Name"].as_str() == Some("StackLimit"))
        .and_then(|item| item["Value"].as_u64())
        .context("CloudFormation returned no stack quota")?;
    anyhow::ensure!(stack_limit > 0, "CloudFormation stack quota is exhausted");

    let connect_quota = aws_json([
        "service-quotas",
        "get-service-quota",
        "--region",
        &descriptor.region,
        "--service-code",
        "connect",
        "--quota-code",
        "L-AA17A6B9",
    ])?;
    let connect_limit = connect_quota["Quota"]["Value"].as_f64().unwrap_or_default();
    let instances = aws_json(["connect", "list-instances", "--region", &descriptor.region])?;
    let connect_instances = instances["InstanceSummaryList"]
        .as_array()
        .map_or(0, Vec::len);

    Ok(json!({
        "lambda_concurrent_limit": concurrent,
        "lambda_unreserved": unreserved,
        "lambda_required": required_concurrency,
        "elastic_ip_limit": address_limit,
        "elastic_ip_in_use": address_count,
        "elastic_ip_required_for_create": required_addresses,
        "cloudformation_stack_limit": stack_limit,
        "connect_instance_limit": connect_limit,
        "connect_instances": connect_instances,
    }))
}

fn validate_account_baseline(
    descriptor: &DeploymentDescriptor,
    environment: DeploymentEnvironment,
) -> Result<Value> {
    let account_id = descriptor
        .expected_account_id
        .as_deref()
        .unwrap_or_default();
    let organization = aws_json(["organizations", "describe-organization"])?;
    anyhow::ensure!(
        organization["Organization"]["Id"].as_str().is_some(),
        "AWS account is not attached to an Organization"
    );
    let trails = aws_json([
        "cloudtrail",
        "describe-trails",
        "--region",
        &descriptor.region,
        "--include-shadow-trails",
        "false",
    ])?;
    let trail_arns = trails["trailList"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|trail| {
            trail["IsMultiRegionTrail"].as_bool() == Some(true)
                && trail["LogFileValidationEnabled"].as_bool() == Some(true)
        })
        .filter_map(|trail| trail["TrailARN"].as_str())
        .collect::<Vec<_>>();
    anyhow::ensure!(
        !trail_arns.is_empty(),
        "account has no multi-region, log-file-validating CloudTrail trail"
    );
    let mut logging_trails = 0;
    for arn in &trail_arns {
        let status = aws_json([
            "cloudtrail",
            "get-trail-status",
            "--region",
            &descriptor.region,
            "--name",
            arn,
        ])?;
        if status["IsLogging"].as_bool() == Some(true) {
            logging_trails += 1;
        }
    }
    anyhow::ensure!(
        logging_trails > 0,
        "no CloudTrail trail is actively logging"
    );

    let analyzers = aws_json([
        "accessanalyzer",
        "list-analyzers",
        "--region",
        &descriptor.region,
        "--type",
        "ACCOUNT",
    ])?;
    anyhow::ensure!(
        analyzers["analyzers"].as_array().is_some_and(|items| {
            items
                .iter()
                .any(|item| item["status"].as_str() == Some("ACTIVE"))
        }),
        "account has no active external-access analyzer"
    );
    let budgets = aws_json(["budgets", "describe-budgets", "--account-id", account_id])?;
    anyhow::ensure!(
        budgets["Budgets"]
            .as_array()
            .is_some_and(|items| !items.is_empty()),
        "account has no AWS Budget"
    );
    let recorders = aws_json([
        "configservice",
        "describe-configuration-recorders",
        "--region",
        &descriptor.region,
    ])?;
    anyhow::ensure!(
        recorders["ConfigurationRecorders"]
            .as_array()
            .is_some_and(|items| !items.is_empty()),
        "region has no AWS Config recorder"
    );
    let recorder_status = aws_json([
        "configservice",
        "describe-configuration-recorder-status",
        "--region",
        &descriptor.region,
    ])?;
    anyhow::ensure!(
        recorder_status["ConfigurationRecordersStatus"]
            .as_array()
            .is_some_and(|items| items.iter().any(|item| {
                item["recording"].as_bool() == Some(true)
                    && item["lastStatus"].as_str() != Some("FAILURE")
            })),
        "AWS Config recorder is not actively recording"
    );
    let delivery_channels = aws_json([
        "configservice",
        "describe-delivery-channels",
        "--region",
        &descriptor.region,
    ])?;
    anyhow::ensure!(
        delivery_channels["DeliveryChannels"]
            .as_array()
            .is_some_and(|items| !items.is_empty()),
        "region has no AWS Config delivery channel"
    );
    if environment == DeploymentEnvironment::Production {
        let guardduty = aws_json([
            "guardduty",
            "list-detectors",
            "--region",
            &descriptor.region,
        ])?;
        let detector_ids = guardduty["DetectorIds"]
            .as_array()
            .context("GuardDuty returned no detector list")?;
        let mut enabled_detector = false;
        for detector_id in detector_ids.iter().filter_map(Value::as_str) {
            let detector = aws_json([
                "guardduty",
                "get-detector",
                "--region",
                &descriptor.region,
                "--detector-id",
                detector_id,
            ])?;
            enabled_detector |= detector["Status"].as_str() == Some("ENABLED");
        }
        anyhow::ensure!(
            enabled_detector,
            "production account has no enabled GuardDuty detector"
        );
        aws_json([
            "securityhub",
            "describe-hub",
            "--region",
            &descriptor.region,
        ])
        .context("production account is not subscribed to Security Hub")?;
    }
    Ok(json!({
        "organization": "attached",
        "logging_trails": logging_trails,
        "access_analyzer": "active",
        "budget": "configured",
        "config_recorder": "configured",
        "guardduty_and_security_hub_required": environment == DeploymentEnvironment::Production,
    }))
}

fn validate_rollback_alarms(descriptor: &DeploymentDescriptor) -> Result<()> {
    for arn in &descriptor.rollback_alarm_arns {
        let name = arn
            .split_once(":alarm:")
            .map(|(_, value)| value)
            .context("invalid rollback alarm ARN")?;
        let alarms = aws_json([
            "cloudwatch",
            "describe-alarms",
            "--region",
            &descriptor.region,
            "--alarm-names",
            name,
        ])?;
        anyhow::ensure!(
            alarms["MetricAlarms"]
                .as_array()
                .is_some_and(|items| items.len() == 1)
                || alarms["CompositeAlarms"]
                    .as_array()
                    .is_some_and(|items| items.len() == 1),
            "rollback alarm does not exist: {name}"
        );
    }
    Ok(())
}

fn change_set_description(
    deployment: &LoadedDeployment,
    profile: DeploymentProfile,
) -> Result<String> {
    let parameter_bytes = std::fs::read(&deployment.parameters_file).with_context(|| {
        format!(
            "reading CloudFormation parameters {}",
            deployment.parameters_file.display()
        )
    })?;
    let manifest_sha256 = deployment
        .descriptor
        .release_manifest_sha256
        .as_deref()
        .context("deployment schema 2 requires release_manifest_sha256")?;
    Ok(format!(
        "Bridgefu {} {} manifest={} parameters={:x}",
        deployment.descriptor.recipe,
        profile.label(),
        manifest_sha256,
        Sha256::digest(parameter_bytes)
    ))
}

fn change_set_tags(deployment: &LoadedDeployment) -> Result<BTreeMap<String, String>> {
    let descriptor = &deployment.descriptor;
    Ok(BTreeMap::from([
        ("Project".to_owned(), PROJECT_TAG.to_owned()),
        ("ManagedBy".to_owned(), "bridgefu-cli".to_owned()),
        (
            "BridgefuExecutionId".to_owned(),
            descriptor.deployment_id.clone(),
        ),
        (
            "Environment".to_owned(),
            descriptor
                .environment
                .context("deployment schema 2 requires environment")?
                .label()
                .to_owned(),
        ),
        (
            "BridgefuRecipe".to_owned(),
            recipe_id(&descriptor.recipe)?.to_owned(),
        ),
        (
            "ReleaseManifestSha256".to_owned(),
            descriptor
                .release_manifest_sha256
                .clone()
                .context("deployment schema 2 requires release_manifest_sha256")?,
        ),
    ]))
}

fn validate_change_set_binding(
    description: &Value,
    deployment: &LoadedDeployment,
    profile: DeploymentProfile,
    change_set_name: &str,
) -> Result<String> {
    let descriptor = &deployment.descriptor;
    anyhow::ensure!(
        description["Status"].as_str() == Some("CREATE_COMPLETE")
            && description["ExecutionStatus"].as_str() == Some("AVAILABLE"),
        "reviewed change set is not available for execution"
    );
    anyhow::ensure!(
        description["StackName"].as_str() == Some(descriptor.stack_name.as_str())
            && description["ChangeSetName"].as_str() == Some(change_set_name),
        "reviewed change set belongs to a different stack or name"
    );
    anyhow::ensure!(
        description["RoleARN"].as_str() == descriptor.cloudformation_service_role_arn.as_deref(),
        "reviewed change set uses a different CloudFormation service role"
    );
    let expected_description = change_set_description(deployment, profile)?;
    anyhow::ensure!(
        description["Description"].as_str() == Some(expected_description.as_str()),
        "reviewed change set is not bound to the current release and parameter file"
    );
    anyhow::ensure!(
        description["IncludeNestedStacks"].as_bool() == Some(true),
        "reviewed change set does not include nested stacks"
    );
    let capabilities = description["Capabilities"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .collect::<BTreeSet<_>>();
    anyhow::ensure!(
        capabilities == BTreeSet::from(["CAPABILITY_AUTO_EXPAND", "CAPABILITY_NAMED_IAM"]),
        "reviewed change set capabilities changed"
    );
    let observed_tags = description["Tags"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|item| {
            Some((
                item["Key"].as_str()?.to_owned(),
                item["Value"].as_str()?.to_owned(),
            ))
        })
        .collect::<BTreeMap<_, _>>();
    anyhow::ensure!(
        observed_tags == change_set_tags(deployment)?,
        "reviewed change set ownership or release tags changed"
    );
    let observed_alarms = description["RollbackConfiguration"]["RollbackTriggers"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|item| item["Arn"].as_str())
        .collect::<BTreeSet<_>>();
    let expected_alarms = descriptor
        .rollback_alarm_arns
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    anyhow::ensure!(
        observed_alarms == expected_alarms,
        "reviewed change set rollback alarms changed"
    );
    let change_type = required_string(description, "ChangeSetType")?.to_owned();
    anyhow::ensure!(
        matches!(change_type.as_str(), "CREATE" | "UPDATE"),
        "reviewed change set has an invalid type"
    );
    if change_type == "CREATE" {
        anyhow::ensure!(
            description["OnStackFailure"].as_str() == Some("ROLLBACK"),
            "create change set does not use automatic rollback"
        );
    }
    Ok(change_type)
}

pub(crate) fn deploy(
    descriptor_path: &Path,
    profile: DeploymentProfile,
    execute: bool,
    confirm: Option<&str>,
    change_set_name: Option<&str>,
) -> Result<()> {
    let deployment = load(descriptor_path, profile)?;
    let descriptor = &deployment.descriptor;
    let preflight_report = preflight_loaded(&deployment, profile)?;
    println!("{}", serde_json::to_string_pretty(&preflight_report)?);
    if execute {
        anyhow::ensure!(
            confirm == Some(descriptor.stack_name.as_str()),
            "--confirm must exactly equal the stack name when --execute is used"
        );
    }
    let generated_name = format!(
        "bridgefu-review-{}-{}",
        profile.label().replace('_', "-"),
        chrono::Utc::now().format("%Y%m%d%H%M%S")
    );
    let change_set = change_set_name.unwrap_or(&generated_name);
    validate_change_set_name(change_set)?;
    let reuse_review = execute && change_set_name.is_some();
    let binding = if reuse_review {
        aws_json([
            "cloudformation",
            "describe-change-set",
            "--region",
            &descriptor.region,
            "--stack-name",
            &descriptor.stack_name,
            "--change-set-name",
            change_set,
            "--include-property-values",
        ])?
    } else {
        let existed_before_review = stack_exists(&descriptor.region, &descriptor.stack_name)?;
        let requested_change_type = if existed_before_review {
            "UPDATE"
        } else {
            "CREATE"
        };
        let parameter_uri = format!("file://{}", deployment.parameters_file.display());
        let mut arguments = vec![
            "cloudformation".to_owned(),
            "create-change-set".to_owned(),
            "--region".to_owned(),
            descriptor.region.clone(),
            "--stack-name".to_owned(),
            descriptor.stack_name.clone(),
            "--change-set-name".to_owned(),
            change_set.to_owned(),
            "--change-set-type".to_owned(),
            requested_change_type.to_owned(),
            "--description".to_owned(),
            change_set_description(&deployment, profile)?,
            "--template-url".to_owned(),
            deployment.template_url.clone(),
            "--role-arn".to_owned(),
            descriptor
                .cloudformation_service_role_arn
                .clone()
                .context("deployment schema 2 requires a CloudFormation service role")?,
            "--parameters".to_owned(),
            parameter_uri,
            "--capabilities".to_owned(),
            "CAPABILITY_NAMED_IAM".to_owned(),
            "CAPABILITY_AUTO_EXPAND".to_owned(),
            "--include-nested-stacks".to_owned(),
            "--tags".to_owned(),
        ];
        if !existed_before_review {
            arguments.push("--on-stack-failure".to_owned());
            arguments.push("ROLLBACK".to_owned());
        }
        if !descriptor.rollback_alarm_arns.is_empty() {
            arguments.push("--rollback-configuration".to_owned());
            arguments.push(
                json!({
                    "RollbackTriggers": descriptor
                        .rollback_alarm_arns
                        .iter()
                        .map(|arn| json!({"Arn": arn, "Type": "AWS::CloudWatch::Alarm"}))
                        .collect::<Vec<_>>(),
                    "MonitoringTimeInMinutes": 10,
                })
                .to_string(),
            );
        }
        arguments.extend(
            change_set_tags(&deployment)?
                .into_iter()
                .map(|(key, value)| format!("Key={key},Value={value}")),
        );
        aws_json(&arguments)?;
        let wait = aws_output([
            "cloudformation",
            "wait",
            "change-set-create-complete",
            "--region",
            &descriptor.region,
            "--stack-name",
            &descriptor.stack_name,
            "--change-set-name",
            change_set,
            "--no-cli-pager",
        ])?;
        if !wait.status.success() {
            let failed = aws_json([
                "cloudformation",
                "describe-change-set",
                "--region",
                &descriptor.region,
                "--stack-name",
                &descriptor.stack_name,
                "--change-set-name",
                change_set,
            ])?;
            let reason = failed["StatusReason"].as_str().unwrap_or_default();
            if existed_before_review && reason.contains("didn't contain changes") {
                let _ = aws([
                    "cloudformation",
                    "delete-change-set",
                    "--region",
                    &descriptor.region,
                    "--stack-name",
                    &descriptor.stack_name,
                    "--change-set-name",
                    change_set,
                ]);
                println!("deployment already matches the requested immutable release");
                return Ok(());
            }
            anyhow::bail!("CloudFormation could not prepare the change set: {reason}");
        }
        aws_json([
            "cloudformation",
            "describe-change-set",
            "--region",
            &descriptor.region,
            "--stack-name",
            &descriptor.stack_name,
            "--change-set-name",
            change_set,
            "--include-property-values",
        ])?
    };
    let change_type = validate_change_set_binding(&binding, &deployment, profile, change_set)?;
    let review = review_change_set_tree(
        &descriptor.region,
        &descriptor.stack_name,
        change_set,
        &change_type,
    )?;
    print_change_set_review(change_set, &review)?;
    if !execute {
        println!(
            "review only; rerun with --execute --change-set-name {} --confirm {} after approval",
            change_set, descriptor.stack_name
        );
        return Ok(());
    }
    aws_json([
        "cloudformation",
        "execute-change-set",
        "--region",
        &descriptor.region,
        "--stack-name",
        &descriptor.stack_name,
        "--change-set-name",
        change_set,
    ])?;
    let waiter = if change_type == "UPDATE" {
        "stack-update-complete"
    } else {
        "stack-create-complete"
    };
    aws([
        "cloudformation",
        "wait",
        waiter,
        "--region",
        &descriptor.region,
        "--stack-name",
        &descriptor.stack_name,
    ])?;
    if descriptor.environment == Some(DeploymentEnvironment::Production) {
        apply_production_protections(&deployment)?;
    }
    println!("deployment ready: {}", descriptor.stack_name);
    Ok(())
}

pub(crate) fn status(descriptor_path: &Path, profile: DeploymentProfile) -> Result<()> {
    let deployment = load(descriptor_path, profile)?;
    let stack = describe_stack(&deployment.descriptor)?;
    println!(
        "{}",
        serde_json::to_string_pretty(&safe_stack_status(&stack)?)?
    );
    Ok(())
}

pub(crate) fn doctor(descriptor_path: &Path, profile: DeploymentProfile) -> Result<()> {
    let deployment = load(descriptor_path, profile)?;
    let descriptor = &deployment.descriptor;
    if descriptor.schema_version == 2 {
        preflight_loaded(&deployment, profile)?;
    }
    let stack = describe_stack(descriptor)?;
    verify_stack_ownership(descriptor, &stack)?;
    let status = required_string(&stack, "StackStatus")?;
    anyhow::ensure!(
        matches!(status, "CREATE_COMPLETE" | "UPDATE_COMPLETE"),
        "stack is not ready: {status}"
    );
    let resources = aws_json([
        "cloudformation",
        "list-stack-resources",
        "--region",
        &descriptor.region,
        "--stack-name",
        &descriptor.stack_name,
    ])?;
    let summaries = resources["StackResourceSummaries"]
        .as_array()
        .context("AWS returned no stack resource summaries")?;
    let unhealthy = summaries
        .iter()
        .filter_map(|resource| {
            let value = resource["ResourceStatus"].as_str()?;
            (!matches!(
                value,
                "CREATE_COMPLETE" | "UPDATE_COMPLETE" | "UPDATE_ROLLBACK_COMPLETE"
            ))
            .then(|| {
                format!(
                    "{}:{}",
                    resource["LogicalResourceId"].as_str().unwrap_or("unknown"),
                    value
                )
            })
        })
        .collect::<Vec<_>>();
    anyhow::ensure!(
        unhealthy.is_empty(),
        "stack contains unhealthy resources: {}",
        unhealthy.join(", ")
    );
    let alarms = aws_json([
        "cloudwatch",
        "describe-alarms",
        "--region",
        &descriptor.region,
        "--alarm-name-prefix",
        &format!("bridgefu-{}-", descriptor.deployment_id),
    ])?;
    let active_alarms = alarms["MetricAlarms"]
        .as_array()
        .into_iter()
        .flatten()
        .chain(alarms["CompositeAlarms"].as_array().into_iter().flatten())
        .filter(|alarm| alarm["StateValue"].as_str() == Some("ALARM"))
        .map(|alarm| alarm["AlarmName"].as_str().unwrap_or("unknown").to_owned())
        .collect::<Vec<_>>();
    anyhow::ensure!(
        active_alarms.is_empty(),
        "active Bridgefu alarms: {}",
        active_alarms.join(", ")
    );
    if descriptor.schema_version == 2 {
        let expected_role = descriptor
            .cloudformation_service_role_arn
            .as_deref()
            .context("missing CloudFormation service role")?;
        anyhow::ensure!(
            stack["RoleARN"].as_str() == Some(expected_role),
            "stack is not bound to the reviewed CloudFormation service role"
        );
        anyhow::ensure!(
            stack["EnableTerminationProtection"].as_bool() == descriptor.termination_protection,
            "stack termination protection does not match the descriptor"
        );
        if descriptor.environment == Some(DeploymentEnvironment::Production) {
            verify_production_stack_policies(&deployment)?;
        }
        verify_recursive_drift(&descriptor.region, &descriptor.stack_name)?;
    }
    let outputs = safe_outputs(&stack)?;
    for required in ["Recipe", "SipUri", "DashboardUrl", "RuntimeProfile"] {
        anyhow::ensure!(
            outputs.contains_key(required),
            "missing stack output {required}"
        );
    }
    let expected_profile = match profile {
        DeploymentProfile::Starter => "Starter",
        DeploymentProfile::HighAvailability => "HighAvailability",
    };
    anyhow::ensure!(
        outputs.get("RuntimeProfile").map(String::as_str) == Some(expected_profile),
        "deployed runtime profile does not match the selected administrator profile"
    );
    match profile {
        DeploymentProfile::Starter => {
            anyhow::ensure!(
                outputs.contains_key("RuntimeInstanceId"),
                "missing stack output RuntimeInstanceId"
            );
        }
        DeploymentProfile::HighAvailability => {
            let cluster = outputs
                .get("RuntimeClusterName")
                .context("missing stack output RuntimeClusterName")?;
            let services = aws_json([
                "ecs",
                "describe-services",
                "--region",
                &descriptor.region,
                "--cluster",
                cluster,
                "--services",
                "gateway-a",
                "gateway-b",
                "worker-a",
                "worker-b",
            ])?;
            let failures = services["failures"]
                .as_array()
                .into_iter()
                .flatten()
                .count();
            anyhow::ensure!(failures == 0, "AWS reported missing HA ECS services");
            let service_values = services["services"]
                .as_array()
                .context("AWS returned no HA ECS services")?;
            anyhow::ensure!(service_values.len() == 4, "expected four HA ECS services");
            for service in service_values {
                let name = required_string(service, "serviceName")?;
                let desired = service["desiredCount"].as_u64().unwrap_or_default();
                let running = service["runningCount"].as_u64().unwrap_or_default();
                anyhow::ensure!(
                    desired == 1 && running == 1,
                    "HA ECS service {name} is not exactly 1/1 ready"
                );
            }
        }
    }
    println!(
        "doctor passed: stack ready, ownership exact, {} root resources healthy, no active alarms, protections and drift verified",
        summaries.len()
    );
    println!("billable call executed: no");
    Ok(())
}

pub(crate) fn test(descriptor_path: &Path, profile: DeploymentProfile) -> Result<()> {
    doctor(descriptor_path, profile)?;
    println!("structural recipe test passed; no voice call or customer data was created");
    println!("run the recipe's protected live qualification for audio and screen-pop evidence");
    Ok(())
}

pub(crate) fn destroy(
    descriptor_path: &Path,
    profile: DeploymentProfile,
    confirm: &str,
) -> Result<()> {
    let deployment = load(descriptor_path, profile)?;
    let descriptor = &deployment.descriptor;
    anyhow::ensure!(
        descriptor.environment != Some(DeploymentEnvironment::Production),
        "production destroy is blocked; use the separately approved break-glass runbook"
    );
    if let Some(expected_account_id) = descriptor.expected_account_id.as_deref() {
        let identity = aws_json(["sts", "get-caller-identity"])?;
        anyhow::ensure!(
            identity["Account"].as_str() == Some(expected_account_id),
            "active AWS account does not match expected_account_id"
        );
        let root_arn = format!("arn:aws:iam::{expected_account_id}:root");
        anyhow::ensure!(
            identity["Arn"].as_str() != Some(root_arn.as_str()),
            "refusing to destroy from the AWS account root principal"
        );
    }
    anyhow::ensure!(
        confirm == descriptor.stack_name,
        "--confirm must exactly equal the stack name"
    );
    let stack = describe_stack(descriptor)?;
    verify_stack_ownership(descriptor, &stack)?;
    aws_json([
        "cloudformation",
        "delete-stack",
        "--region",
        &descriptor.region,
        "--stack-name",
        &descriptor.stack_name,
        "--client-request-token",
        &format!("bridgefu-destroy-{}", descriptor.deployment_id),
    ])?;
    aws([
        "cloudformation",
        "wait",
        "stack-delete-complete",
        "--region",
        &descriptor.region,
        "--stack-name",
        &descriptor.stack_name,
    ])?;
    println!("stack deleted: {}", descriptor.stack_name);
    println!("release artifacts are publisher-owned and were not deleted");
    Ok(())
}

fn load(path: &Path, profile: DeploymentProfile) -> Result<LoadedDeployment> {
    let metadata = std::fs::metadata(path)
        .with_context(|| format!("reading deployment descriptor {}", path.display()))?;
    anyhow::ensure!(metadata.is_file(), "deployment descriptor is not a file");
    anyhow::ensure!(
        metadata.len() <= MAX_DESCRIPTOR_BYTES,
        "deployment descriptor exceeds the size limit"
    );
    let raw = std::fs::read_to_string(path)
        .with_context(|| format!("reading deployment descriptor {}", path.display()))?;
    let descriptor: DeploymentDescriptor = serde_yaml::from_str(&raw)
        .with_context(|| format!("parsing deployment descriptor {}", path.display()))?;
    validate_descriptor(&descriptor)?;
    let profile_descriptor = descriptor
        .profiles
        .get(&profile)
        .with_context(|| format!("profile {} is not configured", profile.label()))?;
    validate_template_url(&profile_descriptor.template_url)?;
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let parameters_file = parent.join(&profile_descriptor.parameters_file);
    let parameters = validate_parameters(&parameters_file, profile)?;
    let stack_policy_file = descriptor
        .stack_policy_file
        .as_ref()
        .map(|value| parent.join(value));
    if let Some(policy) = stack_policy_file.as_deref() {
        validate_stack_policy(policy)?;
    }
    Ok(LoadedDeployment {
        template_url: profile_descriptor.template_url.clone(),
        parameters_file,
        parameters,
        stack_policy_file,
        descriptor,
    })
}

fn validate_descriptor(descriptor: &DeploymentDescriptor) -> Result<()> {
    anyhow::ensure!(
        matches!(descriptor.schema_version, 1 | 2),
        "unsupported deployment schema"
    );
    anyhow::ensure!(
        descriptor.provider == DeploymentProvider::AwsCloudformation,
        "unsupported deployment provider"
    );
    recipe_id(&descriptor.recipe)?;
    anyhow::ensure!(
        valid_lower_id(&descriptor.deployment_id, 3, 24),
        "deployment_id must be 3-24 lowercase letters, digits, or hyphens"
    );
    anyhow::ensure!(valid_region(&descriptor.region), "invalid AWS region");
    anyhow::ensure!(
        valid_stack_name(&descriptor.stack_name),
        "invalid CloudFormation stack name"
    );
    anyhow::ensure!(
        !descriptor.profiles.is_empty() && descriptor.profiles.len() <= 2,
        "one or two deployment profiles are required"
    );
    if descriptor.schema_version == 2 {
        let environment = descriptor
            .environment
            .context("deployment schema 2 requires environment")?;
        let account_id = descriptor
            .expected_account_id
            .as_deref()
            .context("deployment schema 2 requires expected_account_id")?;
        anyhow::ensure!(valid_account_id(account_id), "invalid expected_account_id");
        let service_role = descriptor
            .cloudformation_service_role_arn
            .as_deref()
            .context("deployment schema 2 requires cloudformation_service_role_arn")?;
        anyhow::ensure!(
            valid_role_arn(service_role, account_id),
            "CloudFormation service role must be an IAM role in expected_account_id"
        );
        let manifest_url = descriptor
            .release_manifest_url
            .as_deref()
            .context("deployment schema 2 requires release_manifest_url")?;
        validate_manifest_url(manifest_url)?;
        let manifest_sha256 = descriptor
            .release_manifest_sha256
            .as_deref()
            .context("deployment schema 2 requires release_manifest_sha256")?;
        anyhow::ensure!(
            valid_sha256(manifest_sha256),
            "release_manifest_sha256 must be 64 lowercase hexadecimal characters"
        );
        anyhow::ensure!(
            descriptor.stack_policy_file.is_some(),
            "deployment schema 2 requires stack_policy_file"
        );
        anyhow::ensure!(
            descriptor.termination_protection.is_some(),
            "deployment schema 2 requires termination_protection"
        );
        for arn in &descriptor.rollback_alarm_arns {
            anyhow::ensure!(
                valid_alarm_arn(arn, &descriptor.region, account_id),
                "rollback alarm ARN must belong to the expected account and region"
            );
        }
        if environment == DeploymentEnvironment::Production {
            anyhow::ensure!(
                descriptor.termination_protection == Some(true),
                "production requires termination_protection: true"
            );
            anyhow::ensure!(
                !descriptor.rollback_alarm_arns.is_empty(),
                "production requires at least one rollback alarm ARN"
            );
        }
    }
    Ok(())
}

fn validate_parameters(
    path: &Path,
    profile: DeploymentProfile,
) -> Result<BTreeMap<String, String>> {
    let metadata = std::fs::metadata(path)
        .with_context(|| format!("reading CloudFormation parameters {}", path.display()))?;
    anyhow::ensure!(
        metadata.is_file(),
        "CloudFormation parameters are not a file"
    );
    anyhow::ensure!(
        metadata.len() <= MAX_PARAMETER_BYTES,
        "CloudFormation parameters exceed the size limit"
    );
    let raw = std::fs::read_to_string(path)
        .with_context(|| format!("reading CloudFormation parameters {}", path.display()))?;
    let parameters: Vec<StackParameter> = serde_json::from_str(&raw)
        .with_context(|| format!("parsing CloudFormation parameters {}", path.display()))?;
    anyhow::ensure!(
        !parameters.is_empty() && parameters.len() <= 128,
        "CloudFormation parameters must contain 1-128 entries"
    );
    let mut keys = BTreeSet::new();
    let mut values = BTreeMap::new();
    let mut runtime_profile = None;
    for parameter in parameters {
        anyhow::ensure!(
            valid_parameter_key(&parameter.parameter_key),
            "invalid CloudFormation parameter key"
        );
        anyhow::ensure!(
            parameter.parameter_value.len() <= 4096
                && !parameter.parameter_value.contains(['\r', '\n', '\0']),
            "invalid CloudFormation parameter value"
        );
        if parameter.parameter_key == "RuntimeProfile" {
            runtime_profile = Some(parameter.parameter_value.clone());
        }
        anyhow::ensure!(
            keys.insert(parameter.parameter_key.clone()),
            "duplicate CloudFormation parameter key"
        );
        values.insert(parameter.parameter_key, parameter.parameter_value);
    }
    let expected = match profile {
        DeploymentProfile::Starter => "Starter",
        DeploymentProfile::HighAvailability => "HighAvailability",
    };
    anyhow::ensure!(
        runtime_profile.as_deref() == Some(expected),
        "CloudFormation parameters select a different runtime profile"
    );
    Ok(values)
}

fn validate_stack_policy(path: &Path) -> Result<()> {
    let metadata = std::fs::metadata(path)
        .with_context(|| format!("reading CloudFormation stack policy {}", path.display()))?;
    anyhow::ensure!(
        metadata.is_file(),
        "CloudFormation stack policy is not a file"
    );
    anyhow::ensure!(
        metadata.len() <= MAX_DESCRIPTOR_BYTES,
        "CloudFormation stack policy exceeds the size limit"
    );
    let value: Value = serde_json::from_slice(
        &std::fs::read(path)
            .with_context(|| format!("reading CloudFormation stack policy {}", path.display()))?,
    )
    .with_context(|| format!("parsing CloudFormation stack policy {}", path.display()))?;
    anyhow::ensure!(
        value["Statement"]
            .as_array()
            .is_some_and(|items| !items.is_empty()),
        "CloudFormation stack policy requires statements"
    );
    Ok(())
}

fn recipe_id(selector: &str) -> Result<&str> {
    let value = selector
        .strip_prefix("builtin:")
        .context("administrator deployment requires an exact built-in recipe selector")?;
    let (name, version) = value
        .rsplit_once('@')
        .context("recipe selector requires an exact @version")?;
    anyhow::ensure!(valid_lower_id(name, 3, 64), "invalid recipe name");
    anyhow::ensure!(
        version.parse::<u32>().is_ok_and(|value| value > 0),
        "invalid recipe version"
    );
    Ok(value)
}

fn valid_lower_id(value: &str, min: usize, max: usize) -> bool {
    (min..=max).contains(&value.len())
        && value.as_bytes().first().is_some_and(u8::is_ascii_lowercase)
        && value
            .bytes()
            .all(|value| value.is_ascii_lowercase() || value.is_ascii_digit() || value == b'-')
}

fn valid_region(value: &str) -> bool {
    (5..=32).contains(&value.len())
        && value
            .bytes()
            .all(|value| value.is_ascii_lowercase() || value.is_ascii_digit() || value == b'-')
        && value.contains('-')
}

fn valid_account_id(value: &str) -> bool {
    value.len() == 12 && value.bytes().all(|value| value.is_ascii_digit())
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|value| value.is_ascii_digit() || (b'a'..=b'f').contains(&value))
}

fn valid_role_arn(value: &str, account_id: &str) -> bool {
    let prefix = format!("arn:aws:iam::{account_id}:role/");
    value.strip_prefix(&prefix).is_some_and(|name| {
        !name.is_empty()
            && name.len() <= 512
            && name.bytes().all(|value| {
                value.is_ascii_alphanumeric()
                    || matches!(value, b'+' | b'=' | b',' | b'.' | b'@' | b'_' | b'/' | b'-')
            })
    })
}

fn valid_alarm_arn(value: &str, region: &str, account_id: &str) -> bool {
    let prefix = format!("arn:aws:cloudwatch:{region}:{account_id}:alarm:");
    value
        .strip_prefix(&prefix)
        .is_some_and(|name| !name.is_empty() && !name.contains(['\r', '\n', '\0']))
}

fn valid_stack_name(value: &str) -> bool {
    (1..=128).contains(&value.len())
        && value
            .as_bytes()
            .first()
            .is_some_and(|value| value.is_ascii_alphabetic())
        && value
            .bytes()
            .all(|value| value.is_ascii_alphanumeric() || value == b'-')
}

fn valid_parameter_key(value: &str) -> bool {
    (1..=255).contains(&value.len())
        && value
            .as_bytes()
            .first()
            .is_some_and(|value| value.is_ascii_alphabetic())
        && value.bytes().all(|value| value.is_ascii_alphanumeric())
}

fn validate_template_url(value: &str) -> Result<()> {
    let parsed = url::Url::parse(value).context("template_url is not a URL")?;
    anyhow::ensure!(parsed.scheme() == "https", "template_url must use HTTPS");
    anyhow::ensure!(
        parsed.username().is_empty(),
        "template_url cannot embed credentials"
    );
    anyhow::ensure!(
        parsed.password().is_none(),
        "template_url cannot embed credentials"
    );
    anyhow::ensure!(parsed.host_str().is_some(), "template_url requires a host");
    anyhow::ensure!(
        !parsed.path().ends_with('/'),
        "template_url must name a template"
    );
    anyhow::ensure!(
        parsed.fragment().is_none(),
        "template_url cannot contain a fragment"
    );
    Ok(())
}

fn validate_manifest_url(value: &str) -> Result<()> {
    validate_template_url(value)?;
    let parsed = url::Url::parse(value).context("release_manifest_url is not a URL")?;
    anyhow::ensure!(
        parsed.path().ends_with("/manifest.json"),
        "release_manifest_url must name manifest.json"
    );
    anyhow::ensure!(
        parsed.query().is_none(),
        "release_manifest_url cannot contain a query string"
    );
    Ok(())
}

fn validate_change_set_name(value: &str) -> Result<()> {
    anyhow::ensure!(
        valid_stack_name(value),
        "invalid CloudFormation change-set name"
    );
    Ok(())
}

fn stack_exists(region: &str, stack_name: &str) -> Result<bool> {
    let output = aws_output([
        "cloudformation",
        "describe-stacks",
        "--region",
        region,
        "--stack-name",
        stack_name,
    ])?;
    if output.status.success() {
        return Ok(true);
    }
    let error = String::from_utf8_lossy(&output.stderr);
    if error.contains("does not exist") {
        return Ok(false);
    }
    Err(anyhow::anyhow!(
        "AWS identity could not inspect the target stack"
    ))
}

fn describe_stack(descriptor: &DeploymentDescriptor) -> Result<Value> {
    let value = aws_json([
        "cloudformation",
        "describe-stacks",
        "--region",
        &descriptor.region,
        "--stack-name",
        &descriptor.stack_name,
    ])?;
    value["Stacks"]
        .as_array()
        .and_then(|stacks| stacks.first())
        .cloned()
        .context("AWS returned no matching stack")
}

fn verify_stack_ownership(descriptor: &DeploymentDescriptor, stack: &Value) -> Result<()> {
    let tags = stack["Tags"]
        .as_array()
        .context("stack has no ownership tags")?
        .iter()
        .filter_map(|tag| Some((tag["Key"].as_str()?, tag["Value"].as_str()?)))
        .collect::<BTreeMap<_, _>>();
    anyhow::ensure!(
        tags.get("Project") == Some(&PROJECT_TAG),
        "refusing to administer a stack without the Bridgefu project tag"
    );
    anyhow::ensure!(
        tags.get("BridgefuExecutionId") == Some(&descriptor.deployment_id.as_str()),
        "stack deployment ownership tag does not match the descriptor"
    );
    anyhow::ensure!(
        tags.get("BridgefuRecipe") == Some(&recipe_id(&descriptor.recipe)?),
        "stack recipe ownership tag does not match the descriptor"
    );
    if let Some(environment) = descriptor.environment {
        anyhow::ensure!(
            tags.get("Environment") == Some(&environment.label()),
            "stack environment ownership tag does not match the descriptor"
        );
    }
    Ok(())
}

fn stack_tree(region: &str, root_stack: &str) -> Result<Vec<String>> {
    let mut pending = vec![(root_stack.to_owned(), 0_usize)];
    let mut seen = BTreeSet::new();
    let mut stacks = Vec::new();
    while let Some((stack, depth)) = pending.pop() {
        anyhow::ensure!(
            depth <= 8 && seen.len() < 64,
            "nested stack tree exceeds bounds"
        );
        anyhow::ensure!(
            seen.insert(stack.clone()),
            "nested stack tree contains a cycle"
        );
        let resources = aws_json([
            "cloudformation",
            "list-stack-resources",
            "--region",
            region,
            "--stack-name",
            &stack,
        ])?;
        for resource in resources["StackResourceSummaries"]
            .as_array()
            .into_iter()
            .flatten()
        {
            if resource["ResourceType"].as_str() == Some("AWS::CloudFormation::Stack") {
                let child = resource["PhysicalResourceId"]
                    .as_str()
                    .context("nested stack resource has no physical ID")?;
                pending.push((child.to_owned(), depth + 1));
            }
        }
        stacks.push(stack);
    }
    Ok(stacks)
}

fn nested_protection_policy(resources: &Value) -> Result<Value> {
    let protected = resources["StackResourceSummaries"]
        .as_array()
        .context("AWS returned no stack resource summaries")?
        .iter()
        .filter(|resource| {
            resource["ResourceType"]
                .as_str()
                .is_some_and(|value| PROTECTED_NESTED_RESOURCE_TYPES.contains(&value))
        })
        .map(|resource| {
            required_string(resource, "LogicalResourceId")
                .map(|value| format!("LogicalResourceId/{value}"))
        })
        .collect::<Result<Vec<_>>>()?;
    let mut statements = vec![json!({
        "Effect": "Allow",
        "Action": "Update:*",
        "Principal": "*",
        "Resource": "*",
    })];
    if !protected.is_empty() {
        statements.push(json!({
            "Effect": "Deny",
            "Action": ["Update:Replace", "Update:Delete"],
            "Principal": "*",
            "Resource": protected,
        }));
    }
    Ok(json!({"Statement": statements}))
}

fn apply_production_protections(deployment: &LoadedDeployment) -> Result<()> {
    let descriptor = &deployment.descriptor;
    let policy_file = deployment
        .stack_policy_file
        .as_deref()
        .context("production stack policy file is missing")?;
    let policy_uri = format!("file://{}", policy_file.display());
    aws([
        "cloudformation",
        "set-stack-policy",
        "--region",
        &descriptor.region,
        "--stack-name",
        &descriptor.stack_name,
        "--stack-policy-body",
        &policy_uri,
    ])?;
    let stacks = stack_tree(&descriptor.region, &descriptor.stack_name)?;
    for stack in stacks.iter().skip(1) {
        let resources = aws_json([
            "cloudformation",
            "list-stack-resources",
            "--region",
            &descriptor.region,
            "--stack-name",
            stack,
        ])?;
        let policy = nested_protection_policy(&resources)?.to_string();
        aws([
            "cloudformation",
            "set-stack-policy",
            "--region",
            &descriptor.region,
            "--stack-name",
            stack,
            "--stack-policy-body",
            &policy,
        ])?;
    }
    aws_json([
        "cloudformation",
        "update-termination-protection",
        "--region",
        &descriptor.region,
        "--stack-name",
        &descriptor.stack_name,
        "--enable-termination-protection",
    ])?;
    Ok(())
}

fn get_stack_policy(region: &str, stack: &str) -> Result<Value> {
    let value = aws_json([
        "cloudformation",
        "get-stack-policy",
        "--region",
        region,
        "--stack-name",
        stack,
    ])?;
    match &value["StackPolicyBody"] {
        Value::String(body) => serde_json::from_str(body).context("stack policy is invalid JSON"),
        body @ Value::Object(_) => Ok(body.clone()),
        _ => anyhow::bail!("stack has no policy body"),
    }
}

fn verify_production_stack_policies(deployment: &LoadedDeployment) -> Result<()> {
    let descriptor = &deployment.descriptor;
    let expected_root: Value = serde_json::from_slice(&std::fs::read(
        deployment
            .stack_policy_file
            .as_deref()
            .context("production stack policy file is missing")?,
    )?)?;
    anyhow::ensure!(
        get_stack_policy(&descriptor.region, &descriptor.stack_name)? == expected_root,
        "root stack policy does not match the reviewed policy"
    );
    let stacks = stack_tree(&descriptor.region, &descriptor.stack_name)?;
    for stack in stacks.iter().skip(1) {
        let resources = aws_json([
            "cloudformation",
            "list-stack-resources",
            "--region",
            &descriptor.region,
            "--stack-name",
            stack,
        ])?;
        let expected = nested_protection_policy(&resources)?;
        anyhow::ensure!(
            get_stack_policy(&descriptor.region, stack)? == expected,
            "nested stack policy does not match current protected resources: {stack}"
        );
    }
    Ok(())
}

fn verify_recursive_drift(region: &str, root_stack: &str) -> Result<()> {
    for stack in stack_tree(region, root_stack)? {
        let detection = aws_json([
            "cloudformation",
            "detect-stack-drift",
            "--region",
            region,
            "--stack-name",
            &stack,
        ])?;
        let detection_id = required_string(&detection, "StackDriftDetectionId")?;
        let started = Instant::now();
        loop {
            let status = aws_json([
                "cloudformation",
                "describe-stack-drift-detection-status",
                "--region",
                region,
                "--stack-drift-detection-id",
                detection_id,
            ])?;
            match status["DetectionStatus"].as_str() {
                Some("DETECTION_COMPLETE") => {
                    anyhow::ensure!(
                        status["StackDriftStatus"].as_str() == Some("IN_SYNC"),
                        "stack drift detected: {stack}"
                    );
                    break;
                }
                Some("DETECTION_FAILED") => {
                    anyhow::bail!(
                        "stack drift detection failed for {stack}: {}",
                        status["DetectionStatusReason"]
                            .as_str()
                            .unwrap_or("unknown")
                    );
                }
                Some("DETECTION_IN_PROGRESS") => {
                    anyhow::ensure!(
                        started.elapsed() < DRIFT_TIMEOUT,
                        "stack drift check timed out"
                    );
                    thread::sleep(Duration::from_secs(5));
                }
                _ => anyhow::bail!("CloudFormation returned an unknown drift status"),
            }
        }
    }
    Ok(())
}

fn safe_stack_status(stack: &Value) -> Result<Value> {
    Ok(json!({
        "stack_name": required_string(stack, "StackName")?,
        "status": required_string(stack, "StackStatus")?,
        "created_at": stack["CreationTime"].as_str(),
        "updated_at": stack["LastUpdatedTime"].as_str(),
        "outputs": safe_outputs(stack)?,
    }))
}

fn safe_outputs(stack: &Value) -> Result<BTreeMap<String, String>> {
    let mut outputs = BTreeMap::new();
    for output in stack["Outputs"].as_array().into_iter().flatten() {
        let key = output["OutputKey"]
            .as_str()
            .context("stack output has no key")?;
        let lowered = key.to_ascii_lowercase();
        if ["secret", "password", "token", "private", "correlation"]
            .iter()
            .any(|needle| lowered.contains(needle))
        {
            continue;
        }
        let value = output["OutputValue"]
            .as_str()
            .context("stack output has no string value")?;
        outputs.insert(key.to_owned(), value.to_owned());
    }
    Ok(outputs)
}

fn required_string<'a>(value: &'a Value, key: &str) -> Result<&'a str> {
    value[key]
        .as_str()
        .with_context(|| format!("AWS response is missing {key}"))
}

fn review_change_set_tree(
    region: &str,
    stack_name: &str,
    root_change_set: &str,
    change_type: &str,
) -> Result<Vec<Value>> {
    anyhow::ensure!(
        matches!(change_type, "CREATE" | "UPDATE"),
        "invalid change type"
    );
    let root = aws_json([
        "cloudformation",
        "describe-change-set",
        "--region",
        region,
        "--stack-name",
        stack_name,
        "--change-set-name",
        root_change_set,
        "--include-property-values",
    ])?;
    let root_id = required_string(&root, "ChangeSetId")?.to_owned();
    let mut pending = vec![("root".to_owned(), root_id, 0_usize, Some(root))];
    let mut seen = BTreeSet::new();
    let mut flattened = Vec::new();
    while let Some((path, change_set_id, depth, prefetched)) = pending.pop() {
        anyhow::ensure!(
            depth <= 8 && seen.len() < 64,
            "nested change-set tree exceeds bounds"
        );
        anyhow::ensure!(
            seen.insert(change_set_id.clone()),
            "duplicate nested change set"
        );
        let description = match prefetched {
            Some(value) => value,
            None => aws_json([
                "cloudformation",
                "describe-change-set",
                "--region",
                region,
                "--change-set-name",
                &change_set_id,
                "--include-property-values",
            ])?,
        };
        anyhow::ensure!(
            description["Status"].as_str() == Some("CREATE_COMPLETE"),
            "nested change set is not ready for review"
        );
        let changes = description["Changes"]
            .as_array()
            .context("AWS returned an invalid nested change list")?;
        for change in changes {
            let resource = &change["ResourceChange"];
            let logical_id = required_string(resource, "LogicalResourceId")?;
            let resource_type = required_string(resource, "ResourceType")?;
            let action = required_string(resource, "Action")?;
            let replacement = resource["Replacement"].as_str();
            anyhow::ensure!(
                ALLOWED_STACK_RESOURCE_TYPES.contains(&resource_type),
                "change set contains unapproved resource type {resource_type}"
            );
            match change_type {
                "CREATE" => anyhow::ensure!(
                    action == "Add",
                    "create change set contains unexpected {action} action"
                ),
                "UPDATE" => anyhow::ensure!(
                    matches!(action, "Add" | "Modify"),
                    "update change set contains destructive {action} action"
                ),
                _ => unreachable!(),
            }
            anyhow::ensure!(
                replacement.is_none() || replacement == Some("False"),
                "change set would replace {resource_type}: {}",
                replacement.unwrap_or("unknown")
            );
            let entry_path = format!("{path}/{logical_id}");
            flattened.push(json!({
                "path": entry_path,
                "action": action,
                "resource_type": resource_type,
                "replacement": replacement.unwrap_or("not_applicable"),
            }));
            anyhow::ensure!(
                flattened.len() <= 1_000,
                "change-set resource count exceeds bounds"
            );
            if resource_type == "AWS::CloudFormation::Stack" {
                let child_id = required_string(resource, "ChangeSetId")?.to_owned();
                pending.push((entry_path, child_id, depth + 1, None));
            }
        }
    }
    anyhow::ensure!(!flattened.is_empty(), "change-set tree contains no changes");
    flattened.sort_by(|left, right| {
        left["path"]
            .as_str()
            .unwrap_or_default()
            .cmp(right["path"].as_str().unwrap_or_default())
    });
    Ok(flattened)
}

fn print_change_set_review(change_set_name: &str, changes: &[Value]) -> Result<()> {
    println!(
        "{}",
        serde_json::to_string_pretty(&json!({
            "change_set_name": change_set_name,
            "recursive_review": "passed",
            "resource_count": changes.len(),
            "changes": changes,
        }))?
    );
    Ok(())
}

fn aws_json<I, S>(arguments: I) -> Result<Value>
where
    I: IntoIterator<Item = S>,
    S: AsRef<std::ffi::OsStr>,
{
    let mut arguments = arguments
        .into_iter()
        .map(|value| value.as_ref().to_owned())
        .collect::<Vec<_>>();
    arguments.push("--output".into());
    arguments.push("json".into());
    arguments.push("--no-cli-pager".into());
    let output = aws_output(arguments)?;
    anyhow::ensure!(output.status.success(), "AWS command failed");
    serde_json::from_slice(&output.stdout).context("AWS returned invalid JSON")
}

fn aws<I, S>(arguments: I) -> Result<()>
where
    I: IntoIterator<Item = S>,
    S: AsRef<std::ffi::OsStr>,
{
    let mut arguments = arguments
        .into_iter()
        .map(|value| value.as_ref().to_owned())
        .collect::<Vec<_>>();
    arguments.push("--no-cli-pager".into());
    let output = aws_output(arguments)?;
    anyhow::ensure!(output.status.success(), "AWS command failed");
    Ok(())
}

fn aws_output<I, S>(arguments: I) -> Result<Output>
where
    I: IntoIterator<Item = S>,
    S: AsRef<std::ffi::OsStr>,
{
    Command::new("aws")
        .args(arguments)
        .env("AWS_PAGER", "")
        .output()
        .context("running the AWS CLI; install AWS CLI v2 and authenticate first")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn descriptor_primitives_are_strict() {
        assert!(valid_lower_id("bridgefu-demo", 3, 24));
        assert!(!valid_lower_id("Bridgefu", 3, 24));
        assert!(valid_region("us-west-2"));
        assert!(!valid_region("US West 2"));
        assert!(valid_stack_name("bridgefu-demo"));
        assert!(!valid_stack_name("bridgefu_demo"));
        assert!(valid_parameter_key("ConnectInstanceArn"));
        assert!(!valid_parameter_key("connect-instance"));
        assert!(valid_account_id("123456789012"));
        assert!(!valid_account_id("1234"));
        assert!(valid_role_arn(
            "arn:aws:iam::123456789012:role/bridgefu-production-cloudformation",
            "123456789012"
        ));
        assert!(!valid_role_arn(
            "arn:aws:iam::999999999999:role/bridgefu-production-cloudformation",
            "123456789012"
        ));
    }

    #[test]
    fn template_urls_are_https_and_credential_free() {
        assert!(validate_template_url("https://release.example/sha256/template.yaml").is_ok());
        assert!(validate_template_url("http://release.example/template.yaml").is_err());
        assert!(validate_template_url("https://user:pass@example/template.yaml").is_err());
    }

    #[test]
    fn status_outputs_drop_credential_bearing_names() {
        let stack = json!({
            "Outputs": [
                {"OutputKey": "SipUri", "OutputValue": "sips:bridge@example.test"},
                {"OutputKey": "PrivateToken", "OutputValue": "must-not-print"}
            ]
        });
        let outputs = safe_outputs(&stack).unwrap();
        assert_eq!(outputs.len(), 1);
        assert!(outputs.contains_key("SipUri"));
        assert!(!serde_json::to_string(&outputs)
            .unwrap()
            .contains("must-not-print"));
    }

    #[test]
    fn recipe_deployment_requires_an_exact_builtin_selector() {
        assert_eq!(
            recipe_id("builtin:vapi-amazon-connect-screen-pop@1").unwrap(),
            "vapi-amazon-connect-screen-pop@1"
        );
        assert!(recipe_id("external:example@1").is_err());
        assert!(recipe_id("builtin:example").is_err());
    }

    #[test]
    fn canonical_admin_descriptor_and_parameters_parse_together() {
        let descriptor = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("recipes/vapi-amazon-connect-screen-pop/deployment.example.yaml");
        let loaded = load(&descriptor, DeploymentProfile::Starter).unwrap();
        assert_eq!(loaded.descriptor.schema_version, 2);
        assert_eq!(
            loaded.descriptor.environment,
            Some(DeploymentEnvironment::Production)
        );
        assert!(loaded.descriptor.termination_protection == Some(true));
        assert_eq!(
            loaded.descriptor.recipe,
            "builtin:vapi-amazon-connect-screen-pop@1"
        );
        assert!(loaded.parameters_file.ends_with("parameters-starter.json"));
        let ha = load(&descriptor, DeploymentProfile::HighAvailability).unwrap();
        assert!(ha.parameters_file.ends_with("parameters-ha.json"));
    }

    #[test]
    fn canonical_nonproduction_descriptor_and_parameters_parse_together() {
        let descriptor = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("recipes/vapi-amazon-connect-screen-pop/deployment.nonproduction.example.yaml");
        let loaded = load(&descriptor, DeploymentProfile::Starter).unwrap();
        assert_eq!(loaded.descriptor.schema_version, 2);
        assert_eq!(
            loaded.descriptor.environment,
            Some(DeploymentEnvironment::Nonproduction)
        );
        assert_eq!(loaded.descriptor.termination_protection, Some(false));
        assert!(loaded
            .parameters_file
            .ends_with("parameters-nonproduction-starter.json"));
    }

    #[test]
    fn nonproduction_requires_starter_ip_only_sip_without_dns() {
        let descriptor = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("recipes/vapi-amazon-connect-screen-pop/deployment.nonproduction.example.yaml");
        let mut loaded = load(&descriptor, DeploymentProfile::Starter).unwrap();
        loaded
            .parameters
            .insert("SipSecurity".to_owned(), "sip_rtp".to_owned());
        loaded
            .parameters
            .insert("PublicHostedZoneId".to_owned(), "none".to_owned());

        assert!(validate_environment_parameters(
            &loaded,
            DeploymentProfile::Starter,
            DeploymentEnvironment::Nonproduction,
        )
        .is_ok());
        assert_eq!(
            validate_sip_prerequisites(&loaded).unwrap(),
            "ip_only_sip_rtp_no_dns_or_acm"
        );

        assert!(validate_environment_parameters(
            &loaded,
            DeploymentProfile::HighAvailability,
            DeploymentEnvironment::Nonproduction,
        )
        .is_err());
        loaded
            .parameters
            .insert("PublicHostedZoneId".to_owned(), "ZUNEXPECTED".to_owned());
        assert!(validate_sip_prerequisites(&loaded).is_err());
        loaded
            .parameters
            .insert("SipSecurity".to_owned(), "sips_srtp".to_owned());
        assert!(validate_environment_parameters(
            &loaded,
            DeploymentProfile::Starter,
            DeploymentEnvironment::Nonproduction,
        )
        .is_err());
    }

    #[test]
    fn production_keeps_the_secure_sips_posture() {
        let descriptor = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("recipes/vapi-amazon-connect-screen-pop/deployment.example.yaml");
        let mut loaded = load(&descriptor, DeploymentProfile::Starter).unwrap();
        assert!(validate_environment_parameters(
            &loaded,
            DeploymentProfile::Starter,
            DeploymentEnvironment::Production,
        )
        .is_ok());
        loaded
            .parameters
            .insert("SipSecurity".to_owned(), "sip_rtp".to_owned());
        assert!(validate_environment_parameters(
            &loaded,
            DeploymentProfile::Starter,
            DeploymentEnvironment::Production,
        )
        .is_err());
    }

    #[test]
    fn reviewed_change_set_is_release_parameter_and_role_bound() {
        let descriptor = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("recipes/vapi-amazon-connect-screen-pop/deployment.example.yaml");
        let loaded = load(&descriptor, DeploymentProfile::Starter).unwrap();
        let tags = change_set_tags(&loaded)
            .unwrap()
            .into_iter()
            .map(|(key, value)| json!({"Key": key, "Value": value}))
            .collect::<Vec<_>>();
        let rollback_triggers = loaded
            .descriptor
            .rollback_alarm_arns
            .iter()
            .map(|arn| json!({"Arn": arn, "Type": "AWS::CloudWatch::Alarm"}))
            .collect::<Vec<_>>();
        let mut review = json!({
            "Status": "CREATE_COMPLETE",
            "ExecutionStatus": "AVAILABLE",
            "StackName": loaded.descriptor.stack_name.clone(),
            "ChangeSetName": "bridgefu-production-r1",
            "ChangeSetType": "CREATE",
            "RoleARN": loaded.descriptor.cloudformation_service_role_arn.clone(),
            "Description": change_set_description(&loaded, DeploymentProfile::Starter).unwrap(),
            "IncludeNestedStacks": true,
            "Capabilities": ["CAPABILITY_NAMED_IAM", "CAPABILITY_AUTO_EXPAND"],
            "Tags": tags,
            "RollbackConfiguration": {"RollbackTriggers": rollback_triggers},
            "OnStackFailure": "ROLLBACK"
        });
        assert_eq!(
            validate_change_set_binding(
                &review,
                &loaded,
                DeploymentProfile::Starter,
                "bridgefu-production-r1"
            )
            .unwrap(),
            "CREATE"
        );
        review["Description"] = json!("unbound review");
        assert!(validate_change_set_binding(
            &review,
            &loaded,
            DeploymentProfile::Starter,
            "bridgefu-production-r1"
        )
        .is_err());
    }

    #[test]
    fn nested_policy_protects_stateful_resources_only() {
        let resources = json!({
            "StackResourceSummaries": [
                {"LogicalResourceId": "Data", "ResourceType": "AWS::DynamoDB::Table"},
                {"LogicalResourceId": "Function", "ResourceType": "AWS::Lambda::Function"},
                {"LogicalResourceId": "Vpc", "ResourceType": "AWS::EC2::VPC"}
            ]
        });
        let policy = nested_protection_policy(&resources).unwrap();
        let protected = policy["Statement"][1]["Resource"].as_array().unwrap();
        assert_eq!(
            protected,
            &vec![
                json!("LogicalResourceId/Data"),
                json!("LogicalResourceId/Vpc")
            ]
        );
    }
}
