use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeSet;
use std::process::Command;
use zeroize::Zeroizing;

const MAX_AWS_RESPONSE_BYTES: usize = 8 * 1024 * 1024;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AwsCallerIdentity {
    pub account_id: String,
    pub principal_arn: String,
    pub user_id: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ConnectInstanceSummary {
    pub region: String,
    pub id: String,
    pub arn: String,
    pub alias: String,
    pub status: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ConnectFlowSummary {
    pub id: String,
    pub arn: String,
    pub name: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HostedZoneSummary {
    pub id: String,
    pub name: String,
}

/// Small, shell-free AWS CLI adapter shared by the desktop app and CLI.
#[derive(Clone, Debug, Default)]
pub struct AwsCli;

impl AwsCli {
    pub fn list_profiles(&self) -> Result<Vec<String>> {
        let output = run_aws(None, ["configure", "list-profiles"], false)?;
        let text = String::from_utf8(output).context("AWS profile output was not UTF-8")?;
        let profiles = text
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty() && line.len() <= 128)
            .map(str::to_owned)
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();
        Ok(profiles)
    }

    pub fn caller_identity(&self, profile: &str) -> Result<AwsCallerIdentity> {
        let value = aws_json(profile, ["sts", "get-caller-identity"])?;
        let account_id = required_string(&value, "Account")?.to_owned();
        if account_id.len() != 12 || !account_id.bytes().all(|item| item.is_ascii_digit()) {
            bail!("AWS returned an invalid account ID");
        }
        Ok(AwsCallerIdentity {
            account_id,
            principal_arn: required_string(&value, "Arn")?.to_owned(),
            user_id: required_string(&value, "UserId")?.to_owned(),
        })
    }

    pub fn enabled_regions(&self, profile: &str) -> Result<Vec<String>> {
        let value = aws_json(profile, ["ec2", "describe-regions", "--all-regions"])?;
        let mut regions = value["Regions"]
            .as_array()
            .context("AWS returned no regions")?
            .iter()
            .filter(|item| {
                matches!(
                    item["OptInStatus"].as_str(),
                    None | Some("opt-in-not-required") | Some("opted-in")
                )
            })
            .filter_map(|item| item["RegionName"].as_str())
            .map(str::to_owned)
            .collect::<Vec<_>>();
        regions.sort();
        regions.dedup();
        Ok(regions)
    }

    pub fn connect_instances(
        &self,
        profile: &str,
        regions: &[String],
    ) -> Result<Vec<ConnectInstanceSummary>> {
        let mut result = Vec::new();
        for region in regions {
            let value = aws_json(profile, ["connect", "list-instances", "--region", region])?;
            for item in value["InstanceSummaryList"]
                .as_array()
                .context("AWS returned an invalid Connect instance list")?
            {
                let status = item["InstanceStatus"].as_str().unwrap_or("ACTIVE");
                if status != "ACTIVE" {
                    continue;
                }
                result.push(ConnectInstanceSummary {
                    region: region.clone(),
                    id: required_string(item, "Id")?.to_owned(),
                    arn: required_string(item, "Arn")?.to_owned(),
                    alias: item["InstanceAlias"]
                        .as_str()
                        .unwrap_or("unnamed")
                        .to_owned(),
                    status: status.to_owned(),
                });
            }
        }
        result.sort_by(|left, right| {
            (&left.region, &left.alias, &left.id).cmp(&(&right.region, &right.alias, &right.id))
        });
        Ok(result)
    }

    pub fn published_contact_flows(
        &self,
        profile: &str,
        region: &str,
        instance_id: &str,
    ) -> Result<Vec<ConnectFlowSummary>> {
        validate_identifier("Connect instance ID", instance_id)?;
        let value = aws_json(
            profile,
            [
                "connect",
                "list-contact-flows",
                "--region",
                region,
                "--instance-id",
                instance_id,
                "--contact-flow-types",
                "CONTACT_FLOW",
            ],
        )?;
        let mut flows = value["ContactFlowSummaryList"]
            .as_array()
            .context("AWS returned an invalid contact-flow list")?
            .iter()
            .filter(|item| item["ContactFlowState"].as_str().unwrap_or("ACTIVE") == "ACTIVE")
            .map(|item| {
                Ok(ConnectFlowSummary {
                    id: required_string(item, "Id")?.to_owned(),
                    arn: required_string(item, "Arn")?.to_owned(),
                    name: required_string(item, "Name")?.to_owned(),
                })
            })
            .collect::<Result<Vec<_>>>()?;
        flows.sort_by(|left, right| (&left.name, &left.id).cmp(&(&right.name, &right.id)));
        Ok(flows)
    }

    pub fn public_hosted_zones(&self, profile: &str) -> Result<Vec<HostedZoneSummary>> {
        let value = aws_json(profile, ["route53", "list-hosted-zones"])?;
        let mut zones = value["HostedZones"]
            .as_array()
            .context("AWS returned an invalid hosted-zone list")?
            .iter()
            .filter(|item| {
                item.pointer("/Config/PrivateZone").and_then(Value::as_bool) == Some(false)
            })
            .map(|item| {
                Ok(HostedZoneSummary {
                    id: required_string(item, "Id")?
                        .trim_start_matches("/hostedzone/")
                        .to_owned(),
                    name: required_string(item, "Name")?.to_owned(),
                })
            })
            .collect::<Result<Vec<_>>>()?;
        zones.sort_by(|left, right| (&left.name, &left.id).cmp(&(&right.name, &right.id)));
        Ok(zones)
    }

    pub fn secret_string(&self, profile: &str, region: &str, secret_id: &str) -> Result<String> {
        validate_secret_reference(secret_id)?;
        let value = aws_json(
            profile,
            [
                "secretsmanager",
                "get-secret-value",
                "--region",
                region,
                "--secret-id",
                secret_id,
            ],
        )?;
        let secret = required_string(&value, "SecretString")?;
        if secret.is_empty() || secret.len() > 16_384 {
            bail!("Secrets Manager returned an invalid value");
        }
        Ok(secret.to_owned())
    }

    /// Bind the public Vapi webhooks to the one organization and assistant
    /// created by this deployment. The binding is deliberately stored apart
    /// from the webhook bearer: it is desired-state identity, not a credential.
    pub fn bind_vapi_identity(
        &self,
        profile: &str,
        region: &str,
        secret_id: &str,
        organization_id: &str,
        assistant_id: &str,
    ) -> Result<()> {
        validate_secret_reference(secret_id)?;
        validate_identifier("Vapi organization ID", organization_id)?;
        validate_identifier("Vapi assistant ID", assistant_id)?;
        let expected = serde_json::json!({
            "status": "bound",
            "organization_id": organization_id,
            "assistant_id": assistant_id,
        });
        let encoded = serde_json::to_string(&expected)?;
        run_aws(
            Some(profile),
            [
                "secretsmanager",
                "put-secret-value",
                "--region",
                region,
                "--secret-id",
                secret_id,
                "--secret-string",
                encoded.as_str(),
            ],
            true,
        )?;
        let verified: Value =
            serde_json::from_str(&self.secret_string(profile, region, secret_id)?)
                .context("Vapi identity binding was not valid JSON after writing it")?;
        if verified != expected {
            bail!("Vapi identity binding could not be verified after writing it");
        }
        Ok(())
    }

    /// Generate and install a replacement webhook bearer without exposing it
    /// through command arguments, environment variables, or a temporary file.
    pub async fn rotate_webhook_secret(
        &self,
        profile: &str,
        region: &str,
        secret_id: &str,
    ) -> Result<Zeroizing<String>> {
        validate_profile(profile)?;
        validate_identifier("AWS region", region)?;
        validate_secret_reference(secret_id)?;
        let sdk = aws_config::defaults(aws_config::BehaviorVersion::latest())
            .profile_name(profile)
            .region(aws_config::Region::new(region.to_owned()))
            .load()
            .await;
        let client = aws_sdk_secretsmanager::Client::new(&sdk);
        let generated = client
            .get_random_password()
            .password_length(64)
            .exclude_punctuation(true)
            .send()
            .await
            .context("generating a replacement webhook credential")?;
        let replacement = generated
            .random_password()
            .filter(|value| value.len() == 64)
            .context("Secrets Manager returned an invalid replacement credential")?;
        client
            .put_secret_value()
            .secret_id(secret_id)
            .secret_string(replacement)
            .send()
            .await
            .context("writing the replacement webhook credential")?;
        let verified = client
            .get_secret_value()
            .secret_id(secret_id)
            .send()
            .await
            .context("verifying the replacement webhook credential")?;
        if verified.secret_string() != Some(replacement) {
            bail!("replacement webhook credential could not be verified");
        }
        Ok(Zeroizing::new(replacement.to_owned()))
    }
}

fn validate_secret_reference(secret_id: &str) -> Result<()> {
    if !secret_id.starts_with("arn:")
        || secret_id.len() > 2_048
        || secret_id.chars().any(char::is_control)
    {
        bail!("invalid Secrets Manager reference");
    }
    Ok(())
}

fn aws_json<const N: usize>(profile: &str, arguments: [&str; N]) -> Result<Value> {
    let bytes = run_aws(Some(profile), arguments, true)?;
    serde_json::from_slice(&bytes).context("AWS returned invalid JSON")
}

fn run_aws<const N: usize>(
    profile: Option<&str>,
    arguments: [&str; N],
    json: bool,
) -> Result<Vec<u8>> {
    if let Some(profile) = profile {
        validate_profile(profile)?;
    }
    let mut command = Command::new("aws");
    command.args(arguments).env("AWS_PAGER", "");
    if let Some(profile) = profile {
        command.arg("--profile").arg(profile);
    }
    if json {
        command.arg("--output").arg("json");
    }
    command.arg("--no-cli-pager");
    let output = command
        .output()
        .context("running AWS CLI v2; install it and sign in first")?;
    if !output.status.success() {
        let summary = String::from_utf8_lossy(&output.stderr)
            .lines()
            .next()
            .unwrap_or("AWS command failed")
            .chars()
            .filter(|character| !character.is_control())
            .take(300)
            .collect::<String>();
        bail!("AWS command failed: {summary}");
    }
    if output.stdout.len() > MAX_AWS_RESPONSE_BYTES {
        bail!("AWS response exceeded the safe size limit");
    }
    Ok(output.stdout)
}

fn validate_profile(value: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > 128
        || value.chars().any(char::is_control)
        || value.starts_with('-')
    {
        bail!("invalid AWS profile");
    }
    Ok(())
}

fn validate_identifier(name: &str, value: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|item| item.is_ascii_alphanumeric() || matches!(item, b'-' | b'_'))
    {
        bail!("invalid {name}");
    }
    Ok(())
}

fn required_string<'a>(value: &'a Value, key: &str) -> Result<&'a str> {
    value[key]
        .as_str()
        .filter(|item| !item.is_empty() && item.len() <= 4_096)
        .with_context(|| format!("AWS response omitted {key}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn profile_and_identifiers_cannot_be_cli_options() {
        assert!(validate_profile("--region").is_err());
        assert!(validate_profile("company-sso").is_ok());
        assert!(validate_identifier("instance", "abc-123").is_ok());
        assert!(validate_identifier("instance", "../bad").is_err());
        assert!(validate_secret_reference(
            "arn:aws:secretsmanager:us-west-2:123456789012:secret:bridgefu-test"
        )
        .is_ok());
        assert!(validate_secret_reference("--secret-id").is_err());
    }

    #[test]
    fn discovery_models_never_hold_credentials() {
        let encoded = serde_json::to_string(&AwsCallerIdentity {
            account_id: "123456789012".into(),
            principal_arn: "arn:aws:sts::123456789012:assumed-role/Developer/session".into(),
            user_id: "role:session".into(),
        })
        .unwrap();
        assert!(!encoded.to_ascii_lowercase().contains("credential"));
        assert!(!encoded.to_ascii_lowercase().contains("token"));
    }
}
