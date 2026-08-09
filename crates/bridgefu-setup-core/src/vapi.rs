use crate::artifact::vapi_bundle;
use crate::SetupConfiguration;
use anyhow::{bail, Context, Result};
use async_trait::async_trait;
use vapire_iac::{
    create_owned_template, delete_owned_template, plan_owned_template,
    rotate_owned_template_credential, HttpVapiApi, OwnedTemplatePlan, OwnedTemplateState,
    SecretResolver,
};
use zeroize::Zeroizing;

const VAPI_API_BASE: &str = "https://api.vapi.ai/";

/// Values resolved only after CloudFormation succeeds. Both values remain in
/// native memory and are never written to the deployment bundle or journal.
pub struct VapiResolvedInputs {
    pub tool_url: String,
    pub transfer_url: String,
    pub webhook_bearer: Zeroizing<String>,
}

impl VapiResolvedInputs {
    pub fn new(tool_url: String, transfer_url: String, webhook_bearer: String) -> Result<Self> {
        if webhook_bearer.len() < 32 || webhook_bearer.len() > 16_384 {
            bail!("resolved Vapi webhook credential is invalid");
        }
        Ok(Self {
            tool_url,
            transfer_url,
            webhook_bearer: Zeroizing::new(webhook_bearer),
        })
    }
}

struct OutputResolver<'a> {
    values: &'a VapiResolvedInputs,
}

#[async_trait]
impl SecretResolver for OutputResolver<'_> {
    async fn resolve(&self, reference: &str) -> Result<String> {
        match reference {
            "aws-output:VapiToolUrl" => Ok(self.values.tool_url.clone()),
            "aws-output:VapiTransferUrl" => Ok(self.values.transfer_url.clone()),
            "aws-output:VapiWebhookReference" => Ok(self.values.webhook_bearer.as_str().to_owned()),
            _ => bail!("unknown reviewed deployment output reference"),
        }
    }
}

pub async fn plan_vapi_template(
    config: &SetupConfiguration,
    vapi_api_key: String,
    state: Option<&OwnedTemplateState>,
) -> Result<OwnedTemplatePlan> {
    let api = HttpVapiApi::new(VAPI_API_BASE, vapi_api_key)?;
    plan_owned_template(&api, &vapi_bundle(config)?, state).await
}

pub async fn apply_vapi_template(
    config: &SetupConfiguration,
    vapi_api_key: String,
    resolved: &VapiResolvedInputs,
    reviewed_plan: &OwnedTemplatePlan,
    state: Option<&OwnedTemplateState>,
) -> Result<OwnedTemplateState> {
    let api = HttpVapiApi::new(VAPI_API_BASE, vapi_api_key)?;
    let bundle = vapi_bundle(config)?;
    let result = create_owned_template(
        &api,
        &OutputResolver { values: resolved },
        &bundle,
        reviewed_plan,
        state,
    )
    .await
    .context("creating the owned Vapi template assistant")?;
    Ok(result.state)
}

pub async fn delete_vapi_template(
    config: &SetupConfiguration,
    vapi_api_key: String,
    state: &OwnedTemplateState,
    confirm_assistant_id: &str,
) -> Result<()> {
    let api = HttpVapiApi::new(VAPI_API_BASE, vapi_api_key)?;
    delete_owned_template(&api, &vapi_bundle(config)?, state, confirm_assistant_id).await
}

pub async fn rotate_vapi_credential(
    config: &SetupConfiguration,
    vapi_api_key: String,
    state: &OwnedTemplateState,
    replacement_bearer: &str,
) -> Result<()> {
    let api = HttpVapiApi::new(VAPI_API_BASE, vapi_api_key)?;
    rotate_owned_template_credential(&api, &vapi_bundle(config)?, state, replacement_bearer).await
}
