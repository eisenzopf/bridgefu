use crate::api::VapiApi;
use crate::extension::SecretResolver;
use crate::model::{
    OwnedTemplateBundle, OwnedTemplatePlan, OwnedTemplateResult, OwnedTemplateState,
    TemplatePlanAction,
};
use anyhow::{bail, Context, Result};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

const BUNDLE_SCHEMA: &str = "vapire.bridgefu-template-bundle/v1";
const STATE_SCHEMA: &str = "vapire.owned-template-state/v1";
const PLAN_SCHEMA: &str = "vapire.owned-template-plan/v1";

pub async fn plan_owned_template(
    api: &dyn VapiApi,
    bundle: &OwnedTemplateBundle,
    state: Option<&OwnedTemplateState>,
) -> Result<OwnedTemplatePlan> {
    validate_bundle(bundle)?;
    let desired_artifact_hash = artifact_hash(bundle)?;
    if let Some(state) = state {
        validate_state(bundle, state)?;
        let remote = api
            .get("assistant", &state.assistant_id)
            .await?
            .context("recorded Bridgefu template assistant is missing")?;
        verify_owner(&remote, &state.owner_hash)?;
        let remote_hash = digest(&remote)?;
        let action = if remote_hash == state.created_assistant_hash {
            TemplatePlanAction::AlreadyCreated
        } else {
            // A customer is expected to customize the generated template. The
            // default lifecycle reports those changes and never overwrites them.
            TemplatePlanAction::RemoteDriftRetained
        };
        return Ok(OwnedTemplatePlan {
            schema: PLAN_SCHEMA.into(),
            deployment_id: bundle.assistant.deployment_id.clone(),
            desired_artifact_hash,
            actions: vec![action],
            masked_diff: "The Bridgefu template already exists. Remote edits are retained; no update will be sent.\n".into(),
            remote_assistant_hash: Some(remote_hash),
        });
    }
    Ok(OwnedTemplatePlan {
        schema: PLAN_SCHEMA.into(),
        deployment_id: bundle.assistant.deployment_id.clone(),
        desired_artifact_hash,
        actions: vec![
            TemplatePlanAction::CreateCredential,
            TemplatePlanAction::CreateTool,
            TemplatePlanAction::CreateAssistant,
        ],
        masked_diff: serde_json::to_string_pretty(&json!({
            "create": {
                "credential": {"name": bundle.credential.name, "secret": "<redacted>"},
                "tool": bundle.tool.spec,
                "assistant": desired_assistant_preview(bundle)
            },
            "existingAssistantsModified": false
        }))?,
        remote_assistant_hash: None,
    })
}

pub async fn create_owned_template(
    api: &dyn VapiApi,
    resolver: &dyn SecretResolver,
    bundle: &OwnedTemplateBundle,
    plan: &OwnedTemplatePlan,
    state: Option<&OwnedTemplateState>,
) -> Result<OwnedTemplateResult> {
    validate_bundle(bundle)?;
    if let Some(existing) = state {
        let status = plan_owned_template(api, bundle, Some(existing)).await?;
        let assistant = api
            .get("assistant", &existing.assistant_id)
            .await?
            .context("recorded Bridgefu template assistant is missing")?;
        if status.desired_artifact_hash != plan.desired_artifact_hash {
            bail!("reviewed template plan does not match the current artifact");
        }
        return Ok(OwnedTemplateResult {
            state: existing.clone(),
            assistant,
        });
    }
    if plan.schema != PLAN_SCHEMA
        || plan.deployment_id != bundle.assistant.deployment_id
        || plan.desired_artifact_hash != artifact_hash(bundle)?
        || plan.actions
            != vec![
                TemplatePlanAction::CreateCredential,
                TemplatePlanAction::CreateTool,
                TemplatePlanAction::CreateAssistant,
            ]
    {
        bail!("reviewed template plan does not match the current artifact");
    }
    let bearer = resolver
        .resolve(&bundle.credential.bearer_secret_ref)
        .await?;
    if bearer.len() < 32 {
        bail!("resolved webhook credential is invalid");
    }
    let endpoint = resolver.resolve(&bundle.tool.endpoint_ref).await?;
    validate_https_url(&endpoint)?;
    let server_endpoint = match &bundle.assistant.server_endpoint_ref {
        Some(reference) => {
            let value = resolver.resolve(reference).await?;
            validate_https_url(&value)?;
            Some(value)
        }
        None => None,
    };
    let credential = api
        .create(
            "credential",
            &json!({
                "provider": "custom-credential",
                "name": bundle.credential.name,
                "authenticationPlan": {
                    "type": "bearer",
                    "token": bearer,
                    "headerName": "Authorization",
                    "bearerPrefixEnabled": true
                }
            }),
        )
        .await?;
    let credential_id = resource_id(&credential)?.to_string();

    let mut tool_payload = bundle.tool.spec.clone();
    tool_payload
        .as_object_mut()
        .context("tool spec must be an object")?
        .insert(
            "server".into(),
            json!({"url": endpoint, "credentialId": credential_id}),
        );
    let tool = match api.create("tool", &tool_payload).await {
        Ok(value) => value,
        Err(error) => {
            let _ = api.delete("credential", &credential_id).await;
            return Err(error);
        }
    };
    let tool_id = resource_id(&tool)?.to_string();
    let owner_hash = owner_hash(bundle);
    let assistant_payload = desired_assistant(
        bundle,
        &tool_id,
        &owner_hash,
        server_endpoint
            .as_deref()
            .map(|url| (url, credential_id.as_str())),
    )?;
    let assistant = match api.create("assistant", &assistant_payload).await {
        Ok(value) => value,
        Err(error) => {
            let _ = api.delete("tool", &tool_id).await;
            let _ = api.delete("credential", &credential_id).await;
            return Err(error);
        }
    };
    let assistant_id = resource_id(&assistant)?.to_string();
    let verified = api
        .get("assistant", &assistant_id)
        .await?
        .context("created template assistant could not be verified")?;
    verify_owner(&verified, &owner_hash)?;
    let organization_id = verified
        .get("orgId")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty() && value.len() <= 128)
        .context("created template assistant did not contain an organization ID")?
        .to_owned();
    let state = OwnedTemplateState {
        schema: STATE_SCHEMA.into(),
        deployment_id: bundle.assistant.deployment_id.clone(),
        credential_id,
        tool_id,
        assistant_id,
        organization_id,
        owner_hash,
        desired_artifact_hash: artifact_hash(bundle)?,
        created_assistant_hash: digest(&verified)?,
    };
    Ok(OwnedTemplateResult {
        state,
        assistant: verified,
    })
}

/// Explicit destructive operation. Normal Bridgefu uninstall retains the
/// generated template so customer customizations are never discarded.
pub async fn delete_owned_template(
    api: &dyn VapiApi,
    bundle: &OwnedTemplateBundle,
    state: &OwnedTemplateState,
    confirm_assistant_id: &str,
) -> Result<()> {
    validate_bundle(bundle)?;
    validate_state(bundle, state)?;
    if confirm_assistant_id != state.assistant_id {
        bail!("template deletion confirmation must equal the assistant ID");
    }
    let assistant = api
        .get("assistant", &state.assistant_id)
        .await?
        .context("recorded Bridgefu template assistant is missing")?;
    verify_owner(&assistant, &state.owner_hash)?;
    let attached = assistant
        .pointer("/model/toolIds")
        .and_then(Value::as_array)
        .is_some_and(|ids| ids.iter().any(|id| id.as_str() == Some(&state.tool_id)));
    if !attached {
        bail!("template assistant no longer proves ownership of its Bridgefu tool");
    }
    if api.get("tool", &state.tool_id).await?.is_none()
        || api.get("credential", &state.credential_id).await?.is_none()
    {
        bail!("template resource ownership is incomplete");
    }
    api.delete("assistant", &state.assistant_id).await?;
    api.delete("tool", &state.tool_id).await?;
    api.delete("credential", &state.credential_id).await?;
    Ok(())
}

/// Rotate only the credential created for this owned template. The operation
/// proves the assistant/tool ownership chain first and never rewrites the
/// assistant or any customer-customized prompt/model settings.
pub async fn rotate_owned_template_credential(
    api: &dyn VapiApi,
    bundle: &OwnedTemplateBundle,
    state: &OwnedTemplateState,
    bearer: &str,
) -> Result<()> {
    validate_bundle(bundle)?;
    validate_state(bundle, state)?;
    if bearer.len() < 32 || bearer.len() > 16_384 {
        bail!("replacement webhook credential is invalid");
    }
    let assistant = api
        .get("assistant", &state.assistant_id)
        .await?
        .context("recorded Bridgefu template assistant is missing")?;
    verify_owner(&assistant, &state.owner_hash)?;
    let attached = assistant
        .pointer("/model/toolIds")
        .and_then(Value::as_array)
        .is_some_and(|ids| ids.iter().any(|id| id.as_str() == Some(&state.tool_id)));
    if !attached
        || api.get("tool", &state.tool_id).await?.is_none()
        || api.get("credential", &state.credential_id).await?.is_none()
    {
        bail!("template resource ownership is incomplete");
    }
    api.update(
        "credential",
        &state.credential_id,
        &json!({
            "provider": "custom-credential",
            "name": bundle.credential.name,
            "authenticationPlan": {
                "type": "bearer",
                "token": bearer,
                "headerName": "Authorization",
                "bearerPrefixEnabled": true
            }
        }),
    )
    .await?;
    let verified = api
        .get("credential", &state.credential_id)
        .await?
        .context("rotated Bridgefu credential could not be verified")?;
    if resource_id(&verified)? != state.credential_id {
        bail!("rotated Bridgefu credential identity changed unexpectedly");
    }
    Ok(())
}

fn desired_assistant_preview(bundle: &OwnedTemplateBundle) -> Value {
    desired_assistant(
        bundle,
        "<created:bridgefu-tool>",
        &owner_hash(bundle),
        bundle.assistant.server_endpoint_ref.as_ref().map(|_| {
            (
                "<resolved:bridgefu-transfer-webhook>",
                "<created:bridgefu-credential>",
            )
        }),
    )
    .unwrap_or_else(|_| json!({"invalid": true}))
}

fn desired_assistant(
    bundle: &OwnedTemplateBundle,
    tool_id: &str,
    owner_hash: &str,
    server: Option<(&str, &str)>,
) -> Result<Value> {
    let mut assistant = bundle.assistant.spec.clone();
    let root = assistant
        .as_object_mut()
        .context("assistant spec must be an object")?;
    let model = root
        .entry("model")
        .or_insert_with(|| json!({}))
        .as_object_mut()
        .context("assistant model must be an object")?;
    let tool_ids = model
        .entry("toolIds")
        .or_insert_with(|| json!([]))
        .as_array_mut()
        .context("assistant model.toolIds must be an array")?;
    if !tool_ids.iter().any(|item| item.as_str() == Some(tool_id)) {
        tool_ids.push(json!(tool_id));
    }
    let messages = model
        .entry("messages")
        .or_insert_with(|| json!([]))
        .as_array_mut()
        .context("assistant model.messages must be an array")?;
    if messages.iter().any(|message| {
        message
            .get("content")
            .and_then(Value::as_str)
            .is_some_and(|content| content.starts_with(&bundle.assistant.prompt_marker))
    }) {
        bail!("assistant spec already contains the reserved Bridgefu prompt marker");
    }
    messages.push(json!({
        "role": "system",
        "content": format!("{}\n{}", bundle.assistant.prompt_marker, bundle.assistant.prompt)
    }));
    if let Some((url, credential_id)) = server {
        root.insert(
            "server".into(),
            json!({"url": url, "credentialId": credential_id}),
        );
    }
    let metadata = root
        .entry("metadata")
        .or_insert_with(|| json!({}))
        .as_object_mut()
        .context("assistant metadata must be an object")?;
    metadata.insert("managedBy".into(), json!("bridgefu-setup"));
    metadata.insert(
        "bridgefuDeployment".into(),
        json!(bundle.assistant.deployment_id),
    );
    metadata.insert("bridgefuOwner".into(), json!(owner_hash));
    Ok(assistant)
}

fn validate_bundle(bundle: &OwnedTemplateBundle) -> Result<()> {
    if bundle.schema != BUNDLE_SCHEMA {
        bail!("unsupported owned-template bundle schema");
    }
    for (name, value) in [
        ("credential slug", bundle.credential.slug.as_str()),
        ("tool slug", bundle.tool.slug.as_str()),
        ("assistant slug", bundle.assistant.slug.as_str()),
        ("deployment ID", bundle.assistant.deployment_id.as_str()),
    ] {
        if value.is_empty()
            || value.len() > 128
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        {
            bail!("invalid {name}");
        }
    }
    if bundle.tool.credential_ref != format!("credential:{}", bundle.credential.slug)
        || bundle.assistant.tool_ref != format!("tool:{}", bundle.tool.slug)
    {
        bail!("owned-template references do not match their resources");
    }
    if !bundle.assistant.prompt_marker.starts_with("[BRIDGEFU:")
        || !bundle.assistant.prompt_marker.ends_with(']')
        || bundle.assistant.prompt_marker.contains('\n')
        || bundle.assistant.prompt.is_empty()
    {
        bail!("invalid Bridgefu template prompt");
    }
    if bundle
        .assistant
        .server_endpoint_ref
        .as_ref()
        .is_some_and(|value| value != "aws-output:VapiTransferUrl")
    {
        bail!("invalid Bridgefu transfer webhook reference");
    }
    Ok(())
}

fn validate_state(bundle: &OwnedTemplateBundle, state: &OwnedTemplateState) -> Result<()> {
    if state.schema != STATE_SCHEMA
        || state.deployment_id != bundle.assistant.deployment_id
        || state.desired_artifact_hash != artifact_hash(bundle)?
        || state.owner_hash != owner_hash(bundle)
    {
        bail!("owned-template state does not match the artifact");
    }
    for value in [
        state.assistant_id.as_str(),
        state.organization_id.as_str(),
        state.tool_id.as_str(),
        state.credential_id.as_str(),
    ] {
        if value.is_empty() || value.len() > 128 {
            bail!("owned-template state contains an invalid resource ID");
        }
    }
    Ok(())
}

fn verify_owner(assistant: &Value, owner: &str) -> Result<()> {
    if assistant
        .pointer("/metadata/managedBy")
        .and_then(Value::as_str)
        != Some("bridgefu-setup")
        || assistant
            .pointer("/metadata/bridgefuOwner")
            .and_then(Value::as_str)
            != Some(owner)
    {
        bail!("Vapi assistant ownership could not be proven");
    }
    Ok(())
}

fn owner_hash(bundle: &OwnedTemplateBundle) -> String {
    sha256(
        format!(
            "bridgefu-template|{}|{}",
            bundle.assistant.deployment_id, bundle.assistant.slug
        )
        .as_bytes(),
    )
}

fn artifact_hash(bundle: &OwnedTemplateBundle) -> Result<String> {
    digest(&serde_json::to_value(bundle)?)
}

fn resource_id(value: &Value) -> Result<&str> {
    value
        .get("id")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty() && value.len() <= 128)
        .context("Vapi create response did not contain an ID")
}

fn digest(value: &Value) -> Result<String> {
    Ok(sha256(&serde_json::to_vec(&canonicalize(value))?))
}

fn canonicalize(value: &Value) -> Value {
    match value {
        Value::Object(object) => {
            let mut keys: Vec<_> = object.keys().collect();
            keys.sort();
            let mut result = Map::new();
            for key in keys {
                result.insert(key.clone(), canonicalize(&object[key]));
            }
            Value::Object(result)
        }
        Value::Array(values) => Value::Array(values.iter().map(canonicalize).collect()),
        other => other.clone(),
    }
}

fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn validate_https_url(value: &str) -> Result<()> {
    let parsed = url::Url::parse(value).context("invalid tool endpoint")?;
    if parsed.scheme() != "https"
        || parsed.host_str().is_none()
        || parsed.username() != ""
        || parsed.password().is_some()
        || parsed.fragment().is_some()
    {
        bail!("tool endpoint must be a plain HTTPS URL");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use std::collections::BTreeMap;
    use std::sync::Mutex;

    struct MemoryApi {
        resources: Mutex<BTreeMap<String, BTreeMap<String, Value>>>,
        next: Mutex<u32>,
    }

    impl MemoryApi {
        fn new() -> Self {
            Self {
                resources: Mutex::new(BTreeMap::from([
                    ("assistant".into(), BTreeMap::new()),
                    ("tool".into(), BTreeMap::new()),
                    ("credential".into(), BTreeMap::new()),
                ])),
                next: Mutex::new(0),
            }
        }
    }

    #[async_trait]
    impl VapiApi for MemoryApi {
        async fn get(&self, kind: &str, id: &str) -> Result<Option<Value>> {
            Ok(self.resources.lock().unwrap()[kind].get(id).cloned())
        }
        async fn create(&self, kind: &str, body: &Value) -> Result<Value> {
            let mut next = self.next.lock().unwrap();
            *next += 1;
            let id = format!("{kind}_{next}");
            let mut value = body.clone();
            value
                .as_object_mut()
                .unwrap()
                .insert("id".into(), json!(id));
            if kind == "assistant" {
                value
                    .as_object_mut()
                    .unwrap()
                    .insert("orgId".into(), json!("org_test_001"));
            }
            self.resources
                .lock()
                .unwrap()
                .get_mut(kind)
                .unwrap()
                .insert(id, value.clone());
            Ok(value)
        }
        async fn update(&self, kind: &str, id: &str, body: &Value) -> Result<Value> {
            let mut value = body.clone();
            value
                .as_object_mut()
                .unwrap()
                .insert("id".into(), json!(id));
            self.resources
                .lock()
                .unwrap()
                .get_mut(kind)
                .unwrap()
                .insert(id.into(), value.clone());
            Ok(value)
        }
        async fn delete(&self, kind: &str, id: &str) -> Result<()> {
            self.resources
                .lock()
                .unwrap()
                .get_mut(kind)
                .unwrap()
                .remove(id);
            Ok(())
        }
    }

    struct Resolver;
    #[async_trait]
    impl SecretResolver for Resolver {
        async fn resolve(&self, reference: &str) -> Result<String> {
            Ok(match reference {
                "aws-output:VapiWebhookReference" => "s".repeat(40),
                "aws-output:VapiToolUrl" => "https://bridgefu.example.com/vapi/tool".into(),
                "aws-output:VapiTransferUrl" => "https://bridgefu.example.com/vapi/transfer".into(),
                _ => bail!("unknown reference"),
            })
        }
    }

    fn bundle() -> OwnedTemplateBundle {
        OwnedTemplateBundle {
            schema: BUNDLE_SCHEMA.into(),
            credential: crate::model::CredentialArtifact {
                slug: "bridgefu-demo-credential".into(),
                name: "Bridgefu demo".into(),
                bearer_secret_ref: "aws-output:VapiWebhookReference".into(),
            },
            tool: crate::model::ToolArtifact {
                slug: "bridgefu-demo-tool".into(),
                credential_ref: "credential:bridgefu-demo-credential".into(),
                endpoint_ref: "aws-output:VapiToolUrl".into(),
                spec: json!({"type":"function", "function": {
                    "name":"bridgefu_transfer_to_amazon_connect",
                    "parameters":{"type":"object","properties":{}}
                }}),
            },
            assistant: crate::model::OwnedTemplateArtifact {
                slug: "bridgefu-demo-template".into(),
                deployment_id: "demo".into(),
                tool_ref: "tool:bridgefu-demo-tool".into(),
                prompt_marker: "[BRIDGEFU:demo]".into(),
                prompt: "TODO: add your business prompt. Invoke the Bridgefu tool immediately before transfer.".into(),
                server_endpoint_ref: Some("aws-output:VapiTransferUrl".into()),
                spec: json!({
                    "name":"Bridgefu Amazon Connect template",
                    "serverMessages":["transfer-destination-request"],
                    "voice":{"provider":"vapi","voiceId":"Elliot"},
                    "model":{"provider":"openai","model":"gpt-4.1-mini","messages":[],"tools":[{"type":"transferCall","destinations":[]}]}
                }),
            },
        }
    }

    #[tokio::test]
    async fn creates_without_touching_existing_assistants_and_retains_edits() {
        let api = MemoryApi::new();
        api.create("assistant", &json!({"name":"Existing customer assistant"}))
            .await
            .unwrap();
        let bundle = bundle();
        let proposal = plan_owned_template(&api, &bundle, None).await.unwrap();
        let result = create_owned_template(&api, &Resolver, &bundle, &proposal, None)
            .await
            .unwrap();
        assert_eq!(api.resources.lock().unwrap()["assistant"].len(), 2);
        assert_eq!(result.assistant["metadata"]["managedBy"], "bridgefu-setup");
        assert_eq!(result.state.organization_id, "org_test_001");
        assert_eq!(
            result.assistant["model"]["toolIds"]
                .as_array()
                .unwrap()
                .len(),
            1
        );
        assert_eq!(
            result.assistant["server"]["url"],
            "https://bridgefu.example.com/vapi/transfer"
        );
        assert_eq!(
            result.assistant["serverMessages"],
            json!(["transfer-destination-request"])
        );

        api.resources
            .lock()
            .unwrap()
            .get_mut("assistant")
            .unwrap()
            .get_mut(&result.state.assistant_id)
            .unwrap()["name"] = json!("Developer customized");
        let status = plan_owned_template(&api, &bundle, Some(&result.state))
            .await
            .unwrap();
        assert_eq!(
            status.actions,
            vec![TemplatePlanAction::RemoteDriftRetained]
        );
    }

    #[tokio::test]
    async fn deletion_requires_exact_confirmation_and_proven_owner() {
        let api = MemoryApi::new();
        let bundle = bundle();
        let proposal = plan_owned_template(&api, &bundle, None).await.unwrap();
        let result = create_owned_template(&api, &Resolver, &bundle, &proposal, None)
            .await
            .unwrap();
        assert!(delete_owned_template(&api, &bundle, &result.state, "wrong")
            .await
            .is_err());
        delete_owned_template(&api, &bundle, &result.state, &result.state.assistant_id)
            .await
            .unwrap();
        assert!(api.resources.lock().unwrap()["assistant"].is_empty());
    }

    #[tokio::test]
    async fn rotation_updates_only_the_proven_owned_credential() {
        let api = MemoryApi::new();
        let bundle = bundle();
        let proposal = plan_owned_template(&api, &bundle, None).await.unwrap();
        let result = create_owned_template(&api, &Resolver, &bundle, &proposal, None)
            .await
            .unwrap();
        let assistant_before = result.assistant.clone();
        rotate_owned_template_credential(&api, &bundle, &result.state, &"n".repeat(64))
            .await
            .unwrap();
        assert_eq!(
            api.resources.lock().unwrap()["assistant"][&result.state.assistant_id],
            assistant_before
        );
        assert_eq!(
            api.resources.lock().unwrap()["credential"][&result.state.credential_id]
                ["authenticationPlan"]["token"],
            "n".repeat(64)
        );
    }
}
