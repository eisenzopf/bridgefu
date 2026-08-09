use crate::api::VapiApi;
use crate::model::{
    ApplyResult, BridgefuVapiBundle, ExtensionPlan, ExtensionState, PlanAction, UnapplyResult,
};
use anyhow::{bail, Context, Result};
use async_trait::async_trait;
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

const BUNDLE_SCHEMA: &str = "vapire.bridgefu-bundle/v1";
const STATE_SCHEMA: &str = "vapire.assistant-extension-state/v1";
const PLAN_SCHEMA: &str = "vapire.assistant-extension-plan/v1";

#[async_trait]
pub trait SecretResolver: Send + Sync {
    async fn resolve(&self, reference: &str) -> Result<String>;
}

pub async fn plan(
    api: &dyn VapiApi,
    bundle: &BridgefuVapiBundle,
    state: Option<&ExtensionState>,
) -> Result<ExtensionPlan> {
    validate_bundle(bundle)?;
    validate_state(bundle, state)?;
    let assistant = assistant(api, &bundle.assistant_extension.target_assistant_id).await?;
    let remote_digest = digest(&assistant)?;
    let tool_id = state
        .map(|value| value.tool_id.as_str())
        .unwrap_or("<created:bridgefu-tool>");
    let merged = merge_assistant(&assistant, bundle, tool_id, state)?;
    let desired_owned_hash = owned_hash(&merged, bundle, tool_id)?;
    let current_owned = owned_projection(&assistant, bundle, tool_id);
    let desired_owned = owned_projection(&merged, bundle, tool_id);
    let mut actions = Vec::new();
    match state {
        Some(_) => {
            actions.push(PlanAction::UpdateCredential);
            actions.push(PlanAction::UpdateTool);
            if current_owned == desired_owned {
                actions.push(PlanAction::Noop);
            } else {
                actions.push(PlanAction::UpdateAssistantExtension);
            }
        }
        None => {
            actions.push(PlanAction::CreateCredential);
            actions.push(PlanAction::CreateTool);
            actions.push(PlanAction::AttachAssistantExtension);
        }
    }
    Ok(ExtensionPlan {
        schema: PLAN_SCHEMA.into(),
        assistant_id: bundle.assistant_extension.target_assistant_id.clone(),
        remote_digest,
        desired_owned_hash,
        actions,
        masked_diff: format!(
            "--- current:bridgefu-owned\n+++ desired:bridgefu-owned\n{}\n",
            serde_json::to_string_pretty(&json!({
                "current": current_owned,
                "desired": desired_owned,
                "secrets": "<redacted>"
            }))?
        ),
    })
}

pub async fn apply(
    api: &dyn VapiApi,
    resolver: &dyn SecretResolver,
    bundle: &BridgefuVapiBundle,
    expected_plan: &ExtensionPlan,
    previous_state: Option<&ExtensionState>,
) -> Result<ApplyResult> {
    validate_bundle(bundle)?;
    validate_state(bundle, previous_state)?;
    if expected_plan.schema != PLAN_SCHEMA
        || expected_plan.assistant_id != bundle.assistant_extension.target_assistant_id
    {
        bail!("assistant extension plan does not match bundle");
    }
    let before = assistant(api, &bundle.assistant_extension.target_assistant_id).await?;
    if digest(&before)? != expected_plan.remote_digest {
        bail!("assistant changed after review; create and confirm a new plan");
    }

    let bearer = resolver
        .resolve(&bundle.credential.bearer_secret_ref)
        .await
        .context("resolving credential secret")?;
    if bearer.len() < 32 {
        bail!("resolved webhook credential is invalid");
    }
    let endpoint = resolver
        .resolve(&bundle.tool.endpoint_ref)
        .await
        .context("resolving tool endpoint")?;
    validate_https_url(&endpoint)?;

    let mut created_credential = false;
    let mut created_tool = false;
    let credential_id = if let Some(state) = previous_state {
        require_owned_resource(api, "credential", &state.credential_id).await?;
        api.update(
            "credential",
            &state.credential_id,
            &credential_payload(bundle, &bearer),
        )
        .await?;
        state.credential_id.clone()
    } else {
        let created = api
            .create("credential", &credential_payload(bundle, &bearer))
            .await?;
        created_credential = true;
        resource_id(&created)?.to_string()
    };

    let tool_body = tool_payload(bundle, &endpoint, &credential_id)?;
    let tool_id = if let Some(state) = previous_state {
        require_owned_resource(api, "tool", &state.tool_id).await?;
        api.update("tool", &state.tool_id, &tool_body).await?;
        state.tool_id.clone()
    } else {
        match api.create("tool", &tool_body).await {
            Ok(created) => {
                created_tool = true;
                resource_id(&created)?.to_string()
            }
            Err(error) => {
                if created_credential {
                    let _ = api.delete("credential", &credential_id).await;
                }
                return Err(error);
            }
        }
    };

    let latest = assistant(api, &bundle.assistant_extension.target_assistant_id).await?;
    if digest(&latest)? != expected_plan.remote_digest {
        if created_tool {
            let _ = api.delete("tool", &tool_id).await;
        }
        if created_credential {
            let _ = api.delete("credential", &credential_id).await;
        }
        bail!("assistant changed during apply; no assistant changes were made");
    }

    let previous_control_enabled = previous_state
        .and_then(|state| state.previous_control_enabled)
        .or_else(|| control_enabled(&latest));
    let merged = merge_assistant(&latest, bundle, &tool_id, previous_state)?;
    let patch = assistant_patch(&merged)?;
    let updated = api
        .update(
            "assistant",
            &bundle.assistant_extension.target_assistant_id,
            &patch,
        )
        .await;
    let updated = match updated {
        Ok(value) => value,
        Err(error) => {
            if created_tool {
                let _ = api.delete("tool", &tool_id).await;
            }
            if created_credential {
                let _ = api.delete("credential", &credential_id).await;
            }
            return Err(error);
        }
    };
    let verified = assistant(api, &bundle.assistant_extension.target_assistant_id).await?;
    let expected_owned_hash = owned_hash(&merged, bundle, &tool_id)?;
    if owned_hash(&verified, bundle, &tool_id)? != expected_owned_hash {
        bail!("Vapi assistant verification failed after apply");
    }

    let prompt_hash = sha256(bundle.assistant_extension.prompt.as_bytes());
    let state = ExtensionState {
        schema: STATE_SCHEMA.into(),
        assistant_id: bundle.assistant_extension.target_assistant_id.clone(),
        credential_id,
        tool_id,
        prompt_marker: bundle.assistant_extension.prompt_marker.clone(),
        prompt_hash,
        previous_control_enabled,
        applied_owned_hash: expected_owned_hash,
        credential_artifact_hash: digest(&serde_json::to_value(&bundle.credential)?)?,
        tool_artifact_hash: digest(&serde_json::to_value(&bundle.tool)?)?,
    };
    let assistant = if updated.is_object() {
        verified
    } else {
        merged
    };
    Ok(ApplyResult { state, assistant })
}

pub async fn unapply(
    api: &dyn VapiApi,
    bundle: &BridgefuVapiBundle,
    state: &ExtensionState,
) -> Result<UnapplyResult> {
    validate_bundle(bundle)?;
    validate_state(bundle, Some(state))?;
    let current = assistant(api, &state.assistant_id).await?;
    if owned_hash(&current, bundle, &state.tool_id)? != state.applied_owned_hash {
        bail!("Bridgefu-owned assistant paths drifted; refusing ambiguous removal");
    }
    let mut desired = current.clone();
    let model = desired
        .get_mut("model")
        .and_then(Value::as_object_mut)
        .context("assistant model is missing")?;
    let tool_ids = model
        .entry("toolIds")
        .or_insert_with(|| json!([]))
        .as_array_mut()
        .context("assistant model.toolIds is invalid")?;
    tool_ids.retain(|value| value.as_str() != Some(state.tool_id.as_str()));
    let messages = model
        .entry("messages")
        .or_insert_with(|| json!([]))
        .as_array_mut()
        .context("assistant model.messages is invalid")?;
    let expected_prompt = marked_prompt(bundle);
    let count = messages
        .iter()
        .filter(|message| message.get("content").and_then(Value::as_str) == Some(&expected_prompt))
        .count();
    if count != 1 {
        bail!("Bridgefu prompt ownership is ambiguous");
    }
    messages
        .retain(|message| message.get("content").and_then(Value::as_str) != Some(&expected_prompt));
    if let Some(previous) = state.previous_control_enabled {
        let monitor = desired
            .as_object_mut()
            .context("assistant is invalid")?
            .entry("monitorPlan")
            .or_insert_with(|| json!({}));
        monitor
            .as_object_mut()
            .context("assistant monitorPlan is invalid")?
            .insert("controlEnabled".into(), json!(previous));
    } else if let Some(monitor) = desired
        .get_mut("monitorPlan")
        .and_then(Value::as_object_mut)
    {
        monitor.remove("controlEnabled");
    }
    api.update(
        "assistant",
        &state.assistant_id,
        &assistant_patch(&desired)?,
    )
    .await?;
    let verified = assistant(api, &state.assistant_id).await?;
    let projection = owned_projection(&verified, bundle, &state.tool_id);
    if projection["toolAttached"] != json!(false) || projection["prompt"] != Value::Null {
        bail!("assistant extension removal could not be verified");
    }
    require_owned_resource(api, "tool", &state.tool_id).await?;
    require_owned_resource(api, "credential", &state.credential_id).await?;
    api.delete("tool", &state.tool_id).await?;
    api.delete("credential", &state.credential_id).await?;
    Ok(UnapplyResult {
        assistant: verified,
        deleted_tool_id: state.tool_id.clone(),
        deleted_credential_id: state.credential_id.clone(),
    })
}

fn validate_bundle(bundle: &BridgefuVapiBundle) -> Result<()> {
    if bundle.schema != BUNDLE_SCHEMA {
        bail!("unsupported Vapire Bridgefu bundle schema");
    }
    for (field, value) in [
        ("credential slug", bundle.credential.slug.as_str()),
        ("tool slug", bundle.tool.slug.as_str()),
        ("extension slug", bundle.assistant_extension.slug.as_str()),
        (
            "assistant id",
            bundle.assistant_extension.target_assistant_id.as_str(),
        ),
    ] {
        if value.is_empty()
            || value.len() > 128
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        {
            bail!("invalid {field}");
        }
    }
    if bundle.tool.credential_ref != format!("credential:{}", bundle.credential.slug) {
        bail!("tool credential reference does not match bundle credential");
    }
    if bundle.assistant_extension.tool_ref != format!("tool:{}", bundle.tool.slug) {
        bail!("assistant tool reference does not match bundle tool");
    }
    let marker = &bundle.assistant_extension.prompt_marker;
    if !marker.starts_with("[BRIDGEFU:")
        || !marker.ends_with(']')
        || marker.len() > 160
        || marker.contains('\n')
        || bundle.assistant_extension.prompt.is_empty()
        || bundle.assistant_extension.prompt.len() > 8_192
    {
        bail!("invalid Bridgefu prompt marker or content");
    }
    if !bundle.assistant_extension.control_enabled {
        bail!("Bridgefu live transfer requires monitor control");
    }
    Ok(())
}

fn validate_state(bundle: &BridgefuVapiBundle, state: Option<&ExtensionState>) -> Result<()> {
    let Some(state) = state else {
        return Ok(());
    };
    if state.schema != STATE_SCHEMA
        || state.assistant_id != bundle.assistant_extension.target_assistant_id
        || state.prompt_marker != bundle.assistant_extension.prompt_marker
        || state.prompt_hash != sha256(bundle.assistant_extension.prompt.as_bytes())
    {
        bail!("assistant extension state does not match bundle");
    }
    Ok(())
}

async fn assistant(api: &dyn VapiApi, id: &str) -> Result<Value> {
    api.get("assistant", id)
        .await?
        .context("target Vapi assistant does not exist")
}

async fn require_owned_resource(api: &dyn VapiApi, kind: &str, id: &str) -> Result<()> {
    if api.get(kind, id).await?.is_none() {
        bail!("owned Vapi {kind} no longer exists");
    }
    Ok(())
}

fn credential_payload(bundle: &BridgefuVapiBundle, bearer: &str) -> Value {
    json!({
        "provider": "custom-credential",
        "name": bundle.credential.name,
        "authenticationPlan": {"type": "bearer", "token": bearer}
    })
}

fn tool_payload(bundle: &BridgefuVapiBundle, endpoint: &str, credential_id: &str) -> Result<Value> {
    let mut payload = bundle.tool.spec.clone();
    let object = payload
        .as_object_mut()
        .context("tool spec must be an object")?;
    object.insert(
        "server".into(),
        json!({"url": endpoint, "credentialId": credential_id}),
    );
    Ok(payload)
}

fn merge_assistant(
    assistant: &Value,
    bundle: &BridgefuVapiBundle,
    tool_id: &str,
    state: Option<&ExtensionState>,
) -> Result<Value> {
    let mut merged = assistant.clone();
    let root = merged
        .as_object_mut()
        .context("assistant must be an object")?;
    let model = root
        .get_mut("model")
        .and_then(Value::as_object_mut)
        .context("assistant model is missing")?;
    let tool_ids = model
        .entry("toolIds")
        .or_insert_with(|| json!([]))
        .as_array_mut()
        .context("assistant model.toolIds is invalid")?;
    if !tool_ids.iter().any(|value| value.as_str() == Some(tool_id)) {
        tool_ids.push(json!(tool_id));
    }
    let messages = model
        .entry("messages")
        .or_insert_with(|| json!([]))
        .as_array_mut()
        .context("assistant model.messages is invalid")?;
    let marker = bundle.assistant_extension.prompt_marker.as_str();
    let positions: Vec<_> = messages
        .iter()
        .enumerate()
        .filter_map(|(index, message)| {
            message
                .get("content")
                .and_then(Value::as_str)
                .filter(|content| content.starts_with(marker))
                .map(|_| index)
        })
        .collect();
    if positions.len() > 1 || (positions.len() == 1 && state.is_none()) {
        bail!("Bridgefu prompt marker already exists without matching ownership state");
    }
    let message = json!({"role": "system", "content": marked_prompt(bundle)});
    if let Some(index) = positions.first() {
        messages[*index] = message;
    } else {
        messages.push(message);
    }
    let monitor = root
        .entry("monitorPlan")
        .or_insert_with(|| json!({}))
        .as_object_mut()
        .context("assistant monitorPlan is invalid")?;
    monitor.insert("controlEnabled".into(), json!(true));
    Ok(merged)
}

fn assistant_patch(assistant: &Value) -> Result<Value> {
    Ok(json!({
        "model": assistant.get("model").context("assistant model missing")?,
        "monitorPlan": assistant.get("monitorPlan").cloned().unwrap_or_else(|| json!({}))
    }))
}

fn marked_prompt(bundle: &BridgefuVapiBundle) -> String {
    format!(
        "{}\n{}",
        bundle.assistant_extension.prompt_marker, bundle.assistant_extension.prompt
    )
}

fn control_enabled(assistant: &Value) -> Option<bool> {
    assistant
        .get("monitorPlan")
        .and_then(|value| value.get("controlEnabled"))
        .and_then(Value::as_bool)
}

fn owned_projection(assistant: &Value, bundle: &BridgefuVapiBundle, tool_id: &str) -> Value {
    let messages = assistant
        .pointer("/model/messages")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let marker = bundle.assistant_extension.prompt_marker.as_str();
    let prompt = messages.into_iter().find(|message| {
        message
            .get("content")
            .and_then(Value::as_str)
            .is_some_and(|content| content.starts_with(marker))
    });
    let tool_attached = assistant
        .pointer("/model/toolIds")
        .and_then(Value::as_array)
        .is_some_and(|ids| ids.iter().any(|value| value.as_str() == Some(tool_id)));
    json!({
        "toolId": tool_id,
        "toolAttached": tool_attached,
        "prompt": prompt,
        "controlEnabled": control_enabled(assistant)
    })
}

fn owned_hash(assistant: &Value, bundle: &BridgefuVapiBundle, tool_id: &str) -> Result<String> {
    digest(&owned_projection(assistant, bundle, tool_id))
}

fn resource_id(value: &Value) -> Result<&str> {
    value
        .get("id")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty() && value.len() <= 128)
        .context("Vapi create response did not contain a resource ID")
}

fn digest(value: &Value) -> Result<String> {
    let canonical = canonicalize(value);
    Ok(sha256(&serde_json::to_vec(&canonical)?))
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
        fn new(assistant: Value) -> Self {
            let mut resources = BTreeMap::new();
            resources.insert(
                "assistant".into(),
                BTreeMap::from([("assistant_customer".into(), assistant)]),
            );
            resources.insert("credential".into(), BTreeMap::new());
            resources.insert("tool".into(), BTreeMap::new());
            Self {
                resources: Mutex::new(resources),
                next: Mutex::new(0),
            }
        }
    }

    #[async_trait]
    impl VapiApi for MemoryApi {
        async fn get(&self, resource: &str, id: &str) -> Result<Option<Value>> {
            Ok(self
                .resources
                .lock()
                .unwrap()
                .get(resource)
                .and_then(|items| items.get(id))
                .cloned())
        }

        async fn create(&self, resource: &str, body: &Value) -> Result<Value> {
            let mut next = self.next.lock().unwrap();
            *next += 1;
            let id = format!("{resource}_{next}");
            let mut value = body.clone();
            value
                .as_object_mut()
                .unwrap()
                .insert("id".into(), json!(id));
            self.resources
                .lock()
                .unwrap()
                .get_mut(resource)
                .unwrap()
                .insert(id, value.clone());
            Ok(value)
        }

        async fn update(&self, resource: &str, id: &str, body: &Value) -> Result<Value> {
            let mut resources = self.resources.lock().unwrap();
            let value = resources
                .get_mut(resource)
                .and_then(|items| items.get_mut(id))
                .context("missing memory resource")?;
            if resource == "assistant" {
                for (key, item) in body.as_object().unwrap() {
                    value
                        .as_object_mut()
                        .unwrap()
                        .insert(key.clone(), item.clone());
                }
            } else {
                let resource_id = value.get("id").cloned().unwrap();
                *value = body.clone();
                value
                    .as_object_mut()
                    .unwrap()
                    .insert("id".into(), resource_id);
            }
            Ok(value.clone())
        }

        async fn delete(&self, resource: &str, id: &str) -> Result<()> {
            self.resources
                .lock()
                .unwrap()
                .get_mut(resource)
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
                _ => bail!("unknown reference"),
            })
        }
    }

    fn assistant() -> Value {
        json!({
            "id": "assistant_customer",
            "name": "Customer assistant",
            "voice": {"provider": "vapi", "voiceId": "Elliot"},
            "server": {"url": "https://customer.example/webhook"},
            "model": {
                "provider": "openai",
                "model": "gpt-4.1-mini",
                "toolIds": ["customer_tool"],
                "messages": [{"role": "system", "content": "Customer prompt"}]
            },
            "monitorPlan": {"controlEnabled": false, "listenEnabled": true}
        })
    }

    fn bundle() -> BridgefuVapiBundle {
        BridgefuVapiBundle {
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
                spec: json!({
                    "type": "function",
                    "function": {
                        "name": "bridgefu_transfer_to_amazon_connect",
                        "description": "Transfer to Amazon Connect",
                        "parameters": {"type": "object", "properties": {}}
                    }
                }),
            },
            assistant_extension: crate::model::AssistantExtensionArtifact {
                slug: "bridgefu-demo-extension".into(),
                target_assistant_id: "assistant_customer".into(),
                tool_ref: "tool:bridgefu-demo-tool".into(),
                prompt_marker: "[BRIDGEFU:demo]".into(),
                prompt: "Use the Bridgefu tool immediately before transfer.".into(),
                control_enabled: true,
            },
        }
    }

    #[tokio::test]
    async fn apply_and_unapply_preserve_customer_configuration() {
        let api = MemoryApi::new(assistant());
        let desired = bundle();
        let proposal = plan(&api, &desired, None).await.unwrap();
        let applied = apply(&api, &Resolver, &desired, &proposal, None)
            .await
            .unwrap();
        assert_eq!(applied.assistant["voice"], assistant()["voice"]);
        assert_eq!(applied.assistant["server"], assistant()["server"]);
        assert_eq!(applied.assistant["model"]["toolIds"][0], "customer_tool");
        assert_eq!(applied.assistant["monitorPlan"]["listenEnabled"], true);
        assert_eq!(applied.assistant["monitorPlan"]["controlEnabled"], true);

        let removed = unapply(&api, &desired, &applied.state).await.unwrap();
        assert_eq!(removed.assistant, assistant());
        assert!(api
            .get("tool", &applied.state.tool_id)
            .await
            .unwrap()
            .is_none());
        assert!(api
            .get("credential", &applied.state.credential_id)
            .await
            .unwrap()
            .is_none());
    }

    #[tokio::test]
    async fn concurrent_assistant_change_stops_apply_before_attachment() {
        let api = MemoryApi::new(assistant());
        let desired = bundle();
        let proposal = plan(&api, &desired, None).await.unwrap();
        api.update(
            "assistant",
            "assistant_customer",
            &json!({"model": {
                "provider": "openai",
                "model": "gpt-4.1-mini",
                "toolIds": ["customer_tool", "new_customer_tool"],
                "messages": [{"role": "system", "content": "Customer prompt"}]
            }}),
        )
        .await
        .unwrap();
        let error = apply(&api, &Resolver, &desired, &proposal, None)
            .await
            .unwrap_err();
        assert!(error.to_string().contains("changed after review"));
    }

    #[tokio::test]
    async fn marker_without_state_fails_closed() {
        let mut remote = assistant();
        remote["model"]["messages"]
            .as_array_mut()
            .unwrap()
            .push(json!({"role":"system", "content":"[BRIDGEFU:demo]\nunknown"}));
        let error = plan(&MemoryApi::new(remote), &bundle(), None)
            .await
            .unwrap_err();
        assert!(error.to_string().contains("without matching ownership"));
    }
}
