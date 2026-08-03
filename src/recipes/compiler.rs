use std::collections::{BTreeMap, BTreeSet};

use ipnet::IpNet;
use serde::Serialize;
use serde_yaml::Value;
use sha2::{Digest as _, Sha256};
use thiserror::Error;

use super::manifest::{
    RecipeEndpointSpec, RecipeInputDefinition, RecipeInputType, RecipeManifest, RecipeSipAuthSpec,
    RecipeSpec, RecipeSupport, SipAdmissionMode, SipSecurity, BUILTIN_RECIPE_API_VERSION,
    BUILTIN_RECIPE_KIND,
};

const MAX_MANIFEST_INPUTS: usize = 64;
const MAX_RECIPE_BRIDGES: usize = 16;
const MAX_INPUT_REFERENCES: usize = 256;
const MAX_VALUE_BYTES: usize = 16 * 1024;
const MAX_TEXT_BYTES: usize = 2_048;
const MAX_CIDRS: usize = 64;

#[derive(Debug, Error)]
pub enum RecipeError {
    #[error("invalid recipe: {0}")]
    Invalid(String),
    #[error("reading recipe package: {0}")]
    Io(#[from] std::io::Error),
    #[error("parsing recipe package: {0}")]
    Yaml(#[from] serde_yaml::Error),
}

/// A resolved recipe safe to project into Bridgefu runtime configuration.
#[derive(Clone, Debug)]
pub struct CompiledRecipe {
    pub name: String,
    pub version: u32,
    pub title: String,
    pub support: RecipeSupport,
    pub spec: RecipeSpec,
    pub fingerprint: String,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct RecipeCompiler;

impl RecipeCompiler {
    pub fn compile(
        &self,
        manifest: &RecipeManifest,
        supplied: &BTreeMap<String, Value>,
        effective_support: RecipeSupport,
    ) -> Result<CompiledRecipe, RecipeError> {
        validate_manifest(manifest)?;
        if supplied.len() > MAX_MANIFEST_INPUTS {
            return invalid("too many recipe input values were supplied");
        }
        for name in supplied.keys() {
            if !manifest.inputs.contains_key(name) {
                return invalid(format!("unknown recipe input {name:?}"));
            }
        }

        let mut resolved_inputs = BTreeMap::new();
        for (name, definition) in &manifest.inputs {
            let value = supplied
                .get(name)
                .cloned()
                .or_else(|| definition.default.clone())
                .unwrap_or(Value::Null);
            if matches!(value, Value::Null) && definition.required {
                return invalid(format!("required recipe input {name:?} is missing"));
            }
            validate_input_value(name, definition, &value)?;
            resolved_inputs.insert(name.clone(), value);
        }

        let mut referenced = BTreeMap::<String, usize>::new();
        let resolved_value = substitute(
            &manifest.spec,
            &resolved_inputs,
            &manifest.inputs,
            &mut referenced,
            false,
        )?;
        let mut fingerprint_references = BTreeMap::<String, usize>::new();
        let fingerprint_value = substitute(
            &manifest.spec,
            &resolved_inputs,
            &manifest.inputs,
            &mut fingerprint_references,
            true,
        )?;
        if referenced.values().sum::<usize>() > MAX_INPUT_REFERENCES {
            return invalid("recipe contains too many input references");
        }
        for name in manifest.inputs.keys() {
            if !referenced.contains_key(name) {
                return invalid(format!("declared recipe input {name:?} is unused"));
            }
        }

        let spec: RecipeSpec = serde_yaml::from_value(resolved_value)
            .map_err(|error| RecipeError::Invalid(format!("resolved spec is invalid: {error}")))?;
        validate_spec(&spec)?;
        let fingerprint = recipe_fingerprint(manifest, &fingerprint_value)?;
        Ok(CompiledRecipe {
            name: manifest.metadata.name.clone(),
            version: manifest.metadata.version,
            title: manifest.metadata.title.clone(),
            support: effective_support,
            spec,
            fingerprint,
        })
    }
}

pub(crate) fn validate_manifest(manifest: &RecipeManifest) -> Result<(), RecipeError> {
    if manifest.api_version != BUILTIN_RECIPE_API_VERSION {
        return invalid(format!(
            "unsupported api_version {:?}",
            manifest.api_version
        ));
    }
    if manifest.kind != BUILTIN_RECIPE_KIND {
        return invalid(format!("unsupported recipe kind {:?}", manifest.kind));
    }
    validate_identifier(&manifest.metadata.name, "recipe name")?;
    if manifest.metadata.version == 0 {
        return invalid("recipe version must be greater than zero");
    }
    validate_text(&manifest.metadata.title, "recipe title", 256)?;
    if let Some(description) = &manifest.metadata.description {
        validate_text(description, "recipe description", MAX_TEXT_BYTES)?;
    }
    if manifest.inputs.len() > MAX_MANIFEST_INPUTS {
        return invalid("recipe declares too many inputs");
    }
    for (name, definition) in &manifest.inputs {
        validate_identifier(name, "recipe input name")?;
        if let Some(description) = &definition.description {
            validate_text(description, "recipe input description", MAX_TEXT_BYTES)?;
        }
        match definition.kind {
            RecipeInputType::Enum => {
                if definition.values.is_empty() || definition.values.len() > 64 {
                    return invalid(format!(
                        "enum recipe input {name:?} must declare a bounded non-empty values list"
                    ));
                }
                let mut unique = BTreeSet::new();
                for value in &definition.values {
                    validate_text(value, "enum input value", 128)?;
                    if !unique.insert(value) {
                        return invalid(format!(
                            "enum recipe input {name:?} contains duplicate values"
                        ));
                    }
                }
            }
            _ if !definition.values.is_empty() => {
                return invalid(format!(
                    "non-enum recipe input {name:?} cannot declare values"
                ));
            }
            _ => {}
        }
        if let Some(default) = &definition.default {
            validate_input_value(name, definition, default)?;
        }
    }
    for (provider, profiles) in &manifest.deployments {
        validate_identifier(provider, "deployment provider")?;
        if profiles.len() > 16 {
            return invalid("recipe declares too many deployment profiles");
        }
        for (profile, path) in profiles {
            validate_identifier(profile, "deployment profile")?;
            validate_package_path(path)?;
        }
    }
    for (name, path) in &manifest.assets {
        validate_identifier(name, "asset name")?;
        validate_package_path(path)?;
    }
    Ok(())
}

fn validate_spec(spec: &RecipeSpec) -> Result<(), RecipeError> {
    if spec.bridges.is_empty() || spec.bridges.len() > MAX_RECIPE_BRIDGES {
        return invalid("recipe spec must contain a bounded non-empty bridge map");
    }
    for (bridge_id, bridge) in &spec.bridges {
        validate_identifier(bridge_id, "bridge ID")?;
        if matches!(bridge.source, RecipeEndpointSpec::AmazonConnect { .. }) {
            return invalid(format!(
                "bridge {bridge_id:?} cannot use Amazon Connect as an ingress source"
            ));
        }
        if let RecipeEndpointSpec::Sip {
            security,
            admission,
            target_uri,
            from_uri,
            outbound_proxy,
            auth,
            tls_roots,
            metadata_keys,
            ..
        } = &bridge.source
        {
            if target_uri.is_some()
                || from_uri.is_some()
                || outbound_proxy.is_some()
                || auth.is_some()
                || !tls_roots.is_empty()
                || !metadata_keys.is_empty()
            {
                return invalid(format!(
                    "bridge {bridge_id:?} SIP source cannot declare outbound policy"
                ));
            }
            let admission = admission.as_ref().ok_or_else(|| {
                RecipeError::Invalid(format!(
                    "bridge {bridge_id:?} SIP source requires admission policy"
                ))
            })?;
            validate_admission(bridge_id, *security, admission)?;
        }
        if let RecipeEndpointSpec::Sip {
            security,
            admission,
            target_uri,
            from_uri,
            outbound_proxy,
            auth,
            tls_roots,
            codecs,
            metadata_keys,
            ..
        } = &bridge.destination
        {
            if admission.is_some() {
                return invalid(format!(
                    "bridge {bridge_id:?} SIP destination cannot declare admission"
                ));
            }
            let target = target_uri.as_deref().ok_or_else(|| {
                RecipeError::Invalid(format!(
                    "bridge {bridge_id:?} SIP destination requires target_uri"
                ))
            })?;
            validate_sip_uri(target, *security)?;
            let from_uri = from_uri.as_deref().ok_or_else(|| {
                RecipeError::Invalid(format!(
                    "bridge {bridge_id:?} SIP destination requires from_uri"
                ))
            })?;
            validate_sip_uri(from_uri, *security)?;
            if let Some(proxy) = outbound_proxy {
                validate_sip_uri(proxy, *security)?;
            }
            if *security == SipSecurity::SipRtp && !tls_roots.is_empty() {
                return invalid(format!(
                    "bridge {bridge_id:?} clear SIP destination cannot declare TLS roots"
                ));
            }
            for root in tls_roots {
                validate_runtime_path(root, "recipe SIP TLS root")?;
            }
            if codecs.is_empty() {
                return invalid(format!(
                    "bridge {bridge_id:?} SIP destination requires at least one codec"
                ));
            }
            for key in metadata_keys {
                validate_metadata_key(key)?;
            }
            if let Some(auth) = auth {
                validate_sip_auth(bridge_id, auth)?;
            }
        }
        for (role, endpoint) in [
            ("source", &bridge.source),
            ("destination", &bridge.destination),
        ] {
            if let RecipeEndpointSpec::Webrtc {
                signaling_uri,
                bearer_token_ref,
                tls_roots,
                codecs,
                ..
            } = endpoint
            {
                let signaling_uri = signaling_uri.as_deref().ok_or_else(|| {
                    RecipeError::Invalid(format!(
                        "bridge {bridge_id:?} WebRTC {role} requires signaling_uri"
                    ))
                })?;
                validate_wss_uri(signaling_uri)?;
                if codecs.is_empty() {
                    return invalid(format!(
                        "bridge {bridge_id:?} WebRTC {role} requires at least one codec"
                    ));
                }
                if role == "source" && (bearer_token_ref.is_some() || !tls_roots.is_empty()) {
                    return invalid(format!(
                        "bridge {bridge_id:?} WebRTC source cannot declare outbound credentials or TLS roots"
                    ));
                }
                if let Some(secret) = bearer_token_ref {
                    validate_secret_ref(secret)?;
                }
                for root in tls_roots {
                    validate_runtime_path(root, "recipe WebRTC TLS root")?;
                }
            }
        }
        if let Some((instance_arn, contact_flow_id)) = bridge.destination.amazon_connect_target() {
            validate_connect_instance_arn(instance_arn)?;
            validate_connect_resource_id(contact_flow_id)?;
        }
        if let RecipeEndpointSpec::AmazonConnect {
            context_metadata_keys,
            ..
        } = &bridge.destination
        {
            if context_metadata_keys.len() > 64 {
                return invalid(format!(
                    "bridge {bridge_id:?} Amazon Connect context allowlist is too large"
                ));
            }
            for key in context_metadata_keys {
                validate_metadata_key(key)?;
            }
        }
        if let Some(context) = &bridge.context {
            if !matches!(bridge.source, RecipeEndpointSpec::Sip { .. })
                || !matches!(bridge.destination, RecipeEndpointSpec::AmazonConnect { .. })
            {
                return invalid(format!(
                    "bridge {bridge_id:?} canonical SIP correlation context requires SIP to Amazon Connect"
                ));
            }
            let correlation = &context.correlation;
            if correlation.required {
                if !correlation
                    .from_sip_header
                    .eq_ignore_ascii_case("X-Correlation-Id")
                {
                    return invalid(format!(
                        "bridge {bridge_id:?} required correlation header must be X-Correlation-Id"
                    ));
                }
                if correlation.to_amazon_attribute != "correlation_id"
                    || correlation.format != "opaque_id_v1"
                {
                    return invalid(format!(
                        "bridge {bridge_id:?} required correlation mapping is not the canonical opaque contract"
                    ));
                }
            }
        }
    }
    Ok(())
}

fn validate_admission(
    bridge_id: &str,
    security: SipSecurity,
    admission: &super::manifest::SipAdmissionSpec,
) -> Result<(), RecipeError> {
    if admission.trusted_cidrs.is_empty() || admission.trusted_cidrs.len() > MAX_CIDRS {
        return invalid(format!(
            "bridge {bridge_id:?} SIP admission requires a bounded non-empty trusted CIDR list"
        ));
    }
    let mut cidrs = BTreeSet::new();
    for raw in &admission.trusted_cidrs {
        let parsed = raw.parse::<IpNet>().map_err(|_| {
            RecipeError::Invalid(format!(
                "bridge {bridge_id:?} contains invalid signaling CIDR {raw:?}"
            ))
        })?;
        if !cidrs.insert(parsed) {
            return invalid(format!(
                "bridge {bridge_id:?} contains duplicate signaling CIDRs"
            ));
        }
    }
    match admission.mode {
        SipAdmissionMode::ManagedAttachment if admission.uri_user.is_some() => invalid(format!(
            "bridge {bridge_id:?} managed_attachment admission cannot declare uri_user"
        )),
        SipAdmissionMode::StableUri => {
            let uri_user = admission.uri_user.as_deref().ok_or_else(|| {
                RecipeError::Invalid(format!(
                    "bridge {bridge_id:?} stable_uri admission requires uri_user"
                ))
            })?;
            validate_identifier(uri_user, "stable SIP URI user")?;
            if security == SipSecurity::SipsSrtp {
                return invalid(format!(
                    "bridge {bridge_id:?} secure production posture requires managed_attachment admission"
                ));
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

fn validate_input_value(
    name: &str,
    definition: &RecipeInputDefinition,
    value: &Value,
) -> Result<(), RecipeError> {
    if matches!(value, Value::Null) {
        return Ok(());
    }
    let encoded = serde_yaml::to_string(value)?;
    if encoded.len() > MAX_VALUE_BYTES {
        return invalid(format!("recipe input {name:?} exceeds the size limit"));
    }
    match definition.kind {
        RecipeInputType::String => validate_text_value(name, value, MAX_TEXT_BYTES),
        RecipeInputType::Boolean if matches!(value, Value::Bool(_)) => Ok(()),
        RecipeInputType::Integer if value.as_i64().is_some() => Ok(()),
        RecipeInputType::Enum => {
            let value = value.as_str().ok_or_else(|| {
                RecipeError::Invalid(format!("recipe input {name:?} must be a string enum"))
            })?;
            if definition.values.iter().any(|candidate| candidate == value) {
                Ok(())
            } else {
                invalid(format!(
                    "recipe input {name:?} must be one of {}",
                    definition.values.join(", ")
                ))
            }
        }
        RecipeInputType::CidrList => {
            let values = value.as_sequence().ok_or_else(|| {
                RecipeError::Invalid(format!("recipe input {name:?} must be a CIDR list"))
            })?;
            if values.is_empty() || values.len() > MAX_CIDRS {
                return invalid(format!(
                    "recipe input {name:?} must contain 1..={MAX_CIDRS} CIDRs"
                ));
            }
            let mut unique = BTreeSet::new();
            for value in values {
                let raw = value.as_str().ok_or_else(|| {
                    RecipeError::Invalid(format!(
                        "recipe input {name:?} contains a non-string CIDR"
                    ))
                })?;
                let parsed = raw.parse::<IpNet>().map_err(|_| {
                    RecipeError::Invalid(format!(
                        "recipe input {name:?} contains invalid CIDR {raw:?}"
                    ))
                })?;
                if !unique.insert(parsed) {
                    return invalid(format!("recipe input {name:?} contains duplicate CIDRs"));
                }
            }
            Ok(())
        }
        RecipeInputType::AwsArn => {
            let value = string_input(name, value)?;
            validate_arn(value)
        }
        RecipeInputType::AwsConnectResourceId => {
            let value = string_input(name, value)?;
            validate_connect_resource_id(value)
        }
        RecipeInputType::SecretRef => {
            let value = string_input(name, value)?;
            validate_secret_ref(value)
        }
        RecipeInputType::Boolean => invalid(format!("recipe input {name:?} must be boolean")),
        RecipeInputType::Integer => invalid(format!("recipe input {name:?} must be an integer")),
    }
}

fn substitute(
    value: &Value,
    inputs: &BTreeMap<String, Value>,
    definitions: &BTreeMap<String, RecipeInputDefinition>,
    references: &mut BTreeMap<String, usize>,
    fingerprint: bool,
) -> Result<Value, RecipeError> {
    match value {
        Value::Mapping(mapping) => {
            let input_key = Value::String("$input".to_owned());
            if let Some(name) = mapping.get(&input_key) {
                if mapping.len() != 1 {
                    return invalid("$input must replace a complete YAML node");
                }
                let name = name.as_str().ok_or_else(|| {
                    RecipeError::Invalid("$input value must be an input name".to_owned())
                })?;
                let definition = definitions.get(name).ok_or_else(|| {
                    RecipeError::Invalid(format!("recipe references unknown input {name:?}"))
                })?;
                *references.entry(name.to_owned()).or_default() += 1;
                if fingerprint && definition.kind.is_secret() {
                    return Ok(Value::String(format!("$secret:{name}")));
                }
                return inputs.get(name).cloned().ok_or_else(|| {
                    RecipeError::Invalid(format!("recipe input {name:?} was not resolved"))
                });
            }
            let mut sorted = BTreeMap::new();
            for (key, value) in mapping {
                let key = key
                    .as_str()
                    .ok_or_else(|| {
                        RecipeError::Invalid("recipe spec mapping keys must be strings".to_owned())
                    })?
                    .to_owned();
                sorted.insert(key, value);
            }
            let mut output = serde_yaml::Mapping::new();
            for (key, value) in sorted {
                output.insert(
                    Value::String(key),
                    substitute(value, inputs, definitions, references, fingerprint)?,
                );
            }
            Ok(Value::Mapping(output))
        }
        Value::Sequence(sequence) => sequence
            .iter()
            .map(|value| substitute(value, inputs, definitions, references, fingerprint))
            .collect::<Result<Vec<_>, _>>()
            .map(Value::Sequence),
        Value::Tagged(_) => invalid("YAML tags are not allowed in recipe specs"),
        scalar => Ok(scalar.clone()),
    }
}

#[derive(Serialize)]
struct FingerprintDocument<'a> {
    api_version: &'a str,
    kind: &'a str,
    name: &'a str,
    version: u32,
    spec: &'a Value,
}

fn recipe_fingerprint(
    manifest: &RecipeManifest,
    fingerprint_spec: &Value,
) -> Result<String, RecipeError> {
    let canonical = serde_json::to_vec(&FingerprintDocument {
        api_version: &manifest.api_version,
        kind: &manifest.kind,
        name: &manifest.metadata.name,
        version: manifest.metadata.version,
        spec: fingerprint_spec,
    })
    .map_err(|error| RecipeError::Invalid(format!("fingerprinting recipe: {error}")))?;
    let digest = Sha256::digest(canonical);
    Ok(digest.iter().map(|byte| format!("{byte:02x}")).collect())
}

pub(crate) fn validate_package_path(path: &str) -> Result<(), RecipeError> {
    let path = std::path::Path::new(path);
    if path.as_os_str().is_empty()
        || path.is_absolute()
        || path.components().any(|component| {
            !matches!(
                component,
                std::path::Component::Normal(_) | std::path::Component::CurDir
            )
        })
    {
        return invalid("recipe asset paths must remain relative to the package root");
    }
    Ok(())
}

fn validate_identifier(value: &str, field: &str) -> Result<(), RecipeError> {
    let valid = !value.is_empty()
        && value.len() <= 128
        && value
            .as_bytes()
            .first()
            .is_some_and(u8::is_ascii_alphanumeric)
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'_')
        });
    if valid {
        Ok(())
    } else {
        invalid(format!(
            "{field} must use lowercase letters, digits, dash, or underscore"
        ))
    }
}

fn validate_text(value: &str, field: &str, max: usize) -> Result<(), RecipeError> {
    if !value.is_empty()
        && value.len() <= max
        && value.trim() == value
        && !value.chars().any(char::is_control)
    {
        Ok(())
    } else {
        invalid(format!(
            "{field} must be bounded, trimmed, and control-free"
        ))
    }
}

fn validate_text_value(name: &str, value: &Value, max: usize) -> Result<(), RecipeError> {
    let value = string_input(name, value)?;
    validate_text(value, &format!("recipe input {name:?}"), max)
}

fn string_input<'a>(name: &str, value: &'a Value) -> Result<&'a str, RecipeError> {
    value
        .as_str()
        .ok_or_else(|| RecipeError::Invalid(format!("recipe input {name:?} must be a string")))
}

fn validate_arn(value: &str) -> Result<(), RecipeError> {
    validate_text(value, "AWS ARN input", MAX_TEXT_BYTES)?;
    let fields = value.splitn(6, ':').collect::<Vec<_>>();
    if fields.len() == 6
        && fields[0] == "arn"
        && !fields[1].is_empty()
        && !fields[2].is_empty()
        && !fields[5].is_empty()
    {
        Ok(())
    } else {
        invalid("AWS ARN input is malformed")
    }
}

fn validate_connect_instance_arn(value: &str) -> Result<(), RecipeError> {
    validate_arn(value)?;
    let fields = value.splitn(6, ':').collect::<Vec<_>>();
    if fields[2] == "connect" && fields[5].starts_with("instance/") {
        Ok(())
    } else {
        invalid("Amazon Connect instance input must be an instance ARN")
    }
}

fn validate_connect_resource_id(value: &str) -> Result<(), RecipeError> {
    if !value.is_empty()
        && value.len() <= 512
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'/'))
    {
        Ok(())
    } else {
        invalid("Amazon Connect resource ID is invalid")
    }
}

fn validate_secret_ref(value: &str) -> Result<(), RecipeError> {
    validate_text(value, "secret reference", MAX_VALUE_BYTES)?;
    let valid = value.strip_prefix("env:").is_some_and(|name| {
        !name.is_empty()
            && name.bytes().enumerate().all(|(index, byte)| {
                byte == b'_' || byte.is_ascii_uppercase() || (index > 0 && byte.is_ascii_digit())
            })
    }) || value
        .strip_prefix("file:")
        .is_some_and(|path| std::path::Path::new(path).is_absolute())
        || value
            .strip_prefix("secretsmanager:")
            .is_some_and(|name| !name.is_empty());
    if valid {
        Ok(())
    } else {
        invalid("secret input must be an env:, absolute file:, or secretsmanager: reference")
    }
}

fn validate_sip_uri(value: &str, security: SipSecurity) -> Result<(), RecipeError> {
    validate_text(value, "SIP target URI", MAX_TEXT_BYTES)?;
    let expected = match security {
        SipSecurity::SipsSrtp => "sips:",
        SipSecurity::SipRtp => "sip:",
    };
    let Some(rest) = value.strip_prefix(expected) else {
        return invalid(format!(
            "SIP URI must use {expected} for the selected security posture"
        ));
    };
    if rest.is_empty()
        || value.chars().any(char::is_whitespace)
        || value.contains('?')
        || value.contains('#')
        || rest.matches('@').count() > 1
    {
        return invalid("SIP URI must be absolute, bounded, and credential-free");
    }
    if let Some((user, authority)) = rest.split_once('@') {
        if user.is_empty() || user.contains(':') || authority.is_empty() {
            return invalid("SIP URI must not contain embedded credentials");
        }
    }
    Ok(())
}

fn validate_wss_uri(value: &str) -> Result<(), RecipeError> {
    validate_text(value, "WebRTC signaling URI", MAX_TEXT_BYTES)?;
    let parsed = url::Url::parse(value)
        .map_err(|_| RecipeError::Invalid("WebRTC signaling URI is invalid".to_owned()))?;
    if parsed.scheme() != "wss"
        || parsed.host_str().is_none()
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.query().is_some()
        || parsed.fragment().is_some()
    {
        return invalid("WebRTC signaling URI must be a credential-free WSS URL");
    }
    Ok(())
}

fn validate_runtime_path(value: &str, field: &str) -> Result<(), RecipeError> {
    validate_text(value, field, MAX_TEXT_BYTES)?;
    if std::path::Path::new(value).is_absolute() {
        Ok(())
    } else {
        invalid(format!("{field} must be an absolute path"))
    }
}

fn validate_metadata_key(value: &str) -> Result<(), RecipeError> {
    if !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        Ok(())
    } else {
        invalid("recipe SIP metadata key is invalid")
    }
}

fn validate_sip_auth(bridge_id: &str, auth: &RecipeSipAuthSpec) -> Result<(), RecipeError> {
    match auth {
        RecipeSipAuthSpec::Digest {
            realm,
            username,
            password_ref,
        } => match (username, password_ref) {
            (None, None) if realm.is_none() => Ok(()),
            (Some(username), Some(password)) => {
                validate_text(username, "recipe SIP Digest username", 256)?;
                if let Some(realm) = realm {
                    validate_text(realm, "recipe SIP Digest realm", 256)?;
                }
                validate_secret_ref(password)
            }
            _ => invalid(format!(
                "bridge {bridge_id:?} SIP Digest auth requires username and password_ref together"
            )),
        },
        RecipeSipAuthSpec::Bearer { token_ref } => {
            if let Some(token) = token_ref {
                validate_secret_ref(token)
            } else {
                Ok(())
            }
        }
    }
}

fn invalid<T>(message: impl Into<String>) -> Result<T, RecipeError> {
    Err(RecipeError::Invalid(message.into()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::recipes::RecipeCatalog;

    fn canonical_values() -> BTreeMap<String, Value> {
        serde_yaml::from_str(
            r#"
vapi_signaling_cidrs: [198.51.100.0/24]
connect_instance_arn: arn:aws:connect:us-west-2:123456789012:instance/11111111-1111-1111-1111-111111111111
connect_entry_contact_flow_id: 22222222-2222-2222-2222-222222222222
sip_security: sips_srtp
"#,
        )
        .unwrap()
    }

    #[test]
    fn builtin_compiles_deterministically() {
        let catalog = RecipeCatalog::builtin().unwrap();
        let package = catalog
            .resolve("builtin:vapi-amazon-connect-screen-pop@1")
            .unwrap();
        let first = package.compile(&canonical_values()).unwrap();
        let second = package.compile(&canonical_values()).unwrap();
        assert_eq!(first.fingerprint, second.fingerprint);
        assert_eq!(first.fingerprint.len(), 64);
        assert_eq!(first.spec.bridges.len(), 1);
        assert_eq!(first.support, RecipeSupport::Preview);
    }

    #[test]
    fn directional_transport_recipes_compile_from_their_samples() {
        let catalog = RecipeCatalog::builtin().unwrap();
        for (selector, values) in [
            (
                "builtin:webrtc-sip-bridge@1",
                include_str!("../../recipes/webrtc-sip-bridge/values.example.yaml"),
            ),
            (
                "builtin:sip-webrtc-bridge@1",
                include_str!("../../recipes/sip-webrtc-bridge/values.example.yaml"),
            ),
            (
                "builtin:webrtc-amazon-connect-bridge@1",
                include_str!("../../recipes/webrtc-amazon-connect-bridge/values.example.yaml"),
            ),
        ] {
            let package = catalog.resolve(selector).unwrap();
            let values = serde_yaml::from_str(values).unwrap();
            let compiled = package.compile(&values).unwrap();
            assert_eq!(compiled.support, RecipeSupport::Preview);
            assert_eq!(compiled.spec.bridges.len(), 1);
            assert_eq!(compiled.fingerprint.len(), 64);
        }
    }

    #[test]
    fn directional_recipe_rejects_raw_digest_secret_and_scheme_mismatch() {
        let catalog = RecipeCatalog::builtin().unwrap();
        let package = catalog.resolve("builtin:webrtc-sip-bridge@1").unwrap();
        let mut values: BTreeMap<String, Value> = serde_yaml::from_str(include_str!(
            "../../recipes/webrtc-sip-bridge/values.example.yaml"
        ))
        .unwrap();
        values.insert(
            "sip_digest_username".into(),
            Value::String("bridgefu".into()),
        );
        values.insert(
            "sip_digest_password".into(),
            Value::String("raw-password-forbidden".into()),
        );
        assert!(package
            .compile(&values)
            .unwrap_err()
            .to_string()
            .contains("secret input"));

        values.insert(
            "sip_digest_password".into(),
            Value::String("env:BRIDGEFU_SIP_PASSWORD".into()),
        );
        values.insert("sip_security".into(), Value::String("sip_rtp".into()));
        assert!(package
            .compile(&values)
            .unwrap_err()
            .to_string()
            .contains("must use sip:"));
    }

    #[test]
    fn rejects_unknown_and_missing_inputs() {
        let catalog = RecipeCatalog::builtin().unwrap();
        let package = catalog
            .resolve("builtin:vapi-amazon-connect-screen-pop@1")
            .unwrap();
        let mut values = canonical_values();
        values.insert("typo".into(), Value::Bool(true));
        assert!(package
            .compile(&values)
            .unwrap_err()
            .to_string()
            .contains("unknown recipe input"));
        let mut values = canonical_values();
        values.remove("connect_instance_arn");
        assert!(package
            .compile(&values)
            .unwrap_err()
            .to_string()
            .contains("required recipe input"));
    }

    #[test]
    fn rejects_partial_node_substitution_and_traversal() {
        let catalog = RecipeCatalog::builtin().unwrap();
        let mut manifest = catalog
            .resolve("builtin:vapi-amazon-connect-screen-pop@1")
            .unwrap()
            .manifest()
            .clone();
        manifest.spec = serde_yaml::from_str(
            r#"
bridges:
  transfer:
    source:
      type: sip
      security:
        $input: sip_security
        suffix: forbidden
      admission:
        mode: managed_attachment
        trusted_cidrs: {$input: vapi_signaling_cidrs}
    destination:
      type: amazon_connect
      media: webrtc
      instance_arn: {$input: connect_instance_arn}
      contact_flow_id: {$input: connect_entry_contact_flow_id}
"#,
        )
        .unwrap();
        assert!(RecipeCompiler
            .compile(&manifest, &canonical_values(), RecipeSupport::Preview)
            .unwrap_err()
            .to_string()
            .contains("complete YAML node"));
        assert!(validate_package_path("../escape.yaml").is_err());
        assert!(validate_package_path("/absolute.yaml").is_err());
    }

    #[test]
    fn secret_values_do_not_change_fingerprint() {
        let manifest: RecipeManifest = serde_yaml::from_str(
            r#"
api_version: bridgefu.dev/recipe/v1
kind: bridge_recipe
metadata: {name: secret-test, version: 1, title: Secret test, support: development}
inputs:
  credential: {type: secret_ref, required: true}
spec:
  bridges:
    transfer:
      source:
        type: webrtc
        signaling_uri: wss://bridge.example.test/webrtc
      destination:
        type: webrtc
        signaling_uri: wss://agent.example.test/signaling
        bearer_token_ref: {$input: credential}
"#,
        )
        .unwrap();
        let compile = |secret: &str| {
            RecipeCompiler
                .compile(
                    &manifest,
                    &BTreeMap::from([("credential".into(), Value::String(secret.into()))]),
                    RecipeSupport::Development,
                )
                .unwrap()
        };
        assert_eq!(
            compile("env:FIRST_SECRET").fingerprint,
            compile("env:SECOND_SECRET").fingerprint
        );
    }
}
