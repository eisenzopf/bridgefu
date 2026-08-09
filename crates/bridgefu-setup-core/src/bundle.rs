use crate::artifact::{generate_artifacts, GeneratedArtifacts};
use crate::journal::{load_journal, save_journal, DeploymentJournal, ExecutionPhase};
use crate::schema::SetupConfiguration;
use anyhow::{bail, Context, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use zip::write::SimpleFileOptions;
use zip::{CompressionMethod, ZipArchive, ZipWriter};

const MANIFEST_PATH: &str = "manifest.json";
const MANIFEST_SCHEMA: &str = "bridgefu.deployment-bundle/v1";
const MAX_BUNDLE_BYTES: u64 = 2 * 1024 * 1024;
const MAX_FILE_BYTES: u64 = 512 * 1024;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BundleManifestEntry {
    pub path: String,
    pub bytes: u64,
    pub sha256: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BundleManifest {
    pub schema: String,
    pub created_at: DateTime<Utc>,
    pub deployment_id: String,
    pub bundle_sha256: String,
    pub entries: Vec<BundleManifestEntry>,
    pub contains_secrets: bool,
}

#[derive(Clone, Debug)]
pub struct BundleInspection {
    pub manifest: BundleManifest,
    pub configuration: SetupConfiguration,
    pub files: BTreeMap<String, Vec<u8>>,
}

pub fn seal_bundle(config: &SetupConfiguration, output: &Path) -> Result<BundleManifest> {
    let artifacts = generate_artifacts(config)?;
    reject_secret_material(&artifacts)?;
    let manifest = create_manifest(config, &artifacts)?;
    if let Some(parent) = output.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("create bundle directory {}", parent.display()))?;
    }
    let file = File::create(output).with_context(|| format!("create {}", output.display()))?;
    let mut zip = ZipWriter::new(file);
    let options = SimpleFileOptions::default()
        .compression_method(CompressionMethod::Deflated)
        .unix_permissions(0o600);
    zip.start_file(MANIFEST_PATH, options)?;
    zip.write_all(&serde_json::to_vec_pretty(&manifest)?)?;
    for (path, contents) in &artifacts.files {
        zip.start_file(path, options)?;
        zip.write_all(contents)?;
    }
    zip.finish()?;
    if output.metadata()?.len() > MAX_BUNDLE_BYTES {
        let _ = std::fs::remove_file(output);
        bail!("generated deployment bundle exceeds 2 MiB");
    }
    Ok(manifest)
}

pub fn inspect_bundle(path: &Path) -> Result<BundleInspection> {
    let metadata = path
        .metadata()
        .with_context(|| format!("read {}", path.display()))?;
    if !metadata.is_file() || metadata.len() > MAX_BUNDLE_BYTES {
        bail!("deployment bundle is not a bounded regular file");
    }
    let file = File::open(path)?;
    let mut zip = ZipArchive::new(file).context("invalid deployment bundle ZIP")?;
    let mut files = BTreeMap::new();
    for index in 0..zip.len() {
        let mut entry = zip.by_index(index)?;
        let name = entry.name().to_string();
        validate_path(&name)?;
        if entry.is_dir() || entry.size() > MAX_FILE_BYTES {
            bail!("invalid deployment bundle entry");
        }
        if files.contains_key(&name) {
            bail!("duplicate deployment bundle entry");
        }
        let mut contents = Vec::with_capacity(entry.size() as usize);
        entry.read_to_end(&mut contents)?;
        files.insert(name, contents);
    }
    let manifest_bytes = files
        .remove(MANIFEST_PATH)
        .context("deployment bundle manifest is missing")?;
    let manifest: BundleManifest = serde_json::from_slice(&manifest_bytes)?;
    if manifest.schema != MANIFEST_SCHEMA || manifest.contains_secrets {
        bail!("unsupported or unsafe deployment bundle manifest");
    }
    let expected_paths: BTreeSet<_> = manifest
        .entries
        .iter()
        .map(|item| item.path.clone())
        .collect();
    let actual_paths: BTreeSet<_> = files.keys().cloned().collect();
    if expected_paths != actual_paths || expected_paths.len() != manifest.entries.len() {
        bail!("deployment bundle entries do not match the manifest");
    }
    for expected in &manifest.entries {
        let contents = &files[&expected.path];
        if expected.bytes != contents.len() as u64 || expected.sha256 != sha256(contents) {
            bail!("deployment bundle entry hash mismatch: {}", expected.path);
        }
    }
    if manifest.bundle_sha256 != bundle_hash(&manifest.entries) {
        bail!("deployment bundle manifest hash is invalid");
    }
    reject_secret_material(&GeneratedArtifacts {
        files: files.clone(),
    })?;
    let configuration: SetupConfiguration = serde_yaml::from_slice(
        files
            .get("deployment.yaml")
            .context("deployment configuration is missing")?,
    )?;
    configuration.validate()?;
    if configuration.deployment_id != manifest.deployment_id {
        bail!("deployment bundle identity does not match its manifest");
    }
    Ok(BundleInspection {
        manifest,
        configuration,
        files,
    })
}

pub fn state_journal_path(bundle: &Path) -> PathBuf {
    let mut name = bundle.file_name().unwrap_or_default().to_os_string();
    name.push(".state.json");
    bundle.with_file_name(name)
}

/// Exercise the portable reviewed-bundle workflow without credentials or network access.
///
/// Native release jobs invoke this through the packaged desktop executable. The
/// temporary directory contains only files created by this function, and cleanup
/// removes those exact files rather than traversing an ambient directory.
pub fn run_mocked_workflow_smoke() -> Result<()> {
    let directory =
        std::env::temp_dir().join(format!("bridgefu-setup-smoke-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir(&directory)
        .with_context(|| format!("create smoke directory {}", directory.display()))?;
    let bundle = directory.join("smoke.bridgefu");
    let journal_path = state_journal_path(&bundle);

    let result = (|| {
        let manifest = seal_bundle(&crate::artifact::example_configuration(), &bundle)?;
        let inspected = inspect_bundle(&bundle)?;
        if inspected.manifest.bundle_sha256 != manifest.bundle_sha256 {
            bail!("mocked workflow bundle hash changed during inspection");
        }
        let mut journal = DeploymentJournal::reviewed(&manifest);
        save_journal(&bundle, &mut journal)?;
        let loaded =
            load_journal(&bundle, &manifest)?.context("mocked workflow journal was not saved")?;
        if loaded.phase != ExecutionPhase::Reviewed {
            bail!("mocked workflow journal did not resume at reviewed phase");
        }
        Ok(())
    })();

    let cleanup = (|| {
        if journal_path.exists() {
            std::fs::remove_file(&journal_path)?;
        }
        if bundle.exists() {
            std::fs::remove_file(&bundle)?;
        }
        std::fs::remove_dir(&directory)?;
        Ok::<_, std::io::Error>(())
    })();
    if let Err(error) = result {
        let _ = cleanup;
        return Err(error);
    }
    cleanup.context("clean up mocked setup workflow")?;
    Ok(())
}

/// Export the reviewed human-readable artifacts without interpreting ZIP paths.
/// Existing files are never overwritten.
pub fn export_bundle(bundle: &Path, destination: &Path) -> Result<BundleManifest> {
    let inspection = inspect_bundle(bundle)?;
    if destination.exists() {
        let mut entries = std::fs::read_dir(destination)
            .with_context(|| format!("read artifact directory {}", destination.display()))?;
        if entries.next().is_some() {
            bail!("artifact destination must be empty");
        }
    } else {
        std::fs::create_dir_all(destination)
            .with_context(|| format!("create artifact directory {}", destination.display()))?;
    }
    for (relative, contents) in &inspection.files {
        validate_path(relative)?;
        let output = destination.join(relative);
        if output.exists() {
            bail!("refusing to overwrite artifact {}", output.display());
        }
        if let Some(parent) = output.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        options.open(&output)?.write_all(contents)?;
    }
    Ok(inspection.manifest)
}

fn create_manifest(
    config: &SetupConfiguration,
    artifacts: &GeneratedArtifacts,
) -> Result<BundleManifest> {
    let entries = artifacts
        .files
        .iter()
        .map(|(path, contents)| BundleManifestEntry {
            path: path.clone(),
            bytes: contents.len() as u64,
            sha256: sha256(contents),
        })
        .collect::<Vec<_>>();
    Ok(BundleManifest {
        schema: MANIFEST_SCHEMA.into(),
        created_at: Utc::now(),
        deployment_id: config.deployment_id.clone(),
        bundle_sha256: bundle_hash(&entries),
        entries,
        contains_secrets: false,
    })
}

fn bundle_hash(entries: &[BundleManifestEntry]) -> String {
    let mut material = Vec::new();
    for entry in entries {
        material.extend_from_slice(entry.path.as_bytes());
        material.push(0);
        material.extend_from_slice(entry.sha256.as_bytes());
        material.push(b'\n');
    }
    sha256(&material)
}

fn sha256(contents: &[u8]) -> String {
    format!("{:x}", Sha256::digest(contents))
}

fn validate_path(value: &str) -> Result<()> {
    if value.is_empty()
        || value.starts_with('/')
        || value.contains("..")
        || value.contains('\\')
        || value.chars().any(char::is_control)
    {
        bail!("invalid deployment bundle path");
    }
    Ok(())
}

fn reject_secret_material(artifacts: &GeneratedArtifacts) -> Result<()> {
    const FORBIDDEN_KEYS: &[&str] = &[
        "vapiApiKey",
        "vapiPrivateKey",
        "awsSecretAccessKey",
        "sessionToken",
        "webhookBearerValue",
    ];
    for (path, contents) in &artifacts.files {
        let text = String::from_utf8_lossy(contents);
        if FORBIDDEN_KEYS.iter().any(|needle| text.contains(needle))
            || text.contains("AKIA")
            || text.contains("sk-ant-")
            || text.contains("-----BEGIN PRIVATE KEY-----")
        {
            bail!("secret-like material is forbidden in deployment artifact {path}");
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::artifact::example_configuration;

    #[test]
    fn seals_and_verifies_portable_bundle() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("customer.bridgefu");
        let manifest = seal_bundle(&example_configuration(), &path).unwrap();
        let inspected = inspect_bundle(&path).unwrap();
        assert_eq!(manifest.bundle_sha256, inspected.manifest.bundle_sha256);
        assert_eq!(inspected.configuration.deployment_id, "customer-demo");
        assert!(inspected.files.contains_key("vapi/template-assistant.json"));
        assert!(!inspected
            .files
            .contains_key("vapi/assistant-extension.json"));
    }

    #[test]
    fn modified_artifact_is_rejected() {
        let config = example_configuration();
        let mut artifacts = generate_artifacts(&config).unwrap();
        let manifest = create_manifest(&config, &artifacts).unwrap();
        artifacts
            .files
            .get_mut("vapi/prompt.md")
            .unwrap()
            .extend_from_slice(b" changed");
        let entry = manifest
            .entries
            .iter()
            .find(|item| item.path == "vapi/prompt.md")
            .unwrap();
        assert_ne!(entry.sha256, sha256(&artifacts.files["vapi/prompt.md"]));
    }

    #[test]
    fn state_journal_is_sibling_of_immutable_bundle() {
        assert_eq!(
            state_journal_path(Path::new("customer.bridgefu")),
            PathBuf::from("customer.bridgefu.state.json")
        );
    }

    #[test]
    fn zip_paths_are_validated_without_extracting() {
        assert!(validate_path("../secret").is_err());
        assert!(validate_path("aws/parameters.json").is_ok());
    }

    #[test]
    fn export_never_overwrites_existing_artifacts() {
        let directory = tempfile::tempdir().unwrap();
        let bundle = directory.path().join("customer.bridgefu");
        seal_bundle(&example_configuration(), &bundle).unwrap();
        let export = directory.path().join("review");
        export_bundle(&bundle, &export).unwrap();
        assert!(export.join("deployment.yaml").is_file());
        assert!(export_bundle(&bundle, &export).is_err());
    }

    #[test]
    fn mocked_workflow_smoke_is_credential_free_and_self_cleaning() {
        run_mocked_workflow_smoke().unwrap();
    }
}
