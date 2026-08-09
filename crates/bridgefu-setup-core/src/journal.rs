use crate::{state_journal_path, BundleManifest};
use anyhow::{bail, Context, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::io::Write;
use std::path::Path;
use vapire_iac::OwnedTemplateState;

pub const JOURNAL_SCHEMA: &str = "bridgefu.deployment-journal/v1";
const MAX_JOURNAL_BYTES: u64 = 512 * 1024;

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionPhase {
    Reviewed,
    AwsDeployed,
    VapiTemplateCreated,
    VapiIdentityBound,
    Verified,
    VapiTemplateRetained,
    VapiTemplateDeleted,
    AwsRemoved,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DeploymentJournal {
    pub schema: String,
    pub bundle_sha256: String,
    pub deployment_id: String,
    pub updated_at: DateTime<Utc>,
    pub phase: ExecutionPhase,
    #[serde(default)]
    pub stack_outputs: BTreeMap<String, String>,
    #[serde(default)]
    pub vapi_template: Option<OwnedTemplateState>,
    #[serde(default)]
    pub last_result_category: Option<String>,
}

impl DeploymentJournal {
    pub fn reviewed(manifest: &BundleManifest) -> Self {
        Self {
            schema: JOURNAL_SCHEMA.into(),
            bundle_sha256: manifest.bundle_sha256.clone(),
            deployment_id: manifest.deployment_id.clone(),
            updated_at: Utc::now(),
            phase: ExecutionPhase::Reviewed,
            stack_outputs: BTreeMap::new(),
            vapi_template: None,
            last_result_category: None,
        }
    }

    pub fn validate_for(&self, manifest: &BundleManifest) -> Result<()> {
        if self.schema != JOURNAL_SCHEMA
            || self.bundle_sha256 != manifest.bundle_sha256
            || self.deployment_id != manifest.deployment_id
        {
            bail!("deployment journal does not belong to this sealed bundle");
        }
        if self.stack_outputs.values().any(|value| value.len() > 4_096) {
            bail!("deployment journal contains an oversized output");
        }
        Ok(())
    }
}

pub fn load_journal(bundle: &Path, manifest: &BundleManifest) -> Result<Option<DeploymentJournal>> {
    let path = state_journal_path(bundle);
    if !path.exists() {
        return Ok(None);
    }
    let metadata = path.metadata()?;
    if !metadata.is_file() || metadata.len() > MAX_JOURNAL_BYTES {
        bail!("deployment journal is not a bounded regular file");
    }
    let journal: DeploymentJournal = serde_json::from_slice(&std::fs::read(&path)?)?;
    journal.validate_for(manifest)?;
    Ok(Some(journal))
}

pub fn save_journal(bundle: &Path, journal: &mut DeploymentJournal) -> Result<()> {
    journal.updated_at = Utc::now();
    let path = state_journal_path(bundle);
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    std::fs::create_dir_all(parent)?;
    let temporary = parent.join(format!(
        ".{}.{}.tmp",
        path.file_name().unwrap_or_default().to_string_lossy(),
        uuid::Uuid::new_v4()
    ));
    let bytes = serde_json::to_vec_pretty(journal)?;
    if bytes.len() as u64 > MAX_JOURNAL_BYTES {
        bail!("deployment journal exceeds the safe size limit");
    }
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(&temporary)
        .with_context(|| format!("create state journal {}", temporary.display()))?;
    file.write_all(&bytes)?;
    file.sync_all()?;
    std::fs::rename(&temporary, &path)
        .with_context(|| format!("save state journal {}", path.display()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::artifact::example_configuration;
    use crate::{inspect_bundle, seal_bundle};

    #[test]
    fn journal_is_bound_to_the_sealed_bundle_hash() {
        let directory = tempfile::tempdir().unwrap();
        let bundle = directory.path().join("customer.bridgefu");
        seal_bundle(&example_configuration(), &bundle).unwrap();
        let manifest = inspect_bundle(&bundle).unwrap().manifest;
        let mut journal = DeploymentJournal::reviewed(&manifest);
        save_journal(&bundle, &mut journal).unwrap();
        assert_eq!(
            load_journal(&bundle, &manifest).unwrap().unwrap().phase,
            ExecutionPhase::Reviewed
        );
        let mut wrong = manifest.clone();
        wrong.bundle_sha256 = "0".repeat(64);
        assert!(load_journal(&bundle, &wrong).is_err());
    }
}
