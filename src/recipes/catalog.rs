use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde_yaml::Value;

use super::compiler::{
    validate_manifest, validate_package_path, CompiledRecipe, RecipeCompiler, RecipeError,
};
use super::manifest::{RecipeManifest, RecipeSupport};

const MAX_MANIFEST_BYTES: u64 = 256 * 1024;
const BUILTIN_VAPI_AMAZON: &str =
    include_str!("../../recipes/vapi-amazon-connect-screen-pop/recipe.yaml");
const BUILTIN_WEBRTC_SIP: &str = include_str!("../../recipes/webrtc-sip-bridge/recipe.yaml");
const BUILTIN_SIP_WEBRTC: &str = include_str!("../../recipes/sip-webrtc-bridge/recipe.yaml");
const BUILTIN_WEBRTC_AMAZON: &str =
    include_str!("../../recipes/webrtc-amazon-connect-bridge/recipe.yaml");

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RecipeSource {
    Builtin,
    External(PathBuf),
}

#[derive(Clone, Debug)]
pub struct RecipePackage {
    manifest: RecipeManifest,
    source: RecipeSource,
}

impl RecipePackage {
    pub fn from_builtin(yaml: &str) -> Result<Self, RecipeError> {
        let manifest = parse_manifest(yaml)?;
        // Compile-time packages are still validated without values when the
        // catalog is constructed; exact input validation occurs on compile.
        validate_static_manifest(&manifest)?;
        Ok(Self {
            manifest,
            source: RecipeSource::Builtin,
        })
    }

    pub fn from_directory(path: &Path) -> Result<Self, RecipeError> {
        let root = path.canonicalize()?;
        if !root.is_dir() {
            return Err(RecipeError::Invalid(
                "external recipe package path must be a directory".into(),
            ));
        }
        let manifest_path = root.join("recipe.yaml");
        let metadata = std::fs::metadata(&manifest_path)?;
        if metadata.len() > MAX_MANIFEST_BYTES {
            return Err(RecipeError::Invalid(
                "external recipe manifest exceeds the size limit".into(),
            ));
        }
        let yaml = std::fs::read_to_string(&manifest_path)?;
        let manifest = parse_manifest(&yaml)?;
        validate_static_manifest(&manifest)?;
        validate_referenced_files(&root, &manifest)?;
        Ok(Self {
            manifest,
            source: RecipeSource::External(root),
        })
    }

    #[must_use]
    pub const fn manifest(&self) -> &RecipeManifest {
        &self.manifest
    }

    #[must_use]
    pub const fn source(&self) -> &RecipeSource {
        &self.source
    }

    #[must_use]
    pub fn effective_support(&self) -> RecipeSupport {
        match self.source {
            RecipeSource::Builtin => self.manifest.metadata.support,
            RecipeSource::External(_) => RecipeSupport::Custom,
        }
    }

    pub fn compile(&self, values: &BTreeMap<String, Value>) -> Result<CompiledRecipe, RecipeError> {
        RecipeCompiler.compile(&self.manifest, values, self.effective_support())
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct RecipeSelector {
    pub builtin: bool,
    pub name: String,
    pub version: u32,
}

impl RecipeSelector {
    pub fn parse(value: &str) -> Result<Self, RecipeError> {
        let (source, package) = value.split_once(':').ok_or_else(|| {
            RecipeError::Invalid(
                "recipe selector must be builtin:name@version or external:name@version".into(),
            )
        })?;
        let builtin = match source {
            "builtin" => true,
            "external" => false,
            _ => {
                return Err(RecipeError::Invalid(
                    "recipe selector source must be builtin or external".into(),
                ));
            }
        };
        let (name, version) = package.rsplit_once('@').ok_or_else(|| {
            RecipeError::Invalid("recipe selector must include an exact @version".into())
        })?;
        let version = version
            .parse::<u32>()
            .map_err(|_| RecipeError::Invalid("recipe selector version is invalid".into()))?;
        if name.is_empty() || version == 0 {
            return Err(RecipeError::Invalid("recipe selector is invalid".into()));
        }
        Ok(Self {
            builtin,
            name: name.to_owned(),
            version,
        })
    }
}

#[derive(Clone, Debug, Default)]
pub struct RecipeCatalog {
    packages: BTreeMap<(String, u32), RecipePackage>,
}

impl RecipeCatalog {
    pub fn builtin() -> Result<Self, RecipeError> {
        let mut catalog = Self::default();
        catalog.register(RecipePackage::from_builtin(BUILTIN_VAPI_AMAZON)?)?;
        catalog.register(RecipePackage::from_builtin(BUILTIN_WEBRTC_SIP)?)?;
        catalog.register(RecipePackage::from_builtin(BUILTIN_SIP_WEBRTC)?)?;
        catalog.register(RecipePackage::from_builtin(BUILTIN_WEBRTC_AMAZON)?)?;
        Ok(catalog)
    }

    pub fn with_external_paths(paths: &[PathBuf]) -> Result<Self, RecipeError> {
        let mut catalog = Self::builtin()?;
        if paths.len() > 64 {
            return Err(RecipeError::Invalid(
                "too many external recipe package paths".into(),
            ));
        }
        for path in paths {
            catalog.register(RecipePackage::from_directory(path)?)?;
        }
        Ok(catalog)
    }

    pub fn register(&mut self, package: RecipePackage) -> Result<(), RecipeError> {
        let key = (
            package.manifest.metadata.name.clone(),
            package.manifest.metadata.version,
        );
        if self.packages.insert(key.clone(), package).is_some() {
            return Err(RecipeError::Invalid(format!(
                "duplicate recipe package {}@{}",
                key.0, key.1
            )));
        }
        Ok(())
    }

    pub fn resolve(&self, selector: &str) -> Result<&RecipePackage, RecipeError> {
        let selector = RecipeSelector::parse(selector)?;
        let package = self
            .packages
            .get(&(selector.name.clone(), selector.version))
            .ok_or_else(|| {
                RecipeError::Invalid(format!(
                    "recipe {}@{} is not installed",
                    selector.name, selector.version
                ))
            })?;
        match (selector.builtin, package.source()) {
            (true, RecipeSource::Builtin) | (false, RecipeSource::External(_)) => Ok(package),
            _ => Err(RecipeError::Invalid(
                "recipe selector source does not match the installed package".into(),
            )),
        }
    }

    pub fn iter(&self) -> impl Iterator<Item = &RecipePackage> {
        self.packages.values()
    }
}

fn parse_manifest(yaml: &str) -> Result<RecipeManifest, RecipeError> {
    if yaml.len() as u64 > MAX_MANIFEST_BYTES {
        return Err(RecipeError::Invalid(
            "recipe manifest exceeds the size limit".into(),
        ));
    }
    serde_yaml::from_str(yaml).map_err(Into::into)
}

fn validate_static_manifest(manifest: &RecipeManifest) -> Result<(), RecipeError> {
    validate_manifest(manifest)?;
    for profiles in manifest.deployments.values() {
        for path in profiles.values() {
            validate_package_path(path)?;
        }
    }
    for path in manifest.assets.values() {
        validate_package_path(path)?;
    }
    Ok(())
}

fn validate_referenced_files(root: &Path, manifest: &RecipeManifest) -> Result<(), RecipeError> {
    for path in manifest
        .deployments
        .values()
        .flat_map(BTreeMap::values)
        .chain(manifest.assets.values())
    {
        let resolved = root.join(path).canonicalize()?;
        if !resolved.starts_with(root) || !resolved.is_file() {
            return Err(RecipeError::Invalid(format!(
                "recipe asset {path:?} is outside the package or is not a file"
            )));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;

    #[test]
    fn builtin_catalog_is_exact_and_embedded() {
        let catalog = RecipeCatalog::builtin().unwrap();
        let packages = catalog.iter().collect::<Vec<_>>();
        assert_eq!(packages.len(), 4);
        assert_eq!(
            packages
                .iter()
                .map(|package| package.manifest.metadata.name.as_str())
                .collect::<BTreeSet<_>>(),
            BTreeSet::from([
                "sip-webrtc-bridge",
                "vapi-amazon-connect-screen-pop",
                "webrtc-amazon-connect-bridge",
                "webrtc-sip-bridge",
            ])
        );
        assert!(packages
            .iter()
            .all(|package| matches!(package.source(), RecipeSource::Builtin)));
    }

    #[test]
    fn selectors_require_source_and_exact_version() {
        assert!(RecipeSelector::parse("builtin:vapi-amazon-connect-screen-pop@1").is_ok());
        assert!(RecipeSelector::parse("vapi-amazon-connect-screen-pop@1").is_err());
        assert!(RecipeSelector::parse("builtin:vapi-amazon-connect-screen-pop").is_err());
        assert!(RecipeSelector::parse("https:vapi@1").is_err());
    }
}
