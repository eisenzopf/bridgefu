//! Redacted, late-bound secret references shared by Bridgefu components.

use std::fmt;
use std::fs::File;
use std::io::{Read, Take};
use std::path::Path;

use serde::Deserialize;
use thiserror::Error;

const MAX_SECRET_BYTES: u64 = 16 * 1024;

/// A literal secret or `env:NAME` reference.
///
/// Environment references first read `NAME`. When it is absent, `NAME_FILE`
/// may name a UTF-8 file containing the secret. Direct environment values
/// always take precedence.
///
/// The wrapper never reveals its value through diagnostics. Callers should
/// resolve it only at the operation boundary and zeroize the returned string.
#[derive(Clone, Deserialize)]
#[serde(transparent)]
pub struct SecretRef {
    value: String,
}

/// Fixed, secret-free reference failure.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum SecretRefError {
    #[error("secret reference syntax is invalid")]
    InvalidReference,
    #[error("referenced environment secret is unavailable")]
    EnvironmentUnavailable,
}

impl SecretRef {
    /// Construct a literal or environment reference. Validation is deliberately
    /// separate so serde can retain configuration errors until startup checks.
    #[must_use]
    pub fn new(value: impl Into<String>) -> Self {
        Self {
            value: value.into(),
        }
    }

    /// Validate syntax without reading the environment or exposing material.
    pub fn validate_reference(&self) -> Result<(), SecretRefError> {
        let valid = if let Some(name) = self.value.strip_prefix("env:") {
            !name.is_empty()
                && name.len() <= 256
                && name.bytes().all(|byte| {
                    byte.is_ascii_uppercase()
                        || byte.is_ascii_digit()
                        || byte == b'_'
                        || byte.is_ascii_lowercase()
                })
        } else {
            !self.value.is_empty()
                && self.value.len() <= MAX_SECRET_BYTES as usize
                && !self.value.chars().any(|value| value == '\0')
        };
        valid.then_some(()).ok_or(SecretRefError::InvalidReference)
    }

    /// Resolve the reference. The returned value may be sensitive and should
    /// be wrapped in `Zeroizing<String>` or explicitly zeroized by the caller.
    pub fn resolve(&self) -> Result<String, SecretRefError> {
        self.validate_reference()?;
        if let Some(name) = self.value.strip_prefix("env:") {
            match std::env::var(name) {
                Ok(value) => Ok(value),
                Err(std::env::VarError::NotPresent) => resolve_secret_file(name),
                Err(std::env::VarError::NotUnicode(_)) => {
                    Err(SecretRefError::EnvironmentUnavailable)
                }
            }
        } else {
            Ok(self.value.clone())
        }
    }

    /// Compare the configured references without resolving either value.
    #[must_use]
    pub fn same_reference(&self, other: &Self) -> bool {
        self.value == other.value
    }
}

fn resolve_secret_file(name: &str) -> Result<String, SecretRefError> {
    let path_variable = format!("{name}_FILE");
    let path = std::env::var_os(path_variable).ok_or(SecretRefError::EnvironmentUnavailable)?;
    let mut bytes = Vec::new();
    let file = File::open(Path::new(&path)).map_err(|_| SecretRefError::EnvironmentUnavailable)?;
    let mut bounded: Take<File> = file.take(MAX_SECRET_BYTES + 1);
    bounded
        .read_to_end(&mut bytes)
        .map_err(|_| SecretRefError::EnvironmentUnavailable)?;
    if bytes.len() > MAX_SECRET_BYTES as usize || bytes.contains(&0) {
        return Err(SecretRefError::EnvironmentUnavailable);
    }

    let mut value = String::from_utf8(bytes).map_err(|_| SecretRefError::EnvironmentUnavailable)?;
    if value.ends_with('\n') {
        value.pop();
        if value.ends_with('\r') {
            value.pop();
        }
    }
    Ok(value)
}

impl fmt::Debug for SecretRef {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SecretRef([redacted])")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn diagnostics_and_errors_do_not_reveal_material() {
        let secret = SecretRef::new("canary-secret-value");
        assert_eq!(format!("{secret:?}"), "SecretRef([redacted])");
        assert_eq!(secret.resolve().unwrap(), "canary-secret-value");
        let missing = SecretRef::new("env:BRIDGEFU_SECRET_REF_MISSING_CANARY");
        assert_eq!(
            missing.resolve().unwrap_err(),
            SecretRefError::EnvironmentUnavailable
        );
        assert!(!missing
            .resolve()
            .unwrap_err()
            .to_string()
            .contains("CANARY"));
    }

    #[test]
    fn environment_reference_uses_bounded_file_fallback() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let variable = format!("BRIDGEFU_TEST_SECRET_FILE_{nonce}");
        let file_variable = format!("{variable}_FILE");
        let path = std::env::temp_dir().join(format!(
            "bridgefu-secret-ref-{}-{nonce}",
            std::process::id()
        ));
        std::env::remove_var(&variable);
        std::env::set_var(&file_variable, &path);

        let secret = SecretRef::new(format!("env:{variable}"));
        std::fs::write(&path, vec![b'x'; MAX_SECRET_BYTES as usize + 1]).unwrap();
        assert_eq!(
            secret.resolve().unwrap_err(),
            SecretRefError::EnvironmentUnavailable
        );

        std::fs::write(&path, b"file-secret\r\n").unwrap();
        assert_eq!(secret.resolve().unwrap(), "file-secret");
        std::env::set_var(&variable, "environment-secret");
        assert_eq!(secret.resolve().unwrap(), "environment-secret");

        std::env::remove_var(&variable);
        std::env::remove_var(&file_variable);
        std::fs::remove_file(path).unwrap();
    }
}
