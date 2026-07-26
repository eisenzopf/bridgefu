//! Redacted, late-bound secret references shared by Bridgefu components.

use std::fmt;

use serde::Deserialize;
use thiserror::Error;

/// A literal secret or `env:NAME` reference.
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
                && self.value.len() <= 16 * 1024
                && !self.value.chars().any(|value| value == '\0')
        };
        valid.then_some(()).ok_or(SecretRefError::InvalidReference)
    }

    /// Resolve the reference. The returned value may be sensitive and should
    /// be wrapped in `Zeroizing<String>` or explicitly zeroized by the caller.
    pub fn resolve(&self) -> Result<String, SecretRefError> {
        self.validate_reference()?;
        if let Some(name) = self.value.strip_prefix("env:") {
            std::env::var(name).map_err(|_| SecretRefError::EnvironmentUnavailable)
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

impl fmt::Debug for SecretRef {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SecretRef([redacted])")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
