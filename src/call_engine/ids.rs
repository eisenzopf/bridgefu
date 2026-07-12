//! Strong identifiers and redacted fixed-size digests used by persistence.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize};
use thiserror::Error;
use uuid::Uuid;

/// Identifier parsing failure.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("invalid {kind} identifier")]
pub struct RepositoryIdError {
    kind: &'static str,
}

macro_rules! uuid_id {
    ($name:ident, $label:literal) => {
        #[doc = concat!("Strong ", $label, " identifier.")]
        #[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
        #[serde(transparent)]
        pub struct $name(Uuid);

        impl $name {
            #[doc = concat!("Generates a new ", $label, " identifier.")]
            #[must_use]
            pub fn new() -> Self {
                Self(Uuid::new_v4())
            }

            #[doc = concat!("Constructs a ", $label, " identifier from a non-nil UUID.")]
            pub fn from_uuid(value: Uuid) -> Result<Self, RepositoryIdError> {
                if value.is_nil() {
                    Err(RepositoryIdError { kind: $label })
                } else {
                    Ok(Self(value))
                }
            }

            /// Returns the underlying UUID.
            #[must_use]
            pub const fn as_uuid(self) -> Uuid {
                self.0
            }
        }

        impl Default for $name {
            fn default() -> Self {
                Self::new()
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                self.0.fmt(formatter)
            }
        }

        impl FromStr for $name {
            type Err = RepositoryIdError;

            fn from_str(value: &str) -> Result<Self, Self::Err> {
                let value =
                    Uuid::parse_str(value).map_err(|_| RepositoryIdError { kind: $label })?;
                Self::from_uuid(value)
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: Deserializer<'de>,
            {
                let value = Uuid::deserialize(deserializer)?;
                Self::from_uuid(value).map_err(serde::de::Error::custom)
            }
        }
    };
}

uuid_id!(CommandId, "command");
uuid_id!(EffectId, "effect");
uuid_id!(AttachmentId, "attachment");
uuid_id!(WorkerId, "worker");

macro_rules! redacted_digest {
    ($name:ident, $label:literal) => {
        #[doc = concat!("Redacted SHA-256-sized ", $label, ".")]
        #[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
        #[serde(transparent)]
        pub struct $name([u8; 32]);

        impl $name {
            /// Constructs a digest from exactly 32 bytes.
            #[must_use]
            pub const fn new(bytes: [u8; 32]) -> Self {
                Self(bytes)
            }

            /// Explicitly exposes the bytes to a persistence or cryptographic boundary.
            #[must_use]
            pub const fn expose_bytes(&self) -> &[u8; 32] {
                &self.0
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(concat!(stringify!($name), "([redacted])"))
            }
        }
    };
}

redacted_digest!(IdempotencyKeyDigest, "idempotency-key digest");
redacted_digest!(RequestDigest, "canonical-request digest");
redacted_digest!(AttachmentTokenDigest, "attachment-token digest");
redacted_digest!(PrincipalFingerprint, "principal ownership fingerprint");
redacted_digest!(ProviderEventDigest, "provider event identifier digest");
redacted_digest!(ProviderPayloadDigest, "provider event payload digest");

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn digest_debug_is_redacted() {
        let digest = AttachmentTokenDigest::new([0xabu8; 32]);
        let rendered = format!("{digest:?}");
        assert_eq!(rendered, "AttachmentTokenDigest([redacted])");
        assert!(!rendered.contains("171"));
    }

    #[test]
    fn identifiers_reject_nil_uuid() {
        assert_eq!(
            CommandId::from_uuid(Uuid::nil()),
            Err(RepositoryIdError { kind: "command" })
        );
    }
}
