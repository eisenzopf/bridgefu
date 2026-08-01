//! Bounded, aggregate-safe control-API request admission.
//!
//! Authenticated control requests are keyed by a process-salted, one-way
//! digest of the principal identity. Provider webhooks use one gateway-wide key because
//! their tenant identity is not trusted until after signature verification.
//! Neither raw credentials nor tenant/subject identifiers are retained or
//! emitted as metric labels.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde::Serialize;
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::config::ApiRateLimitCfg;

const IDENTITY_DOMAIN: &[u8] = b"bridgefu.api-rate-limit.identity.v1\0";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ApiRateSurface {
    Control,
    Diagnostics,
    Webhook,
}

impl ApiRateSurface {
    const fn metric_label(self) -> &'static str {
        match self {
            Self::Control => "control",
            Self::Diagnostics => "diagnostics",
            Self::Webhook => "webhook",
        }
    }
}

#[derive(Clone, Copy, Debug)]
struct BucketPolicy {
    requests_per_second: u32,
    burst: u32,
}

#[derive(Clone, Debug)]
struct RatePolicy {
    enabled: bool,
    control: BucketPolicy,
    diagnostics: BucketPolicy,
    webhook: BucketPolicy,
    max_tracked_identities: usize,
    idle_ttl: Duration,
}

impl From<&ApiRateLimitCfg> for RatePolicy {
    fn from(config: &ApiRateLimitCfg) -> Self {
        Self {
            enabled: config.enabled,
            control: BucketPolicy {
                requests_per_second: config.control_requests_per_second,
                burst: config.control_burst,
            },
            diagnostics: BucketPolicy {
                requests_per_second: config.diagnostics_requests_per_second,
                burst: config.diagnostics_burst,
            },
            webhook: BucketPolicy {
                requests_per_second: config.webhook_requests_per_second,
                burst: config.webhook_burst,
            },
            max_tracked_identities: config.max_tracked_identities,
            idle_ttl: Duration::from_secs(config.identity_idle_ttl_secs),
        }
    }
}

#[derive(Clone, Copy, Debug)]
struct TokenBucket {
    tokens: f64,
    last_refill: Instant,
}

impl TokenBucket {
    fn full(policy: BucketPolicy, now: Instant) -> Self {
        Self {
            tokens: f64::from(policy.burst),
            last_refill: now,
        }
    }

    fn admit(&mut self, policy: BucketPolicy, now: Instant) -> Result<(), Duration> {
        let elapsed = now.saturating_duration_since(self.last_refill);
        self.tokens = (self.tokens + elapsed.as_secs_f64() * f64::from(policy.requests_per_second))
            .min(f64::from(policy.burst));
        self.last_refill = now;
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            return Ok(());
        }
        let wait_seconds = (1.0 - self.tokens) / f64::from(policy.requests_per_second);
        Err(Duration::from_secs_f64(wait_seconds.max(0.001)))
    }
}

#[derive(Clone, Copy, Debug)]
struct IdentityBuckets {
    control: TokenBucket,
    diagnostics: TokenBucket,
    webhook: TokenBucket,
    last_seen: Instant,
}

impl IdentityBuckets {
    fn new(policy: &RatePolicy, now: Instant) -> Self {
        Self {
            control: TokenBucket::full(policy.control, now),
            diagnostics: TokenBucket::full(policy.diagnostics, now),
            webhook: TokenBucket::full(policy.webhook, now),
            last_seen: now,
        }
    }

    fn bucket_and_policy(
        &mut self,
        policy: &RatePolicy,
        surface: ApiRateSurface,
    ) -> (&mut TokenBucket, BucketPolicy) {
        match surface {
            ApiRateSurface::Control => (&mut self.control, policy.control),
            ApiRateSurface::Diagnostics => (&mut self.diagnostics, policy.diagnostics),
            ApiRateSurface::Webhook => (&mut self.webhook, policy.webhook),
        }
    }
}

#[derive(Debug)]
struct RateState {
    identities: HashMap<[u8; 32], IdentityBuckets>,
}

#[derive(Clone)]
pub struct ApiRateLimiter {
    policy: Arc<RatePolicy>,
    state: Arc<Mutex<RateState>>,
    identity_salt: [u8; 32],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RateLimitRejection {
    retry_after: Duration,
}

#[derive(Clone, Copy, Debug, Serialize)]
pub struct RateLimitSurfaceDiagnostics {
    requests_per_second: u32,
    burst: u32,
}

impl From<BucketPolicy> for RateLimitSurfaceDiagnostics {
    fn from(policy: BucketPolicy) -> Self {
        Self {
            requests_per_second: policy.requests_per_second,
            burst: policy.burst,
        }
    }
}

#[derive(Clone, Copy, Debug, Serialize)]
pub struct ApiRateLimitDiagnostics {
    enabled: bool,
    tracked_identities: usize,
    max_tracked_identities: usize,
    identity_idle_ttl_secs: u64,
    control: RateLimitSurfaceDiagnostics,
    diagnostics: RateLimitSurfaceDiagnostics,
    webhook: RateLimitSurfaceDiagnostics,
}

impl RateLimitRejection {
    #[must_use]
    pub fn retry_after_seconds(self) -> u64 {
        self.retry_after.as_secs().max(1)
    }
}

impl ApiRateLimiter {
    #[must_use]
    pub fn from_config(config: &ApiRateLimitCfg) -> Self {
        metrics::gauge!("bridgefu_api_rate_limit_tracked_identities").set(0.0);
        let mut identity_salt = [0_u8; 32];
        identity_salt[..16].copy_from_slice(Uuid::new_v4().as_bytes());
        identity_salt[16..].copy_from_slice(Uuid::new_v4().as_bytes());
        Self {
            policy: Arc::new(RatePolicy::from(config)),
            state: Arc::new(Mutex::new(RateState {
                identities: HashMap::new(),
            })),
            identity_salt,
        }
    }

    /// Aggregate policy and occupancy suitable for an authenticated
    /// diagnostics response. No identity digest or credential is exposed.
    #[must_use]
    pub fn diagnostics(&self) -> ApiRateLimitDiagnostics {
        let tracked_identities = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .identities
            .len();
        ApiRateLimitDiagnostics {
            enabled: self.policy.enabled,
            tracked_identities,
            max_tracked_identities: self.policy.max_tracked_identities,
            identity_idle_ttl_secs: self.policy.idle_ttl.as_secs(),
            control: self.policy.control.into(),
            diagnostics: self.policy.diagnostics.into(),
            webhook: self.policy.webhook.into(),
        }
    }

    /// Applies the policy to a caller identity without retaining its raw
    /// value. The table is strictly bounded and fails closed for a new
    /// identity when no idle entry can be reclaimed.
    pub fn check(
        &self,
        surface: ApiRateSurface,
        identity: &[u8],
    ) -> Result<(), RateLimitRejection> {
        if !self.policy.enabled {
            return Ok(());
        }
        self.check_at(
            surface,
            identity_digest(&self.identity_salt, identity),
            Instant::now(),
        )
    }

    fn check_at(
        &self,
        surface: ApiRateSurface,
        identity: [u8; 32],
        now: Instant,
    ) -> Result<(), RateLimitRejection> {
        let (result, outcome, tracked) = {
            let mut state = self.state.lock().unwrap_or_else(|poisoned| {
                tracing::error!("API rate-limit state mutex was poisoned; recovering state");
                poisoned.into_inner()
            });
            if !state.identities.contains_key(&identity) {
                if state.identities.len() >= self.policy.max_tracked_identities {
                    let idle_ttl = self.policy.idle_ttl;
                    state.identities.retain(|_, entry| {
                        now.saturating_duration_since(entry.last_seen) < idle_ttl
                    });
                }
                if state.identities.len() < self.policy.max_tracked_identities {
                    state
                        .identities
                        .insert(identity, IdentityBuckets::new(&self.policy, now));
                }
            }

            let tracked = state.identities.len();
            match state.identities.get_mut(&identity) {
                Some(entry) => {
                    entry.last_seen = now;
                    let (bucket, bucket_policy) = entry.bucket_and_policy(&self.policy, surface);
                    let result = bucket.admit(bucket_policy, now).map_err(|retry_after| {
                        RateLimitRejection {
                            retry_after: round_retry_after(retry_after),
                        }
                    });
                    let outcome = if result.is_ok() { "allowed" } else { "limited" };
                    (result, outcome, tracked)
                }
                None => (
                    Err(RateLimitRejection {
                        retry_after: self.policy.idle_ttl.min(Duration::from_secs(60)),
                    }),
                    "capacity",
                    tracked,
                ),
            }
        };
        record_decision(surface, outcome, tracked);
        result
    }

    #[cfg(test)]
    fn tracked_identities(&self) -> usize {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .identities
            .len()
    }
}

fn identity_digest(salt: &[u8; 32], identity: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(IDENTITY_DOMAIN);
    hasher.update(salt);
    hasher.update((identity.len() as u64).to_be_bytes());
    hasher.update(identity);
    hasher.finalize().into()
}

fn round_retry_after(value: Duration) -> Duration {
    Duration::from_secs(
        value
            .as_secs()
            .saturating_add(u64::from(value.subsec_nanos() > 0))
            .max(1),
    )
}

fn record_decision(surface: ApiRateSurface, outcome: &'static str, tracked: usize) {
    metrics::counter!(
        "bridgefu_api_rate_limit_requests_total",
        "surface" => surface.metric_label(),
        "outcome" => outcome,
    )
    .increment(1);
    metrics::gauge!("bridgefu_api_rate_limit_tracked_identities").set(tracked as f64);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config() -> ApiRateLimitCfg {
        ApiRateLimitCfg {
            enabled: true,
            control_requests_per_second: 2,
            control_burst: 2,
            diagnostics_requests_per_second: 1,
            diagnostics_burst: 1,
            webhook_requests_per_second: 4,
            webhook_burst: 4,
            max_tracked_identities: 2,
            identity_idle_ttl_secs: 10,
        }
    }

    fn digest_identity(value: &[u8]) -> [u8; 32] {
        identity_digest(&[0x5a; 32], value)
    }

    #[test]
    fn each_surface_has_an_independent_token_bucket() {
        let limiter = ApiRateLimiter::from_config(&config());
        let now = Instant::now();
        let identity = digest_identity(b"principal-a");

        assert!(limiter
            .check_at(ApiRateSurface::Control, identity, now)
            .is_ok());
        assert!(limiter
            .check_at(ApiRateSurface::Control, identity, now)
            .is_ok());
        assert_eq!(
            limiter
                .check_at(ApiRateSurface::Control, identity, now)
                .unwrap_err()
                .retry_after_seconds(),
            1
        );
        assert!(limiter
            .check_at(
                ApiRateSurface::Control,
                digest_identity(b"principal-b"),
                now,
            )
            .is_ok());
        assert!(limiter
            .check_at(ApiRateSurface::Diagnostics, identity, now)
            .is_ok());
        assert!(limiter
            .check_at(ApiRateSurface::Webhook, identity, now)
            .is_ok());
    }

    #[test]
    fn identities_are_bounded_and_idle_entries_are_reclaimed() {
        let limiter = ApiRateLimiter::from_config(&config());
        let start = Instant::now();
        for identity in [b"one".as_slice(), b"two".as_slice()] {
            assert!(limiter
                .check_at(ApiRateSurface::Control, digest_identity(identity), start)
                .is_ok());
        }
        assert_eq!(limiter.tracked_identities(), 2);
        assert!(limiter
            .check_at(ApiRateSurface::Control, digest_identity(b"three"), start)
            .is_err());
        assert_eq!(limiter.tracked_identities(), 2);

        assert!(limiter
            .check_at(
                ApiRateSurface::Control,
                digest_identity(b"three"),
                start + Duration::from_secs(11),
            )
            .is_ok());
        assert_eq!(limiter.tracked_identities(), 1);
    }

    #[test]
    fn disabled_policy_retains_no_identity_state() {
        let mut disabled = config();
        disabled.enabled = false;
        let limiter = ApiRateLimiter::from_config(&disabled);
        for index in 0..100 {
            limiter
                .check(ApiRateSurface::Control, index.to_string().as_bytes())
                .unwrap();
        }
        assert_eq!(limiter.tracked_identities(), 0);
    }
}
