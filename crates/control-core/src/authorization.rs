//! Local operator policy for SPIFFE-ID-bound, one-use artifact grants.

use std::{
    collections::HashMap,
    fs::File,
    io::Read,
    path::PathBuf,
    sync::Mutex,
    time::{Instant, SystemTime, UNIX_EPOCH},
};

use ring::{digest, rand::SecureRandom};
use serde::{Deserialize, Serialize};
use spiffe::SpiffeId;

const POLICY_BYTES: u64 = 256 * 1024;
const MAX_GRANTS: usize = 256;
const MAX_REDEEMED: usize = 4096;
const MAX_TTL_MS: u64 = 60_000;

#[derive(Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Scope {
    schema_version: String,
    attempt: Attempt,
    manifest_digest: String,
    purpose: Purpose,
}

#[derive(Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Attempt {
    schema_version: String,
    tenant_scope: String,
    operation_id: String,
    workflow_epoch: String,
    attempt_epoch: String,
    fence: String,
}

#[derive(Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
enum Purpose {
    ComputeRead,
    ComputeWrite,
    EvidenceRead,
}

fn identifier(s: &str) -> bool {
    s.len() <= 128
        && s.as_bytes().first().is_some_and(u8::is_ascii_alphanumeric)
        && s.bytes()
            .all(|c| c.is_ascii_alphanumeric() || b"._:-".contains(&c))
}

fn decimal(s: &str) -> bool {
    s.parse::<u64>().is_ok_and(|n| n.to_string() == s)
}

fn lowercase_digest(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}

impl Scope {
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        let scope: Self = serde_json::from_slice(bytes).ok()?;
        let attempt = &scope.attempt;
        (scope.schema_version == "1"
            && attempt.schema_version == "1"
            && identifier(&attempt.tenant_scope)
            && identifier(&attempt.operation_id)
            && decimal(&attempt.workflow_epoch)
            && decimal(&attempt.attempt_epoch)
            && decimal(&attempt.fence)
            && lowercase_digest(&scope.manifest_digest))
        .then_some(scope)
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Policy {
    boot_id: String,
    grants: Vec<Grant>,
    #[serde(default)]
    registry_grants: Vec<RegistryGrant>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Grant {
    spiffe_id: String,
    token_sha256: String,
    scope: Scope,
    expires_unix_ms: u64,
}

#[derive(Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct RegistryScope {
    pub tenant_scope: String,
    pub operation_id: String,
    pub workflow_epoch: String,
    pub attempt_epoch: Option<String>,
    pub fence: Option<String>,
}

#[derive(Deserialize, PartialEq, Eq, Clone, Copy)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RegistryAction {
    CreateOperation,
    GetOperation,
    EnsureAttempt,
    ExecutionRegister,
    ResultSelect,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RegistryGrant {
    spiffe_id: String,
    token_sha256: String,
    scope: RegistryScope,
    actions: Vec<RegistryAction>,
    expires_unix_ms: u64,
}

/// A freshly redeemed compute-write grant. Runtime callers supply the verified peer.
pub struct UploadPermit {
    pub(crate) tenant: String,
    pub(crate) certificate: String,
    pub(crate) scope: serde_json::Value,
    expires: u64,
    deadline: Option<Instant>,
}

impl UploadPermit {
    pub(crate) fn bind_transport(&mut self, expiry: u64, deadline: Instant) {
        self.expires = self.expires.min(expiry);
        self.bound_deadline(deadline);
    }
    pub(crate) fn bound_deadline(&mut self, deadline: Instant) {
        self.deadline = Some(self.deadline.map_or(deadline, |old| old.min(deadline)));
    }
    pub(crate) fn live(&self) -> bool {
        now_unix_ms().is_some_and(|now| now < self.expires)
            && self
                .deadline
                .is_none_or(|deadline| Instant::now() < deadline)
    }
}

pub fn now_unix_ms() -> Option<u64> {
    u64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .ok()?
            .as_millis(),
    )
    .ok()
}

pub struct Authorizer {
    path: PathBuf,
    boot_id: String,
    redeemed: Mutex<ReplayWindow>,
}

pub fn sha256_hex(der: &[u8]) -> String {
    hex::encode(digest::digest(&digest::SHA256, der))
}

impl Authorizer {
    pub fn new(path: PathBuf) -> std::io::Result<Self> {
        let mut boot = [0; 32];
        ring::rand::SystemRandom::new()
            .fill(&mut boot)
            .map_err(|_| std::io::Error::other("runtime entropy unavailable"))?;
        Ok(Self {
            path,
            boot_id: hex::encode(boot),
            redeemed: Mutex::new(ReplayWindow::default()),
        })
    }

    pub fn boot_id(&self) -> &str {
        &self.boot_id
    }

    pub fn upload_permit(&self, workload: &SpiffeId, token: &str) -> Option<UploadPermit> {
        let scope = (|| {
            if !lowercase_digest(token) {
                return Err(Denial::Credential);
            }
            let hash = sha256_hex(token.as_bytes());
            let mut matches = self
                .read_policy()?
                .grants
                .into_iter()
                .filter(|grant| grant.token_sha256 == hash);
            let grant = matches.next().ok_or(Denial::Policy)?;
            if matches.next().is_some() {
                return Err(Denial::Policy);
            }
            Scope::decode(&serde_json::to_vec(&grant.scope).map_err(|_| Denial::Policy)?)
                .ok_or(Denial::Policy)
        })()
        .map_err(Denial::audit)
        .ok()?;
        self.redeem_upload(workload, token, &scope)
    }

    pub fn redeem_upload(
        &self,
        workload: &SpiffeId,
        token: &str,
        scope: &Scope,
    ) -> Option<UploadPermit> {
        if scope.purpose != Purpose::ComputeWrite {
            Denial::Policy.audit();
            return None;
        }
        let expires = self.redeem(workload, token, scope)?;
        Some(UploadPermit {
            tenant: scope.attempt.tenant_scope.clone(),
            certificate: workload.to_string(),
            scope: serde_json::to_value(scope).ok()?,
            expires,
            deadline: None,
        })
    }

    pub fn redeem(&self, workload: &SpiffeId, token: &str, scope: &Scope) -> Option<u64> {
        self.try_redeem(workload, token, scope)
            .map_err(Denial::audit)
            .ok()
    }

    fn try_redeem(&self, workload: &SpiffeId, token: &str, scope: &Scope) -> Result<u64, Denial> {
        if !lowercase_digest(token) {
            return Err(Denial::Credential);
        }
        // Serialize policy reads and replay consumption; never evict an unexpired token.
        let mut redeemed = self.redeemed.lock().map_err(|_| Denial::Policy)?;
        let token = sha256_hex(token.as_bytes());
        let policy = self.read_policy()?;
        let mut matching = policy
            .grants
            .into_iter()
            .filter(|grant| grant.token_sha256 == token);
        let grant = matching.next().ok_or(Denial::Policy)?;
        if matching.next().is_some()
            || grant.spiffe_id != workload.to_string()
            || grant.scope != *scope
        {
            return Err(Denial::Policy);
        }
        let now = now_unix_ms().ok_or(Denial::Clock)?;
        if !grant_live(grant.expires_unix_ms, now) {
            return Err(Denial::Expiry);
        }
        redeemed.consume(token, grant.expires_unix_ms, now)?;
        Ok(grant.expires_unix_ms)
    }
    fn read_policy(&self) -> Result<Policy, Denial> {
        if !self.path.metadata().map_err(|_| Denial::Policy)?.is_file() {
            return Err(Denial::Policy);
        }
        let mut bytes = Vec::new();
        File::open(&self.path)
            .map_err(|_| Denial::Policy)?
            .take(POLICY_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| Denial::Policy)?;
        if bytes.len() as u64 > POLICY_BYTES {
            return Err(Denial::Policy);
        }
        let policy: Policy = serde_json::from_slice(&bytes).map_err(|_| Denial::Policy)?;
        if policy.boot_id != self.boot_id
            || policy.grants.len() + policy.registry_grants.len() > MAX_GRANTS
        {
            return Err(Denial::Policy);
        }
        Ok(policy)
    }

    /// Reusable coordinator capability; separate from one-use artifact grants.
    pub fn registry_scope(
        &self,
        workload: &SpiffeId,
        token: &str,
        action: RegistryAction,
    ) -> Option<RegistryScope> {
        let result = (|| {
            if !lowercase_digest(token) {
                return Err(Denial::Credential);
            }
            let hash = sha256_hex(token.as_bytes());
            let mut matching = self
                .read_policy()?
                .registry_grants
                .into_iter()
                .filter(|grant| grant.token_sha256 == hash);
            let grant = matching.next().ok_or(Denial::Policy)?;
            if matching.next().is_some()
                || grant.spiffe_id != workload.to_string()
                || grant.actions.len() > 3
                || !grant.actions.contains(&action)
                || !identifier(&grant.scope.tenant_scope)
                || !identifier(&grant.scope.operation_id)
                || !decimal(&grant.scope.workflow_epoch)
                || match (
                    grant.scope.attempt_epoch.as_deref(),
                    grant.scope.fence.as_deref(),
                ) {
                    (Some(epoch), Some(fence)) => {
                        !matches!(
                            action,
                            RegistryAction::ExecutionRegister | RegistryAction::ResultSelect
                        ) || !decimal(epoch)
                            || !decimal(fence)
                    }
                    (None, None) => matches!(
                        action,
                        RegistryAction::ExecutionRegister | RegistryAction::ResultSelect
                    ),
                    _ => true,
                }
            {
                return Err(Denial::Policy);
            }
            let now = {
                let mut window = self.redeemed.lock().map_err(|_| Denial::Policy)?;
                let now = now_unix_ms().ok_or(Denial::Clock)?;
                window.observe(now)?;
                now
            };
            if !grant_live(grant.expires_unix_ms, now) {
                return Err(Denial::Expiry);
            }
            Ok(grant.scope)
        })();
        result.map_err(Denial::audit).ok()
    }
}

/// Fixed audit vocabulary; no identity, credential, scope, or parser error is logged.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum Denial {
    Credential,
    Policy,
    Expiry,
    Replay,
    Capacity,
    Clock,
    Scope,
    Body,
    Deadline,
    Handshake,
    Identity,
    Provider,
}

impl Denial {
    pub fn audit(self) {
        eprintln!("runtime_auth_denied {}", self.code());
    }
    pub fn code(self) -> &'static str {
        match self {
            Self::Credential => "credential",
            Self::Policy => "policy",
            Self::Expiry => "expiry",
            Self::Replay => "replay",
            Self::Capacity => "capacity",
            Self::Clock => "clock",
            Self::Scope => "invalid_scope",
            Self::Body => "body",
            Self::Deadline => "deadline",
            Self::Handshake => "handshake",
            Self::Identity => "identity",
            Self::Provider => "provider",
        }
    }
}

fn grant_live(expiry: u64, now: u64) -> bool {
    expiry
        .checked_sub(now)
        .is_some_and(|remaining| (1..=MAX_TTL_MS).contains(&remaining))
}

#[derive(Default)]
struct ReplayWindow {
    entries: HashMap<String, u64>,
    high_water: u64,
}

impl ReplayWindow {
    fn observe(&mut self, now: u64) -> Result<(), Denial> {
        if now < self.high_water {
            return Err(Denial::Clock);
        }
        self.high_water = now;
        Ok(())
    }

    fn consume(&mut self, hash: String, expiry: u64, now: u64) -> Result<(), Denial> {
        self.observe(now)?;
        self.entries.retain(|_, expires| *expires > now);
        if self.entries.contains_key(&hash) {
            return Err(Denial::Replay);
        }
        if self.entries.len() >= MAX_REDEEMED {
            return Err(Denial::Capacity);
        }
        self.entries.insert(hash, expiry);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn replay_window_recovers_capacity_without_evicting_live_tokens() {
        let mut window = ReplayWindow::default();
        for n in 0..MAX_REDEEMED {
            assert!(window.consume(n.to_string(), 20, 10).is_ok());
        }
        assert_eq!(
            window.consume("extra".into(), 30, 10),
            Err(Denial::Capacity)
        );
        assert_eq!(window.consume("0".into(), 30, 19), Err(Denial::Replay));
        assert!(window.consume("fresh".into(), 40, 20).is_ok());
        assert_eq!(window.consume("fresh".into(), 50, 21), Err(Denial::Replay));
        assert_eq!(
            window.consume("rollback".into(), 30, 19),
            Err(Denial::Clock)
        );
        assert!(window.entries.len() <= MAX_REDEEMED);
    }

    #[test]
    fn grant_lifetime_is_positive_and_bounded_including_overflow() {
        assert!(!grant_live(10, 10));
        assert!(!grant_live(9, 10));
        assert!(grant_live(60_010, 10));
        assert!(!grant_live(60_011, 10));
        assert!(!grant_live(0, u64::MAX));
    }
    #[test]
    fn expired_redemptions_do_not_create_a_lifetime_cutoff() {
        struct Cleanup(PathBuf);
        impl Drop for Cleanup {
            fn drop(&mut self) {
                let _ = std::fs::remove_file(&self.0);
            }
        }
        let mut auth = Authorizer::new(PathBuf::new()).unwrap();
        auth.path = std::env::temp_dir().join(format!("fabric-replay-{}.json", auth.boot_id()));
        let _cleanup = Cleanup(auth.path.clone());
        let workload: SpiffeId = "spiffe://fabric.test/worker".parse().unwrap();
        let scope = Scope::decode(br#"{"schema_version":"1","attempt":{"schema_version":"1","tenant_scope":"tenant","operation_id":"op","workflow_epoch":"1","attempt_epoch":"1","fence":"1"},"manifest_digest":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","purpose":"COMPUTE_READ"}"#).unwrap();
        for n in 0..=MAX_REDEEMED {
            if n == MAX_REDEEMED {
                std::thread::sleep(std::time::Duration::from_millis(1100));
            }
            let token = sha256_hex(&n.to_le_bytes());
            let expiry = now_unix_ms().unwrap() + 1000;
            std::fs::write(
                &auth.path,
                serde_json::json!({"boot_id":auth.boot_id(), "grants":[{
                    "spiffe_id":workload.to_string(), "token_sha256":sha256_hex(token.as_bytes()),
                    "scope":scope, "expires_unix_ms":expiry
                }]})
                .to_string(),
            )
            .unwrap();
            assert_eq!(
                auth.redeem(&workload, &token, &scope),
                Some(expiry),
                "expired redemptions must not cause a lifetime cutoff"
            );
        }
    }
}
