//! Local operator policy for certificate-bound, one-use artifact grants.

use std::{
    collections::HashSet,
    fs::File,
    io::Read,
    path::PathBuf,
    sync::Mutex,
    time::{SystemTime, UNIX_EPOCH},
};

use ring::{digest, rand::SecureRandom};
use serde::Deserialize;

const POLICY_BYTES: u64 = 256 * 1024;
const MAX_GRANTS: usize = 256;
const MAX_REDEEMED: usize = 4096;
const MAX_TTL_MS: u64 = 60_000;

#[derive(Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Scope {
    schema_version: String,
    attempt: Attempt,
    manifest_digest: String,
    purpose: Purpose,
}

#[derive(Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Attempt {
    schema_version: String,
    tenant_scope: String,
    operation_id: String,
    workflow_epoch: String,
    attempt_epoch: String,
    fence: String,
}

#[derive(Deserialize, PartialEq, Eq)]
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
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Grant {
    certificate_sha256: String,
    token_sha256: String,
    scope: Scope,
    expires_unix_ms: u64,
}

pub struct Authorizer {
    path: PathBuf,
    boot_id: String,
    redeemed: Mutex<HashSet<String>>,
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
            redeemed: Mutex::new(HashSet::new()),
        })
    }

    pub fn boot_id(&self) -> &str {
        &self.boot_id
    }

    pub fn redeem(&self, certificate: &str, token: &str, scope: &Scope) -> Option<u64> {
        if !lowercase_digest(token) {
            return None;
        }
        // Serialize the fresh policy read with one-use redemption. No policy cache.
        let mut redeemed = self.redeemed.lock().ok()?;
        let token = sha256_hex(token.as_bytes());
        if redeemed.len() >= MAX_REDEEMED || redeemed.contains(&token) {
            return None;
        }
        if !self.path.metadata().ok()?.is_file() {
            return None;
        }
        let mut bytes = Vec::new();
        File::open(&self.path)
            .ok()?
            .take(POLICY_BYTES + 1)
            .read_to_end(&mut bytes)
            .ok()?;
        if bytes.len() as u64 > POLICY_BYTES {
            return None;
        }
        let policy: Policy = serde_json::from_slice(&bytes).ok()?;
        if policy.boot_id != self.boot_id || policy.grants.len() > MAX_GRANTS {
            return None;
        }
        let mut matching = policy
            .grants
            .into_iter()
            .filter(|grant| grant.token_sha256 == token);
        let grant = matching.next()?;
        if matching.next().is_some()
            || grant.certificate_sha256 != certificate
            || grant.scope != *scope
        {
            return None;
        }
        let now = u64::try_from(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .ok()?
                .as_millis(),
        )
        .ok()?;
        let remaining = grant.expires_unix_ms.checked_sub(now)?;
        if !(1..=MAX_TTL_MS).contains(&remaining) {
            return None;
        }
        redeemed.insert(token);
        Some(grant.expires_unix_ms)
    }
}
