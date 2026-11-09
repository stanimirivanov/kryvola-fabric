//! Boot-local, single-use upload tokens issued under execution-specific policy.
use serde_json::{Value, json};

use super::*;
use crate::upload::UploadError;

const MAX_OUTSTANDING_OUTPUT_GRANTS: usize = 256;

#[derive(Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct OutputAuthority {
    spiffe_id: String,
    pub(super) token_sha256: String,
    attempt: Attempt,
    execution_id: String,
    expires_unix_ms: u64,
}

impl OutputAuthority {
    pub fn matches(&self, body: &Value) -> bool {
        serde_json::from_value::<Attempt>(body["attempt"].clone())
            .ok()
            .as_ref()
            == Some(&self.attempt)
            && body["execution_id"] == self.execution_id
    }
}

pub(super) struct IssuedOutputGrant {
    authority: OutputAuthority,
    scope: Value,
    target: Value,
    expires: u64,
    lease: Instant,
}

impl Policy {
    fn output_authority(self, hash: &str, workload: &str, now: u64) -> Option<OutputAuthority> {
        if self.grants.iter().any(|grant| grant.token_sha256 == hash)
            || self
                .registry_grants
                .iter()
                .any(|grant| grant.token_sha256 == hash)
            || self
                .receipt_grants
                .iter()
                .any(|grant| grant.token_sha256 == hash)
        {
            return None;
        }
        let mut candidates = self
            .output_grants
            .into_iter()
            .filter(|grant| grant.token_sha256 == hash);
        let authority = candidates.next()?;
        (candidates.next().is_none()
            && authority.spiffe_id == workload
            && grant_live(authority.expires_unix_ms, now))
        .then_some(authority)
    }
}

impl Authorizer {
    pub(crate) fn output_authority(
        &self,
        workload: &SpiffeId,
        token: &str,
    ) -> Result<OutputAuthority, UploadError> {
        if !lowercase_digest(token) {
            return Err(UploadError::Denied);
        }
        let policy = self.read_policy().map_err(|_| UploadError::Denied)?;
        let now = now_unix_ms().ok_or(UploadError::Unavailable)?;
        policy
            .output_authority(&sha256_hex(token.as_bytes()), &workload.to_string(), now)
            .ok_or(UploadError::Denied)
    }

    pub(crate) fn mint_output(
        &self,
        authority: OutputAuthority,
        body: &Value,
        lease: Instant,
        (identity_expiry, provider_deadline): (u64, Instant),
    ) -> Result<(String, u64), UploadError> {
        let mut window = self.redeemed.lock().map_err(|_| UploadError::Unavailable)?;
        let policy = self.read_policy().map_err(|_| UploadError::Denied)?;
        let now = now_unix_ms().ok_or(UploadError::Unavailable)?;
        window.observe(now).map_err(|_| UploadError::Unavailable)?;
        if policy
            .output_authority(&authority.token_sha256, &authority.spiffe_id, now)
            .as_ref()
            != Some(&authority)
            || Instant::now() >= provider_deadline
        {
            return Err(UploadError::Denied);
        }
        let remaining = lease.saturating_duration_since(Instant::now()).as_millis() as u64;
        if remaining == 0 {
            return Err(UploadError::AttemptExpired);
        }
        let expires = authority
            .expires_unix_ms
            .min(identity_expiry)
            .min(now.saturating_add(remaining.min(MAX_TTL_MS)));
        if expires <= now {
            return Err(UploadError::Denied);
        }
        window.issued_outputs.retain(|_, grant| grant.expires > now);
        if window.issued_outputs.len() >= MAX_OUTSTANDING_OUTPUT_GRANTS {
            return Err(UploadError::Quota);
        }
        let mut random = [0; 32];
        ring::rand::SystemRandom::new()
            .fill(&mut random)
            .map_err(|_| UploadError::Unavailable)?;
        let token = hex::encode(random);
        let hash = sha256_hex(token.as_bytes());
        if window.issued_outputs.contains_key(&hash) || window.entries.contains_key(&hash) {
            return Err(UploadError::Unavailable);
        }
        let scope = json!({
            "schema_version": "1", "attempt": body["attempt"], "purpose": "COMPUTE_WRITE",
            "manifest_digest": body["manifest_digest"], "execution_id": body["execution_id"],
        });
        window.issued_outputs.insert(
            hash,
            IssuedOutputGrant {
                authority,
                scope,
                target: body["target"].clone(),
                expires,
                lease,
            },
        );
        Ok((token, expires))
    }

    pub(crate) fn upload_permit_for(
        &self,
        workload: &SpiffeId,
        token: &str,
        target: &Value,
    ) -> Option<UploadPermit> {
        let result = (|| {
            if !lowercase_digest(token) {
                return Err(Denial::Credential);
            }
            let mut window = self.redeemed.lock().map_err(|_| Denial::Policy)?;
            let hash = sha256_hex(token.as_bytes());
            if !window.issued_outputs.contains_key(&hash) {
                drop(window);
                return Ok(self.upload_permit(workload, token));
            }
            let policy = self.read_policy()?;
            let now = now_unix_ms().ok_or(Denial::Clock)?;
            window.observe(now)?;
            let grant = window.issued_outputs.get(&hash).ok_or(Denial::Policy)?;
            let peer = workload.to_string();
            if grant.authority.spiffe_id != peer {
                return Err(Denial::Policy);
            }
            if policy
                .output_authority(&grant.authority.token_sha256, &peer, now)
                .as_ref()
                != Some(&grant.authority)
            {
                window.issued_outputs.remove(&hash);
                return Err(Denial::Policy);
            }
            if grant.target != *target {
                return Err(Denial::Policy);
            }
            if !grant_live(grant.expires, now) || Instant::now() >= grant.lease {
                return Err(Denial::Expiry);
            }
            let expires = grant.expires;
            window.consume(hash.clone(), expires, now)?;
            let grant = window.issued_outputs.remove(&hash).ok_or(Denial::Replay)?;
            Ok(Some(UploadPermit {
                tenant: grant.authority.attempt.tenant_scope,
                certificate: peer,
                scope: grant.scope,
                expires,
                deadline: Some(grant.lease),
            }))
        })();
        result.map_err(Denial::audit).ok().flatten()
    }
}
