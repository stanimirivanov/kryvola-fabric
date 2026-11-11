use serde_json::Value;

use super::*;
use crate::{registry::Trust, upload::UploadError};

#[derive(Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct SubmissionGrant {
    spiffe_id: String,
    pub(super) token_sha256: String,
    action: String,
    target: Value,
    pub tenant_scope: String,
    pub owner_identity: String,
    pub owner: Trust,
    pub policy_digest: String,
    pub policy_epoch: String,
    pub evidence_policy_digest: String,
    pub evidence_policy: String,
    expires_unix_ms: u64,
}

impl Authorizer {
    pub(crate) fn submission_grant(
        &self,
        peer: &SpiffeId,
        token: &str,
        action: &str,
        target: &Value,
    ) -> Result<SubmissionGrant, UploadError> {
        if !lowercase_digest(token) {
            return Err(UploadError::Denied);
        }
        let hash = sha256_hex(token.as_bytes());
        let policy = self.read_policy().map_err(|_| UploadError::Unavailable)?;
        let grant = policy
            .owner_submission_grants
            .into_iter()
            .find(|grant| grant.token_sha256 == hash)
            .ok_or(UploadError::Denied)?;
        let now = now_unix_ms().ok_or(UploadError::Unavailable)?;
        self.redeemed
            .lock()
            .map_err(|_| UploadError::Unavailable)?
            .observe(now)
            .map_err(|_| UploadError::Unavailable)?;
        if grant.spiffe_id != peer.to_string()
            || grant.action != action
            || grant.target != *target
            || !grant_live(grant.expires_unix_ms, now)
        {
            return Err(UploadError::Denied);
        }
        Ok(grant)
    }

    pub(crate) fn submission_current(&self, grant: &SubmissionGrant) -> Result<(), UploadError> {
        let policy = self.read_policy().map_err(|_| UploadError::Unavailable)?;
        let now = now_unix_ms().ok_or(UploadError::Unavailable)?;
        if !grant_live(grant.expires_unix_ms, now)
            || !policy.owner_submission_grants.contains(grant)
        {
            return Err(UploadError::Denied);
        }
        Ok(())
    }
}

impl SubmissionGrant {
    pub(crate) fn permit(&self, scope: Value, transport: (u64, Instant)) -> UploadPermit {
        UploadPermit {
            tenant: self.tenant_scope.clone(),
            certificate: self.spiffe_id.clone(),
            scope,
            expires: self.expires_unix_ms.min(transport.0),
            deadline: Some(transport.1),
        }
    }
}
