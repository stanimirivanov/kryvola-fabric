use serde_json::Value;

use super::*;
use crate::{registry::Trust, upload::UploadError};

#[derive(Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct ConsumerGrant {
    spiffe_id: String,
    token_sha256: String,
    scope: Value,
    part_index: Option<u16>,
    pub expires_unix_ms: u64,
    pub policy_digest: String,
    pub policy_epoch: String,
    pub coordinator: Trust,
}

impl Policy {
    pub(super) fn consumer_credentials_separate(&self) -> bool {
        let mut hashes = std::collections::HashSet::new();
        hashes.extend(self.grants.iter().map(|g| &g.token_sha256));
        hashes.extend(self.registry_grants.iter().map(|g| &g.token_sha256));
        hashes.extend(self.receipt_grants.iter().map(|g| &g.token_sha256));
        hashes.extend(self.output_grants.iter().map(|g| &g.token_sha256));
        self.consumer_grants
            .iter()
            .all(|g| hashes.insert(&g.token_sha256))
    }
}

impl Authorizer {
    pub(crate) fn redeem_consumer(
        &self,
        workload: &SpiffeId,
        token: &str,
        scope: &Value,
        part: Option<u16>,
    ) -> Result<ConsumerGrant, UploadError> {
        if !lowercase_digest(token) {
            return Err(UploadError::Denied);
        }
        let mut replay = self.redeemed.lock().map_err(|_| UploadError::Unavailable)?;
        let hash = sha256_hex(token.as_bytes());
        let grant = self
            .read_policy()
            .map_err(|_| UploadError::Unavailable)?
            .consumer_grants
            .into_iter()
            .find(|grant| grant.token_sha256 == hash)
            .ok_or(UploadError::Denied)?;
        let now = now_unix_ms().ok_or(UploadError::Unavailable)?;
        if grant.spiffe_id != workload.to_string()
            || grant.scope != *scope
            || grant.part_index != part
            || !grant_live(grant.expires_unix_ms, now)
            || !lowercase_digest(&grant.policy_digest)
            || !decimal(&grant.policy_epoch)
        {
            return Err(UploadError::Denied);
        }
        replay
            .consume(hash, grant.expires_unix_ms, now)
            .map_err(|_| UploadError::Denied)?;
        Ok(grant)
    }

    pub(crate) fn check_consumer(&self, grant: &ConsumerGrant) -> Result<(), UploadError> {
        let now = now_unix_ms().ok_or(UploadError::Unavailable)?;
        if !grant_live(grant.expires_unix_ms, now)
            || !self
                .read_policy()
                .map_err(|_| UploadError::Unavailable)?
                .consumer_grants
                .contains(grant)
        {
            return Err(UploadError::Denied);
        }
        Ok(())
    }
}
