//! Owner-local approval over published canonical v3 objects.
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use ring::signature::{ED25519, Ed25519KeyPair, KeyPair, UnparsedPublicKey};
use serde_json::{Value, json};
use std::{
    path::Path,
    sync::OnceLock,
    time::{SystemTime, UNIX_EPOCH},
};

use super::{Result, Store, lookup_for, validate_slot};

pub const CONTROL: usize = 65536;
const LABEL: &str = "CONFIDENTIALITY_ONLY";
const APPROVAL: &str = include_str!("../../../contracts/spec/canonical/v3/approval.schema.json");
pub(super) const ENVELOPE: &str =
    include_str!("../../../contracts/spec/canonical/v3/signature.schema.json");
const PLAN: &str = include_str!("../../../contracts/spec/canonical/v2/plan.schema.json");
const CONSENT: &str = include_str!("../../../contracts/spec/consent-declaration.schema.json");
static APPROVAL_VALIDATOR: OnceLock<Option<jsonschema::Validator>> = OnceLock::new();
pub(super) static SIGNATURE_VALIDATOR: OnceLock<Option<jsonschema::Validator>> = OnceLock::new();
static PLAN_VALIDATOR: OnceLock<Option<jsonschema::Validator>> = OnceLock::new();
static CONSENT_VALIDATOR: OnceLock<Option<jsonschema::Validator>> = OnceLock::new();

pub(super) fn canonical(value: &Value) -> Result<Vec<u8>> {
    let mut sorted = value.clone();
    sorted.sort_all_objects();
    serde_json::to_vec(&sorted).map_err(|_| "OWNER_APPROVAL_FORMAT")
}

pub(super) fn parse(bytes: &[u8]) -> Result<Value> {
    if bytes.is_empty() || bytes.len() > CONTROL {
        return Err("OWNER_APPROVAL_FORMAT");
    }
    let value = serde_json::from_slice(bytes).map_err(|_| "OWNER_APPROVAL_FORMAT")?;
    if canonical(&value)? != bytes {
        return Err("OWNER_APPROVAL_FORMAT");
    }
    Ok(value)
}

pub(super) fn validate(
    value: &Value,
    schema: &str,
    cache: &OnceLock<Option<jsonschema::Validator>>,
) -> Result<()> {
    if cache
        .get_or_init(|| {
            jsonschema::validator_for(&serde_json::from_str::<Value>(schema).ok()?).ok()
        })
        .as_ref()
        .is_some_and(|v| v.is_valid(value))
    {
        Ok(())
    } else {
        Err("OWNER_APPROVAL_FORMAT")
    }
}

pub(super) fn digest(domain: &[u8], bytes: &[u8]) -> String {
    blake3::Hasher::new()
        .update(domain)
        .update(bytes)
        .finalize()
        .to_hex()
        .to_string()
}

pub fn approval_digest(bytes: &[u8]) -> Result<String> {
    validate(&parse(bytes)?, APPROVAL, &APPROVAL_VALIDATOR)?;
    Ok(digest(b"kryvola/approval/v3\0", bytes))
}

pub(super) fn preimage(kind: &str, header: &Value, payload: &[u8]) -> Result<Vec<u8>> {
    let header = canonical(header)?;
    let mut message = format!("kryvola/signature/{kind}/v3\0").into_bytes();
    for bytes in [header.as_slice(), payload] {
        message.extend_from_slice(&(bytes.len() as u64).to_le_bytes());
        message.extend_from_slice(bytes);
    }
    Ok(message)
}

pub struct Policy {
    pub(super) approval: Value,
    pub(super) plan: Value,
    bytes: Vec<u8>,
    header: Value,
    public_key: [u8; 32],
}

impl Policy {
    pub fn load(store: &Store, slot: &str) -> Result<Self> {
        validate_slot(slot)?;
        Self::from_bytes(
            &store.read_bounded(&format!("{slot}.approval-policy"), CONTROL)?,
            &store.read_bounded(&format!("{slot}.plan"), CONTROL)?,
            &store.read_bounded(&format!("{slot}.consent"), CONTROL)?,
        )
    }

    pub fn from_bytes(policy: &[u8], plan: &[u8], consent: &[u8]) -> Result<Self> {
        let value = parse(policy)?;
        let plan_value = parse(plan)?;
        let consent_value = parse(consent)?;
        validate(&plan_value, PLAN, &PLAN_VALIDATOR)?;
        validate(&consent_value, CONSENT, &CONSENT_VALIDATOR)?;
        let leakage = consent_value["accepted_leakage"]
            .as_array()
            .ok_or("OWNER_APPROVAL_POLICY")?;
        // The pinned FHE-Q1 baseline exposes all seven schema-listed metadata classes.
        if leakage
            .iter()
            .collect::<std::collections::HashSet<_>>()
            .len()
            != 7
        {
            return Err("OWNER_APPROVAL_POLICY");
        }
        let approval = value["approval"].clone();
        validate(&approval, APPROVAL, &APPROVAL_VALIDATOR)?;
        if value.as_object().is_none_or(|fields| fields.len() != 6)
            || value["assurance"] != LABEL
            || approval["subject_kind"] != "plan"
            || approval["subject_digest"] != approval["plan_digest"]
            || !matches!(approval["purpose"].as_str(), Some("COMPUTE" | "RELEASE"))
            || (approval["purpose"] == "RELEASE"
                && consent_value["allow_unverified_release"] != true)
            || approval["plan_digest"] != digest(b"kryvola/plan/v2\0", plan)
            || approval["consent_digest"] != digest(b"kryvola/blob/v1\0", consent)
            || [
                "tenant_scope",
                "key_context_digest",
                "model_digest",
                "program_digest",
                "evidence_policy_digest",
                "consent_digest",
            ]
            .iter()
            .any(|field| approval[*field] != plan_value[*field])
        {
            return Err("OWNER_APPROVAL_POLICY");
        }
        let bytes = canonical(&approval)?;
        let mut public_key = [0; 32];
        hex::decode_to_slice(
            value["public_key_hex"]
                .as_str()
                .ok_or("OWNER_APPROVAL_POLICY")?,
            &mut public_key,
        )
        .map_err(|_| "OWNER_APPROVAL_POLICY")?;
        let header = json!({"schema_version":"3","algorithm":"Ed25519","payload_kind":"approval",
            "signer":value["signer"],"key_id":value["key_id"],"key_epoch":value["key_epoch"],
            "payload_digest":digest(b"kryvola/approval/v3\0", &bytes)});
        let mut envelope = header.clone();
        envelope["signature"] = json!(URL_SAFE_NO_PAD.encode([0u8; 64]));
        validate(&envelope, ENVELOPE, &SIGNATURE_VALIDATOR)?;
        Ok(Self {
            approval,
            plan: plan_value,
            bytes,
            header,
            public_key,
        })
    }

    fn tombstone(&self) -> Result<String> {
        Ok(format!(
            "revoked-{}",
            self.header["payload_digest"]
                .as_str()
                .ok_or("OWNER_APPROVAL_POLICY")?
        ))
    }

    pub fn revoke(&self, store: &Store) -> Result<()> {
        let name = self.tombstone()?;
        if store.exists(&name)? {
            return Ok(());
        }
        store.publish(&name, b"revoked\n")
    }

    fn check(&self, store: &Store, request: &Value, now: u64) -> Result<()> {
        if store.exists(&self.tombstone()?)? {
            return Err("OWNER_APPROVAL_REVOKED");
        }
        if request["assurance"] != LABEL || request["approval"] != self.approval {
            return Err("OWNER_APPROVAL_POLICY");
        }
        let timestamp = |name: &str| {
            self.approval[name]
                .as_str()
                .and_then(|v| v.parse::<u64>().ok())
                .ok_or("OWNER_APPROVAL_FORMAT")
        };
        if !(timestamp("valid_from_unix_ms")?..timestamp("expires_unix_ms")?).contains(&now) {
            return Err("OWNER_APPROVAL_EXPIRED");
        }
        Ok(())
    }

    pub fn sign(
        &self,
        store: &Store,
        request: &[u8],
        seed: &[u8; 32],
        now: u64,
    ) -> Result<Vec<u8>> {
        let request = parse(request)?;
        if request.as_object().is_none_or(|fields| fields.len() != 2) {
            return Err("OWNER_APPROVAL_FORMAT");
        }
        self.check(store, &request, now)?;
        let key = Ed25519KeyPair::from_seed_unchecked(seed).map_err(|_| "OWNER_APPROVAL_KEY")?;
        if key.public_key().as_ref() != self.public_key {
            return Err("OWNER_APPROVAL_KEY");
        }
        let mut envelope = self.header.clone();
        envelope["signature"] = json!(
            URL_SAFE_NO_PAD.encode(
                key.sign(&preimage("approval", &self.header, &self.bytes)?)
                    .as_ref()
            )
        );
        canonical(&json!({"assurance":LABEL,"approval":self.approval,"envelope":envelope}))
    }

    pub fn verify(&self, store: &Store, signed: &[u8], now: u64) -> Result<()> {
        let signed = parse(signed)?;
        if signed.as_object().is_none_or(|fields| fields.len() != 3) {
            return Err("OWNER_APPROVAL_FORMAT");
        }
        self.check(store, &signed, now)?;
        let mut header = signed["envelope"].clone();
        validate(&header, ENVELOPE, &SIGNATURE_VALIDATOR)?;
        let signature = header
            .as_object_mut()
            .and_then(|fields| fields.remove("signature"))
            .and_then(|encoded| URL_SAFE_NO_PAD.decode(encoded.as_str()?).ok())
            .ok_or("OWNER_APPROVAL_FORMAT")?;
        if header != self.header {
            return Err("OWNER_APPROVAL_POLICY");
        }
        UnparsedPublicKey::new(&ED25519, self.public_key)
            .verify(&preimage("approval", &header, &self.bytes)?, &signature)
            .map_err(|_| "OWNER_APPROVAL_SIGNATURE")
    }
}

pub fn local_sign(policy: &Policy, store: &Store, slot: &str, request: &[u8]) -> Result<Vec<u8>> {
    let seed = lookup_for(
        Path::new("/usr/bin/secret-tool"),
        slot,
        "kryvola-owner-approval-v1",
    )?;
    policy.sign(store, request, &seed, now_unix_ms()?)
}

pub fn now_unix_ms() -> Result<u64> {
    let elapsed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| "OWNER_APPROVAL_CLOCK")?;
    elapsed
        .as_millis()
        .try_into()
        .map_err(|_| "OWNER_APPROVAL_CLOCK")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signature_preimage_matches_published_vector() {
        let fixture: Value = serde_json::from_str(include_str!(
            "../../../contracts/spec/fixtures/canonical-approval-receipt-v3.json"
        ))
        .unwrap();
        let vector = &fixture["objects"][0];
        let payload = hex::decode(vector["canonical_hex"].as_str().unwrap()).unwrap();
        let mut header = vector["envelope"].clone();
        let signature = header.as_object_mut().unwrap().remove("signature").unwrap();
        let preimage = preimage("approval", &header, &payload).unwrap();
        assert_eq!(hex::encode(&preimage), vector["preimage_hex"]);
        let public = hex::decode(fixture["public_key_hex"].as_str().unwrap()).unwrap();
        UnparsedPublicKey::new(&ED25519, public)
            .verify(
                &preimage,
                &URL_SAFE_NO_PAD.decode(signature.as_str().unwrap()).unwrap(),
            )
            .unwrap();
    }
}
