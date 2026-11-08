//! Verify the existing canonical v3 receipt format against deployment trust.
use std::sync::OnceLock;

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ring::signature::{ED25519, UnparsedPublicKey};
use serde_json::Value;

use crate::{authorization::ReceiptGrant, registry::RegistryError};

static RECEIPT: OnceLock<Option<jsonschema::Validator>> = OnceLock::new();
static SIGNATURE: OnceLock<Option<jsonschema::Validator>> = OnceLock::new();

pub(crate) struct SignedReceipt {
    pub payload: Vec<u8>,
    pub envelope: Vec<u8>,
    pub value: Value,
    pub digest: String,
}

fn canonical(
    encoded: &Value,
    limit: usize,
    validator: &'static OnceLock<Option<jsonschema::Validator>>,
    schema: &str,
) -> Result<(Vec<u8>, Value), RegistryError> {
    let encoded = encoded.as_str().ok_or(RegistryError::InvalidIntent)?;
    let raw = URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|_| RegistryError::InvalidIntent)?;
    if raw.len() > limit || !raw.is_ascii() || URL_SAFE_NO_PAD.encode(&raw) != encoded {
        return Err(RegistryError::InvalidIntent);
    }
    let mut value: Value =
        serde_json::from_slice(&raw).map_err(|_| RegistryError::InvalidIntent)?;
    value.sort_all_objects();
    let validator = validator
        .get_or_init(|| {
            jsonschema::validator_for(&serde_json::from_str::<Value>(schema).ok()?).ok()
        })
        .as_ref()
        .ok_or(RegistryError::Unavailable)?;
    // These schemas permit ASCII strings, arrays and objects, without JSON numbers.
    // Comparing sorted compact JSON also rejects duplicate object keys.
    if !validator.is_valid(&value)
        || serde_json::to_vec(&value).map_err(|_| RegistryError::InvalidIntent)? != raw
    {
        return Err(RegistryError::InvalidIntent);
    }
    Ok((raw, value))
}

impl SignedReceipt {
    pub(crate) fn verify(body: &Value, trust: &ReceiptGrant) -> Result<Self, RegistryError> {
        let (payload, value) = canonical(
            &body["receipt_base64url"],
            32768,
            &RECEIPT,
            include_str!("../../../contracts/spec/canonical/v3/receipt.schema.json"),
        )?;
        let (envelope, mut header) = canonical(
            &body["signature_base64url"],
            2048,
            &SIGNATURE,
            include_str!("../../../contracts/spec/canonical/v3/signature.schema.json"),
        )?;
        let timestamp = |field: &str| value[field].as_str().and_then(|s| s.parse::<u64>().ok());
        if timestamp("completed_unix_ms") < timestamp("started_unix_ms")
            || header["payload_kind"] != "receipt"
        {
            return Err(RegistryError::InvalidIntent);
        }
        let mut hash = blake3::Hasher::new();
        let digest = hash
            .update(b"kryvola/receipt/v3\0")
            .update(&payload)
            .finalize()
            .to_hex()
            .to_string();
        if header["payload_digest"] != digest
            || header["signer"] != trust.signer
            || value["signer"] != trust.signer
            || header["key_id"] != trust.key_id
            || header["key_epoch"] != trust.key_epoch
        {
            return Err(RegistryError::Forbidden);
        }
        let signature = header
            .as_object_mut()
            .and_then(|fields| fields.remove("signature"))
            .and_then(|encoded| URL_SAFE_NO_PAD.decode(encoded.as_str()?).ok())
            .ok_or(RegistryError::InvalidIntent)?;
        let key = hex::decode(&trust.public_key_hex).map_err(|_| RegistryError::Forbidden)?;
        let metadata = serde_json::to_vec(&header).map_err(|_| RegistryError::InvalidIntent)?;
        let mut preimage = b"kryvola/signature/receipt/v3\0".to_vec();
        for bytes in [&metadata, &payload] {
            preimage.extend_from_slice(&(bytes.len() as u64).to_le_bytes());
            preimage.extend_from_slice(bytes);
        }
        UnparsedPublicKey::new(&ED25519, key)
            .verify(&preimage, &signature)
            .map_err(|_| RegistryError::Forbidden)?;
        Ok(Self {
            payload,
            envelope,
            value,
            digest,
        })
    }
}
