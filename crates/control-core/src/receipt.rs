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

pub(crate) fn canonical(
    encoded: &Value,
    limit: usize,
    validator: &'static OnceLock<Option<jsonschema::Validator>>,
    schema: &str,
) -> Result<(Vec<u8>, Value), RegistryError> {
    let encoded = encoded.as_str().ok_or(RegistryError::InvalidIntent)?;
    let raw = URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|_| RegistryError::InvalidIntent)?;
    if raw.len() > limit || URL_SAFE_NO_PAD.encode(&raw) != encoded {
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
    // These schemas constrain the canonical value and its permitted strings.
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
        let timestamp = |field: &str| value[field].as_str().and_then(|s| s.parse::<u64>().ok());
        if timestamp("completed_unix_ms") < timestamp("started_unix_ms") {
            return Err(RegistryError::InvalidIntent);
        }
        if value["signer"] != trust.signer {
            return Err(RegistryError::Forbidden);
        }
        let (envelope, digest) = verify_signature(
            &body["signature_base64url"],
            &payload,
            "receipt",
            (
                &trust.signer,
                &trust.key_id,
                &trust.key_epoch,
                &trust.public_key_hex,
            ),
        )?;
        Ok(Self {
            payload,
            envelope,
            value,
            digest,
        })
    }
}

pub(crate) fn commitment(kind: &str, version: u8, payload: &[u8]) -> String {
    blake3::Hasher::new()
        .update(format!("kryvola/{kind}/v{version}\0").as_bytes())
        .update(payload)
        .finalize()
        .to_hex()
        .to_string()
}

pub(crate) fn signature_preimage(kind: &str, metadata: &[u8], payload: &[u8]) -> Vec<u8> {
    let mut preimage = format!("kryvola/signature/{kind}/v3\0").into_bytes();
    for bytes in [metadata, payload] {
        preimage.extend_from_slice(&(bytes.len() as u64).to_le_bytes());
        preimage.extend_from_slice(bytes);
    }
    preimage
}

pub(crate) fn verify_signature(
    signature: &Value,
    payload: &[u8],
    kind: &str,
    trust: (&str, &str, &str, &str),
) -> Result<(Vec<u8>, String), RegistryError> {
    let (envelope, mut header) = canonical(
        signature,
        2048,
        &SIGNATURE,
        include_str!("../../../contracts/spec/canonical/v3/signature.schema.json"),
    )?;
    let digest = commitment(kind, 3, payload);
    if header["payload_kind"] != kind
        || header["payload_digest"] != digest
        || header["signer"] != trust.0
        || header["key_id"] != trust.1
        || header["key_epoch"] != trust.2
    {
        return Err(RegistryError::Forbidden);
    }
    let signature = header
        .as_object_mut()
        .and_then(|fields| fields.remove("signature"))
        .and_then(|encoded| URL_SAFE_NO_PAD.decode(encoded.as_str()?).ok())
        .ok_or(RegistryError::InvalidIntent)?;
    let key = hex::decode(trust.3).map_err(|_| RegistryError::Forbidden)?;
    let metadata = serde_json::to_vec(&header).map_err(|_| RegistryError::InvalidIntent)?;
    UnparsedPublicKey::new(&ED25519, key)
        .verify(&signature_preimage(kind, &metadata, payload), &signature)
        .map_err(|_| RegistryError::Forbidden)?;
    Ok((envelope, digest))
}
