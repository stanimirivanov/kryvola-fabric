//! Bounded Protobuf metadata validation; never authorization, signing or ciphertext decoding.
use crate::{check_control_size, limits};
use prost_reflect::{DescriptorPool, DynamicMessage, SerializeOptions, Value};
use serde_json::Value as Json;
use std::{collections::BTreeMap, fmt};

#[derive(Debug, PartialEq, Eq)]
pub enum ControlError {
    TooLarge,
    InvalidControl,
    InvalidAssets,
}
impl fmt::Display for ControlError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::TooLarge => "CONTROL_TOO_LARGE",
            Self::InvalidControl => "INVALID_CONTROL",
            Self::InvalidAssets => "INVALID_ASSETS",
        })
    }
}
impl std::error::Error for ControlError {}

/// Compile trusted vendored schemas once; no caller schemas or remote retrieval.
pub struct ControlValidator {
    pool: DescriptorPool,
    schemas: BTreeMap<String, jsonschema::Validator>,
}
impl ControlValidator {
    pub fn new() -> Result<Self, ControlError> {
        let pool = DescriptorPool::decode(
            include_bytes!("../../../contracts/native/descriptor.bin").as_slice(),
        )
        .map_err(|_| ControlError::InvalidAssets)?;
        let raw: BTreeMap<String, Json> =
            serde_json::from_slice(include_bytes!("../../../contracts/native/schemas.json"))
                .map_err(|_| ControlError::InvalidAssets)?;
        let schemas = raw
            .into_iter()
            .map(|(name, schema)| {
                jsonschema::validator_for(&schema)
                    .map(|v| (name, v))
                    .map_err(|_| ControlError::InvalidAssets)
            })
            .collect::<Result<_, _>>()?;
        Ok(Self { pool, schemas })
    }
    /// Validate the actual serialized payload before a permissive typed decoder or transport.
    pub fn decode(&self, kind: &str, bytes: &[u8], temporal: bool) -> Result<Json, ControlError> {
        check_control_size(bytes.len(), temporal).map_err(|_| ControlError::TooLarge)?;
        let schema = self.schemas.get(kind).ok_or(ControlError::InvalidControl)?;
        let descriptor = self
            .pool
            .get_message_by_name(&format!("kryvola.spec.v1.{kind}"))
            .ok_or(ControlError::InvalidAssets)?;
        let message =
            DynamicMessage::decode(descriptor, bytes).map_err(|_| ControlError::InvalidControl)?;
        if !known(&message) {
            return Err(ControlError::InvalidControl);
        }
        let value = message
            .serialize_with_options(
                serde_json::value::Serializer,
                &SerializeOptions::new()
                    .use_proto_field_name(true)
                    .skip_default_fields(false),
            )
            .map_err(|_| ControlError::InvalidControl)?;
        if !schema.is_valid(&value) || !consistent(&value) {
            return Err(ControlError::InvalidControl);
        }
        Ok(value)
    }
    /// Metadata is complete application framing/headers excluding the supplied payloads.
    pub fn temporal_call(
        &self,
        payloads: &[(&str, &[u8])],
        metadata: &[u8],
    ) -> Result<Vec<Json>, ControlError> {
        let mut total = metadata.len();
        if total > limits::TEMPORAL_CALL_BYTES {
            return Err(ControlError::TooLarge);
        }
        for (_, bytes) in payloads {
            total = total
                .checked_add(bytes.len())
                .ok_or(ControlError::TooLarge)?;
            if total > limits::TEMPORAL_CALL_BYTES {
                return Err(ControlError::TooLarge);
            }
        }
        payloads
            .iter()
            .map(|(kind, bytes)| self.decode(kind, bytes, true))
            .collect()
    }
}
fn known(message: &DynamicMessage) -> bool {
    message.unknown_fields().next().is_none()
        && message.fields().all(|(_, v)| match v {
            Value::Message(child) => known(child),
            Value::List(items) => items.iter().all(|v| match v {
                Value::Message(child) => known(child),
                _ => true,
            }),
            _ => true,
        })
}
fn consistent(v: &Json) -> bool {
    let children_ok = match v {
        Json::Array(a) => a.iter().all(consistent),
        Json::Object(o) => o.values().all(consistent),
        _ => true,
    };
    if !children_ok {
        return false;
    }
    if v.get("plan_ref").is_some() {
        for name in ["plan_ref", "key_context_ref", "disclosure_identity"] {
            if v[name]["tenant_scope"] != v["tenant_scope"] {
                return false;
            }
        }
        if v["disclosure_identity"]["logical_job_id"] != v["logical_job_id"] {
            return false;
        }
    }
    if let Some(op) = v.get("operation") {
        let execution = v
            .get("execution")
            .or_else(|| v.get("observation").and_then(|o| o.get("execution")));
        if let Some(ex) = execution {
            for name in ["tenant_scope", "operation_id", "workflow_epoch"] {
                if op[name] != ex["attempt"][name] {
                    return false;
                }
            }
            if op["deadline_unix_ms"] != ex["deadline_unix_ms"] {
                return false;
            }
        }
    }
    for name in [
        "operators",
        "required_operators",
        "program_digests",
        "security_profiles",
    ] {
        if let Some(a) = v.get(name).and_then(Json::as_array)
            && a.iter().enumerate().any(|(i, x)| a[..i].contains(x))
        {
            return false;
        }
    }
    if let Some(refs) = v.get("input_refs").and_then(Json::as_array)
        && (v["security_profile"] != "FHE-Q1"
            || refs
                .iter()
                .any(|r| r["tenant_scope"] != v["operation"]["tenant_scope"]))
    {
        return false;
    }
    if let Some(refs) = v.get("output_refs").and_then(Json::as_array) {
        let state = v["execution"]["physical_state"].as_str().unwrap_or("");
        let failed = ["FAILED", "CANCELLED", "EXPIRED"].contains(&state);
        if failed == (v["error_code"] == "NONE")
            || ((state == "SUCCEEDED") == refs.is_empty())
            || refs
                .iter()
                .any(|r| r["tenant_scope"] != v["execution"]["attempt"]["tenant_scope"])
        {
            return false;
        }
    }
    true
}
