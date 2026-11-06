//! Strict, bounded runtime JSON projections. Returned metadata is never authorization.
use crate::{check_control_size, wire::ControlError};
use serde_json::Value;
use std::collections::BTreeMap;

pub struct RuntimeValidator {
    schemas: BTreeMap<&'static str, jsonschema::Validator>,
}
impl RuntimeValidator {
    /// Compile trusted embedded artifacts once; no user schemas or external resolution.
    pub fn new() -> Result<Self, ControlError> {
        macro_rules! schemas {
            ($($name:literal),+ $(,)?) => {
                [$(($name, include_str!(concat!("../../../contracts/spec/runtime/", $name, ".schema.json")))),+]
            };
        }
        let raw = schemas!(
            "AbortUploadRequest",
            "AuthorizeArtifactRequest",
            "AuthorizeArtifactResponse",
            "CancelOperationRequest",
            "CancelOperationResponse",
            "CancellationPending",
            "Cancelled",
            "CreateOperationRequest",
            "CreateUploadRequest",
            "CreateUploadResponse",
            "EnsureAttemptRequest",
            "EnsureAttemptResponse",
            "FenceRecoveryRequest",
            "FinalizeUploadRequest",
            "FinalizeUploadResponse",
            "OperationResponse",
            "RecoveryFenceResponse",
            "RegisterExecutionRequest",
            "RuntimeConflictError",
            "RuntimeError",
            "RuntimeForbiddenError",
            "RuntimeNotFoundError",
            "RuntimeUnavailableError",
            "SelectResultRequest",
            "SelectResultResponse",
        );
        let schemas = raw
            .into_iter()
            .map(|(name, bytes)| {
                let value: Value =
                    serde_json::from_str(bytes).map_err(|_| ControlError::InvalidAssets)?;
                jsonschema::validator_for(&value)
                    .map(|schema| (name, schema))
                    .map_err(|_| ControlError::InvalidAssets)
            })
            .collect::<Result<_, _>>()?;
        Ok(Self { schemas })
    }

    pub fn decode(&self, name: &str, bytes: &[u8]) -> Result<Value, ControlError> {
        check_control_size(bytes.len(), false).map_err(|_| ControlError::TooLarge)?;
        let schema = self.schemas.get(name).ok_or(ControlError::InvalidControl)?;
        let value = serde_json::from_slice(bytes).map_err(|_| ControlError::InvalidControl)?;
        if !schema.is_valid(&value) {
            return Err(ControlError::InvalidControl);
        }
        Ok(value)
    }
}

#[derive(Clone, Copy, Debug)]
pub enum RuntimeCode {
    InvalidRequest,
    Forbidden,
    NotFound,
    PayloadTooLarge,
    QuotaExceeded,
    AttemptExpired,
    StaleFence,
    IdempotencyConflict,
    Unavailable,
}
impl RuntimeCode {
    pub fn body(self) -> String {
        let code = match self {
            Self::InvalidRequest => "INVALID_REQUEST",
            Self::Forbidden => "FORBIDDEN",
            Self::NotFound => "NOT_FOUND",
            Self::PayloadTooLarge => "PAYLOAD_TOO_LARGE",
            Self::QuotaExceeded => "QUOTA_EXCEEDED",
            Self::AttemptExpired => "ATTEMPT_EXPIRED",
            Self::StaleFence => "STALE_FENCE",
            Self::IdempotencyConflict => "IDEMPOTENCY_CONFLICT",
            Self::Unavailable => "UNAVAILABLE",
        };
        format!(r#"{{"schema_version":"1","code":"{code}"}}"#)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn adopted_runtime_schemas_bound_json_without_retaining_diagnostics() {
        let validator = RuntimeValidator::new().unwrap();
        let valid = json!({"schema_version":"1","tenant_scope":"t","byte_length":1});
        assert_eq!(
            validator.decode("CreateUploadRequest", &serde_json::to_vec(&valid).unwrap()),
            Ok(valid)
        );
        for bytes in [
            b"{secret".as_slice(),
            &[255],
            br#"{"schema_version":"1","tenant_scope":"t","byte_length":1,"credentials":"secret"}"#,
        ] {
            let error = validator.decode("CreateUploadRequest", bytes).unwrap_err();
            assert_eq!(error, ControlError::InvalidControl);
            assert_eq!(error.to_string(), "INVALID_CONTROL");
            assert!(std::error::Error::source(&error).is_none());
        }
        assert_eq!(
            validator.decode("CreateUploadRequest", &vec![b'x'; 65537]),
            Err(ControlError::TooLarge)
        );
        assert_eq!(
            validator.decode("unknown", b"{}"),
            Err(ControlError::InvalidControl)
        );
        for code in [
            RuntimeCode::InvalidRequest,
            RuntimeCode::Forbidden,
            RuntimeCode::NotFound,
            RuntimeCode::PayloadTooLarge,
            RuntimeCode::QuotaExceeded,
            RuntimeCode::AttemptExpired,
            RuntimeCode::StaleFence,
            RuntimeCode::IdempotencyConflict,
            RuntimeCode::Unavailable,
        ] {
            let value = validator
                .decode("RuntimeError", code.body().as_bytes())
                .unwrap();
            assert_eq!(value.as_object().unwrap().len(), 2);
        }
    }
}
