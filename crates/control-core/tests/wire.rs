use kryvola_fabric_core::wire::{ControlError, ControlValidator};
use prost::Message;
use prost_reflect::{DescriptorPool, DynamicMessage};
use serde_json::Value as Json;
use std::{error::Error, sync::OnceLock};

fn validator() -> &'static ControlValidator {
    static VALIDATOR: OnceLock<ControlValidator> = OnceLock::new();
    VALIDATOR.get_or_init(|| ControlValidator::new().expect("pinned assets"))
}
fn fixtures() -> Json {
    serde_json::from_str(include_str!("../../../contracts/native/fixtures.json")).unwrap()
}
fn wire(kind: &str, value: Json) -> Vec<u8> {
    let pool = DescriptorPool::decode(
        include_bytes!("../../../contracts/native/descriptor.bin").as_slice(),
    )
    .unwrap();
    let descriptor = pool
        .get_message_by_name(&format!("kryvola.spec.v1.{kind}"))
        .unwrap();
    DynamicMessage::deserialize(descriptor, value)
        .unwrap()
        .encode_to_vec()
}
#[test]
fn golden_vectors_and_actual_transport_boundaries() {
    let vectors: Vec<Json> =
        serde_json::from_str(include_str!("../../../contracts/native/vectors.json")).unwrap();
    for vector in vectors {
        let kind = vector["type"].as_str().unwrap();
        let bytes = hex::decode(vector["wire"].as_str().unwrap()).unwrap();
        assert_eq!(
            validator().decode(kind, &bytes, false).unwrap(),
            vector["value"]
        );
        if bytes.len() == 65536 {
            assert_eq!(
                validator().decode(kind, &[bytes, vec![0]].concat(), false),
                Err(ControlError::TooLarge)
            );
        }
    }
    let boundary = include_bytes!("../../../tests/fixtures/temporal-execute.bin");
    assert_eq!(boundary.len(), 32768);
    assert!(validator().decode("ExecuteRequest", boundary, true).is_ok());
    assert_eq!(
        validator().decode(
            "ExecuteRequest",
            &[boundary.as_slice(), &[0]].concat(),
            true
        ),
        Err(ControlError::TooLarge)
    );
    let bytes = wire(
        "GetCapabilitiesRequest",
        fixtures()["GetCapabilitiesRequest"].clone(),
    );
    let payloads = [("GetCapabilitiesRequest", bytes.as_slice()); 4];
    let mut metadata = vec![0; 131072 - 4 * bytes.len()];
    assert_eq!(
        validator()
            .temporal_call(&payloads, &metadata)
            .unwrap()
            .len(),
        4
    );
    metadata.push(0);
    assert_eq!(
        validator().temporal_call(&payloads, &metadata),
        Err(ControlError::TooLarge)
    );
    metadata.resize(131073, 0);
    assert_eq!(
        validator().temporal_call(&[], &metadata),
        Err(ControlError::TooLarge)
    );
}
#[test]
fn malformed_unknown_fields_versions_and_errors_are_safe() {
    for (kind, value) in fixtures().as_object().unwrap() {
        let valid = wire(kind, value.clone());
        let mut version = value.clone();
        version["schema_version"] = "2".into();
        let mut absent = value.clone();
        absent.as_object_mut().unwrap().remove("schema_version");
        for bytes in [
            [valid, b"\xf8\x1f\x01".to_vec()].concat(),
            wire(kind, version),
            wire(kind, absent),
            b"\xffSECRET_X".to_vec(),
            br#"{"private_key":"SECRET_X"}"#.to_vec(),
        ] {
            let error = validator().decode(kind, &bytes, false).unwrap_err();
            assert_eq!(error, ControlError::InvalidControl);
            assert_eq!(error.to_string(), "INVALID_CONTROL");
            assert!(error.source().is_none());
            assert!(!format!("{error:?}").contains("SECRET_X"));
        }
    }
    let bytes = wire("ExecuteRequest", fixtures()["ExecuteRequest"].clone());
    // Duplicate embedded message merges an unknown field into Execution; it must not be dropped.
    assert_eq!(
        validator().decode(
            "ExecuteRequest",
            &[bytes, b"\x1a\x0b\xfa\x1f\x08SECRET_X".to_vec()].concat(),
            false
        ),
        Err(ControlError::InvalidControl)
    );
    assert_eq!(
        validator().decode("FutureVersion", &[], false),
        Err(ControlError::InvalidControl)
    );
}
#[test]
fn correlations_and_artifact_policy_are_checked() {
    let original = fixtures()["ExecuteRequest"].clone();
    for (path, replacement) in [
        (vec!["operation", "plan_ref", "tenant_scope"], "other"),
        (vec!["execution", "attempt", "workflow_epoch"], "1"),
        (vec!["execution", "deadline_unix_ms"], "0"),
        (vec!["security_profile"], "FHE-A1"),
    ] {
        let mut value = original.clone();
        let mut target = &mut value;
        for name in &path[..path.len() - 1] {
            target = &mut target[*name];
        }
        target[*path.last().unwrap()] = replacement.into();
        assert_eq!(
            validator().decode("ExecuteRequest", &wire("ExecuteRequest", value), false),
            Err(ControlError::InvalidControl)
        );
    }
    let mut value = original;
    value["input_refs"][0]["byte_length"] = "1073741825".into();
    assert!(
        validator()
            .decode("ExecuteRequest", &wire("ExecuteRequest", value), false)
            .is_err()
    );
    let mut observation = fixtures()["GetExecutionStatusResponse"].clone();
    observation["execution"]["physical_state"] = "RUNNING".into();
    assert!(
        validator()
            .decode(
                "GetExecutionStatusResponse",
                &wire("GetExecutionStatusResponse", observation),
                false
            )
            .is_err()
    );
}
