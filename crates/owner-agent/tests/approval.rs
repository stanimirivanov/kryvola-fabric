use kryvola_owner_agent::approval::approval_digest;

#[test]
fn canonical_approval_commitment_matches_spec() {
    let fixture: serde_json::Value = serde_json::from_str(include_str!(
        "../../../contracts/spec/fixtures/canonical-approval-receipt-v3.json"
    ))
    .unwrap();
    let approval = &fixture["objects"][0];
    let bytes = hex::decode(approval["canonical_hex"].as_str().unwrap()).unwrap();
    assert_eq!(
        approval_digest(&bytes).unwrap(),
        approval["digest"].as_str().unwrap()
    );
    assert!(approval_digest(&[bytes.as_slice(), b" "].concat()).is_err());
}

use kryvola_owner_agent::{Store, approval::Policy};
use ring::signature::{Ed25519KeyPair, KeyPair};
use serde_json::{Value, json};
use std::{
    fs,
    io::Write,
    os::unix::fs::PermissionsExt,
    path::Path,
    process::{Command, Stdio},
};

fn encode(value: &Value) -> Vec<u8> {
    let mut value = value.clone();
    value.sort_all_objects();
    serde_json::to_vec(&value).unwrap()
}

fn commitment(domain: &[u8], bytes: &[u8]) -> String {
    blake3::Hasher::new()
        .update(domain)
        .update(bytes)
        .finalize()
        .to_hex()
        .to_string()
}

fn documents() -> (Value, Vec<u8>, Vec<u8>) {
    let corpus: Value = serde_json::from_str(include_str!(
        "../../../contracts/spec/fixtures/canonical-modular-v2.json"
    ))
    .unwrap();
    let mut plan = corpus["objects"]
        .as_array()
        .unwrap()
        .iter()
        .find(|v| v["kind"] == "plan")
        .unwrap()["value"]
        .clone();
    let mut consent: Value = serde_json::from_str(include_str!(
        "../../../contracts/spec/fixtures/fhe-q1-consent.json"
    ))
    .unwrap();
    consent["allow_unverified_release"] = json!(true);
    let consent = encode(&consent);
    plan["consent_digest"] = json!(commitment(b"kryvola/blob/v1\0", &consent));
    let plan_bytes = encode(&plan);
    let digest = commitment(b"kryvola/plan/v2\0", &plan_bytes);
    let fixture: Value = serde_json::from_str(include_str!(
        "../../../contracts/spec/fixtures/canonical-approval-receipt-v3.json"
    ))
    .unwrap();
    let mut approval = fixture["objects"][0]["value"].clone();
    for field in [
        "tenant_scope",
        "key_context_digest",
        "model_digest",
        "program_digest",
        "evidence_policy_digest",
        "consent_digest",
    ] {
        approval[field] = plan[field].clone();
    }
    approval["subject_kind"] = json!("plan");
    approval["subject_digest"] = json!(digest);
    approval["plan_digest"] = json!(digest);
    approval["valid_from_unix_ms"] = json!("1");
    let key = Ed25519KeyPair::from_seed_unchecked(&[7; 32]).unwrap();
    let policy = json!({"approval":approval,"assurance":"CONFIDENTIALITY_ONLY","signer":"owner-1",
        "key_id":"signing-1","key_epoch":"1","public_key_hex":hex::encode(key.public_key())});
    (policy, plan_bytes, consent)
}

fn write_private(path: &Path, data: &[u8]) {
    fs::write(path, data).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
}

#[test]
fn exact_policy_rejects_substitution_and_revocation_survives_process_restart() {
    let directory = tempfile::tempdir().unwrap();
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let (policy_document, plan, consent) = documents();
    let policy = Policy::from_bytes(&encode(&policy_document), &plan, &consent).unwrap();
    for (name, bytes) in [
        ("slot.approval-policy", encode(&policy_document)),
        ("slot.plan", plan.clone()),
        ("slot.consent", consent.clone()),
    ] {
        write_private(&directory.path().join(name), &bytes);
    }
    let store = Store::open(directory.path()).unwrap();
    let request =
        json!({"assurance":"CONFIDENTIALITY_ONLY","approval":policy_document["approval"]});
    let signed = policy.sign(&store, &encode(&request), &[7; 32], 1).unwrap();
    policy.verify(&store, &signed, 1).unwrap();
    assert_eq!(
        policy.sign(&store, &encode(&request), &[7; 32], 1).unwrap(),
        signed
    );
    assert!(policy.sign(&store, &encode(&request), &[8; 32], 1).is_err());
    assert!(policy.sign(&store, &encode(&request), &[7; 32], 0).is_err());
    assert!(policy.verify(&store, &signed, u64::MAX).is_err());
    let mut tampered: Value = serde_json::from_slice(&signed).unwrap();
    tampered["envelope"]["signature"] = json!("A".repeat(86));
    assert!(policy.verify(&store, &encode(&tampered), 1).is_err());
    for name in request["approval"].as_object().unwrap().keys() {
        let mut substituted = request.clone();
        substituted["approval"][name] = json!("other");
        assert!(
            policy
                .sign(&store, &encode(&substituted), &[7; 32], 1)
                .is_err(),
            "{name}"
        );
        let mut substituted: Value = serde_json::from_slice(&signed).unwrap();
        substituted["approval"][name] = json!("other");
        assert!(
            policy.verify(&store, &encode(&substituted), 1).is_err(),
            "{name}"
        );
    }
    let mut unsupported = request.clone();
    unsupported["assurance"] = json!("PROVEN");
    assert!(
        policy
            .sign(&store, &encode(&unsupported), &[7; 32], 1)
            .is_err()
    );
    assert!(Policy::from_bytes(&encode(&policy_document), &plan, b"{}").is_err());
    drop(store);

    let command = |action| {
        let mut command = Command::new(env!("CARGO_BIN_EXE_kryvola-owner-agent"));
        command.arg(action).arg(directory.path()).arg("slot");
        command
    };
    let verify = || {
        let mut child = command("verify-approval")
            .stdin(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        child.stdin.take().unwrap().write_all(&signed).unwrap();
        child.wait_with_output().unwrap()
    };
    assert!(verify().status.success());
    for _ in 0..2 {
        assert!(command("revoke-approval").status().unwrap().success());
    }
    let rejected = verify();
    assert!(!rejected.status.success());
    assert_eq!(rejected.stderr, b"OWNER_APPROVAL_REVOKED\n");
    let store = Store::open(directory.path()).unwrap();
    assert_eq!(
        policy.sign(&store, &encode(&request), &[7; 32], 1),
        Err("OWNER_APPROVAL_REVOKED")
    );
}
