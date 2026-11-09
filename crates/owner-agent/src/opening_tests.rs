use ring::signature::{Ed25519KeyPair, KeyPair};
use std::cell::Cell;

use super::*;

const SLOT: &str = "opening";
const WRAP: [u8; 32] = [3; 32];

fn sample(path: &str) -> Value {
    match path {
        "modular" => serde_json::from_str(include_str!(
            "../../../contracts/spec/fixtures/canonical-modular-v2.json"
        )),
        "approval" => serde_json::from_str(include_str!(
            "../../../contracts/spec/fixtures/canonical-approval-receipt-v3.json"
        )),
        "base" => serde_json::from_str(include_str!(
            "../../../contracts/spec/fixtures/canonical-corpus.json"
        )),
        "consent" => serde_json::from_str(include_str!(
            "../../../contracts/spec/fixtures/fhe-q1-consent.json"
        )),
        _ => unreachable!(),
    }
    .unwrap()
}

fn kind(corpus: &Value, kind: &str) -> Value {
    corpus["objects"]
        .as_array()
        .unwrap()
        .iter()
        .find(|value| value["kind"] == kind)
        .unwrap()["value"]
        .clone()
}

fn sign_release(payload: &Value) -> (Value, Value) {
    let key = Ed25519KeyPair::from_seed_unchecked(&[8; 32]).unwrap();
    let release_digest = digest(
        b"kryvola/release-authorization/v3\0",
        &canonical(payload).unwrap(),
    );
    let policy = json!({"signer":"coordinator", "key_id":"release", "key_epoch":"1",
        "public_key_hex":hex::encode(key.public_key()),"release_digest":release_digest});
    let mut signature = json!({"schema_version":"3","algorithm":"Ed25519",
        "payload_kind":"release-authorization","payload_digest":release_digest,
        "signer":policy["signer"],"key_id":policy["key_id"],"key_epoch":policy["key_epoch"]});
    let input = preimage(
        "release-authorization",
        &signature,
        &canonical(payload).unwrap(),
    )
    .unwrap();
    signature["signature"] = json!(URL_SAFE_NO_PAD.encode(key.sign(&input)));
    (policy, signature)
}

fn provision(store: &Store, ciphertext: &[u8], evaluation: &str) -> (Value, Vec<u8>) {
    let mut plan = kind(&sample("modular"), "plan");
    plan["output_shape"] = json!(["2"]);
    let mut context = kind(&sample("base"), "key-context");
    context["tenant_scope"] = plan["tenant_scope"].clone();
    context["parameters"] = plan["parameters"].clone();
    context["native_codec_version"] = json!("tfhe-rs-1.8.1");
    context["evaluation_key_blob_digest"] = json!(evaluation);
    let context = canonical(&context).unwrap();
    plan["key_context_digest"] = json!(digest(b"kryvola/key-context/v1\0", &context));
    let consent = canonical(&sample("consent")).unwrap();
    plan["consent_digest"] = json!(digest(b"kryvola/blob/v1\0", &consent));
    let plan_bytes = canonical(&plan).unwrap();
    let mut approval = kind(&sample("approval"), "approval");
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
    approval["plan_digest"] = json!(digest(b"kryvola/plan/v2\0", &plan_bytes));
    approval["subject_digest"] = approval["plan_digest"].clone();
    let owner_key = Ed25519KeyPair::from_seed_unchecked(&[7; 32]).unwrap();
    let owner = json!({"approval":approval,"assurance":"CONFIDENTIALITY_ONLY","signer":"owner",
        "key_id":"approval","key_epoch":"1","public_key_hex":hex::encode(owner_key.public_key())});
    let owner_bytes = canonical(&owner).unwrap();
    let policy = Policy::from_bytes(&owner_bytes, &plan_bytes, &consent).unwrap();
    let signed = policy
        .sign(
            store,
            &canonical(&json!({
                "assurance":"CONFIDENTIALITY_ONLY","approval":approval
            }))
            .unwrap(),
            &[7; 32],
            100,
        )
        .unwrap();
    let mut manifest = kind(&sample("modular"), "manifest");
    manifest["tenant_scope"] = plan["tenant_scope"].clone();
    manifest["key_context_digest"] = plan["key_context_digest"].clone();
    manifest["parameters"] = plan["parameters"].clone();
    manifest["native_codec_version"] = json!("tfhe-rs-1.8.1");
    manifest["precision"] = json!({"dtype":"uint8","fractional_bits":"0","overflow":"WRAP"});
    manifest["shape"] = json!(["2"]);
    manifest["serialized_bytes"] = json!(ciphertext.len().to_string());
    manifest["max_expanded_bytes"] = json!(MAX_PAIR.to_string());
    manifest["full_blob_digest"] = json!(digest(b"kryvola/blob/v1\0", ciphertext));
    let manifest = canonical(&manifest).unwrap();
    let mut release = approval.clone();
    for field in ["purpose", "subject_kind", "subject_digest"] {
        release.as_object_mut().unwrap().remove(field);
    }
    release["object_type"] = json!("release-authorization");
    release["output_manifest_digest"] = json!(digest(b"kryvola/manifest/v2\0", &manifest));
    release["approval_digest"] = json!(approval_digest(&canonical(&approval).unwrap()).unwrap());
    release["receipt_digest"] = json!("1".repeat(64));
    release["assurance"] = json!("CONFIDENTIALITY_ONLY");
    release["attempt_epoch"] = json!("1");
    release["execution_id"] = json!("execution");
    release["fence"] = json!("1");
    let (policy, signature) = sign_release(&release);
    for (suffix, bytes) in [
        ("approval-policy", owner_bytes),
        ("plan", plan_bytes),
        ("consent", consent),
        ("approval", signed),
        ("release", canonical(&release).unwrap()),
        ("release-signature", canonical(&signature).unwrap()),
        ("open-policy", canonical(&policy).unwrap()),
        ("key-context", context),
        ("ciphertext", ciphertext.to_vec()),
    ] {
        store.publish(&format!("{SLOT}.{suffix}"), &bytes).unwrap();
    }
    (release, manifest)
}

#[test]
fn authorization_rejects_substitution_and_rechecks_revocation() {
    let dir = tempfile::tempdir().unwrap();
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let store = Store::open(dir.path()).unwrap();
    let (release, manifest) = provision(&store, b"pair", &"a".repeat(64));
    let owner = Policy::load(&store, SLOT).unwrap();
    let (policy, envelope) = sign_release(&release);
    let now = now_unix_ms().unwrap();
    assert!(
        verify_release(
            &policy,
            &owner,
            &canonical(&release).unwrap(),
            &canonical(&envelope).unwrap(),
            now
        )
        .is_ok()
    );
    for field in [
        "recipient",
        "output_manifest_digest",
        "model_digest",
        "program_digest",
        "key_context_digest",
        "workflow_epoch",
        "session_epoch",
        "policy_epoch",
        "policy_digest",
        "expires_unix_ms",
        "execution_id",
        "fence",
    ] {
        let mut changed = release.clone();
        changed[field] = match field {
            "recipient" | "execution_id" => json!("different"),
            "workflow_epoch" | "session_epoch" | "policy_epoch" | "fence" => json!("999"),
            "expires_unix_ms" => json!("2"),
            _ => json!("f".repeat(64)),
        };
        let (changed_policy, changed_signature) = sign_release(&changed);
        assert!(
            verify_release(
                &policy,
                &owner,
                &canonical(&changed).unwrap(),
                &canonical(&changed_signature).unwrap(),
                now
            )
            .is_err(),
            "{field}"
        );
        if !matches!(field, "output_manifest_digest" | "execution_id" | "fence") {
            assert!(
                verify_release(
                    &changed_policy,
                    &owner,
                    &canonical(&changed).unwrap(),
                    &canonical(&changed_signature).unwrap(),
                    now
                )
                .is_err(),
                "{field}"
            );
        }
    }
    assert!(
        verify_release(
            &policy,
            &owner,
            &canonical(&release).unwrap(),
            &canonical(&envelope).unwrap(),
            u64::MAX
        )
        .is_err()
    );
    assert!(
        open_authorized(
            &store,
            SLOT,
            |_, _| Err(REJECTED),
            |_, _| panic!("opened without authority")
        )
        .is_err()
    );
    let admissions = Cell::new(0);
    let scope = manifest_scope(&release).unwrap();
    for _ in 0..2 {
        let plaintext = open_authorized(
            &store,
            SLOT,
            |_, request| {
                assert_eq!(request, &scope);
                admissions.set(admissions.get() + 1);
                Ok(manifest.clone())
            },
            |pair, _| {
                assert_eq!(pair, b"pair");
                Ok(Zeroizing::new(vec![7, 9]))
            },
        )
        .unwrap();
        assert_eq!(plaintext.as_slice(), &[7, 9]);
    }
    assert_eq!(admissions.get(), 2);
    owner.revoke(&store).unwrap();
    assert!(
        open_authorized(
            &store,
            SLOT,
            |_, _| panic!("authority called after revocation"),
            |_, _| panic!("opened after revocation")
        )
        .is_err()
    );
}

#[test]
fn socketpair_is_authenticated_as_owner() {
    let (owner, client) = UnixStream::pair().unwrap();
    let mut authenticated = peer(&owner).unwrap();
    authenticated.write_all(b"ok").unwrap();
    let mut result = [0; 2];
    (&client).read_exact(&mut result).unwrap();
    assert_eq!(&result, b"ok");
}

#[test]
#[ignore = "requires the isolated pinned owner wheel"]
fn live_authorized_native_open() {
    protect().unwrap();
    let python = std::path::PathBuf::from(std::env::var_os("KRYVOLA_OWNER_TEST_PYTHON").unwrap());
    let dir = tempfile::tempdir().unwrap();
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let store = Store::open(dir.path()).unwrap();
    execute(&store, &python, Action::Init, SLOT, &WRAP, None).unwrap();
    let command = r#"
import sys
from pathlib import Path
from kryvola_owner import OwnerKey, blob_digest
key = OwnerKey.restore(bytes([3])*32, bytes.fromhex(sys.argv[2]), Path(sys.argv[1]).read_bytes())
pair = key.encrypt_pair(bytes([7, 9]))
sys.stdout.buffer.write(blob_digest(key.evaluation_key()) + pair)
"#;
    let output = Command::new(&python)
        .args(["-I", "-c", command])
        .arg(dir.path().join(format!("{SLOT}.key")))
        .arg(hex::encode(context(SLOT, false)))
        .output()
        .unwrap();
    assert!(output.status.success());
    let (evaluation, pair) = output.stdout.split_at(32);
    let (release, manifest) = provision(&store, pair, &hex::encode(evaluation));
    let cert = dir.path().join(format!("{SLOT}.consumer-cert"));
    let private = dir.path().join(format!("{SLOT}.consumer-key"));
    let ca = dir.path().join(format!("{SLOT}.consumer-ca"));
    assert!(
        Command::new("/usr/bin/openssl")
            .args([
                "req",
                "-x509",
                "-newkey",
                "ec",
                "-pkeyopt",
                "ec_paramgen_curve:P-256",
                "-nodes",
                "-subj",
                "/CN=localhost",
                "-addext",
                "subjectAltName=URI:spiffe://fixture.test/fabric",
                "-days",
                "1",
                "-keyout",
            ])
            .arg(&private)
            .arg("-out")
            .arg(&cert)
            .stderr(Stdio::null())
            .status()
            .unwrap()
            .success()
    );
    std::fs::copy(&cert, &ca).unwrap();
    let response = dir.path().join("test-manifest");
    std::fs::write(&response, manifest).unwrap();
    let expected = manifest_scope(&release).unwrap().to_string();
    let server_script = r#"
import http.server, json, pathlib, ssl, sys
cert, key, expected, manifest = sys.argv[1:]
class Handler(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        assert self.path == '/v1/released-outputs/manifest'
        assert self.connection.getpeercert()
        assert self.headers['Authorization'] == 'Bearer ' + 'a' * 64
        assert json.loads(self.rfile.read(int(self.headers['Content-Length']))) == json.loads(expected)
        data = pathlib.Path(manifest).read_bytes()
        self.send_response(200)
        self.send_header('Content-Length', str(len(data)))
        self.end_headers()
        self.wfile.write(data)
server = http.server.HTTPServer(('127.0.0.1', 0), Handler)
context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain(cert, key)
context.load_verify_locations(cert)
context.verify_mode = ssl.CERT_REQUIRED
server.socket = context.wrap_socket(server.socket, server_side=True)
server.timeout = 15
print(server.server_port, flush=True)
server.handle_request()
"#;
    use std::io::BufRead;
    let mut server = limited_command(&python, "20s");
    let mut child = server
        .args(["-I", "-c", server_script])
        .arg(&cert)
        .arg(&private)
        .arg(&expected)
        .arg(&response)
        .spawn()
        .unwrap();
    let mut port = String::new();
    io::BufReader::new(child.stdout.take().unwrap())
        .read_line(&mut port)
        .unwrap();
    assert!(port.trim().parse::<u16>().is_ok());
    let mut policy = sign_release(&release).0;
    policy["authority"] = json!(format!("localhost:{}", port.trim()));
    policy["server_spiffe_id"] = json!("spiffe://fixture.test/fabric");
    let opened = open_authorized(
        &store,
        SLOT,
        |_, scope| live_manifest(dir.path(), &python, SLOT, &policy, scope, &"a".repeat(64)),
        |pair, binding| decrypt(&store, SLOT, &python, &WRAP, pair, binding),
    )
    .unwrap();
    assert!(child.wait().unwrap().success());
    assert_eq!(opened.as_slice(), &[7, 9]);
    assert!(
        open_authorized(
            &store,
            SLOT,
            |_, scope| live_manifest(dir.path(), &python, SLOT, &policy, scope, &"a".repeat(64)),
            |_, _| panic!("opened without a reachable authority")
        )
        .is_err()
    );

    let malformed = b"malformed";
    let binding = (
        evaluation.try_into().unwrap(),
        hex::decode(digest(b"kryvola/blob/v1\0", malformed))
            .unwrap()
            .try_into()
            .unwrap(),
    );
    assert!(decrypt(&store, SLOT, &python, &WRAP, malformed, binding).is_err());
}
