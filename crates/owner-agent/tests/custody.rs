use kryvola_owner_agent::validate_slot;

#[test]
fn rejects_ambiguous_or_traversing_slot_names() {
    assert!(validate_slot("owner-1").is_ok());
    for invalid in ["", ".", "..", "../other", "/root", "other/slot", "a\n"] {
        assert!(validate_slot(invalid).is_err());
    }
}

#[test]
fn command_has_no_remote_open_or_export_route() {
    use std::process::Command;
    for action in ["decrypt", "open", "export", "serve"] {
        let output = Command::new(env!("CARGO_BIN_EXE_kryvola-owner-agent"))
            .args([action, "/missing", "/missing", "owner"])
            .output()
            .unwrap();
        assert!(!output.status.success());
        assert!(output.stdout.is_empty());
        assert_eq!(output.stderr, b"OWNER_ARGUMENT\n");
    }
}

#[test]
#[ignore = "requires an installed owner wheel and isolated Secret Service"]
fn live_owner_recovery() {
    use kryvola_owner_agent::{Action, Store, execute, lookup, protect};
    use std::{
        fs,
        io::Write,
        os::unix::fs::PermissionsExt,
        path::{Path, PathBuf},
        process::{Command, Stdio},
    };

    fn provision(tool: &Path, key: &[u8; 32]) {
        let mut child = Command::new(tool)
            .args([
                "store",
                "--label=Fabric custody test",
                "application",
                "kryvola-owner-v1",
                "slot",
                "live",
            ])
            .stdin(Stdio::piped())
            .spawn()
            .unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(hex::encode(key).as_bytes())
            .unwrap();
        assert!(child.wait().unwrap().success());
    }

    protect().unwrap();
    let python = PathBuf::from(std::env::var_os("KRYVOLA_OWNER_TEST_PYTHON").unwrap());
    let tool = PathBuf::from(std::env::var_os("KRYVOLA_OWNER_TEST_SECRET_TOOL").unwrap());
    let directory = tempfile::tempdir().unwrap();
    let first = directory.path().join("first");
    let recovered = directory.path().join("recovered");
    for path in [&first, &recovered] {
        fs::create_dir(path).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
    }

    let slot = "live";
    let backup_key = [9; 32];
    assert!(lookup(Path::new("/missing/secret-tool"), slot).is_err());
    provision(&tool, &[3; 32]);
    let local = lookup(&tool, slot).unwrap();
    let store = Store::open(&first).unwrap();
    execute(&store, &python, Action::Init, slot, &local, None).unwrap();
    assert_eq!(
        execute(&store, &python, Action::Init, slot, &local, None),
        Err("OWNER_EXISTS")
    );
    execute(&store, &python, Action::Check, slot, &local, None).unwrap();
    execute(
        &store,
        &python,
        Action::Backup,
        slot,
        &local,
        Some(&backup_key),
    )
    .unwrap();
    drop(store);

    let backup = fs::read(first.join("live.backup")).unwrap();
    let backup_path = recovered.join("live.backup");
    fs::write(&backup_path, &backup).unwrap();
    fs::set_permissions(&backup_path, fs::Permissions::from_mode(0o600)).unwrap();
    provision(&tool, &[6; 32]);
    let destination_key = lookup(&tool, slot).unwrap();
    assert_ne!(&*local, &*destination_key);
    let destination = Store::open(&recovered).unwrap();
    assert!(
        execute(
            &destination,
            &python,
            Action::Restore,
            slot,
            &destination_key,
            Some(&[1; 32])
        )
        .is_err()
    );
    let mut corrupted = backup.clone();
    *corrupted.last_mut().unwrap() ^= 1;
    fs::write(&backup_path, corrupted).unwrap();
    assert!(
        execute(
            &destination,
            &python,
            Action::Restore,
            slot,
            &destination_key,
            Some(&backup_key)
        )
        .is_err()
    );
    assert!(!recovered.join("live.key").exists());
    fs::write(&backup_path, backup).unwrap();

    let test = r#"
import sys
from pathlib import Path
from kryvola_owner import OwnerKey, blob_digest
first, recovered, context, operation = sys.argv[1:]
if operation == 'prepare':
    original = OwnerKey.restore(bytes([3]) * 32, bytes.fromhex(context), Path(first, 'live.key').read_bytes())
    Path(first, 'test-pair').write_bytes(original.encrypt_pair(bytes([7, 9])))
    Path(first, 'test-digest').write_bytes(blob_digest(original.evaluation_key()))
else:
    restored = OwnerKey.restore(bytes([6]) * 32, bytes.fromhex(context), Path(recovered, 'live.key').read_bytes())
    original_digest = Path(first, 'test-digest').read_bytes()
    assert blob_digest(restored.evaluation_key()) == original_digest
    pair = Path(first, 'test-pair').read_bytes()
    assert restored.open_result(pair, original_digest, blob_digest(pair)) == bytes([7, 9])
"#;
    let context = hex::encode(blake3::hash(b"kryvola/owner-custody/v1\0live").as_bytes());
    let check = |operation: &str| {
        assert!(
            Command::new(&python)
                .args(["-I", "-c", test])
                .args([&first, &recovered])
                .args([context.as_str(), operation])
                .status()
                .unwrap()
                .success()
        );
    };
    check("prepare");
    execute(
        &destination,
        &python,
        Action::Restore,
        slot,
        &destination_key,
        Some(&backup_key),
    )
    .unwrap();
    execute(
        &destination,
        &python,
        Action::Check,
        slot,
        &destination_key,
        None,
    )
    .unwrap();
    check("verify");
}

#[test]
fn authorized_open_requires_an_authenticated_unix_peer() {
    use std::process::{Command, Stdio};
    let output = Command::new(env!("CARGO_BIN_EXE_kryvola-owner-agent"))
        .args(["open-result", "/missing", "/missing", "owner"])
        .stdin(Stdio::piped())
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert_eq!(output.stderr, b"OWNER_OPEN_REJECTED\n");
}
