//! Verify a single authorized FHE-Q1 result before using the owner key.
use std::{io, os::unix::net::UnixStream, sync::OnceLock, time::Duration};

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ring::signature::{ED25519, UnparsedPublicKey};
use rustix::net::{AddressFamily, SocketType, sockopt};
use serde_json::{Value, json};

use super::*;
use crate::approval::{
    CONTROL, ENVELOPE, Policy, SIGNATURE_VALIDATOR, approval_digest, canonical, digest,
    now_unix_ms, parse, preimage, validate,
};

const REJECTED: &str = "OWNER_OPEN_REJECTED";
const MAX_PAIR: usize = 2 * ((1 << 20) + 8);
static RELEASE: OnceLock<Option<jsonschema::Validator>> = OnceLock::new();
static MANIFEST: OnceLock<Option<jsonschema::Validator>> = OnceLock::new();
static CONTEXT: OnceLock<Option<jsonschema::Validator>> = OnceLock::new();

fn peer(fd: impl std::os::fd::AsFd) -> Result<UnixStream> {
    if sockopt::socket_domain(&fd) != Ok(AddressFamily::UNIX)
        || sockopt::socket_type(&fd) != Ok(SocketType::STREAM)
        || !sockopt::socket_peercred(&fd)
            .is_ok_and(|credentials| credentials.uid == process::geteuid())
    {
        return Err(REJECTED);
    }
    let stream = UnixStream::from(rustix::io::dup(fd).map_err(|_| REJECTED)?);
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .map_err(|_| REJECTED)?;
    stream
        .set_write_timeout(Some(Duration::from_secs(5)))
        .map_err(|_| REJECTED)?;
    Ok(stream)
}

fn string<'a>(value: &'a Value, key: &str) -> Result<&'a str> {
    value[key].as_str().ok_or(REJECTED)
}

fn timestamp(value: &Value, key: &str) -> Result<u64> {
    string(value, key)?.parse().map_err(|_| REJECTED)
}

fn current(value: &Value, now: u64) -> Result<()> {
    if (timestamp(value, "valid_from_unix_ms")?..timestamp(value, "expires_unix_ms")?)
        .contains(&now)
    {
        Ok(())
    } else {
        Err(REJECTED)
    }
}

fn verify_release(
    policy: &Value,
    owner: &Policy,
    payload: &[u8],
    signature: &[u8],
    now: u64,
) -> Result<Value> {
    let value = parse(payload)?;
    validate(
        &value,
        include_str!("../../../contracts/spec/canonical/v3/release-authorization.schema.json"),
        &RELEASE,
    )?;
    current(&value, now)?;
    let mut header = parse(signature)?;
    validate(&header, ENVELOPE, &SIGNATURE_VALIDATOR)?;
    let commitment = digest(b"kryvola/release-authorization/v3\0", payload);
    if owner.approval["purpose"] != "RELEASE"
        || value["approval_digest"] != approval_digest(&canonical(&owner.approval)?)?
        || policy["release_digest"] != commitment
        || header["payload_digest"] != commitment
        || header["payload_kind"] != "release-authorization"
        || ["signer", "key_id", "key_epoch"]
            .iter()
            .any(|key| header[*key] != policy[*key])
        || owner
            .approval
            .as_object()
            .ok_or(REJECTED)?
            .iter()
            .filter(|(key, _)| {
                !matches!(
                    key.as_str(),
                    "object_type" | "purpose" | "subject_kind" | "subject_digest"
                )
            })
            .any(|(key, field)| value[key] != *field)
    {
        return Err(REJECTED);
    }
    let signature = URL_SAFE_NO_PAD
        .decode(string(&header, "signature")?)
        .map_err(|_| REJECTED)?;
    header.as_object_mut().ok_or(REJECTED)?.remove("signature");
    let key = hex::decode(string(policy, "public_key_hex")?).map_err(|_| REJECTED)?;
    UnparsedPublicKey::new(&ED25519, key)
        .verify(
            &preimage("release-authorization", &header, payload)?,
            &signature,
        )
        .map_err(|_| REJECTED)?;
    Ok(value)
}

fn manifest_scope(release: &Value) -> Result<Value> {
    let identity = json!({
        "schema_version":"1","tenant_scope":release["tenant_scope"],
        "logical_job_id":release["logical_job_id"],"output_stage":release["output_stage"],
        "recipient":release["recipient"],"disclosure_index":release["disclosure_index"],
    });
    Ok(json!({
        "schema_version":"1", "tenant_scope":release["tenant_scope"], "recipient":release["recipient"],
        "disclosure_id":digest(b"kryvola/disclosure-identity/v3\0", &canonical(&identity)?),
        "output_manifest_digest":release["output_manifest_digest"],
    }))
}

fn live_manifest(
    root: &Path,
    python: &Path,
    slot: &str,
    policy: &Value,
    scope: &Value,
    token: &str,
) -> Result<Vec<u8>> {
    if !python.is_absolute() {
        return Err(REJECTED);
    }
    let authority = string(policy, "authority")?;
    let (host, port) = authority.rsplit_once(':').ok_or(REJECTED)?;
    if host.is_empty()
        || !host
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b".-".contains(&b))
        || !port.parse::<u16>().is_ok_and(|p| p != 0)
    {
        return Err(REJECTED);
    }
    let peer = string(policy, "server_spiffe_id")?;
    if !peer.starts_with("spiffe://") {
        return Err(REJECTED);
    }
    let mut command = limited_command(python, "10s");
    command.args([
        "-I",
        "-c",
        include_str!("release_authority.py"),
        host,
        port,
        peer,
    ]);
    for file in ["consumer-cert", "consumer-key", "consumer-ca"] {
        command.arg(root.join(format!("{slot}.{file}")));
    }
    let body = scope.to_string();
    let response = capture(
        &mut command,
        &[token.as_bytes(), body.as_bytes()],
        CONTROL,
        REJECTED,
    )?;
    Ok(response.to_vec())
}

fn output_binding(
    release: &Value,
    plan: &Value,
    manifest: &[u8],
    context: &[u8],
    pair: &[u8],
) -> Result<([u8; 32], [u8; 32])> {
    let value = parse(manifest)?;
    validate(
        &value,
        include_str!("../../../contracts/spec/canonical/v2/manifest.schema.json"),
        &MANIFEST,
    )?;
    let key = parse(context)?;
    validate(
        &key,
        include_str!("../../../contracts/spec/canonical/key-context.schema.json"),
        &CONTEXT,
    )?;
    let blob = digest(b"kryvola/blob/v1\0", pair);
    if digest(b"kryvola/manifest/v2\0", manifest) != release["output_manifest_digest"]
        || digest(b"kryvola/key-context/v1\0", context) != release["key_context_digest"]
        || value["key_context_digest"] != release["key_context_digest"]
        || value["tenant_scope"] != release["tenant_scope"]
        || key["tenant_scope"] != release["tenant_scope"]
        || value["artifact_kind"] != "CIPHERTEXT"
        || value["native_codec_version"] != "tfhe-rs-1.8.1"
        || value["native_codec_version"] != key["native_codec_version"]
        || value["parameters"] != key["parameters"]
        || value["parameters"] != plan["parameters"]
        || value["precision"] != plan["precision"]
        || value["shape"] != plan["output_shape"]
        || value["arithmetic"] != plan["arithmetic"]
        || value["precision"] != json!({"dtype":"uint8","fractional_bits":"0","overflow":"WRAP"})
        || value["shape"] != json!(["2"])
        || value["full_blob_digest"] != blob
        || timestamp(&value, "serialized_bytes")? != pair.len() as u64
    {
        return Err(REJECTED);
    }
    let decode = |value: &str| -> Result<[u8; 32]> {
        hex::decode(value)
            .map_err(|_| REJECTED)?
            .try_into()
            .map_err(|_| REJECTED)
    };
    Ok((
        decode(string(&key, "evaluation_key_blob_digest")?)?,
        decode(&blob)?,
    ))
}

fn decrypt(
    store: &Store,
    slot: &str,
    python: &Path,
    local: &[u8; 32],
    pair: &[u8],
    (evaluation, blob): ([u8; 32], [u8; 32]),
) -> Result<Zeroizing<Vec<u8>>> {
    if !python.is_absolute() || *local == [0; 32] {
        return Err(REJECTED);
    }
    let sealed = store.read(&format!("{slot}.key"))?;
    let mut command = limited_command(python, "60s");
    command.args(["-I", "-c", PYTHON, "open-result"]);
    let size = (sealed.len() as u64).to_le_bytes();
    let plaintext = capture(
        &mut command,
        &[
            local,
            &context(slot, false),
            &evaluation,
            &blob,
            &size,
            &sealed,
            pair,
        ],
        2,
        REJECTED,
    )?;
    if plaintext.len() != 2 {
        return Err(REJECTED);
    }
    Ok(plaintext)
}

pub fn run(root: &Path, python: &Path, slot: &str) -> Result<()> {
    let open = || {
        let mut stream = peer(io::stdin())?;
        let mut token = Zeroizing::new([0; 64]);
        stream.read_exact(&mut *token).map_err(|_| REJECTED)?;
        if !token
            .iter()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
            || stream.read(&mut [0]).map_err(|_| REJECTED)? != 0
        {
            return Err(REJECTED);
        }
        validate_slot(slot)?;
        let store = Store::open(root)?;
        let plaintext = open_authorized(
            &store,
            slot,
            |policy, scope| {
                live_manifest(
                    root,
                    python,
                    slot,
                    policy,
                    scope,
                    std::str::from_utf8(&*token).map_err(|_| REJECTED)?,
                )
            },
            |pair, binding| {
                let local = lookup(Path::new("/usr/bin/secret-tool"), slot)?;
                decrypt(&store, slot, python, &local, pair, binding)
            },
        )?;
        stream.write_all(&plaintext).map_err(|_| REJECTED)
    };
    open().map_err(|_| REJECTED)
}

fn open_authorized(
    store: &Store,
    slot: &str,
    authority: impl FnOnce(&Value, &Value) -> Result<Vec<u8>>,
    open_pair: impl FnOnce(&[u8], ([u8; 32], [u8; 32])) -> Result<Zeroizing<Vec<u8>>>,
) -> Result<Zeroizing<Vec<u8>>> {
    let read = |suffix: &str| store.read_bounded(&format!("{slot}.{suffix}"), CONTROL);
    let owner = Policy::load(store, slot)?;
    let approval = read("approval")?;
    let now = now_unix_ms()?;
    owner.verify(store, &approval, now)?;
    let policy = parse(&read("open-policy")?)?;
    let release = verify_release(
        &policy,
        &owner,
        &read("release")?,
        &read("release-signature")?,
        now,
    )?;
    let manifest = authority(&policy, &manifest_scope(&release)?)?;
    let pair = store.read_bounded(&format!("{slot}.ciphertext"), MAX_PAIR)?;
    let binding = output_binding(
        &release,
        &owner.plan,
        &manifest,
        &read("key-context")?,
        &pair,
    )?;
    let plaintext = open_pair(&pair, binding)?;
    let now = now_unix_ms()?;
    owner.verify(store, &approval, now)?;
    current(&release, now)?;
    Ok(plaintext)
}

#[cfg(test)]
#[path = "opening_tests.rs"]
mod tests;
