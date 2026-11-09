# Authorized local result opening

Run `kryvola-owner-agent open-result ROOT PYTHON SLOT` as the dedicated owner
OS account. Use the private custody directory and the qualified
`kryvola-owner==0.1.0.dev2` interpreter. The owner-side caller creates a
connected Unix stream, gives the agent one endpoint as stdin, and retains
the peer endpoint. The agent checks the kernel's peer UID against its own
effective UID. Keep the peer endpoint within the trusted owner account.

Send a fresh 64-character lowercase hexadecimal consumer bearer on the peer
endpoint, then shut down its write half. The bearer must authorize the exact
released manifest. On success, the agent returns exactly two uint8 result
bytes on the same socket. Failures close the socket without a result and
report only a fixed error code on stderr. The command has no listening socket
or remote plaintext response.

## Local inputs

In addition to the existing custody and approval policy files, provision these
files in the owner directory.

- `SLOT.approval` is the signed owner approval bundle produced by `approve`.
- `SLOT.release` and `SLOT.release-signature` are the exact canonical v3
  payload and coordinator signature envelope that Fabric committed.
- `SLOT.open-policy` is canonical JSON with the reviewed `release_digest`,
  coordinator `signer`, `key_id`, `key_epoch`, `public_key_hex`, Fabric
  `authority` as a DNS name or IPv4 address followed by a port, and the exact
  `server_spiffe_id`.
- `SLOT.consumer-cert`, `SLOT.consumer-key`, and `SLOT.consumer-ca` are
  PEM workload TLS credentials and trust roots.
- `SLOT.key-context` is the approved canonical v1 key context.
  `SLOT.ciphertext` contains the delivered TFHE result bytes. The agent
  accepts the fixed two-element FHE-Q1 result within the native pair limit.

Keep these files owner-only. The agent uses bounded, no-symlink reads for
the signed documents, key context, and ciphertext. The configured
interpreter and TLS files must be provisioned by the trusted owner.

The agent verifies the owner signature, approval revocation, coordinator
signature, exact release commitment, and approval context. It authenticates
Fabric's exact URI SAN before sending the bearer for a live manifest read.
It checks the manifest and ciphertext commitments before invoking the owner
wheel. The custody lock serializes local approval revocation with opening.
The agent rechecks local approval and release expiry before returning
plaintext. Each repeated delivery requires a fresh bearer for the same
pinned release.

The live native check uses the isolated installed wheel and a disposable
mTLS fixture. Set `KRYVOLA_OWNER_TEST_PYTHON` to the verified interpreter to
include it in the full gate, or run
`cargo test --locked -p kryvola-owner-agent --lib live_authorized_native_open -- --ignored`.
The live native test uses a fixture wrapping key. The command uses the
owner's local Secret Service entry.
