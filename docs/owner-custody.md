# Recoverable owner custody

Run the Linux `kryvola-owner-agent` binary as a dedicated owner OS account.
The agent takes a command, an absolute custody directory, an absolute Python
interpreter path and a stable slot name. It returns only an exit status and
fixed error codes. The only IPC is a private pipe to the local native wheel
helper. No listener or key retrieval interface is exposed to compute, Ray,
Temporal, Redpanda, or platform identities.

## Provisioning

1. Install the verified Engines owner wheel `kryvola-owner==0.1.0.dev2` in a
   dedicated owner environment. Select its immutable build and verify provenance
   under the existing owner-wheel policy. The agent checks the installed version.
   The environment, executable and custody directory ancestors must be trusted.
2. Unlock a local Secret Service session for the owner. Provision a random
   256-bit wrapping key as 64 hexadecimal characters under Secret Service
   attributes `application=kryvola-owner-v1` and `slot=<slot>`. The agent uses
   `/usr/bin/secret-tool` and the local Unix session bus. A missing, locked,
   unavailable or malformed entry fails closed. This agent supports Secret
   Service only.
3. Create a directory owned by the owner account with mode `0700`. Use a
   persistent local filesystem that supports advisory flock, atomic no-replace
   rename and directory fsync. Keep the wrapping key and agent environment
   inaccessible to other accounts.

## Lifecycle

- `kryvola-owner-agent init ROOT PYTHON SLOT` generates the owner key and
  durably publishes `SLOT.key` with mode `0600`.
- `kryvola-owner-agent check ROOT PYTHON SLOT` authenticates and opens the
  opaque handle locally, then discards it.
- `kryvola-owner-agent backup ROOT PYTHON SLOT` accepts an independent 32-byte
  high-entropy recovery key on stdin and publishes `SLOT.backup`. Store the
  encrypted backup offline and keep the recovery material separately.
- To restore, provision a fresh local wrapping key on the destination owner
  account for the same slot. Place the backup in the private destination
  directory as `SLOT.backup` with mode `0600`. Run
  `kryvola-owner-agent restore ROOT PYTHON SLOT` with the original recovery key
  on stdin. The resulting `SLOT.key` keeps the original TFHE key and public
  evaluation identity under the destination wrapping key.

The agent takes a directory lock and never overwrites a published key or
backup. Use a fresh destination to recover. If a command loses its completion
acknowledgment, run `check` against the resulting key before deciding to retry.
A stale temporary encrypted file is cleared on the next publish. Slot names
bind the envelope context, and backup and primary contexts are distinct.
Recovery does not provide anti-rollback or restore any release or approval state.

## Process protection and evidence

The Rust agent disables core dumps and process dumpability. The Python
helper re-applies dumpability protection before reading secrets because
Linux resets it on exec. Rust wrapping and recovery buffers and native
serialization staging use best-effort zeroization. Python byte objects,
native key internals, subprocess and kernel buffers, and the keystore
may retain copies. The dedicated owner account is the isolation boundary
against other workloads. Root and a compromised owner session remain trusted.

The default Rust tests cover private files, no-overwrite, symlink rejection,
process protection and the command inventory. For the live recovery test,
start a disposable unlocked Secret Service session. Point
`KRYVOLA_OWNER_TEST_PYTHON` at the isolated owner-wheel interpreter and
`KRYVOLA_OWNER_TEST_SECRET_TOOL` at the system Secret Service client. Run
`cargo test --locked -p kryvola-owner-agent --test custody live_owner_recovery -- --ignored`.
This test provisions temporary wrapping entries. It requires a disposable
session and tests actual pre-recovery ciphertext against the restored key.
