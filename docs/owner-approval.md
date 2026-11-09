# Exact owner plan approval

The Linux owner agent signs and verifies canonical Spec v3 approvals locally.
Use the same private mode-0700 owner directory as for custody. For each slot,
the trusted owner provisions three regular mode-0600 files with canonical
JSON and no trailing newline:

- `SLOT.plan` is the reviewed canonical v2 FHE-Q1 plan.
- `SLOT.consent` is the reviewed FHE-Q1 consent declaration. Its full-blob
  commitment must match the approval and plan. A RELEASE-purpose approval
  requires explicit `allow_unverified_release` consent.
- `SLOT.approval-policy` has exactly `approval`, `assurance`, `signer`,
  `key_id`, `key_epoch` and `public_key_hex`. The approval is the full
  reviewed v3 object, scoped to the plan commitment. The only assurance
  label is `CONFIDENTIALITY_ONLY`. The supported purposes are COMPUTE
  and RELEASE. A RELEASE-purpose approval is input to a separate release
  decision.

Provision an independent random 32-byte Ed25519 seed as hex in Secret Service
under `application=kryvola-owner-approval-v1` and `slot=SLOT`. The signer
must match the independently provisioned public key in the policy. The
approval command never loads the TFHE custody wrapping key.

- `kryvola-owner-agent approve ROOT SLOT` reads a canonical JSON object
  containing exactly `approval` and `assurance` on stdin and writes the
  signed bundle on stdout. The bundle adds the published v3 `envelope`.
- `kryvola-owner-agent verify-approval ROOT SLOT` reads that bundle on stdin.
  It checks the exact current policy, signature, half-open validity interval
  and local revocation. Exit status zero indicates verification succeeded.
- `kryvola-owner-agent revoke-approval ROOT SLOT` durably revokes the current
  policy's approval commitment. Repeating the command is safe.

The signature binds every field of the approval. A signed bundle remains
verifiable on an identical retry while its policy is current, its validity
interval is open, and it has not been revoked. An earlier bundle cannot
authorize changed context or bypass a revocation. Keep the revocation
tombstones when moving the owner directory. Restoring a stale directory
snapshot can lose revocation history. This command does not select results,
verify computation integrity, or authorize result opening.
