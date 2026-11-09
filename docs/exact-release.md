# Exact release decisions

Register `CoordinatorRelease.commit` on the trusted Temporal coordinator
queue alongside prepare, dispatch and select. Configure the trusted
notification starter with `release=True` only for release-enabled work.
The workflow requests release after selection completes, and records the
exact operation, application epoch, execution and manifest digest in
history. A worker observation alone cannot request release.

The coordinator calls the private command
`fabric-runtime --commit-release DATABASE_URL_FILE POLICY_FILE`.
Use separate OS credentials for the coordinator and Engine workers.
Keep the database URL, policy and signing material in coordinator-only
files with mode 0600 and a private parent directory. The runtime has no
network release route. Apply the additive registry migration through
the normal runtime deployment before starting the release worker.

Provision an exact current owner approval in the policy file. The
JSON fields `approval_base64url` and `signature_base64url` contain
the canonical v3 approval and envelope. Configure independent `owner`,
`receipt` and `coordinator` trust records with `signer`, `key_id`,
`key_epoch` and `public_key_hex`. Supply the coordinator's Ed25519 seed
in `coordinator_seed_hex`. The remaining fields pin `policy_digest`,
`policy_epoch`, `evidence_policy`, `evidence_policy_digest`, and the
reviewed `consent` declaration. The approved consent bytes must match
compact canonical JSON. The only supported evidence policy is `NONE`,
with explicit consent to unverified release. The receipt and release
signatures provide provenance.

Propagate owner revocations through
`fabric-runtime --revoke-release-approval DATABASE_URL_FILE APPROVAL_DIGEST`.
Use the canonical v3 approval digest printed or derived in the owner
domain. Complete this step before relying on the revocation in Fabric
or replacing an old approval or policy. Fabric serializes release with
revocation and with the operation's cancellation and recovery barriers.
The dispatch lease can expire after selection without invalidating an
otherwise authorized decision.

The immutable ledger preserves the first exact output binding for the
stable disclosure tuple. An authorized retry for the same manifest
returns that disclosure ID. A different manifest conflicts, even under
a later application workflow epoch. Preserve the ledger and approval
tombstones across rollback. Disable release-enabled workers when
rolling back to an incompatible binary. This slice does not mint an
artifact read capability or serve output bytes.
