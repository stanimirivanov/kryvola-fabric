# Approved encrypted submission

Fabric implements the owner submission contract from Spec PR #82. A trusted
owner client registers the canonical key context, stages and finalizes the
evaluation key and ciphertext inputs, registers the signed compute approval,
then submits the immutable references to `POST /v1/operations/admit`.
The input routes do not require an operation or a dispatch attempt.

## Runtime policy

Configure `owner_submission_grants` in the existing boot-bound runtime policy.
Each entry specifies `spiffe_id`, `token_sha256`, `tenant_scope`,
`owner_identity`, `expires_unix_ms`, and one `action` and `target`.
Grants are separate from the other runtime credentials and can be retried
for the same target while live. Use a lifetime of at most 60 seconds.

| Action | Exact target |
| --- | --- |
| `KEY_CONTEXT_REGISTER` | The request's `key_context_ref` |
| `INPUT_UPLOAD_RESERVE` | The complete reservation request |
| `INPUT_UPLOAD_PART` | Object with `upload_id` and `part_index` |
| `INPUT_UPLOAD_MANIFEST`, `INPUT_UPLOAD_FINALIZE` | Object with `upload_id` |
| `COMPUTE_APPROVAL_REGISTER` | Object with `plan_ref` and `approval_digest` |
| `APPROVED_OPERATION_ADMIT` | The complete reference-only admission request |

Each grant carries the trusted `owner` signing record with `signer`, `key_id`,
`key_epoch` and `public_key_hex`. It also pins `policy_digest`, `policy_epoch`,
`evidence_policy_digest` and `evidence_policy`. The supported evidence policy
is `NONE`. The configured workload must be authorized for the exact owner
and tenant. Use the same workload identity for input uploads and admission.

Propagate owner revocation with
`fabric-runtime --revoke-compute-approval DATABASE_URL_FILE APPROVAL_DIGEST`.
The command uses the same durable approval tombstones and transaction locks
as release. Remove outdated grants when rotating policy.

## Durable behavior

Identical reservations return the same upload ID. Identical part, manifest,
and finalization retries reuse the stored data. If a reservation has already
been reclaimed, its retry conflicts. Keep the original reservation identity
until admission completes.

Admission verifies the current owner signature and policy, resolves the
registered context, and validates the exact finalized input set. It commits
the immutable upload IDs, deadline-bound input pins, operation and outbox
record together. An identical authorized retry returns the recorded operation
without another notification. Compute reads for approved operations use only
the pinned upload IDs. The existing coordinator admission path retains its
separate authority and behavior.
