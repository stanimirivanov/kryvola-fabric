# Released output reads

The runtime implements the Spec release-bound manifest and indexed-part routes
on its workload mTLS listener. Use `POST /v1/released-outputs/manifest` or
`POST /v1/released-outputs/parts/{part_index}` with the exact
`ReadReleasedOutputRequest` and a fresh consumer bearer. Each successful
response contains the complete verified bytes with `Cache-Control: no-store`.

Provision consumer grants in the existing boot-bound runtime policy file under
`consumer_grants`. Each entry has `spiffe_id` for the authorized recipient
workload, `token_sha256`, `scope` equal to the request body, `part_index`
as null or omitted for a manifest or an exact integer for a part, and
`expires_unix_ms`. Pin the current `policy_digest`, `policy_epoch` and
`coordinator` trust record with `signer`, `key_id`, `key_epoch` and
`public_key_hex`. Use a separate token for each read, with a lifetime of at
most 60 seconds. Removing an entry revokes its grant. Remove superseded
grants during policy rotation and propagate owner approval revocations
to the registry before relying on them.

Fabric verifies the recorded coordinator signature, recipient and exact output
binding before accessing the recorded immutable upload. Read admission
serializes with operation cancellation, recovery and approval revocation.
The runtime rechecks the grant and transport validity before returning
buffered bytes. An eligible release survives dispatch lease expiry.
An unavailable authority or failed artifact integrity check returns 503
with no artifact bytes. The runtime never returns object-store URLs.
