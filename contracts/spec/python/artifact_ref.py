"""Generated structural projection; not a decoder, signature verifier or authorization check."""
from typing import TypedDict


class ArtifactRef(TypedDict):
    opaque_artifact_id: str
    tenant_scope: str
    immutable_version: str
    manifest_digest: str
    byte_length: str
    media_type: str
    schema_version: str
