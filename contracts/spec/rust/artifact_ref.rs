// Generated structural projection; not a decoder or authorization check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArtifactRef {
    pub opaque_artifact_id: String,
    pub tenant_scope: String,
    pub immutable_version: String,
    pub manifest_digest: String,
    pub byte_length: String,
    pub media_type: String,
    pub schema_version: String,
}
