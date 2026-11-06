use std::sync::OnceLock;

use serde_json::Value;

use super::*;
use crate::limits::CONTROL_BYTES;

static MANIFEST: OnceLock<Option<jsonschema::Validator>> = OnceLock::new();

/// Internal metadata handle. It confers no right to fetch or disclose bytes.
#[derive(Debug, PartialEq, Eq)]
pub struct FinalizedArtifact {
    pub upload_id: String,
    pub tenant_scope: String,
    pub manifest_digest: String,
    pub byte_length: u64,
}

fn number(value: &Value) -> Result<u64> {
    value
        .as_str()
        .and_then(|s| s.parse().ok())
        .ok_or(UploadError::Integrity)
}

pub(super) fn digest(domain: &[u8], parts: &[&[u8]]) -> String {
    let mut state = blake3::Hasher::new();
    state.update(domain);
    for part in parts {
        state.update(part);
    }
    state.finalize().to_hex().to_string()
}

pub(super) fn manifest(bytes: &[u8]) -> Result<Value> {
    if bytes.len() > CONTROL_BYTES || !bytes.is_ascii() {
        return Err(UploadError::Size);
    }
    let mut value: Value = serde_json::from_slice(bytes).map_err(|_| UploadError::Integrity)?;
    let validator = MANIFEST
        .get_or_init(|| {
            let schema: Value = serde_json::from_str(include_str!(
                "../../../../contracts/spec/canonical/v2/manifest.schema.json"
            ))
            .ok()?;
            jsonschema::validator_for(&schema).ok()
        })
        .as_ref()
        .ok_or(UploadError::Unavailable)?;
    // All manifest keys and permitted string values are ASCII and the schema
    // permits no JSON numbers. Sorted compact JSON is JCS for this subset.
    value.sort_all_objects();
    if !validator.is_valid(&value)
        || serde_json::to_vec(&value).map_err(|_| UploadError::Integrity)? != bytes
    {
        return Err(UploadError::Integrity);
    }
    let size = number(&value["serialized_bytes"])?;
    let expanded = number(&value["max_expanded_bytes"])?;
    let params = &value["parameters"];
    let shape = value["shape"].as_array().ok_or(UploadError::Integrity)?;
    let elements = shape.iter().try_fold(1u64, |count, dim| {
        count
            .checked_mul(number(dim)?)
            .ok_or(UploadError::Integrity)
    })?;
    let dtype = value["precision"]["dtype"]
        .as_str()
        .ok_or(UploadError::Integrity)?;
    if size == 0
        || expanded < size
        || expanded > ARTIFACT_MAX_BYTES as u64
        || params["radix_bits"].as_str() != dtype.strip_prefix("uint")
        || number(&params["message_modulus"])? == 0
        || number(&params["carry_modulus"])? == 0
        || !(1..=1_048_576).contains(&elements)
        || number(&value["precision"]["fractional_bits"])? != 0
    {
        return Err(UploadError::Integrity);
    }
    Ok(value)
}

async fn read_exact_object(
    objects: &dyn ObjectStore,
    key: &Path,
    length: usize,
) -> Result<Vec<u8>> {
    timeout(IO_TIMEOUT, async {
        let result = object_store::ObjectStoreExt::get(objects, key)
            .await
            .map_err(|error| {
                if matches!(error, object_store::Error::NotFound { .. }) {
                    UploadError::Integrity
                } else {
                    UploadError::Unavailable
                }
            })?;
        let mut stream = result.into_stream();
        let mut data = Vec::with_capacity(length);
        while let Some(bytes) = stream
            .try_next()
            .await
            .map_err(|_| UploadError::Unavailable)?
        {
            if bytes.len() > length - data.len() {
                return Err(UploadError::Integrity);
            }
            data.extend_from_slice(&bytes);
        }
        if data.len() != length {
            return Err(UploadError::Integrity);
        }
        Ok(data)
    })
    .await
    .map_err(|_| UploadError::Unavailable)?
}

impl UploadStore {
    pub async fn finalize(
        &self,
        mut permit: UploadPermit,
        id: &str,
        canonical: &[u8],
    ) -> Result<FinalizedArtifact> {
        check_permit(&permit)?;
        let manifest = manifest(canonical)?;
        let commitment = digest(b"kryvola/manifest/v2\0", &[canonical]);
        if manifest["tenant_scope"] != permit.tenant
            || permit.scope["manifest_digest"] != commitment
        {
            return Err(UploadError::Denied);
        }
        let size = number(&manifest["serialized_bytes"])?;
        let mut tx = self.begin(&mut permit).await?;
        let upload = lock_upload(&mut tx, &permit, id, self.fenced).await?;
        if upload.try_get::<i64, _>("reserved_bytes")? as u64 != size
            || upload.try_get::<i64, _>("remaining")? != 0
        {
            return Err(UploadError::Integrity);
        }
        let reference = FinalizedArtifact {
            upload_id: id.to_owned(),
            tenant_scope: permit.tenant.clone(),
            manifest_digest: commitment,
            byte_length: size,
        };
        let existing: Option<Vec<u8>> = sqlx::query_scalar(
            "SELECT canonical_manifest FROM fabric_finalized_artifacts WHERE upload_id = $1",
        )
        .bind(id)
        .fetch_optional(&mut *tx)
        .await?;
        if let Some(saved) = existing {
            return if saved == canonical {
                Ok(reference)
            } else {
                Err(UploadError::Conflict)
            };
        }

        let chunks = manifest["ordered_chunk_entries"]
            .as_array()
            .ok_or(UploadError::Integrity)?;
        let indices: Vec<i32> = sqlx::query_scalar(
            "SELECT part_index FROM fabric_upload_parts WHERE upload_id = $1 ORDER BY part_index",
        )
        .bind(id)
        .fetch_all(&mut *tx)
        .await?;
        if indices.len() != chunks.len()
            || indices
                .iter()
                .enumerate()
                .any(|(i, index)| *index != i as i32)
        {
            return Err(UploadError::Integrity);
        }
        let mut offset = 0u64;
        let mut blob = blake3::Hasher::new();
        blob.update(b"kryvola/blob/v1\0");
        for (index, chunk) in chunks.iter().enumerate() {
            check_permit(&permit)?;
            let length = number(&chunk["byte_length"])?;
            if !(1..=CHUNK_MAX_BYTES as u64).contains(&length)
                || number(&chunk["index"])? != index as u64
                || number(&chunk["byte_offset"])? != offset
                || offset + length > size
            {
                return Err(UploadError::Integrity);
            }
            let mapped: Option<String> = sqlx::query_scalar(
                "SELECT object_key FROM fabric_upload_parts WHERE upload_id=$1 AND part_index=$2",
            )
            .bind(id)
            .bind(index as i32)
            .fetch_one(&mut *tx)
            .await?;
            let staged = Path::from(mapped.unwrap_or_else(|| format!("staging/{id}/{index}")));
            let bytes = read_exact_object(self.objects.as_ref(), &staged, length as usize).await?;
            let expected = digest(
                b"kryvola/chunk/v1\0",
                &[&(index as u64).to_le_bytes(), &length.to_le_bytes(), &bytes],
            );
            if chunk["chunk_digest"] != expected {
                return Err(UploadError::Integrity);
            }
            offset += length;
            blob.update(&bytes);
            let key = Path::from(format!("immutable/{id}/{index}"));
            check_permit(&permit)?;
            match timeout(
                IO_TIMEOUT,
                self.objects
                    .put_opts(&key, bytes.into(), PutMode::Create.into()),
            )
            .await
            .map_err(|_| UploadError::Unavailable)?
            {
                Ok(_) => {}
                Err(
                    object_store::Error::AlreadyExists { .. }
                    | object_store::Error::Precondition { .. },
                ) => {
                    let existing =
                        read_exact_object(self.objects.as_ref(), &key, length as usize).await?;
                    if digest(
                        b"kryvola/chunk/v1\0",
                        &[
                            &(index as u64).to_le_bytes(),
                            &length.to_le_bytes(),
                            &existing,
                        ],
                    ) != expected
                    {
                        return Err(UploadError::Integrity);
                    }
                }
                Err(_) => return Err(UploadError::Unavailable),
            }
        }
        if offset != size
            || manifest["full_blob_digest"].as_str() != Some(blob.finalize().to_hex().as_str())
        {
            return Err(UploadError::Integrity);
        }
        check_permit(&permit)?;
        sqlx::query("INSERT INTO fabric_finalized_artifacts VALUES ($1, $2, $3)")
            .bind(id)
            .bind(&reference.manifest_digest)
            .bind(canonical)
            .execute(&mut *tx)
            .await?;
        sqlx::query("UPDATE fabric_uploads SET touched_at = clock_timestamp() WHERE id = $1")
            .bind(id)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(reference)
    }
}
