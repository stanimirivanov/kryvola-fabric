//! Scoped staging and verified metadata publication. No endpoint grants byte access.
use crate::{
    authorization::{Authorizer, Denial},
    limits::{CHUNK_MAX_BYTES, CONTROL_BYTES},
    runtime_contract::{RuntimeCode, RuntimeValidator},
    upload::{UploadError, UploadStore},
};
use axum::{
    body::{Body, to_bytes},
    extract::Request,
    http::{Method, StatusCode, header},
};
use futures_util::TryStreamExt;
use object_store::{ClientOptions, aws::AmazonS3Builder};
use serde::Deserialize;
use serde_json::json;
use spiffe::SpiffeId;
use sqlx::PgPool;
use std::{
    fs::File,
    io::Read,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::time::timeout;
use tokio_util::io::StreamReader;

type Reply = (StatusCode, String);
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Config {
    endpoint: String,
    bucket: String,
    region: String,
    access_key_id: String,
    secret_access_key: String,
    tenant_quota_bytes: u64,
    #[serde(default)]
    allow_http: bool,
}
pub struct UploadApi {
    store: UploadStore,
}
impl UploadApi {
    pub fn connect(pool: PgPool, path: &str) -> Result<Self, &'static str> {
        fn load(pool: PgPool, path: &str) -> Result<UploadApi, Box<dyn std::error::Error>> {
            if !std::fs::metadata(path)?.is_file() {
                return Err("invalid config".into());
            }
            let mut bytes = Vec::new();
            File::open(path)?.take(16385).read_to_end(&mut bytes)?;
            if bytes.len() > 16384 {
                return Err("invalid config".into());
            }
            let config: Config = serde_json::from_slice(&bytes)?;
            if config.tenant_quota_bytes == 0 || config.tenant_quota_bytes > i64::MAX as u64 {
                return Err("invalid quota".into());
            }
            let objects = AmazonS3Builder::new()
                .with_endpoint(config.endpoint)
                .with_bucket_name(config.bucket)
                .with_region(config.region)
                .with_access_key_id(config.access_key_id)
                .with_secret_access_key(config.secret_access_key)
                .with_client_options(
                    ClientOptions::new()
                        .with_timeout(Duration::from_secs(5))
                        .with_connect_timeout(Duration::from_secs(2)),
                )
                .with_allow_http(config.allow_http)
                .build()?;
            Ok(UploadApi {
                store: UploadStore::fenced(pool, Arc::new(objects), config.tenant_quota_bytes),
            })
        }
        load(pool, path).map_err(|_| "upload store unavailable")
    }
    pub fn matches(method: &Method, path: &str) -> bool {
        if *method == Method::POST && path == "/v1/uploads" {
            return true;
        }
        let p: Vec<_> = path.split('/').collect();
        matches!(p.as_slice(), ["", "v1", "uploads", _, "parts", _] if *method == Method::PUT)
            || matches!(p.as_slice(), ["", "v1", "uploads", _, "manifest"] if *method == Method::PUT)
            || matches!(p.as_slice(), ["", "v1", "uploads", _, "abort" | "finalize"] if *method == Method::POST)
    }
    pub async fn handle(
        &self,
        request: Request,
        authorization: (&SpiffeId, &Authorizer, u64, Instant),
        schemas: &RuntimeValidator,
    ) -> Reply {
        let (peer, auth, identity_expiry, deadline) = authorization;
        let (parts, body) = request.into_parts();
        if !Self::matches(&parts.method, parts.uri.path()) {
            return error(RuntimeCode::NotFound, StatusCode::NOT_FOUND);
        }
        let mut values = parts.headers.get_all(header::AUTHORIZATION).iter();
        let token = values
            .next()
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "));
        let Some(token) = token.filter(|_| values.next().is_none()) else {
            return deny(Denial::Credential);
        };
        if Instant::now() >= deadline {
            return deny(Denial::Provider);
        }
        if !crate::authorization::now_unix_ms().is_some_and(|now| now < identity_expiry) {
            return deny(Denial::Identity);
        }
        let Some(mut permit) = auth.upload_permit(peer, token) else {
            return error(RuntimeCode::Forbidden, StatusCode::FORBIDDEN);
        };
        permit.bind_transport(identity_expiry, deadline);
        if parts.uri.query().is_some() {
            return invalid();
        }
        let path: Vec<_> = parts.uri.path().split('/').collect();
        let part = path.get(4) == Some(&"parts");
        let length = parts
            .headers
            .get(header::CONTENT_LENGTH)
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.parse::<usize>().ok());
        let maximum = if part { CHUNK_MAX_BYTES } else { CONTROL_BYTES };
        if length.is_some_and(|n| n > maximum) {
            return error(RuntimeCode::PayloadTooLarge, StatusCode::PAYLOAD_TOO_LARGE);
        }
        let outcome: Result<Reply, UploadError> = async {
            if part {
                let Some(declared) = length.filter(|n| *n > 0) else {
                    return Ok(invalid());
                };
                let Some(index) = path[5]
                    .parse::<u16>()
                    .ok()
                    .filter(|n| *n <= 1023 && n.to_string() == path[5])
                else {
                    return Ok(invalid());
                };
                let stream =
                    StreamReader::new(body.into_data_stream().map_err(std::io::Error::other));
                self.store
                    .put_part(permit, path[3], index, declared, stream)
                    .await?;
                return Ok((StatusCode::NO_CONTENT, String::new()));
            }
            let bytes = collect(body).await?;
            if parts.uri.path() == "/v1/uploads" {
                let value = schemas
                    .decode("CreateUploadRequest", &bytes)
                    .map_err(|_| UploadError::Integrity)?;
                if value["tenant_scope"] != permit.tenant {
                    return Err(UploadError::Denied);
                }
                let size = value["byte_length"]
                    .as_u64()
                    .and_then(|n| usize::try_from(n).ok())
                    .ok_or(UploadError::Size)?;
                let id = self.store.reserve(permit, size).await?;
                let result = json!({"schema_version":"1", "upload_id":id}).to_string();
                schemas
                    .decode("CreateUploadResponse", result.as_bytes())
                    .map_err(|_| UploadError::Unavailable)?;
                Ok((StatusCode::CREATED, result))
            } else if path[4] == "finalize" {
                let value = schemas
                    .decode("FinalizeUploadRequest", &bytes)
                    .map_err(|_| UploadError::Integrity)?;
                if value["tenant_scope"] != permit.tenant
                    || value["manifest_digest"] != permit.scope["manifest_digest"]
                {
                    return Err(UploadError::Denied);
                }
                let artifact = self.store.finalize_staged(permit, path[3]).await?;
                let result =
                    json!({"schema_version":"1", "manifest_digest":artifact.manifest_digest})
                        .to_string();
                schemas
                    .decode("FinalizeUploadResponse", result.as_bytes())
                    .map_err(|_| UploadError::Unavailable)?;
                Ok((StatusCode::OK, result))
            } else if path[4] == "manifest" {
                self.store.put_manifest(permit, path[3], &bytes).await?;
                Ok((StatusCode::NO_CONTENT, String::new()))
            } else {
                let value = schemas
                    .decode("AbortUploadRequest", &bytes)
                    .map_err(|_| UploadError::Integrity)?;
                if value["attempt"] != permit.scope["attempt"] {
                    return Err(UploadError::Denied);
                }
                self.store.abort(permit, path[3]).await?;
                Ok((StatusCode::NO_CONTENT, String::new()))
            }
        }
        .await;
        match outcome {
            Ok(reply) => reply,
            Err(UploadError::Denied) => deny(Denial::Policy),
            Err(UploadError::Size) => {
                error(RuntimeCode::PayloadTooLarge, StatusCode::PAYLOAD_TOO_LARGE)
            }
            Err(UploadError::Quota) => {
                error(RuntimeCode::QuotaExceeded, StatusCode::TOO_MANY_REQUESTS)
            }
            Err(UploadError::NotFound) => error(RuntimeCode::NotFound, StatusCode::NOT_FOUND),
            Err(UploadError::AttemptExpired) => {
                error(RuntimeCode::AttemptExpired, StatusCode::CONFLICT)
            }
            Err(UploadError::StaleFence | UploadError::Conflict) => {
                error(RuntimeCode::StaleFence, StatusCode::CONFLICT)
            }
            Err(UploadError::Integrity) => invalid(),
            Err(UploadError::Unavailable) => {
                error(RuntimeCode::Unavailable, StatusCode::SERVICE_UNAVAILABLE)
            }
        }
    }
}
async fn collect(body: Body) -> Result<axum::body::Bytes, UploadError> {
    timeout(Duration::from_secs(2), to_bytes(body, CONTROL_BYTES))
        .await
        .map_err(|_| UploadError::Unavailable)?
        .map_err(|_| UploadError::Size)
}
fn error(code: RuntimeCode, status: StatusCode) -> Reply {
    (status, code.body())
}
fn deny(reason: Denial) -> Reply {
    reason.audit();
    error(RuntimeCode::Forbidden, StatusCode::FORBIDDEN)
}
fn invalid() -> Reply {
    Denial::Scope.audit();
    error(RuntimeCode::InvalidRequest, StatusCode::BAD_REQUEST)
}
