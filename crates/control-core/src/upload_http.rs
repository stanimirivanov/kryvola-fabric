//! Scoped staging, verified finalization and fenced compute-input reads.
use crate::{
    authorization::{Authorizer, Denial, Scope, now_unix_ms},
    limits::{CHUNK_MAX_BYTES, CONTROL_BYTES},
    runtime_contract::{RuntimeCode, RuntimeValidator},
    upload::{ReclaimReport, UploadError, UploadStore},
};
use axum::{
    body::{Body, to_bytes},
    extract::Request,
    http::{HeaderMap, Method, StatusCode, header},
    response::{IntoResponse, Response},
};
use futures_util::TryStreamExt;
use object_store::{ClientOptions, aws::AmazonS3Builder};
use serde::Deserialize;
use serde_json::{Value, json};
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
    pub async fn reclamation_pass(
        &self,
        retention_seconds: u32,
        delete: bool,
    ) -> Result<ReclaimReport, &'static str> {
        self.store
            .reclamation_pass(retention_seconds, delete)
            .await
            .map_err(|_| "reclamation unavailable")
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
    pub fn matches_output_grant(method: &Method, path: &str) -> bool {
        *method == Method::POST && path == "/v1/executions/output-grants"
    }

    pub async fn handle_output_grant(
        &self,
        request: Request,
        (peer, auth, identity_expiry, provider_deadline): (&SpiffeId, &Authorizer, u64, Instant),
        schemas: &RuntimeValidator,
    ) -> Response {
        let (parts, body) = request.into_parts();
        let result = async {
            if Instant::now() >= provider_deadline
                || !now_unix_ms().is_some_and(|now| now < identity_expiry)
            {
                return Err(UploadError::Denied);
            }
            let token = bearer(&parts.headers).ok_or(UploadError::Denied)?;
            let authority = auth.output_authority(peer, token)?;
            if parts.uri.query().is_some() {
                return Err(UploadError::Integrity);
            }
            let bytes = collect(body).await?;
            let body = schemas
                .decode("IssueOutputGrantRequest", &bytes)
                .map_err(|_| UploadError::Integrity)?;
            if !authority.matches(&body) {
                return Err(UploadError::Denied);
            }
            let deadline = self.store.output_deadline(&body, &peer.to_string()).await?;
            let (grant, expires) = auth.mint_output(
                authority,
                &body,
                deadline,
                (identity_expiry, provider_deadline),
            )?;
            let response =
                json!({"schema_version": "1", "expires_unix_ms": expires.to_string()}).to_string();
            schemas
                .decode("IssueOutputGrantResponse", response.as_bytes())
                .map_err(|_| UploadError::Unavailable)?;
            let mut credential =
                header::HeaderValue::from_str(&grant).map_err(|_| UploadError::Unavailable)?;
            credential.set_sensitive(true);
            Ok::<_, UploadError>(
                (
                    [
                        (
                            header::CONTENT_TYPE,
                            header::HeaderValue::from_static("application/json"),
                        ),
                        (
                            header::CACHE_CONTROL,
                            header::HeaderValue::from_static("no-store"),
                        ),
                        (
                            header::HeaderName::from_static("kryvola-output-grant"),
                            credential,
                        ),
                    ],
                    response,
                )
                    .into_response(),
            )
        }
        .await;
        result.unwrap_or_else(|failure| {
            let (status, body) = upload_error(failure);
            (status, [(header::CONTENT_TYPE, "application/json")], body).into_response()
        })
    }

    pub fn matches_read(method: &Method, path: &str) -> bool {
        *method == Method::POST
            && ["/v1/compute-inputs", "/v1/released-outputs"]
                .iter()
                .any(|prefix| {
                    path.strip_prefix(prefix).is_some_and(|target| {
                        target == "/manifest"
                            || target
                                .strip_prefix("/parts/")
                                .is_some_and(|index| !index.is_empty() && !index.contains('/'))
                    })
                })
    }

    pub async fn handle_read(
        &self,
        request: Request,
        authorization: (&SpiffeId, &Authorizer, u64, Instant),
        schemas: &RuntimeValidator,
    ) -> Response {
        let result = self.read(request, authorization, schemas).await;
        match result {
            Ok(bytes) => (
                [
                    (header::CONTENT_TYPE, "application/octet-stream".into()),
                    (header::CACHE_CONTROL, "no-store".into()),
                    (header::CONTENT_LENGTH, bytes.len().to_string()),
                ],
                bytes,
            )
                .into_response(),
            Err(failure) => {
                let (status, body) = match failure {
                    UploadError::Denied => deny(Denial::Policy),
                    UploadError::NotFound => error(RuntimeCode::NotFound, StatusCode::NOT_FOUND),
                    UploadError::AttemptExpired => {
                        error(RuntimeCode::AttemptExpired, StatusCode::CONFLICT)
                    }
                    UploadError::StaleFence => error(RuntimeCode::StaleFence, StatusCode::CONFLICT),
                    UploadError::Size => {
                        error(RuntimeCode::PayloadTooLarge, StatusCode::PAYLOAD_TOO_LARGE)
                    }
                    UploadError::Integrity => invalid(),
                    _ => error(RuntimeCode::Unavailable, StatusCode::SERVICE_UNAVAILABLE),
                };
                (status, [(header::CONTENT_TYPE, "application/json")], body).into_response()
            }
        }
    }

    async fn read(
        &self,
        request: Request,
        (peer, auth, identity_expiry, deadline): (&SpiffeId, &Authorizer, u64, Instant),
        schemas: &RuntimeValidator,
    ) -> Result<Vec<u8>, UploadError> {
        let (parts, body) = request.into_parts();
        let token = bearer(&parts.headers).ok_or(UploadError::Denied)?;
        if Instant::now() >= deadline || !now_unix_ms().is_some_and(|now| now < identity_expiry) {
            return Err(UploadError::Denied);
        }
        if parts.uri.query().is_some() || parts.headers.contains_key(header::RANGE) {
            return Err(UploadError::Integrity);
        }
        let path = parts.uri.path();
        let released = path.starts_with("/v1/released-outputs/");
        let target = path
            .strip_prefix(if released {
                "/v1/released-outputs"
            } else {
                "/v1/compute-inputs"
            })
            .ok_or(UploadError::NotFound)?;
        let index = if target == "/manifest" {
            None
        } else {
            let raw = target
                .strip_prefix("/parts/")
                .ok_or(UploadError::NotFound)?;
            Some(
                raw.parse::<u16>()
                    .ok()
                    .filter(|index| *index <= 1023 && index.to_string() == raw)
                    .ok_or(UploadError::Integrity)?,
            )
        };
        let bytes = collect(body).await?;
        if released {
            let scope = schemas
                .decode("ReadReleasedOutputRequest", &bytes)
                .map_err(|_| UploadError::Integrity)?;
            let grant = auth.redeem_consumer(peer, token, &scope, index)?;
            return self
                .store
                .read_released_output(&scope, index, &grant, || {
                    if Instant::now() >= deadline
                        || !now_unix_ms().is_some_and(|now| now < identity_expiry)
                    {
                        return Err(UploadError::Denied);
                    }
                    auth.check_consumer(&grant)
                })
                .await;
        }
        let mut value = schemas
            .decode("ReadComputeInputRequest", &bytes)
            .map_err(|_| UploadError::Integrity)?;
        value["purpose"] = json!("COMPUTE_READ");
        let scope = Scope::decode(&serde_json::to_vec(&value).map_err(|_| UploadError::Integrity)?)
            .ok_or(UploadError::Integrity)?;
        let expires = auth
            .redeem(peer, token, &scope)
            .ok_or(UploadError::Denied)?;
        self.store
            .read_compute_input(&value, index, expires.min(identity_expiry), deadline)
            .await
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
        let Some(token) = bearer(&parts.headers) else {
            return deny(Denial::Credential);
        };
        if Instant::now() >= deadline {
            return deny(Denial::Provider);
        }
        if !crate::authorization::now_unix_ms().is_some_and(|now| now < identity_expiry) {
            return deny(Denial::Identity);
        }
        let path: Vec<_> = parts.uri.path().split('/').collect();
        let Some(mut permit) = auth.upload_permit_for(peer, token, &upload_target(&path)) else {
            return error(RuntimeCode::Forbidden, StatusCode::FORBIDDEN);
        };
        permit.bind_transport(identity_expiry, deadline);
        if parts.uri.query().is_some() {
            return invalid();
        }
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
        outcome.unwrap_or_else(upload_error)
    }
}

fn upload_target(path: &[&str]) -> Value {
    match path {
        ["", "v1", "uploads"] => json!({"action": "RESERVE"}),
        ["", "v1", "uploads", id, "parts", index] => index
            .parse::<u16>()
            .ok()
            .filter(|part| *part <= 1023 && part.to_string() == *index)
            .map_or(
                Value::Null,
                |part| json!({"action": "PUT_PART", "upload_id": id, "part_index": part}),
            ),
        ["", "v1", "uploads", id, action] => {
            let action = match *action {
                "manifest" => "PUT_MANIFEST",
                "finalize" => "FINALIZE",
                "abort" => "ABORT",
                _ => return Value::Null,
            };
            json!({"action": action, "upload_id": id})
        }
        _ => Value::Null,
    }
}

fn upload_error(failure: UploadError) -> Reply {
    match failure {
        UploadError::Denied => deny(Denial::Policy),
        UploadError::Size => error(RuntimeCode::PayloadTooLarge, StatusCode::PAYLOAD_TOO_LARGE),
        UploadError::Quota => error(RuntimeCode::QuotaExceeded, StatusCode::TOO_MANY_REQUESTS),
        UploadError::NotFound => error(RuntimeCode::NotFound, StatusCode::NOT_FOUND),
        UploadError::AttemptExpired => error(RuntimeCode::AttemptExpired, StatusCode::CONFLICT),
        UploadError::StaleFence | UploadError::Conflict => {
            error(RuntimeCode::StaleFence, StatusCode::CONFLICT)
        }
        UploadError::IdempotencyConflict => {
            error(RuntimeCode::IdempotencyConflict, StatusCode::CONFLICT)
        }
        UploadError::Integrity => invalid(),
        UploadError::Unavailable => {
            error(RuntimeCode::Unavailable, StatusCode::SERVICE_UNAVAILABLE)
        }
    }
}
fn bearer(headers: &HeaderMap) -> Option<&str> {
    let mut values = headers.get_all(header::AUTHORIZATION).iter();
    let token = values.next()?.to_str().ok()?.strip_prefix("Bearer ")?;
    values.next().is_none().then_some(token)
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
