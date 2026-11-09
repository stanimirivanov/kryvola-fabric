use std::sync::OnceLock;

use super::*;
use crate::{registry::RegistryError, wire::ControlValidator};

enum Route<'a> {
    Context,
    Approval,
    Admit,
    Reserve,
    Part(&'a str, &'a str),
    Manifest(&'a str),
    Finalize(&'a str),
}

fn route<'a>(method: &Method, path: &'a str) -> Option<Route<'a>> {
    let segments = path.split('/').collect::<Vec<_>>();
    match (method, segments.as_slice()) {
        (&Method::POST, ["", "v1", "key-contexts"]) => Some(Route::Context),
        (&Method::POST, ["", "v1", "compute-approvals"]) => Some(Route::Approval),
        (&Method::POST, ["", "v1", "operations", "admit"]) => Some(Route::Admit),
        (&Method::POST, ["", "v1", "input-uploads"]) => Some(Route::Reserve),
        (&Method::PUT, ["", "v1", "input-uploads", id, "parts", index]) => {
            Some(Route::Part(id, index))
        }
        (&Method::PUT, ["", "v1", "input-uploads", id, "manifest"]) => Some(Route::Manifest(id)),
        (&Method::POST, ["", "v1", "input-uploads", id, "finalize"]) => Some(Route::Finalize(id)),
        _ => None,
    }
}

fn registry_failure(error: RegistryError) -> UploadError {
    match error {
        RegistryError::InvalidIntent => UploadError::Integrity,
        RegistryError::IdempotencyConflict => UploadError::IdempotencyConflict,
        RegistryError::Unavailable => UploadError::Unavailable,
        _ => UploadError::Denied,
    }
}

impl UploadApi {
    pub fn matches_submission(method: &Method, path: &str) -> bool {
        route(method, path).is_some()
    }

    pub async fn handle_submission(
        &self,
        request: Request,
        authorization: (&SpiffeId, &Authorizer, u64, Instant),
        schemas: &RuntimeValidator,
    ) -> Reply {
        match self.submit(request, authorization, schemas).await {
            Ok(result) => result,
            Err(UploadError::Conflict) => upload_error(UploadError::IdempotencyConflict),
            Err(error) => upload_error(error),
        }
    }

    async fn submit(
        &self,
        request: Request,
        (peer, auth, expiry, deadline): (&SpiffeId, &Authorizer, u64, Instant),
        schemas: &RuntimeValidator,
    ) -> Result<Reply, UploadError> {
        let (parts, body) = request.into_parts();
        let route = route(&parts.method, parts.uri.path()).ok_or(UploadError::NotFound)?;
        let token = bearer(&parts.headers).ok_or(UploadError::Denied)?;
        let transport =
            || Instant::now() < deadline && now_unix_ms().is_some_and(|now| now < expiry);
        if !transport() {
            return Err(UploadError::Denied);
        }
        if parts.uri.query().is_some() || parts.headers.contains_key(header::RANGE) {
            return Err(UploadError::Integrity);
        }
        let length = || {
            parts
                .headers
                .get(header::CONTENT_LENGTH)
                .and_then(|value| value.to_str().ok()?.parse::<usize>().ok())
                .filter(|length| *length > 0)
                .ok_or(UploadError::Integrity)
        };
        let decode = |name, bytes: &[u8]| {
            schemas
                .decode(name, bytes)
                .map_err(|_| UploadError::Integrity)
        };
        let registry = self.store.registry();
        let mutation = match route {
            Route::Part(id, raw) => {
                let index = raw
                    .parse::<u16>()
                    .ok()
                    .filter(|index| *index <= 1023 && index.to_string() == raw)
                    .ok_or(UploadError::Integrity)?;
                Some(("INPUT_UPLOAD_PART", id, Some(index)))
            }
            Route::Manifest(id) => Some(("INPUT_UPLOAD_MANIFEST", id, None)),
            Route::Finalize(id) => Some(("INPUT_UPLOAD_FINALIZE", id, None)),
            _ => None,
        };
        if let Some((action, id, index)) = mutation {
            let target = match index {
                Some(index) => json!({"upload_id":id,"part_index":index}),
                None => json!({"upload_id":id}),
            };
            let grant = auth.submission_grant(peer, token, action, &target)?;
            let scope = self
                .store
                .input_scope(&grant.tenant_scope, &peer.to_string(), id)
                .await?;
            if scope["owner_identity"] != grant.owner_identity || !transport() {
                return Err(UploadError::Denied);
            }
            auth.submission_current(&grant)?;
            let permit = grant.permit(scope.clone(), (expiry, deadline));
            if let Some(index) = index {
                let declared = length()?;
                if declared > CHUNK_MAX_BYTES {
                    return Err(UploadError::Size);
                }
                self.store
                    .put_part(
                        permit,
                        id,
                        index,
                        declared,
                        StreamReader::new(body.into_data_stream().map_err(std::io::Error::other)),
                    )
                    .await?;
            } else if matches!(route, Route::Manifest(_)) {
                let declared = length()?;
                let bytes = collect(body).await?;
                if bytes.len() != declared {
                    return Err(UploadError::Integrity);
                }
                self.store.put_manifest(permit, id, &bytes).await?;
            } else {
                let value = decode("FinalizeUploadRequest", &collect(body).await?)?;
                if value["tenant_scope"] != grant.tenant_scope
                    || value["manifest_digest"] != scope["manifest_digest"]
                {
                    return Err(UploadError::Denied);
                }
                let saved = self.store.finalize_staged(permit, id).await?;
                return Ok((
                    StatusCode::OK,
                    json!({"schema_version":"1","manifest_digest":saved.manifest_digest})
                        .to_string(),
                ));
            }
            return Ok((StatusCode::NO_CONTENT, String::new()));
        }

        let (name, action) = match route {
            Route::Context => ("RegisterKeyContextRequest", "KEY_CONTEXT_REGISTER"),
            Route::Approval => (
                "RegisterComputeApprovalRequest",
                "COMPUTE_APPROVAL_REGISTER",
            ),
            Route::Admit => ("AdmitApprovedOperationRequest", "APPROVED_OPERATION_ADMIT"),
            Route::Reserve => ("CreateInputUploadRequest", "INPUT_UPLOAD_RESERVE"),
            _ => return Err(UploadError::NotFound),
        };
        let value = decode(name, &collect(body).await?)?;
        let target = match route {
            Route::Context => value["key_context_ref"].clone(),
            Route::Approval => {
                json!({"plan_ref":value["plan_ref"],"approval_digest":value["approval_digest"]})
            }
            _ => value.clone(),
        };
        let grant = auth.submission_grant(peer, token, action, &target)?;
        let live = || {
            if !transport() {
                return Err(RegistryError::Forbidden);
            }
            auth.submission_current(&grant)
                .map_err(|error| match error {
                    UploadError::Unavailable => RegistryError::Unavailable,
                    _ => RegistryError::Forbidden,
                })
        };
        live().map_err(registry_failure)?;
        let response = match route {
            Route::Context => registry
                .register_key_context(&value, &grant, live)
                .await
                .map_err(registry_failure)?,
            Route::Approval => registry
                .register_compute_approval(&value, &grant, live)
                .await
                .map_err(registry_failure)?,
            Route::Admit => {
                static CONTROL: OnceLock<Option<ControlValidator>> = OnceLock::new();
                let validator = CONTROL
                    .get_or_init(|| ControlValidator::new().ok())
                    .as_ref()
                    .ok_or(UploadError::Unavailable)?;
                let saved = registry
                    .admit_approved(validator, &value, &grant, &peer.to_string(), live)
                    .await
                    .map_err(registry_failure)?;
                let status = registry
                    .public_status(crate::registry::OperationKey {
                        tenant_scope: &grant.tenant_scope,
                        operation_id: saved.operation["operation_id"]
                            .as_str()
                            .ok_or(UploadError::Unavailable)?,
                    })
                    .await
                    .map_err(registry_failure)?;
                json!({"schema_version":"1","operation":saved.operation,"public_status":status})
            }
            Route::Reserve => {
                if value["key_context_ref"]["tenant_scope"] != grant.tenant_scope {
                    return Err(UploadError::Denied);
                }
                let mut scope = value;
                let length = scope["byte_length"].as_u64().ok_or(UploadError::Size)?;
                scope["purpose"] = json!("INPUT_UPLOAD");
                scope["owner_identity"] = json!(grant.owner_identity);
                let id = self
                    .store
                    .reserve(grant.permit(scope, (expiry, deadline)), length as usize)
                    .await?;
                return Ok((
                    StatusCode::CREATED,
                    json!({"schema_version":"1","upload_id":id}).to_string(),
                ));
            }
            _ => return Err(UploadError::NotFound),
        };
        Ok((StatusCode::OK, response.to_string()))
    }
}
