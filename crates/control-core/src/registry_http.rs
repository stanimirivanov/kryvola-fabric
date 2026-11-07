//! Authenticated HTTP projections over the existing transactional registry.
use std::{fs::File, io::Read, str::FromStr, time::Duration};

use axum::http::{Method, StatusCode};
use serde_json::{Value, json};
use spiffe::SpiffeId;
use sqlx::postgres::{PgConnectOptions, PgPoolOptions};

use crate::{
    authorization::{Authorizer, Denial, RegistryAction},
    registry::{
        Cancellation, ExecutionTarget, OperationIntent, OperationKey, Registry, RegistryError,
    },
    runtime_contract::{RuntimeCode, RuntimeValidator},
    wire::ControlValidator,
};

type Reply = (StatusCode, String);
fn error(code: RuntimeCode, status: StatusCode) -> Reply {
    (status, code.body())
}
fn forbidden() -> Reply {
    Denial::Policy.audit();
    error(RuntimeCode::Forbidden, StatusCode::FORBIDDEN)
}

pub struct RegistryApi {
    registry: Registry,
    control: ControlValidator,
}
impl RegistryApi {
    pub fn pool(&self) -> sqlx::PgPool {
        self.registry.pool()
    }
    pub async fn connect(path: &str) -> Result<Self, &'static str> {
        async fn load(path: &str) -> Result<RegistryApi, Box<dyn std::error::Error>> {
            if !std::fs::metadata(path)?.is_file() {
                return Err("invalid config".into());
            }
            let mut url = String::new();
            File::open(path)?.take(4097).read_to_string(&mut url)?;
            if url.len() > 4096 {
                return Err("invalid config".into());
            }
            let options = PgConnectOptions::from_str(url.trim())?
                .options([("statement_timeout", "2000"), ("lock_timeout", "1000")]);
            let pool = PgPoolOptions::new()
                .max_connections(8)
                .acquire_timeout(Duration::from_secs(2))
                .connect_with(options)
                .await?;
            let registry = Registry::new(pool);
            registry.migrate().await.map_err(|_| "migration failed")?;
            Ok(RegistryApi {
                registry,
                control: ControlValidator::new()?,
            })
        }
        load(path).await.map_err(|_| "registry unavailable")
    }

    pub fn matches(method: &Method, path: &str) -> bool {
        (*method == Method::POST
            && matches!(
                path,
                "/v1/operations"
                    | "/v1/attempts/ensure"
                    | "/v1/executions/register"
                    | "/v1/results/select"
                    | "/v1/operations/cancel"
                    | "/v1/admin/operations/cancel"
                    | "/v1/admin/operations/fence-recovery"
            ))
            || (*method == Method::GET && path.starts_with("/v1/operations/"))
    }

    pub async fn handle(
        &self,
        method: &Method,
        path: &str,
        bytes: &[u8],
        authorization: (&SpiffeId, &Authorizer, Option<&str>),
        schemas: &RuntimeValidator,
    ) -> Reply {
        if !Self::matches(method, path) {
            return error(RuntimeCode::NotFound, StatusCode::NOT_FOUND);
        }
        let (peer, auth, token) = authorization;
        let action = match (*method == Method::GET, path) {
            (true, _) => RegistryAction::GetOperation,
            (_, "/v1/operations") => RegistryAction::CreateOperation,
            (_, "/v1/executions/register") => RegistryAction::ExecutionRegister,
            (_, "/v1/results/select") => RegistryAction::ResultSelect,
            (_, "/v1/operations/cancel") => RegistryAction::CancelOperation,
            (_, "/v1/admin/operations/cancel") => RegistryAction::AdminCancel,
            (_, "/v1/admin/operations/fence-recovery") => RegistryAction::AdminRecovery,
            _ => RegistryAction::EnsureAttempt,
        };
        let Some(token) = token else {
            Denial::Credential.audit();
            return error(RuntimeCode::Forbidden, StatusCode::FORBIDDEN);
        };
        let Some(scope) = auth.registry_scope(peer, token, action) else {
            return error(RuntimeCode::Forbidden, StatusCode::FORBIDDEN);
        };
        let key = OperationKey {
            tenant_scope: &scope.tenant_scope,
            operation_id: &scope.operation_id,
        };
        let result: Result<(Value, Option<&str>), RegistryError> = async {
            if action == RegistryAction::GetOperation {
                if !bytes.is_empty() {
                    return Err(RegistryError::InvalidIntent);
                }
                if path.strip_prefix("/v1/operations/") != Some(scope.operation_id.as_str()) {
                    return Err(RegistryError::StaleWorkflow);
                }
                let saved = self
                    .registry
                    .lookup_operation(key)
                    .await?
                    .ok_or(RegistryError::NotFound)?;
                if saved.operation["workflow_epoch"] != scope.workflow_epoch {
                    return Err(RegistryError::StaleWorkflow);
                }
                return Ok((
                    json!({"schema_version":"1", "operation":saved.operation,
                    "public_status": self.registry.public_status(key).await?}),
                    Some("OperationResponse"),
                ));
            }
            if matches!(action, RegistryAction::CancelOperation | RegistryAction::AdminCancel | RegistryAction::AdminRecovery) {
                let recovery = action == RegistryAction::AdminRecovery;
                let schema = if recovery { "FenceRecoveryRequest" } else { "CancelOperationRequest" };
                let body = schemas.decode(schema, bytes).map_err(|_| RegistryError::InvalidIntent)?;
                if body["tenant_scope"] != scope.tenant_scope
                    || body["operation_id"] != scope.operation_id
                    || (recovery && body["workflow_epoch"] != scope.workflow_epoch)
                {
                    return Err(RegistryError::StaleWorkflow);
                }
                let workflow = scope.workflow_epoch.parse().map_err(|_| RegistryError::InvalidIntent)?;
                if recovery {
                    let barrier = self.registry.fence_for_recovery(key, workflow).await.map_err(|error| {
                        if error == RegistryError::StaleWorkflow { RegistryError::EpochConflict } else { error }
                    })?;
                    return Ok((json!({"schema_version":"1", "outcome":"RECOVERY_FENCED",
                        "fence":barrier.fence.to_string(), "successor_epoch":barrier.successor_epoch.to_string()}),
                        Some("RecoveryFenceResponse")));
                }
                let id = body["idempotency_key"].as_str().ok_or(RegistryError::InvalidIntent)?;
                return Ok(match self.registry.cancel(key, Some(workflow), id).await? {
                    Cancellation::Pending => (
                        json!({"schema_version":"1", "outcome":"CANCELLATION_PENDING"}),
                        Some("CancellationPending"),
                    ),
                    Cancellation::Cancelled { fence } => (
                        json!({"schema_version":"1", "outcome":"CANCELLED", "fence":fence.to_string()}),
                        Some("Cancelled"),
                    ),
                });
            }
            let schema = match action {
                RegistryAction::CreateOperation => "CreateOperationRequest",
                RegistryAction::ExecutionRegister => "RegisterExecutionRequest",
                RegistryAction::ResultSelect => "SelectResultRequest",
                _ => "EnsureAttemptRequest",
            };
            let body = schemas
                .decode(schema, bytes)
                .map_err(|_| RegistryError::InvalidIntent)?;
            let identity = if action == RegistryAction::CreateOperation {
                &body["operation"]
            } else {
                &body["attempt"]
            };
            if identity["tenant_scope"] != scope.tenant_scope
                || identity["operation_id"] != scope.operation_id
                || identity["workflow_epoch"] != scope.workflow_epoch
            {
                return Err(RegistryError::StaleWorkflow);
            }
            if matches!(action, RegistryAction::ExecutionRegister | RegistryAction::ResultSelect) {
                if identity["attempt_epoch"].as_str() != scope.attempt_epoch.as_deref()
                    || identity["fence"].as_str() != scope.fence.as_deref()
                {
                    return Err(RegistryError::StaleWorkflow);
                }
                let number = |field: &str| -> Result<u64, RegistryError> {
                    identity[field].as_str().and_then(|s| s.parse().ok()).ok_or(RegistryError::InvalidIntent)
                };
                let saved;
                let (plan, policy) = if action == RegistryAction::ExecutionRegister {
                    (&body["plan_digest"], &body["policy_digest"])
                } else {
                    saved = self.registry.lookup_operation(key).await?.ok_or(RegistryError::NotFound)?;
                    (&saved.operation["plan_ref"]["plan_digest"], &saved.operation["policy_digest"])
                };
                let target = ExecutionTarget {
                    workflow_epoch: number("workflow_epoch")?,
                    attempt_epoch: number("attempt_epoch")?,
                    fence: number("fence")?,
                    execution_id: body["execution_id"].as_str().ok_or(RegistryError::InvalidIntent)?,
                    plan_digest: plan.as_str().ok_or(RegistryError::InvalidIntent)?,
                    policy_digest: policy.as_str().ok_or(RegistryError::InvalidIntent)?,
                };
                if action == RegistryAction::ExecutionRegister {
                    self.registry.register_execution(key, target).await?;
                    return Ok((Value::Null, None));
                }
                let digest = body["output_manifest_digest"].as_str().ok_or(RegistryError::InvalidIntent)?;
                let selected = self.registry.select_by_digest(key, target, digest).await?;
                return Ok((json!({"schema_version":"1","outcome":"COMPUTE_SELECTED",
                    "execution_id":selected.execution_id,"output_manifest_digest":selected.manifest_digest}),
                    Some("SelectResultResponse")));
            }
            if action == RegistryAction::CreateOperation {
                let inputs = serde_json::from_value(body["input_manifest_digests"].clone())
                    .map_err(|_| RegistryError::InvalidIntent)?;
                let intent =
                    OperationIntent::new(&self.control, body["operation"].clone(), inputs)?;
                let saved = self.registry.create_operation(&intent).await?;
                Ok((
                    json!({"schema_version":"1", "operation":saved.operation,
                    "public_status": self.registry.public_status(key).await?}),
                    Some("OperationResponse"),
                ))
            } else {
                let epoch = body["attempt"]["attempt_epoch"]
                    .as_str()
                    .and_then(|s| s.parse().ok())
                    .ok_or(RegistryError::InvalidIntent)?;
                let workflow = scope
                    .workflow_epoch
                    .parse()
                    .map_err(|_| RegistryError::InvalidIntent)?;
                let lease = self.registry.ensure_attempt(key, workflow, epoch).await?;
                let mut attempt = body["attempt"].clone();
                attempt["fence"] = json!(lease.fence.to_string());
                Ok((
                    json!({"schema_version":"1", "attempt":attempt,
                    "lease_expires_unix_ms":lease.expires_unix_ms.to_string()}),
                    Some("EnsureAttemptResponse"),
                ))
            }
        }
        .await;
        match result {
            Ok((_, None)) => (StatusCode::NO_CONTENT, String::new()),
            Ok((body, Some(schema)))
                if schemas.decode(schema, body.to_string().as_bytes()).is_ok() =>
            {
                let status = if schema == "CancellationPending" {
                    StatusCode::ACCEPTED
                } else {
                    StatusCode::OK
                };
                (status, body.to_string())
            }
            Ok(_) | Err(RegistryError::Unavailable) => {
                error(RuntimeCode::Unavailable, StatusCode::SERVICE_UNAVAILABLE)
            }
            Err(RegistryError::InvalidIntent) => {
                Denial::Scope.audit();
                error(RuntimeCode::InvalidRequest, StatusCode::BAD_REQUEST)
            }
            Err(RegistryError::NotFound) => error(RuntimeCode::NotFound, StatusCode::NOT_FOUND),
            Err(RegistryError::IdempotencyConflict) => {
                error(RuntimeCode::IdempotencyConflict, StatusCode::CONFLICT)
            }
            Err(RegistryError::AttemptExpired) => {
                error(RuntimeCode::AttemptExpired, StatusCode::CONFLICT)
            }
            Err(RegistryError::StaleWorkflow) => forbidden(),
            Err(_) => error(RuntimeCode::StaleFence, StatusCode::CONFLICT),
        }
    }
}
