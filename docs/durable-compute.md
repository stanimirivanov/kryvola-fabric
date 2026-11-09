# Durable logical compute workflows

Install Fabric with the `workflow` extra and configure both the Temporal
client and workers with `compute_workflow.DATA_CONVERTER`. Register
`ComputeWorkflow` and the three bound methods of `ComputeActivities`.
The caller supplies an authenticated registry connection and the physical
dispatcher. For the isolated Ray adapter, see
[Fenced Ray dispatch](ray-dispatch.md).

Pass committed v2 notifications to `start_from_notification`. Only
`operation_created` starts a workflow. Its ID derives from tenant and
operation, independently of event ID or delivery attempt. The client
uses Temporal's reject-duplicate policy for running and closed executions.
Keep namespace retention at least as long as the notification replay
window. Acknowledge delivery after start or duplicate confirmation.

The workflow reads the committed operation, ensures the first attempt,
and registers one physical execution before dispatch. An already terminal
registry observation returns its status without launching work. The dispatcher
receives the validated operation and attempt plus the execution ID, and
returns the exact published selection request. The dispatcher supplies
its separately authorized inputs. A launch with ambiguous completion fails
the workflow. The workflow does not automatically launch again or acquire
a successor epoch.

Temporal records the candidate before starting selection. A lost selection
completion retries the same request against the registry's idempotent
selection path, including when that request has already committed.
Result metadata does not grant release or artifact access.

The converter checks each encoded payload against 32 KiB and its serialized
application envelope against 128 KiB. The workflow does not add application
headers. Heartbeats contain only fixed phase labels. Serialized failures
contain a fixed code and retry classification without backend details.
Registry and dispatcher credentials stay in activity configuration.
The HTTP adapter requires verified TLS and the exact Fabric SPIFFE URI.
Provide the TLS context and short-lived registry credentials out of band.

The full gate runs the real Temporal server and replays history against
a controlled registry that commits selection before losing completion.
The Fabric runtime suite separately verifies the published registry routes
and live fencing. See [Compute workflow recovery](workflow-recovery.md) for
replay compatibility, attempt advancement and fence-first reconciliation.
