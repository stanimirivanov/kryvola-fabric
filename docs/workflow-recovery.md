# Compute workflow recovery

The Temporal workflow ID is derived from the tenant and operation. Run IDs
identify histories for diagnostics. The application workflow epoch, logical
job and disclosure identity remain bound to the operation across worker
restart, Continue-As-New and explicit attempt advancement.

Use the existing notification starter for new workflows. Retain the
`compute-recovery-v2` patch and legacy command path until histories that
can replay the old path are outside the namespace retention window.
Before rollout, replay recorded histories with the new worker. The
F-live gate checks real Temporal histories from the legacy command path,
a restarted worker and both sides of Continue-As-New.

A workflow awaiting recovery reports its expired epoch through
`waiting_attempt`. An authorized coordinator can submit `advance_attempt`
with that exact epoch while the workflow is open. The registry admits only
the next attempt, subject to the existing deadline and fencing checks.
The workflow never renews an expired lease or advances it through an
activity retry. The existing two-minute workflow execution timeout applies
across rollover, so operators must act within that bound. If the workflow
has closed, reconcile it from the registry. A recovery fence does not itself
admit a successor application workflow.

For public or administrative cancellation and administrative termination, use
`stop_compute` from the authorized coordinator. It confirms the registry
barrier before contacting Temporal or requesting cleanup. Cancellation
pending requires another call. After a committed barrier, the supplied
idempotent cleanup callback runs independently of Temporal and survives
cancellation of the calling coroutine. Reconcile an interrupted call by
resubmitting the same scope, mode and cancellation idempotency key. The
registry barrier is the durable source for retry after coordinator process
loss. Retry either incomplete follow-up using the same command.
