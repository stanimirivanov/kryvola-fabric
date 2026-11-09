# Fenced Ray dispatch

Register `ComputeActivities.dispatch_ray` on a dedicated Temporal queue
alongside prepare and select. Configure the activities with
`RayDispatcher(local_jobs(port), local_candidates(root))` and pass
`ray=True` to the notification starter. The default workflow retains its
existing dispatch activity and retry policy. The Ray activity can retry
transport failure or worker loss using the same registered execution.
Engine failures, conflicting observations and malformed jobs fail closed.

SQL registration precedes the Ray Jobs submission. The submission ID and
filesystem namespace derive from the full attempt fence and execution ID.
A fresh dispatcher looks up the job before submitting, validates the
fixed entrypoint and exact runtime environment on reattachment, then
checks that the observed candidate names the same attempt and execution.
Only the existing SQL selection transaction can select an output. A
different physical execution needs a distinct registered execution ID.

Use the pinned Ray 2.59.0 image and mount the Fabric Python source package
read-only on its Python path. The Jobs entrypoint and its dependencies
run in Ray's Python environment. The Fabric host uses the standard
library HTTP client and requires no Ray dependency. Expose the Ray
dashboard only to the trusted bridge over loopback or an authenticated
local tunnel. The Jobs API can launch arbitrary commands for callers
with direct access, so do not expose it to tenants or untrusted networks.

The trusted assignment provisioner must supply a dedicated private
directory under `/run/kryvola/ray/<namespace>` before dispatch. Expose
only the credential-free `execute.pb`, the matching private Engine Unix
socket `engine.sock`, and writable space for the launch marker and
candidate observation. Keep the Engine assignment, tokens and signing
keys in the Engine process's separate private directory. The Ray Jobs
request carries only the bounded execution identity and plan and policy
digests. The worker validates the assignment against them before issuing
one Engine Execute RPC. The launch marker prevents a second Execute
after Ray loses its job state. Preserve the namespace and marker across
restarts. If the worker dies after the marker and before Execute, the
execution may be stranded and needs a distinct registered execution
for another launch.

The Ray live gate uses the pinned Ray scheduler and a controlled Engine
RPC fixture. SQL fencing and selection races are checked by the live
registry suite. Deployment wiring, credentials and full native inference
qualification remain separate milestone tasks.

The adapter uses Ray's submission, lookup and status endpoints.
[Ray 2.59 Jobs REST API](https://docs.ray.io/en/latest/cluster/running-applications/job-submission/rest.html)
