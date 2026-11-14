# Reviewed current-service shutdown for upgrade

`tools/close_current_for_upgrade.py` is a separate finite shutdown primitive
with an independently reviewed explicit fixed-original recovery entrypoint.
It closes only the dedicated portal nginx snippet, confirms the public503,
records the native post-close session census, stops the exact current portal
once, proves its CID absent, and then stops its existing transport once.
Shutdown does not activate anything, take a backup, restore/migrate/promote DATA, replace
selection/host sources, alter legacy services, or replay an interrupted action.
Normal database shutdown writes are performed by the original supervisor; the
tool never edits database files or replaces the original DATA directory.

Import order deliberately selects `current_backup_window` first so its actual
installed operating host/catalog/network modules are used. Staged newer
modules must not replace the identity being stopped. This tool reuses B's
stage/load_case/snapshot, protected files/source binding, locks and nginx/native
helpers. B's full backup-window `run` is not called because it automatically
resumes the original service.

Source-only inert tests are available; actual shutdown/use remains a separate
root operational decision. Nothing in this source document admits a deployment.

Use a NEW B-style staged case for the actual current active CID/run and exact
installed original selection. The configuration is the existing B contract:
schema1, dedicated `/etc/nginx/snippets/*.conf`, normal public HTTPS
`/desktop/app/` URL, and distinct retained legacy service. Do not reuse an
earlier completed backup window or a stale pre-restart plan.

```sh
sudo python3 tools/close_current_for_upgrade.py stage --case /protected/new-final-window \
  --config /protected/window.json
```

Review the actual B `plan.json` SHA, source hash returned by stage, current
CID/run, original snippet, installed source/file identities and unchanged
transport/legacy units. The new external root-private review has this schema:

```json
{
  "schema": 1,
  "scope": "one current upgrade shutdown",
  "plan_sha256": "EXACT_B_WINDOW_PLAN_SHA256",
  "shutdown_source_sha256": "EXACT_SHUTDOWN_HELPER_SHA256",
  "operator_reference": "operator:reviewed-final-shutdown",
  "allow_fixed_original_recovery": true,
  "reviewed_at": 1800000000,
  "expires_at": 1800000240
}
```

Times are Unix seconds. The review must be effective, not expired, and valid
for at most300 seconds. Its separate scope prevents a routine backup-window
review from silently authorizing a prolonged upgrade outage. Recovery authority
is explicit, but this helper never exercises it automatically.

```sh
sudo python3 tools/close_current_for_upgrade.py run --case /protected/new-final-window \
  --expected-plan-sha256 EXACT_B_WINDOW_PLAN_SHA256 \
  --maintenance-review /protected/fresh-shutdown-review.json
```

Run takes the same global B lock and protected case lock. It requires a fresh
unused case, exact live snapshot, fixed root-reviewed helper source and empty
native session census before recording a durable single-use intent. It repeats
the exact current record and source/file bindings before changing the route.
The existing nginx replacement helper touches only the dedicated snippet;
syntax, one reload and bounded public503 convergence precede the second native
census. An active or unknown census leaves both services running and the route
closed for operator reconciliation; no owner desktop is stopped.

`session-census.json` contains the actual native `guacd_processes:1` response,
the full original CID/run and timestamp, with `closed_before_census:true`.
`closed-route.conf` preserves the exact installed fixed503 route bytes;
`closed-route.json` binds the dedicated path, its SHA, observed public status,
confirmation time and plan. These are observed artifacts for subsequent fresh
network/transport/promotion review, not a reusable permission or fabricated
application acceptance. Recheck the actual route/service state before issuing
each later operation's separate short-lived root review.

After another identity/source check, only the fixed current portal unit is
stopped. The helper requires inactive/dead/PID0, absent readiness, exact old
stopped controller identity, exact integer exists returncode1 for its full CID,
no remaining appliance containers, and the genuine stopped/exclusive DATA
check. Only then may it stop the exact existing transport unit. Both stops
are single dispatches, and approval is checked again before each action.

After transport stop, the original B `static_binding` cannot be used because
it requires an active transport. The shutdown helper separately verifies the
same original selected release/config/network/prepared/DATA/secrets identity,
installed unit files/source hashes, transport key metadata/public files, nginx
scope, snippet ownership/mode and complete unchanged legacy unit state. It
allows only the transport's inactive/dead/PID0 state with its original or empty
InvocationID; a foreign invocation, source/file change or container prevents
success. The result records actual stopped state and evidence hashes. It never
creates readiness or changes enable/disable state.

The whole run has a180-second deadline. Any failure records its original error
class and safe fixed refusal reason, when available, then stops work. It never
reopens the route, retries a stop/reload, starts a service, or invokes backup.
Even an after-effect timeout remains a single attempt. Original errors survive
diagnostic persistence failures.

Explicit read-only reconciliation:

```sh
sudo python3 tools/close_current_for_upgrade.py reconcile --case /protected/new-final-window \
  --expected-plan-sha256 EXACT_B_WINDOW_PLAN_SHA256
```

It checks original bindings, route bytes, exact controller/container identity
and services, then reports disk route and one actual public HTTP status
separately. It does not write receipts/locks, stop/start/reload anything, or
convert uncertainty into another attempt. A changed/transitional/foreign state
may refuse rather than pretend the operation completed.

Fixed-original recovery remains a separate root decision. Before transport
stop, while its complete original active binding still matches, the existing
B `restore_original()` primitive can consume this case's `progress.json` and
explicit `stop_dispatched` flag. It proves the original DATA/selection, starts
only the original supervised service once, requires a fresh CID/run and actual
65-second hold, performs its single empty native challenge, and restores only
the staged original snippet. Do not run B's full backup-window command or
delete intent files to enable retry.

After transport stop, directly calling B recovery is insufficient: restarting
the transport gives a new InvocationID/PID that the original B plan did not
authorize. The separate recovery actions accept only the proven stopped state
and exact original sources/config/network/client transport bytes, DATA identity
and old stopped controller CID/run. This is narrow pre-promotion recovery. If a
new application has written `current.json`, the old-CID-bound recovery does not
cover that controller, even after restoring files. Independent reconciliation
and separate root review are required; this helper never adopts that state.

Prepare a NEW independent recovery case only after a complete shutdown result
and actual original stopped/closed state have been proved:

```sh
sudo python3 tools/close_current_for_upgrade.py stage-recovery \
  --case /protected/new-final-window --expected-plan-sha256 EXACT_B_WINDOW_PLAN_SHA256 \
  --recovery-case /protected/new-original-recovery
```

Review the new `recovery-plan.json` SHA. It binds the exact B plan, shutdown
result, current helper source and original case. Create a new root-private
review with the same fields as the shutdown review, except scope is
`one fixed original recovery` and one additional field is required:
`recovery_plan_sha256`, equal to that independently reviewed recovery plan SHA.
The review is separately fresh for at most300 seconds; shutdown authority does
not silently authorize a restart.

```sh
sudo python3 tools/close_current_for_upgrade.py recover \
  --case /protected/new-final-window --expected-plan-sha256 EXACT_B_WINDOW_PLAN_SHA256 \
  --recovery-case /protected/new-original-recovery \
  --expected-recovery-plan-sha256 EXACT_RECOVERY_PLAN_SHA256 \
  --maintenance-review /protected/fresh-original-recovery-review.json
```

Recovery records a single durable intent and starts ONLY the original guarded
portal unit first, while transport remains pinned inactive. The original host
supervisor can bootstrap its own admitted bridge if ordinary last-container
teardown removed it; this helper issues no network command. The portal unit
must not require transport. The helper verifies actual native health, a fresh
original image/release CID/run and actual65-second hold. Only then does it
start the original transport once, requiring its unchanged immutable source/
unit/config/key bindings, active state and fresh InvocationID/PID. One empty
native challenge must pass before it restores only the staged original snippet,
checks nginx syntax, reloads once and verifies public200 and original identity.
Approval is checked after source reads, before each action and before success.

The whole explicit recovery has a300-second deadline and never retries a start,
challenge or reload, including after-effect uncertainty. Failure preserves its
first exception and case; no automatic restart or compensating shutdown occurs.
It may leave the original service privately ready and route closed, or a known
original reload outcome uncertain. Read-only diagnosis of that recovery:

```sh
sudo python3 tools/close_current_for_upgrade.py reconcile-recovery \
  --case /protected/new-final-window --expected-plan-sha256 EXACT_B_WINDOW_PLAN_SHA256 \
  --recovery-case /protected/new-original-recovery \
  --expected-recovery-plan-sha256 EXACT_RECOVERY_PLAN_SHA256
```

Neither recovery nor diagnosis weakens B's original binding or manufactures an
updated old plan. If network/transport/promotion changes have occurred, root
must restore their exact original bytes and DATA identity in the reviewed
dependency order before considering this recovery. A changed controller needs
separate reconciliation first. Never overwrite original DATA or stop an
owner's active desktop blindly.

Inert checks use synthetic private /run cases with every process/engine/HTTP
boundary mocked:

```sh
sudo env PYTHONPATH=deploy/appliance:deploy/appliance/tools \
  python3 -m unittest deploy/appliance/tools/test_close_current_for_upgrade.py
```
