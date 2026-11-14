# One reviewed current backup window

`tools/current_backup_window.py` stages and executes one bounded backup of the
currently admitted portal, then restores that same service and DATA. This is
separate from image/catalog/network promotion and independent migration. No
operator should run it merely to test argument parsing. `--help` and inert
tests do not stop a service or establish actual recovery acceptance.

The only lifecycle targets are `guacamole-portal.service` stop/start and nginx
reload. The transport and externally identified old legacy service must retain
their exact states, invocations, unit fragments and source hashes. No image,
release, catalog, network, credential, firewall, enablement or archive rollback
is installed. The source DATA is always the installed host module's
`PERSIST/data`; arbitrary source trees and fabricated inactive services are not
accepted. Inhibit unrelated maintenance and automatic restart activity externally.

## Prepare a protected operator bundle and plan

The reviewed helper may live in a new root-protected directory. It needs sibling
`public_cutover.py`, current-format `cold_copy.py`, `prepare_instance.py` and
`render_proxy.py`. Keep the operating `/opt/guacamole-portal` source unchanged.
On the host, the helper deliberately imports the installed host/catalog/network
modules before staged helpers. Its plan separately binds actual operating
source/unit hashes and the operator bundle's own source paths/hashes; a staged
copy cannot silently substitute a new controller for the running installation.

Use root-owned mode0600 single-link external configuration under protected
ancestry. All hostnames and instance-specific nginx paths stay outside Git.
This synthetic object shows the complete schema:

```json
{
  "schema": 1,
  "snippet_path": "/etc/nginx/snippets/synthetic-portal.conf",
  "public_base": "https://portal.example.invalid/desktop/app/",
  "legacy_unit": "legacy-portal.service"
}
```

The snippet must be an existing included file in `/etc/nginx/snippets`.
The case parent must already be root-protected, and the new case must be
independent of current DATA. Both the public URL and legacy unit describe the
actual reviewed installation; examples are not facts about a live host.

```sh
sudo python3 -B /root/reviewed-portal-tools/current_backup_window.py stage --config "$EXTERNAL_WINDOW_CONFIG" --case "$NEW_WINDOW_CASE"
```

Stage creates only a new private evidence case. It makes no route or service
change. Two fresh snapshots bind the ready current CID/run/image, exact
release/config/network/prepared receipt, DATA and secrets-directory identities,
actual current-unit fragment/enablement, preserved services, public transport
configuration and private-key metadata. Private-key bytes are never opened.
The plan binds every other nginx configuration byte independently of the one
owned snippet; its original bytes/mode are preserved separately. Native health,
native no-session probes and public200 must pass. A changed deployment or an
active desktop session is not made eligible by a receipt flag.

Review `plan.json`, saved originals, actual service/CID/DATA bindings and source
hashes. The command returns its plan SHA256. Retain an independent operator
session and explicitly clear active portal sessions before authorizing execution.

## Authorize and run one window

Supply a separate fresh root-private mode0600 review with exactly these fields;
the digest/reference/timestamps below are illustrative and must be replaced by
the actual reviewed plan and observed current time:

```json
{
  "schema": 1,
  "scope": "one current backup window",
  "plan_sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "operator_reference": "operator:reviewed-current-window",
  "allow_fixed_original_recovery": true,
  "reviewed_at": 1000,
  "expires_at": 1290
}
```

The review must currently be valid and span at most300seconds. Native session
probes establish actual no-session state; the review is operator authority, not
a substitute for those probes. Its fixed-original recovery authority is consumed
with the once-only transaction intent and remains valid for restoration if the
short dispatch review expires during an owned outage. Expiry blocks a new close,
reload, stop or backup dispatch; it cannot strand an already disrupted service.
A backup already dispatched has its genuine helper's own600second bound.

```sh
sudo python3 -B /root/reviewed-portal-tools/current_backup_window.py run --case "$NEW_WINDOW_CASE" --expected-plan-sha256 "$REVIEWED_PLAN_SHA256" --maintenance-review "$EXTERNAL_WINDOW_REVIEW"
```

The run uses a global nonblocking window lock and private case lock. It rejects
every previous run intent, including incomplete/failed attempts. It rechecks
the exact snapshot and native sessions, durably records intent, installs only
the fixed temporary503 snippet, syntax-checks nginx, freshly rechecks dispatch
authority and reloads. A bounded no-auth GET must confirm503. Another fresh
native no-session probe precedes the sole current-service stop.

The real service must become inactive/failed with MainPID0 and absent readiness.
`cold_copy.py backup` then checks the actual unit, exact container name and
externally pinned original full CID. When the controller removed that CID,
both exact name/CID absence checks must pass. No unit or engine response is
fabricated. The copy must be a new `cold-backup` child case. Its ready result,
source/target/CID/no-migration bindings, private manifest SHA256 and complete
backup/source census are independently rechecked. Partial copies remain intact.

The unchanged original service starts once on the original DATA, without any
restore from backup. Readiness requires a fresh owned CID/run on the same image,
release and host bindings, the actual65second startup hold and native health.
Exactly one empty native username-form challenge is allowed per run; failures,
429 and uncertain responses are never retried. Only then does the original
snippet load again and a bounded GET confirm200. A fresh known503 with the
original file already on disk permits one fixed-original recovery reload;
an already observed200 does not dispatch another reload.

The whole execution has a1200second deadline, with at most200seconds for one
fixed-state recovery after failure. The original error remains primary and is
re-raised even when diagnostic persistence or recovery fails. No stop/start is
blindly repeated after an uncertain dispatch. Exact fresh stopped state permits
the one original start; an uncertain prior start is observed, never dispatched
again. Recovery cannot install another image, change DATA, touch the transport
or start the legacy service. Failed health/identity/challenge checks leave access
closed or unconfirmed for explicit operator reconciliation.

## Reconcile without replay

```sh
sudo python3 -B /root/reviewed-portal-tools/current_backup_window.py reconcile --case "$NEW_WINDOW_CASE" --expected-plan-sha256 "$REVIEWED_PLAN_SHA256"
```

Reconcile reads exact bindings, service state, route bytes, current ownership
record and actual owned-container presence. It performs no lifecycle action or
new backup. Preserve run/progress/failure/recovery receipts and all partial
copies; a failed case is not permission to rerun it or point an old runtime at
changed data. A completed backup remains separate from an independently restored
and accepted rehearsal. The window's200/native health checks do not establish
browser/TOTP/desktop acceptance or a migration result.

Inert validation uses only synthetic private cases and mocked process/engine/
HTTP calls; protected filesystem cases require root:

```sh
sudo python3 -B -m unittest discover -s deploy/appliance/tools -p test_current_backup_window.py -v
```

Do not interpret those source tests as an executed production window. Root must
independently review the actual staged plan and operator inputs before any real
service action, then preserve actual cold backup and independent restore proof.
