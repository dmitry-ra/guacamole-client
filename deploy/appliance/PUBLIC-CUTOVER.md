# Reviewed public RDP cutover

`tools/public_cutover.py` is an operator tool for a separately reviewed route
transition. Preparing its source and passing inert tests perform no deployment.
Do not switch while either actual Windows target is pending or failing. A
transport/TLS pass, synthetic desktop, private restored review, or a successful
first target cannot replace both actual Windows browser results. No password
reset, guessing, Windows changes, migration, image build, or SSH/tmux acceptance
is performed by this tool. Public Git publication remains a separate decision.

Install the reviewed tool next to `render_proxy.py` under the protected tools
directory and retain `host.py`, `catalog.py`, `network.py` and
`network_service.py` with its `network_upgrade.py` dependency at their installed
product paths. All input/case ancestry
must be root owned without group/other writes or symlinks. Use new mode-0700
case directories under a protected parent. Source, evidence, unit and nginx
hashes must stay unchanged between staging and switching.

## External configuration

The following synthetic example is a template only. Supply actual paths,
identities, reviewed reference strings and 64-character lowercase SHA256 values
outside tracked source. The old and new DATA directories must be independent.
The legacy controller must implement the existing root-owned `instance`,
`container_id`, product label and `.instance` label contract and native health.

```json
{
  "schema": 1,
  "legacy_unit": "legacy-portal.service",
  "legacy_container": "legacy-portal",
  "legacy_label": "example.legacy",
  "legacy_record_path": "/run/legacy-portal/instance.json",
  "legacy_ready_path": "/run/legacy-portal-public/ready",
  "legacy_data_path": "/var/lib/legacy-portal/data",
  "snippet_path": "/etc/nginx/snippets/example-portal.conf",
  "rate_limit_path": "/etc/nginx/conf.d/guacamole-portal-limit.conf",
  "public_base": "https://portal.example.invalid/desktop/app/",
  "private_base": "http://127.0.0.1:10080/guacamole/",
  "private_review": {
    "path": "/var/lib/portal-review/review.json",
    "sha256": "<review SHA256>"
  },
  "private_windows": {
    "path": "/var/lib/portal-review/windows-private.json",
    "sha256": "<actual private browser result SHA256>"
  },
  "browser_driver_sha256": "<reviewed test_live.py SHA256>",
  "private_windows_review_reference": "operator-actual-Windows-review-1",
  "session_clearance_reference": "operator-desktop-session-review-1"
}
```

The current release must bind the exact private restored review. Staging
rechecks all eleven primary receipt hashes from that review and the actual
two-target `test_live.py` result: image, driver, both exact aliases, CONNECTED
status 0, nonblack pixels, refresh, awaited own logout and owned browser cleanup.
Both configured targets must use NLA. The operator reviews that the configured
endpoints are the intended actual Windows systems; reference strings preserve
that review but do not stand in for the browser receipt.

Use the deployment-bound live driver described in LIVE-ACCEPTANCE.md. A receipt
must contain the observed browser base, and identical `deployment_before` and
`deployment_after` objects with exactly these identities:

```json
{
  "container_id": "<64 lowercase hex>",
  "run_id": "<32 lowercase hex>",
  "image_id": "sha256:<64 lowercase hex>",
  "config_sha256": "<64 lowercase hex>",
  "network_sha256": "<64 lowercase hex>",
  "release_sha256": "<64 lowercase hex>"
}
```

Private acceptance must match the current private base, current candidate CID
and run, and current release/config/network/image hashes. Older receipts without
these proofs cannot qualify. The candidate's controller record must match the
admitted release and image. No key, code, token, account name, desktop text,
raw subprocess output or credential enters stdout from the cutover tool.

## Stage and review

```sh
sudo python3 -B /opt/guacamole-portal/tools/public_cutover.py stage \
  --config /etc/guacamole-portal/cutover.json \
  --case /var/lib/portal-cutover/new-case
```

Stage preserves the exact old snippet, private release and three original
service unit fragments. It records enablement/invocation identities, actual
nginx configuration hash, independent DATA device/inode identities and source
hashes. It neither copies nor changes the running databases. The existing cold
backup and independently restored migration evidence remain the data rollback
sources. Old configuration, service unit bytes, data and evidence are retained.

It renders the new marker-gated snippet through the existing renderer and a
separate HTTP-scope authentication limit, rate 6/minute and burst 10. The old
rate-limit file is never edited. The new rate file must not already exist.
Current full nginx syntax and the isolated candidate syntax are checked without
starting a listener. The actual full configuration is tested again after any
authorized file selection and before each reload.

The case contains `admission-candidate.json` with public admission false and
SSH/tmux admission false. Review `plan.json`, staged files and primary evidence;
retain the returned exact plan SHA. This is the concrete result to approve.

## Switch, then accept separately

```sh
sudo python3 -B /opt/guacamole-portal/tools/public_cutover.py switch \
  --case /var/lib/portal-cutover/new-case \
  --expected-plan-sha256 REVIEWED_PLAN_SHA256 \
  --review-reference operator-reviewed-RDP-cutover-1
```

Switch refuses every changed initial binding and existing intent. It installs
an exact temporary 503 route, tests/reloads nginx and confirms public 503.
After each route reload, a bounded five-second sequence of normal TLS GETs
waits for the exact expected public status, with at most one second per request.
Transient old-worker responses do not authorize session checks or shutdown;
actual public 503 must be observed first. These GETs carry no authentication,
do not replay transactions and do not weaken the expected 503/200 gates.
It then counts native guacd processes in both exact inspected containers.
Exactly one supervisor is required; active children, missing processes or
uninspectable processes refuse shutdown. The NUL-delimited native process probe
is tested as executable source, not merely by a mocked success response. The
operator must keep other maintenance and browser tests out of this transition.

Only after closing new public requests and checking sessions does it stop the
old service and candidate. It writes reviewed RDP-only admission bound to both
actual private Windows results and all primary/source hashes, retaining
SSH/tmux pending. It backs up and atomically rebinds the release to this actual
admission file. It never silently promotes the prior private-only review.

The candidate starts from a fresh CID and run. Its real supervised readiness,
native health and authentication form must pass, with ready_at at least 65
seconds after fresh start, before the new proxy is selected. This protects the
copied TOTP identity at the old-to-new boundary. No readiness marker is invented.
The tool installs the new exact rate file/snippet, runs full nginx syntax,
reloads and checks public 200 plus native health. The old unit remains enabled;
the candidate and transport remain disabled until separate public acceptance.

Run a fresh actual public HTTPS browser case using the deployment-bound driver.
Stage a protected review JSON with the actual receipt hash:

```json
{
  "schema": 1,
  "scope": "actual public RDP acceptance",
  "plan_sha256": "<reviewed plan SHA256>",
  "public_base": "https://portal.example.invalid/desktop/app/",
  "browser": {
    "path": "/var/lib/portal-review/windows-public.json",
    "sha256": "<actual public browser result SHA256>"
  },
  "operator_reference": "operator-public-Windows-review-1"
}
```

The public result must be independent, occur after route selection, observe the
exact public base, and bind the new public CID/run and rebound release. A
loopback result or a review wrapper without those actual proofs is refused.

```sh
sudo python3 -B /opt/guacamole-portal/tools/public_cutover.py accept \
  --case /var/lib/portal-cutover/new-case \
  --expected-plan-sha256 REVIEWED_PLAN_SHA256 \
  --public-review /var/lib/portal-review/public-review.json \
  --public-review-sha256 ACTUAL_PUBLIC_REVIEW_SHA256
```

Accept rechecks native candidate and active transport health, exact release,
DATA identity and exact public route. It enables the new service and transport,
rechecks those enablements and native health, then disables the old unit. It
does not remove the old unit, old data, old guard, old limit file or any backup.
An actual cold-boot rehearsal and later SSH/tmux acceptance remain separate.

## Rollback and uncertain outcomes

Before rollback, known switch or acceptance failures fsync `switch.failure.json`
or `accept.failure.json` with the original fixed failure phase and reviewed
source refusal reason, plus numeric expected/last HTTP status when relevant.
Unmarked refusal messages are replaced by a fixed unclassified category; raw
subprocess/HTTP messages never enter diagnostics. A failing rollback receives
a separate `*.rollback-failure.json`, preserving the primary failure unchanged.
If the primary diagnostic cannot be persisted, containment is attempted and
transaction rollback is left for operator review.

Known switch or enablement failures attempt rollback to the preserved route,
release and original enablements. Before any candidate shutdown rollback first
selects and confirms 503, then performs a fresh native session census. An active
desktop refuses shutdown. In that case containment preserves the process and
readiness, leaving the exact known public nginx route permanently closed for
operator review. Existing upgraded WebSocket sessions are not forcibly killed.

A stopped legacy service restarts with a full additional 65-second hold,
owned marker, native health and actual username challenge checked before public
recovery is considered complete. Unexpected already-running legacy consumers
after a candidate transition require review. Legacy DATA identity must remain
the staged identity. A successful rollback leaves a changed candidate stopped;
it preserves its data and external evidence for diagnosis.

Timeouts and other uncertain command outcomes never authorize automatic replay
or a success receipt. Containment only replaces this case's known old/new/closed
nginx snippet with the exact 503 route and attempts syntax/reload/status checks.
It never unpublishes readiness, stops a container, or changes a foreign route.
Failure to prove route closure is explicitly retained as unconfirmed.

After inspecting live state and receipts, an operator may request one bounded
explicit rollback with a new review reference:

```sh
sudo python3 -B /opt/guacamole-portal/tools/public_cutover.py rollback \
  --case /var/lib/portal-cutover/new-case \
  --expected-plan-sha256 REVIEWED_PLAN_SHA256 \
  --review-reference operator-reviewed-recovery-1
```

Updating the tool changes its staged source hash: retain the old failed case
and intent, then stage and independently review a new case before a separately
authorized switch. A source fix does not permit replay of an existing intent.

Every phase retains private durable intent/progress/result records. A per-case
nonblocking lock excludes concurrent tool operations. Existing switch,
acceptance and rollback intents are not replayed; unresolved state requires
inspection. Never remove receipts to make a retry appear new. No source or unit
is installed by this tool, no database is deleted or restored, and only the
case-owned rate file can be removed during rollback.

```sh
python3 -B -m unittest discover -s deploy/appliance/tools -p test_public_cutover.py -v
```

The suite is host inert. Passing it proves validation/transaction behavior,
including active-session refusal and uncertain containment, rather than actual
deployment, Windows acceptance, reboot behavior or operator approval.
