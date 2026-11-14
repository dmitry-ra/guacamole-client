# Installed portal browser acceptance

`tools/test_live.py` is an operator-invoked test of an already installed portal.
Source preparation and offline validation do not authorize or establish a live
run. Run only after migration/restore acceptance, readiness, target-session
checks and explicit owner authorization to connect both actual desktops. This
test opens real RDP connections and can attach to existing Windows sessions.
It never types into either remote desktop, reads Windows credentials, captures
screenshots, exports canvas data or reads desktop text.

Supply every deployment binding externally. The only accepted public base is
`https://portal.example.invalid/desktop/app/` with normal certificate validation.
For private pre-cutover testing, use an operator-created tunnel to
`http://127.0.0.1:10432/guacamole/`; HTTP is restricted to loopback ports
10000 through 10999. This tool does not create a tunnel or change deployment.
Use a new evidence directory and separate fresh Chrome profile for each run.
Never repeat an uncertain login automatically.

Run as an ordinary user with Python 3, aiohttp and sandbox-capable Google Chrome.
An existing administrative SSH alias must have a verified known-host entry and
noninteractive root sudo access to the installed helper. Install the reviewed
file at `/opt/guacamole-portal/tools/test_live.py` as root-owned source before
running; do not replace the runtime inside the image.

```sh
python3 deploy/appliance/tools/test_live.py \
  --base https://portal.example.invalid/desktop/app/ \
  --ssh-host portal-admin \
  --expected-image SHA256_FROM_ACCEPTED_RELEASE \
  --username operator \
  --aliases desktop-a,desktop-b \
  --directory /private/new-public-browser-case \
  --wait-fresh-code
```

The symbolic digest above must be replaced by the exact 64-character lowercase
image SHA256. All sample aliases and identity names are synthetic. Run the
private tunnel case first, and a separate fresh public HTTPS case after cutover.
`--wait-fresh-code` waits for the next UTC TOTP boundary inside the root helper
before requesting a code. Use it when any previous operator login may have
consumed the current period. The driver makes no wrong-code or replay attempts.

The driver uses the actual username form and optional target dropdown, selects
the first requested alias, completes the native TOTP challenge, reads the
native authenticated PostgreSQL connection tree and derives both exact client
IDs from that tree. It requires both native connections to reach CONNECTED
with status 0 and more than 10000 nonblack canvas pixels. Both alias navigations
must retain the same native authentication token. It then reloads the native
client and requires an authenticated connected nonblack canvas again. These
pixel counts establish rendering only, not desktop contents or font quality.
Use `--desktop-hold-seconds 30` for a bounded additional connection-stability
observation on each target. During its explicit stability-hold phase an operator
can independently check guest logon and shell readiness. Native CONNECTED and
nonblack pixels alone do not prove that Windows completed an interactive logon.
The hold sends no desktop input and does not capture or read desktop content.
The final native logout is awaited and must produce HTTP 204. Failure cleanup
also attempts to revoke only this browser's token. Logout failure is recorded
and cannot replace an earlier test failure.

All authentication and refresh requests originate in that one fresh browser
and traverse the supplied base. The operator must install and verify the
nginx rate limit for the **entire** native `api/tokens` endpoint, including
refresh requests: rate 6 requests/minute, burst 10. Do not exempt this test,
bypass nginx for public acceptance, poll login for readiness or retry 429.
The driver retains only method/category/status metadata for login and logout;
it never records request or response bodies, full URLs, tokens or cookies.

The root-only `--otp` protocol is used exclusively over the existing pinned
administrative SSH connection with connection sharing explicitly disabled
(`ControlMaster=no`, `ControlPath=none`, `ControlPersist=no`). It inspects the exact running production
container named `guacamole-portal`, label `guacamole.portal=1`, and accepted
image SHA before and after execution. The helper executes a bounded constant
Python source via stdin inside that actual image, imports its runtime and
lifecycle, validates the configured identity against `--username`, and uses
`pg_sql(app=True)` to read the confirmed TOTP attribute for that identity.
Only the six-digit ephemeral code leaves the container through captured stdout;
the Base32 key stays inside. This helper is a root maintenance capability, not
a product authentication endpoint or bypass. Never invoke `--otp` in a logging
terminal or retain its protocol output. No code or key is written to evidence.

The browser uses its own temporary profile, loopback CDP port and process group;
it never connects to an owner's browser. Chrome sandboxing and TLS verification
remain enabled. Cleanup terminates only the owned process group and removes the
owned temporary profile, including transient native browser authentication
storage. The driver is bounded below 300 seconds under normal OS process cleanup;
SSH, container execution, CDP and logout have individual bounds. Evidence is a
new mode-0700 directory containing intent, progress and result JSON. All three
include the driver SHA256; progress records fixed phase names and timestamps
before login DOM, username submission, TOTP DOM/code retrieval/submission,
connection checks, reload and logout. A failure preserves its original phase
even while cleanup advances. Connection checks distinguish exact-route, native
connection and pixel waits. A failing authenticated run also attempts a bounded
sanitized snapshot before logout: expected-client presence, whitelisted native
state, numeric status and dimensions, route/selection index
within the two expected clients, and a boolean token equality check. No raw
route, unknown selection value, tunnel UUID, error text or desktop text is
returned. Each field is guarded separately so an unavailable display or tunnel
getter cannot discard the native client state/status. The upstream Client has
no public getState method: diagnostics use ManagedClient.clientState and the
outer tunnel.state field only as `outer_tunnel_state_non_authoritative`.
ChainedTunnel forwards inner callbacks without updating its inherited stored
state, so this outer value can remain CLOSED even during a healthy connection
and must never be used as evidence of effective transport state.
Connection waits retain up to 64 changed sanitized
observations, including intermediate error states before any native reconnect;
no callbacks or connection behavior are replaced. Tunnel HTTP and WebSocket
handshake statuses include their fixed test
phase. Only reviewed static driver failure reasons are
recorded; arbitrary exception strings and external error payloads are omitted.
Result JSON contains check names,
nonsecret HTTP statuses, client IDs, canvas dimensions/counts and cleanup flags.
A failed or interrupted run is not acceptance, even if some checks passed.


## Deployment and browser receipt binding

Before opening Chrome and after browser cleanup, the driver obtains a separate
root-only `--deployment-proof --expected-image SHA` JSON protocol over the same
pinned nonmultiplexed administrative SSH transport. This mode does not perform
product authentication and does not require a username or read target passwords.
The installed helper must be updated before running the extended driver; an
older helper without this mode fails before opening Chrome.

Each proof has exactly these six fields: `container_id` (64 lowercase hex),
`run_id` (32 lowercase hex), `image_id` (canonical `sha256:` plus 64 lowercase
hex), `config_sha256`, `network_sha256` and `release_sha256` (64 lowercase hex).
The helper uses the installed supervisor's protected admitted selection and
private current record, requires a ready record bound to that exact release
and image, verifies the owned running CID/name/labels/run, readiness marker
and dedicated network membership, and repeats capture to reject concurrent
changes. Selection verifies the protected configuration/network digests and
reviewed release files. No authentication or target secret values are returned.

The result contains `deployment_before` and `deployment_after`; a passing run
requires identical validated proofs. The final proof is attempted even if the
browser failed, while preserving the original browser failure. A proof failure
or changed admission cannot produce `passed: true`.

`observed_base` is the normalized base observed from actual browser
`location.protocol`, `hostname`, `port` and `pathname` before form submission.
It excludes fragment, query, tokens and credentials. Exact comparison with the
supplied base is required there and again after logout. Default ports are
normalized away and hosts are lowercase. An HTTP loopback run cannot claim
an HTTPS public base. URL identity alone does not prove the backend: the exact
before/after deployment proofs provide that separate binding.

A cutover validator must bind the private receipt to its exact configured
private base and pre-switch CID/run/release/config/network/image, then require
a separate fresh public receipt bound to the exact public base and post-switch
CID/run/new release. Old receipts without these fields are insufficient.

Offline boundary checks, including changed run/config and an unexpected
browser scheme/host/port/path:

```sh
python3 deploy/appliance/tools/test_live_receipts.py -v
```


## Passive reload diagnostics

`network_events` retains up to 256 passive CDP events with local numeric request
ordinals, wall-clock timestamps, optional numeric CDP timestamps and fixed
endpoint categories. It observes WebSocket creation, handshake send/response,
closure/errors and selected native HTTP request/response/failure metadata.
It retains no raw request IDs, URLs, queries, headers, tokens, frame contents or
error text. Network errors are an exact allowlist of known `net::ERR_*` codes
or fixed categories; unknown text is `UNKNOWN`. Internal request correlation is
bounded to 128 entries; event overflow records only a dropped-event count.
These observers persist across Page.reload and do not replace product callbacks.

For a separately authorized single diagnostic reproduction, add
`--fail-on-tunnel-error` (default false). During route/connection/pixel/hold
observations, the first observed selected current client's CLIENT_ERROR or
TUNNEL_ERROR raises a fixed failure immediately. The result saves its sanitized
state/status/index/time and reuses that snapshot, beginning own-token logout
without another diagnostic round trip. It does not patch or disable native
reconnection; prompt termination aims to close the owned session before a
subsequent delayed native attempt. Other clients' errors do not trigger this
option. Authentication and transaction retries remain unauthorized.

Focused offline privacy/selection tests:
`python3 deploy/appliance/tools/test_live_telemetry.py -v`.


Before each single native username or TOTP submission, the driver records a
`username_submit_ready` or `TOTP_submit_ready` phase and waits at most ten
seconds for a visible, enabled submit control. Readiness polling only evaluates
the DOM and sends no authentication requests. Once ready, it records the submit
phase and attempts exactly one click. A control that disappears or becomes
disabled is a failure, without a click or authentication retry. This handles
test-client form readiness only; it is not a server or production behavior fix.


HTTP response events also retain only finite numeric CDP timing fields:
requestTime, proxyStart/proxyEnd, dnsStart/dnsEnd, connectStart/connectEnd,
sslStart/sslEnd, sendStart/sendEnd and receiveHeadersStart/receiveHeadersEnd.
Negative numeric sentinel values are preserved. Other timing keys and nonnumeric
or nonfinite values are dropped. Responses also include boolean connection reuse
and disk-cache flags, plus protocol enum h2/http1.1/h3/OTHER. No response headers,
URLs or arbitrary protocol strings are retained.
