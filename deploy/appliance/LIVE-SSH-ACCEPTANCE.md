# Operator-invoked SSH browser acceptance

`tools/test_live_ssh.py` is a separate operator-invoked SSH acceptance driver.
Preparing or unit-testing it does not authorize a live login. It must only run
after the operator has reviewed the exact deployment, host launcher/key policy,
session state and existing isolated native/mixed acceptance evidence. The Windows
driver remains tools/test_live.py with two RDP aliases and its optional extra
expected SSH catalog entry.

```
python-with-aiohttp tools/test_live_ssh.py \
  --expected-image EXACT_IMAGE_SHA256 \
  --base https://portal.example.invalid/desktop/app/ \
  --ssh-host ADMINISTRATIVE_SSH_ALIAS \
  --directory /absolute/new-private-case \
  --username PORTAL_USERNAME \
  --ssh-alias TERMINAL_ALIAS \
  --expected-catalog-aliases WINDOWS_ALIAS_A,WINDOWS_ALIAS_B,TERMINAL_ALIAS
```

The catalog argument must contain exactly three distinct literal aliases,
including the selected SSH alias. Native authenticated JDBC data must contain
exactly those aliases and distinct numeric IDs, with protocol ssh for the
selected alias and rdp for the other two. Only SSH is connected by this driver.
All actual instance bindings remain external arguments; no owner data belongs
in tracked source or documentation.

Run as an ordinary user with aiohttp and sandbox-capable Chrome installed.
There is no root-browser mode, remote-debugging attachment argument, browser
profile argument, arbitrary helper path, backend override or command/input
option. A fresh owned Chrome process group/profile is created and removed.
The same strict URL rules as test_live apply: public HTTPS /desktop/app/, or
private HTTP loopback /guacamole/ on laboratory ports10000..10999. Observed
browser scheme/host/port/path must match before and after acceptance; hashes,
queries and authentication tokens are not included in that observation.

The driver reuses test_live's exact installed helper path and strict fresh
nonmultiplexed SSH protocol. Root deployment proofs before/after must be
identical across container ID, run ID, image, config, network and release hashes.
The root-only OTP helper validates the configured username and expected image,
derives one ephemeral code inside the exact running container and returns only
six digits. The driver always requests the next fresh TOTP period, waits for
visible/enabled native submit controls, and clicks each login stage once. It
does not retry authentication. Ensure the installed test_live helper supports
the current proof format before invoking this driver.

The actual native username/TOTP form selects the SSH alias. The resulting
authenticated JDBC ID must reach native CONNECTED/status0 and nonblack canvas
activity. A sparse shell prompt can contain few pixels: the threshold is100
nonblack pixels, which proves display activity only. It does not prove an actual
shell, process persistence, terminal text or a correct glyph. The operator must
independently verify the intended root-managed launcher, separate tmux socket
and pane PID/start identity through trusted host metadata. The tool sends no
terminal keys, clipboard or commands and captures no screenshots.
Exact synthetic BMP UTF-8 and SSH PTY resize evidence belongs to the isolated
mixed fixture; supplementary Unicode behavior remains outside that acceptance.

The driver refreshes the owned page, verifies the same native identity/client
ID without another TOTP submission, removes only its selected managed client,
visits the chooser and reconnects once with the existing native token. It never
attaches to an owner's browser profile or controls a default/agent tmux socket.
Optional `--hold-seconds 0..20` adds a passive hold after each successful terminal
connection for independent host observations; the default is zero. Progress
phases contain fixed labels/timestamps/driver SHA only. The selected client fails
on its first observed native client/tunnel error; frontend callbacks and native
reconnect behavior are not replaced.

Cleanup attempts native logout and requires HTTP204, stops only the owned Chrome
process group and removes its profile even after failure. The initial failure
is preserved if logout/proof cleanup also fails. Result/progress artifacts retain
only fixed phase/reason categories, safe native state/status/dimensions/pixel
counts, alias/client mappings, bounded passive network status/timing telemetry,
source hashes and before/after deployment proofs. No raw URLs, request bodies,
headers, tokens, codes, keys, cookies, terminal text or payloads are persisted.
Browser authentication storage exists only in its disposable native profile.

The acceptance deadline is260seconds plus bounded failure/proof cleanup. A new
private case is mandatory; an existing case cannot be replayed. A successful
result establishes only actual SSH browser behavior on the exact bound run;
actual host pane identity, Windows connections, backup/restore, public routing
admission and owner acceptance remain separate evidence.

`test_live_ssh_boundaries.py` uses inert catalog/protocol/canvas/privacy and
owned-profile failure cases. The existing test_live_receipts and
test_live_telemetry suites cover shared deployment proof/URL/helper and passive
diagnostic privacy boundaries. None invokes a live browser, SSH, OTP helper or
actual authentication.
