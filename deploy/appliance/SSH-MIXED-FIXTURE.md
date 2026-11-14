# Complete-image mixed browser fixture

`tools/test_mixed_image.py` runs an exact local candidate image with its packaged
runtime, native guacd plugins, WAR, Java provider and frontend. It does not mount
replacement product modules. A new synthetic PG16 cluster and confirmed test
TOTP identity are disposable container tmpfs data. The test-only entry script
prepares that cluster through the real runtime entrypoint, seeds the synthetic
TOTP attributes and runs the packaged service. No owner DATA or credentials are
read or mounted.

The schema-2 catalog preserves both original example RDP entries and portal
settings exactly and appends terminal-c. That SSH target uses a freshly generated
key and exact host pin for the separate synthetic endpoint's loopback listener.
The full appliance and endpoint share one owned network namespace with no
external network interface. Only a private host loopback HTTP relay in ports
10840..10859 enters this namespace, after checking exact CID/image/run label,
running PID and namespace inode. No host addresses or firewall rules change.

Build the disposable endpoint with build_ssh_endpoint.py first, and complete
test_ssh.py against the same exact candidate. Supply its successful result and
SHA256 as explicit prerequisites:

```
sudo /absolute/python-with-aiohttp tools/test_mixed_image.py \
  --image sha256:EXACT_CANDIDATE_IMAGE_ID \
  --endpoint-image sha256:EXACT_ENDPOINT_IMAGE_ID \
  --native-receipt /absolute/private-native-case/result.json \
  --native-receipt-sha256 EXACT_RESULT_SHA256 \
  --browser-uid EXPLICIT_NONROOT_UID \
  --directory /absolute/new-private-mixed-case
```

The controller runs rootful lab containers. Chrome drops to the explicitly
selected nonroot UID, its primary GID and no supplementary groups. A fresh
private profile and HOME/XDG directories belong only to this owned browser;
the browser sandbox remains enabled. No owner profile is attached. Only the
new browser process group is terminated. The controller has a 420-second
deadline, bounded relay/cleanup operations and finite container/runtime leases.

The browser uses the native username form, chooses terminal-c from the actual
three-option dropdown and completes native TOTP. It checks the authenticated
JDBC tree IDs1/2/3 and selects both original RDP aliases with the existing token.
Those two checks establish routing only; actual RDP endpoint success remains a
separate acceptance result. The SSH connection must reach native CONNECTED with
status0 and a nonblack canvas through packaged Java private-key substitution.

The first owned synthetic SSH terminal receives one fixed command by native
key events and one fixed Cyrillic/lambda/CJK BMP Unicode line through the same
native key path. The controlled pane hashes the exact UTF-8 bytes received; that
hash must equal the fixed expected line, rather than merely observing canvas
activity. The pane also emits fixed Unicode output, but the test does not claim
visual glyph correctness. Upstream Guacamole1.6 terminal key events accept BMP
characters. Its StringWriter also processes UTF-16 surrogate units separately;
supplementary input/clipboard behavior is not accepted by this fixture and is
not patched here. Changing browser dimensions must change measured
SSH PTY rows/columns; the receipt records safe numeric terminal and canvas
geometry before/after. No terminal text, screenshot or protocol payload is saved.

The fixture explicitly disconnects its managed SSH client, visits the native
home chooser, reconnects once without sending further input, and requires the
same pane PID/start identity with an advancing counter. The same synthetic Unix
account's default tmux sentinel PID/start identity must remain unchanged. The
endpoint consumes terminal_launcher.render verbatim with an explicit separate
socket and root-owned empty configuration. Socket separation is not account
isolation.

The browser logs out its token and must observe HTTP204. Receipts contain only
fixed phases, numeric state/geometry/PID/counters, fixed-input/source/config/
evidence hashes, health and cleanup results. Private keys, TOTP codes, tokens,
arbitrary errors, request bodies, headers and raw logs are not persisted. The
root-only endpoint exports synthetic key material through captured memory pipes;
the application's key exists only in its secrets tmpfs and Java staging tmpfs.
Both exact owned containers, relays and browser processes must be cleaned up.

`test_mixed_boundaries.py` performs inert checks for unchanged RDP entries,
root-browser refusal, exact native-refusal evidence/image/cleanup binding,
strict numeric metadata and exact UTF-8 input hashes. It invokes no engine,
database, browser or SSH endpoint. A successful mixed fixture still does not
admit production transport, an actual account, owner terminal data, guarded
deployment, public proxy behavior or backup/restore; those remain separate gates.
