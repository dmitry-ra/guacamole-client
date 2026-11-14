# Isolated native SSH fixture

`tools/test_ssh.py` tests the exact candidate's native guacd SSH plugin against
an owned disposable OpenSSH/tmux endpoint. It does not test JDBC private-key
injection, browser/TOTP login, alias selection, actual owner endpoints or restored
DATA. Those remain separate gates in SSH-ACCEPTANCE.md. A protocol display event
alone does not prove a usable terminal: this fixture additionally requires its
controlled pane process to remain alive and advance after one disconnect and
reconnect, with the same PID and process start time.

First build the separate endpoint image using a verified public bootstrap CA
from the project's current public inputs. The builder checks source-inputs-lock.json's CA
checksum, exact Ubuntu base and apt snapshot, uses `--pull=never`, one build job,
a two-CPU quota and a 420-second deadline. It installs packages only inside the
disposable endpoint image, never on the host. The new private build case records
the endpoint image and source hashes; the native case records the installed
package manifest and its hash. No images are published.

```
sudo python3 tools/build_ssh_endpoint.py \
  --bootstrap-ca /absolute/verified-public-inputs/bootstrap-ca-certificates.crt \
  --directory /absolute/new-private-endpoint-build
sudo python3 tools/test_ssh.py \
  --image sha256:EXACT_CANDIDATE_IMAGE_ID \
  --endpoint-image sha256:EXACT_ENDPOINT_IMAGE_ID \
  --directory /absolute/new-private-native-case
```

Use complete 64-hex local image IDs. The endpoint image must carry the dedicated
fixture label. Both containers have private filesystems, bounded memory/PIDs/CPU
and finite leases. The candidate has network disabled and the endpoint shares
only that container's loopback namespace; neither publishes ports, uses host
networking or mounts host instance files. The candidate runs read-only as guacd
UID2002. Containers are removed in reverse order only after exact CID, name,
image and per-run label checks. An engine error is not proof of absence. The
controller alarm and bounded cleanup complete within 240 seconds; finite
container leases also limit an interrupted controller's owned processes.

All endpoint identities and keys are freshly generated synthetic material.
Application keys cross only captured in-memory exec pipes into the native SSH
client. Keys, error text, protocol payloads and terminal output are never written
to receipts or printed. The owned endpoint's tmpfs disappears on removal.
The tool reuses only the bounded wire codec from probe_login.py; it does not run
or relax that helper's operator-authorized Windows credential scope.

The endpoint uses the shared terminal_launcher.render output verbatim, a fixed
absolute command, root-owned empty tmux configuration, and an explicit private
socket in the synthetic account's home. The same synthetic account also has a
default-socket sentinel tmux pane. Receipts must prove that sentinel PID/start
identity is unchanged. No owner/default/agent sockets outside the container are
accessible. This tests socket separation, not account isolation.

Required native checks are loadable SSH linkage, NONE authentication refusal,
unapproved forced-command exit126, valid but wrong host key refusal, wrong
application key refusal, correct pinned authentication and display activity,
then one reconnect with the same controlled process and advancing counter.
Only the fixed synthetic command is typed into the first owned terminal; the
reconnect sends no input. No password fallback is supplied; the endpoint permits
public-key authentication only. Resize/UTF-8 rendering and full mixed native
browser acceptance remain explicitly pending and must not be inferred from this
receipt. Existing RDP acceptance must run independently against the same image.

Run `python3 -B -m unittest discover -s tools -p test_ssh_fixture.py -q` for
inert privacy, exact ownership, mutable-image refusal, fixed synthetic endpoint,
wire-error, secret-size and PID-reuse/counter boundaries. These tests do not
start an engine, browser, SSH connection or database.
