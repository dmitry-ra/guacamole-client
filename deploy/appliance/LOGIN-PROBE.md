# One authorized empty-domain login probe

This is a root maintenance diagnostic, not a product login endpoint or browser
acceptance. It opens one real Windows RDP attempt through the existing guacd.
Run only for an explicitly authorized alias, expected Windows username and
empty domain. The operator must verify safe target-session state and authorization
before dispatch, and inspect final Windows authentication/session events after
completion. A failed, lost or uncertain invocation must not be retried.

`tools/probe_login.py` runs only as UID0 inside the operator-selected exact
running production image. It verifies runtime integrity and protected read-only
catalog configuration, requires the requested target username to match exactly
and requires NLA. Connection parameters come directly from that target's runtime
catalog. Only the password placeholder is replaced by that target's mounted
secret in memory and the domain is overridden to empty. No configuration,
database or secret is modified. Endpoints, port, security and SHA256 certificate
pin are preserved. Other aliases' password files are never read.

The helper makes one loopback guacd connection, selects RDP, uses the actual
server argument list and sends one credential-bearing connect. It acknowledges
sync and blob instructions; it sends no keyboard/mouse/clipboard/desktop input.
It stops on a numeric guacd error or a display-bearing sync, EOF, timeout or a
protocol bound. Maximum wall time is 30 seconds with one absolute socket
read/write deadline, 16 MiB received bytes, 1 MiB per instruction and 10000
instructions. It closes only its own socket and never reconnects.

Raw error messages, protocol content, password, desktop text, image data and
screenshots are never returned or saved. The result contains only fixed
stage/outcome categories, UID, numeric error status, instruction/display counts
and aggregate blob payload length. `display_activity` records protocol activity;
it does not establish Windows authentication, a nonblack rendered desktop or
full browser acceptance. The operator's independent Windows event check remains
necessary even when the wrapper's narrow protocol check reports `passed: true`.

Use `tools/run_login_probe.py` from the operator machine. It requires a new
absolute private case directory and fsyncs a mode-0600 intent plus its directory
and parent before starting SSH. The intent binds expected full CID, image,
alias, expected username, empty-domain choice, authorization reference and exact
helper source SHA256. Every existing case is refused, including failed and
uncertain cases. The SSH transport uses verified host keys and disables shared
connections. Before the helper is streamed as stdin through root Podman exec,
a root remote guard verifies that exact existing CID is running with the
expected immutable image, production name, ownership label and run label.
No container is created, restarted or removed.

All example identities are synthetic; supply actual values externally:

```sh
python3 deploy/appliance/tools/run_login_probe.py \
  --ssh-host portal-admin \
  --container FULL_64_HEX_CID \
  --expected-image FULL_64_HEX_IMAGE_SHA \
  --alias desktop-a \
  --expected-username SyntheticUser \
  --authorization owner:explicit-request-reference \
  --directory /private/new-single-login-case
```

The wrapper requires bare lowercase image SHA256, not an image tag. It has a
55-second outer bound covering guarded execution and the inner 30-second probe.
It writes only the initial intent and a sanitized result/exit receipt. SSH
stderr and unvalidated stdout are never written. Source bytes are kept in
memory during dispatch; the receipt pins their digest. The operator may use the
installed `test_live.py --deployment-proof --expected-image SHA` root-only
non-authentication mode before and after to retain the exact ready deployment
binding. Updating an installed helper is separate from this invocation.

Offline tests use fake protocol sockets and mocked dispatch only:

```sh
python3 deploy/appliance/tools/test_probe_login.py -v
```

These tests do not contact guacd, Windows, SSH or any container. The older
synthetic wrong-pin helper and credential-free transport probes retain their
original scope and are not reused for actual credentials.


## Updating one stopped target credential

`tools/update_target_secret.py` is a separate root-only maintenance operation.
It uses fixed installed config and secrets paths, an exact externally supplied
current config SHA256, a catalog alias and exact expected Windows username.
The candidate service must be inactive with no owned candidate container. It
holds the existing supervisor lock and requires protected root-owned ancestry,
a mode-0600 single-link regular secret and a new private case outside the data,
config, secrets and publication trees. Shared target secret filenames are refused.

It reads at most 514 bytes from stdin, accepts one nonempty UTF-8 secret line
with at most one trailing LF, and writes no value, length or secret hash. The
caller must close stdin after supplying the bytes. A new fsynced intent and
root-private `previous-secret` backup precede any replacement. Safety, mapping
and original-file identity/content are rechecked, excluding access time that
can change during verification. A same-directory atomic replacement preserves
owner, group and mode and is fsynced. Every existing case is refused; interrupted
cases require independent reconciliation rather than retry. It does not update
DATA/config/public files, another target, or start/authenticate any service.

Example remote argv below receives the secret through the SSH process stdin
from an operator's no-echo input; never put it in argv, shell text or a log:

```sh
ssh -T -oBatchMode=yes -oStrictHostKeyChecking=yes -oControlMaster=no \
  -oControlPath=none -oControlPersist=no portal-admin \
  sudo -n python3 /opt/guacamole-portal/tools/update_target_secret.py \
  --alias desktop-a --expected-username SyntheticUser \
  --expected-config-sha256 EXACT_CURRENT_CONFIG_SHA256 \
  --directory /var/lib/guacamole-portal/new-private-secret-update-case
```

Only phase, success, alias and username appear in the printed JSON. The prior
secret exists only in the explicitly private backup; do not collect that file
as ordinary evidence. Offline checks:
`python3 deploy/appliance/tools/test_update_target_secret.py -v`.
