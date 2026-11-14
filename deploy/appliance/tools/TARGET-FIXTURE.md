# Synthetic RDP target fixture

`synthetic_rdp_targets.py` prepares two visibly distinct synthetic desktops on
an existing, explicitly identified disposable Ubuntu XRDP guest. It installs
no packages and changes no firewall, host network, production service or owner
account. This is a TLS-only XRDP acceptance fixture, not a Windows NLA test.

Prerequisites: Python3, systemd, XRDP, xorgxrdp, OpenSSL, xterm, openbox, useradd,
chpasswd, loginctl and pkill. The existing listener must be active on3389 with
its existing sesman, default user `startwm.sh` support, and a synthetic TLS
certificate at `/etc/xrdp/synthetic-fixture.crt`. The selected beta port must be
unused. The operator must verify that the guest belongs to the isolated lab,
including its DMI UUID; a hostname alone is insufficient.

## Prepare

Review the source and exact guest mutation plan before transferring it. Use a
new root-only external directory and pinned SSH host key. All endpoints, guest
identity, account names, credentials and evidence stay outside Git.

```sh
sudo python3 synthetic_rdp_targets.py prepare \
  --directory /var/lib/portal-synthetic-CASE \
  --hostname SYNTHETIC_GUEST --uuid VERIFIED_DMI_UUID \
  --address PRIVATE_GUEST_IPV4 --beta-port 3390
```

Prepare creates two random, initially locked synthetic Unix accounts with
separate `/home/` directories, avoiding a private-parent traversal failure.
Their respective `startwm.sh` scripts open green/blue xterms labelled
`SYNTHETIC TARGET ALPHA` and `SYNTHETIC TARGET BETA`. Existing users and desktop
sessions are preserved. Alpha uses the existing3389 listener; beta uses its
own listener3390 and a new one-day synthetic RSA2048 certificate. Separate
users prevent shared sesman from reattaching alpha to beta's desktop.

Private `credentials.json` contains the generated passwords and SHA256 DER
certificate fingerprints. It must be exported only through a private,
hash-verified channel. Never print it, commit it or use owner credentials.
This tool does not read the earlier fixture's credential file.

Guest changes are confined to the two generated accounts/homes, the selected
new private evidence directory, and a random `/run/portal-synthetic-*` directory
owned by xrdp. Package versions are inherited, not upgraded; record them before
execution (`dpkg-query -W xrdp xorgxrdp xterm`). The reviewed reference fixture
had XRDP0.9.24 and xorgxrdp0.9.19; other versions need separate verification.

## Start and observe

```sh
sudo python3 synthetic_rdp_targets.py start \
  --directory /var/lib/portal-synthetic-CASE --seconds 600
sudo python3 synthetic_rdp_targets.py status \
  --directory /var/lib/portal-synthetic-CASE
```

Start is once-only: an existing intent prevents replay after an uncertain
result. The root watchdog starts before passwords become usable. Its finite
systemd service expires and locks both accounts, terminates only their UID
processes, and stops beta. Beta has its own finite service and control group.
Both RuntimeMaxSec values are at most600seconds; no enabled boot service,
cron job, production restart or broad process kill is created.

Beta runs `xrdp --nodaemon --config OWN_CONFIG` as xrdp. Its private mount
namespace binds an empty owned directory over `/run/xrdp`, then binds the
original sesman socket directory into it. XRDP0.9 refuses even an empty existing
PID file; binding a file alone is insufficient. Existing sesman sockets remain
visible through the nested host-source bind. Original3389 PID/config/pidfile are
compared before and after start and stop. Preserve receipts and inspect failure
journals if beta does not start; do not restart3389 or edit old fixture users.

Acceptance must establish two actual guacd RDP handshakes and distinct native
browser canvases. A listening socket or successful HTTP request is insufficient.
A fresh login must show the correct target marker, then stopping beta should
break beta while alpha continues displaying its own target. The portal image,
network namespace and browser acceptance tools are separate from this helper.

```sh
sudo python3 synthetic_rdp_targets.py stop-beta \
  --directory /var/lib/portal-synthetic-CASE
```

This checks the recorded beta systemd InvocationID before stopping it. It does
not stop3389, sesman, the alpha account or the watchdog. Use only in an active
synthetic acceptance window. A new start after stop is deliberately refused;
prepare a fresh case for another run.

## Expire and retain evidence

```sh
sudo python3 synthetic_rdp_targets.py expire \
  --directory /var/lib/portal-synthetic-CASE
sudo python3 synthetic_rdp_targets.py status \
  --directory /var/lib/portal-synthetic-CASE
```

Expiry is safe to repeat. It validates account home/comment ownership, locks
and expires only generated accounts, terminates only their UID sessions, and
stops only the recorded beta invocation. It retains users, home files, private
credentials, logs and receipts. No account or file deletion is implemented.
The remaining watchdog can run to its original finite deadline and repeat the
same scoped expiry. Verify locked/expired account metadata, absent synthetic
UID processes, stopped beta, and unchanged original3389 identity afterwards.
Retained artifact deletion and full guest removal require a separately reviewed
exact scope. The helper never removes the guest.

Source compilation is not live fixture acceptance. A clean guest creation cycle
and complete portal/browser evidence remain separate project gates.
