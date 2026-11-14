# Portable host launcher contract

`host.py` supervises one rootful Podman appliance after external admission.
It never installs a service, creates a network/profile, migrates data, enrolls
TOTP, opens an SSH transport or changes a proxy. Those operations require the
independently restored migration rehearsal and deployment procedure. Source
unit tests execute no host Podman, network or service operations.

## External paths and release admission

Install the reviewed launcher, `network_service.py`, `network_upgrade.py`,
`network.py` and `catalog.py` together beneath
root-protected `/opt/guacamole-portal`. All path ancestors must be root owned,
must deny group/other writes, and must contain no symlinks. Inputs are bounded
regular files; duplicate JSON keys and unknown release fields are rejected.

The product uses these fixed external paths:

- `/etc/guacamole-portal/config.json`: validated catalog schema 1.
- `/etc/guacamole-portal/network.json`: validated network schema 1.
- `/etc/guacamole-portal/release.json`: release schema 1 below.
- `/var/lib/guacamole-portal`: root owned, mode 0700.
- `/var/lib/guacamole-portal/data`: UID/GID 2000, mode 0700, independently
  prepared or migrated data. `prepared.json` must be root owned, mode 0600,
  a regular file with one hard link. Runtime verifies its configuration binding.
- `/var/lib/guacamole-portal/secrets`: root owned, mode 0700. Host checks
  required secret file metadata without reading credential bytes; runtime
  validates the contents. Every target retains its distinct filename reference.
- `/var/lib/guacamole-portal/host`: root owned, mode 0700, private host receipts,
  lock and bounded per-run component/entrypoint diagnostics.
- `/run/guacamole-portal`: root owned, mode 0755. `ready` is a root-owned mode
  0600 regular marker; nginx may stat its existence without reading its bytes.

Release schema 1 has exactly these keys. Documentation placeholders below
must be replaced with actual reviewed values outside the checkout:

```json
{
  "schema": 1,
  "image_id": "sha256:<64 lowercase hex>",
  "config_sha256": "<64 lowercase hex>",
  "network_sha256": "<64 lowercase hex>",
  "acceptance_evidence_path": "/var/lib/portal-acceptance/accepted.json",
  "acceptance_evidence_sha256": "<64 lowercase hex>",
  "backend_loopback_port": 10080,
  "podman_network": "portal-test",
  "apparmor_profile": "portal-test",
  "apparmor_profile_path": "/etc/apparmor.d/portal-test",
  "apparmor_profile_sha256": "<64 lowercase hex>"
}
```

The acceptance file must actually exist with protected ancestry and match the
reviewed SHA. The launcher does not generate acceptance records or infer that
an arbitrary manifest proves browser/RDP/restore success. The operator reviews
and stages that real evidence, binding its primary artifact hashes before
creating the root-controlled release. No synthetic booleans are admission.
Only exact immutable local image IDs are accepted; startup inspects that ID
and requires amd64. Runtime independently checks its image integrity manifest.

The AppArmor source must be a protected file immediately in `/etc/apparmor.d`.
Its hash and enforcing loaded profile name are checked before launch and while
serving. The profile may be an externally selected existing compatible profile;
no historical installation profile name is compiled into the launcher. The
operator must load the exact reviewed source before starting the service. Root
and profile includes remain trusted, as with the network manager and firewall.

## Network and startup ordering

Before starting the service, the operator provisions one dedicated rootful
Podman bridge network with label `guacamole.portal=1`, with no other consumers.
Its name comes from the release; its interface, canonical subnet, gateway,
source address and internal HTTP port come from the validated network file.
This image's WAR listener is fixed at 8080; a different configured internal
port is rejected before container creation rather than published incorrectly.
Its driver must be bridge, with DNS and IPv6 disabled and `internal=false`. The external
loopback publication port comes only from the release. No target or host
instance values occur in launcher source. The catalog exclusively controls
permitted destination tuples through `network.py`.

The service requires and starts after `guacamole-portal-network.service` and
starts after `network-online.target`. The operator provides that network unit
to create/check the owned bridge, apply/check its policy and order profile
loading on cold boot before this unit. This launcher does not create either object. The
host must already satisfy forwarding/route prerequisites in NETWORK-CONTRACT.

Startup first reconciles an interrupted prior run, then invokes
`network_service.py boot` before checking the empty owned bridge and AppArmor
profile. This ordering handles Netavark deleting the kernel bridge when the
last owned container is removed, including removal by prior-run cleanup. Only
the bootstrap module may recreate that bridge, under its exact ready binding,
owned definition, empty-consumer and live-firewall checks described in
NETWORK-SERVICE.md. The launcher never invokes bootstrap in the serving loop.
A failed bootstrap refuses container creation. Startup then invokes
`network.py apply` and `network.py check`,
and verifies immutable image/name/loopback-port availability. The network CLI
alone owns firewall transactions and its restricted boot-ID recreation rule;
the host never deletes a network receipt or blindly repairs partial rules.
Every serving iteration checks exact bridge membership, the network CLI,
external release/mount bindings, immutable container ownership and native health.
Any failed check closes this run's readiness marker and stops this run's CID.
Out-of-band root firewall resets remain within the trusted host boundary.

Podman uses at most two CPUs, 2 GiB memory with equal total memory+swap limit,
384 PIDs, read-only root, bounded private tmpfs, no-new-privileges and all
capabilities dropped except SETUID, SETGID, CHOWN, DAC_OVERRIDE, FOWNER and KILL.
Config and secrets mounts are read-only; only data and private diagnostics are
writable persistent mounts. Production runtime supervision stops its process
groups and PostgreSQL when any required component exits.

## Readiness, shutdown and recovery

The service uses `Type=notify`; the startup budget is 120 seconds including
host checks, bootstrap and firewall apply/check. The bootstrap command has a
90-second outer bound capped by the same remaining 120-second startup budget.
Individual commands are bounded by the
remaining startup budget. No marker is published until database_ready,
web_ready and enrolled are all exact JSON true, at least 65 seconds have
elapsed since the container was confirmed, and the real anonymous token API
returns the catalog's exact 403 challenge: a USERNAME field, plus an ENUM
`wrdp-target` field with the exact ordered catalog aliases only when
`publish_target_labels` is true. Extra/password fields, altered options and
HTTP 200 responses are rejected. The latter preserves the
mandatory WAR startup gate. HTTP proxy environment and redirects are disabled.
After publication, losing any component closes access and stops the container.
The native health report preserves separate component status and exception
types; raw command output and credentials are never copied into host reports.

Before creation, an atomic, fsynced `start_intent` records a random run ID and
the image/release binding. Containers carry exact product and run labels.
Creation is issued once. An uncertain response is reconciled by a fresh engine
query using both labels and full immutable IDs. Existing foreign containers,
ambiguous results or an uninspectable engine never authorize a blind stop.
If uncertain creation has no confirmed CID and a fresh query finds nothing,
the receipt remains `unresolved_creation`; absence at one instant does not
authorize replay of a potentially delayed creation. Operator review is required.
Restart first reconciles/stops the prior identified run; it does not replay an
unresolved creation. Every stop checks CID, name, image and both labels before
acting. It sends TERM through `podman stop`, rechecks ownership, and only then
uses a pinned-CID kill if still running. Removal follows confirmed exit.
Unknown cleanup retains the receipt for review, with no successful result.

Readiness cleanup checks root ownership, mode, one hard link, regular-file type
and exact run marker bytes. A foreign marker is preserved and reported; it
does not prevent an independently identified owned container from being stopped.
Successful cleanup writes private durable `stopped` state and a per-run result.
Uncertain stop/creation state must be inspected rather than deleted by hand.
`cutoff` performs only this owned reconciliation and cleanup; it cannot select
an unrelated container merely because it has reused the product name.

The unit retries failures after 60 seconds, at most three starts in 30 minutes.
It has a 45-second shutdown budget and an ExecStopPost cutoff for crash recovery.
`KillMode=mixed` sends the initial TERM only to the Python supervisor. This
lets an in-flight owned engine/network check complete before the existing STOP
flag enters cleanup; TERM to the entire cgroup can instead kill that child and
make the unchanged command checker report a failure even when cutoff succeeds.
The stop timeout still escalates to SIGKILL for all remaining cgroup processes.
Command, ownership and cleanup failures remain errors even when STOP is true;
there is no blanket stop-time exception suppression. An isolated process-group
regression reproduces both signal modes using the actual command helper and a
synthetic Python child, including a genuine child failure under main-only TERM.
Per-run entrypoint logs are engine-bounded at 64 KiB; the immutable runtime
independently bounds each of its three component diagnostic streams. The
host engine logs use a separate root-private `engine-logs-RUN` sibling that is
never mounted into the container. Only `logs-RUN` component diagnostics are
container-writable. Do not combine these directories: host-root conmon rotation
must not consume symlinks planted by an in-container root through a writable
mount. Original run directories remain untouched when the launcher is upgraded.
Retained
run directories/receipts require operator archival; no automatic evidence or
database deletion occurs. This is a launcher, not an install/backup manager.

```sh
python3 -B -m unittest discover -s deploy/appliance -p test_host.py -v
sudo python3 -B /opt/guacamole-portal/host.py run
sudo python3 -B /opt/guacamole-portal/host.py cutoff
```

The tests use synthetic addresses and mock all engine/network/service calls.
They cover release and argv constraints, ownership, uncertain creation,
private markers, stop timeout, health loss, startup expiry and the real-gate
requirement. Actual deployment still requires the independently restored
fixture to verify rootful publication, AppArmor, boot order, migration identity,
end-to-end RDP and shutdown. Unit tests alone establish none of those outcomes.
