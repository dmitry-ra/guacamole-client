# External installation and lifecycle

This is an operator procedure for the current private appliance. Existing
private preparation evidence covers its former clean-source image, synthetic
desktops, kernel policy, stopped legacy restore/migration and installed behavior.
The selected current-main candidate separately passes packaged HTTP/native TOTP,
native SSH/tmux and independent same-image/cross-version mixed restore rehearsals.
The current image also passes full synthetic TLS two-target RDP and independent
target-failure acceptance with verified cleanup. An independent clean-host
lifecycle rehearsal passes installation, native TOTP/browser checks, stopped
backup/independent restore, matched rollback, real reboot and owned removal,
preserving unrelated services. Its pre-enrolled synthetic catalog used
documentation endpoints and exercised no target desktop or SSH sessions.

A separate operator-run fresh installation of the same image passes both
actual Windows NLA desktops, native TOTP, concurrent native clients, stability
holds, authenticated refresh, logout and browser/tunnel cleanup. Independent
read-only WTS observations show Active sessions during the holds and
Disconnected sessions afterwards. This private-loopback result is distinct
from the independent host lifecycle and exact-image SSH/restore fixtures.
The ensuing integrated same-VM run also passes native SSH/tmux reconnect,
both Windows targets after real reboot, independent cold restore and matched
rollback, intentional route isolation, and exact owned removal preserving
unrelated services. External SSH process identities survive the portal's
lifecycle. Matched native correct-pin/wrong-pin controls pass separately.
This accepts the pre-enrolled private lifecycle with a synthetic SSH endpoint
and reviewed manual network replacement/selection/removal; it is not a general
fresh-host or enrollment installer. Published-main rebuild and new-image
production HTTPS acceptance remain separate actions. Check the current
project status before performing a live step; never infer acceptance from this
recipe or relabel earlier production receipts as tests of a different image.

The supported migration route retains the existing personal identity and TOTP.
A clean destination host may receive that independently restored legacy data.
Creating a new personal identity is a different operation: the runtime has a
`prepare` API, but there is no accepted general fresh-instance host preparer or
initial TOTP enrollment controller. Do not substitute a stock administrator,
new TOTP enrollment or database initialization for migration.

All variable names below denote reviewed external paths or public deployment
bindings. Supply them explicitly outside the checkout. No real host, address,
username, certificate pin, password or acceptance receipt belongs in source.
Keep source and operational evidence separate. Commands are individual review
steps, not an unattended installer; a failed or unknown operation requires
inspection before another attempt. Never delete a receipt to make a retry run.

## Host prerequisites and fixed layout

Use an amd64 Linux host with systemd, cgroups/resource limits, rootful Podman
with the native Netavark bridge backend, enforcing AppArmor, Python 3, OpenSSH,
iproute2, nftables, and IPv4/IPv6 iptables with the nft backend. The actual
private network-manager checks used Podman 5.7 and Netavark 1.16.1. Their
existing-bridge behavior matters; another version needs acceptance rather
than an assumption of compatibility. This repository does not yet provide a
pinned host package/bootstrap manifest or provision these prerequisites.

The image supplies PostgreSQL16, Java25 LTS, Tomcat and guacd. The host also needs
`apparmor_parser`, `cp` with numeric ownership preservation and `ssh-keygen`.
Browser fixtures additionally need ordinary-user Python aiohttp and
sandbox-capable Google Chrome. Builder dependencies and exact artifact URLs,
hashes, signatures and versions are in
[source-inputs-lock.json](source-inputs-lock.json) and the source build tools.
The historical images-lock/dependency-lock recipe and its released-input and
FreeRDP compatibility helpers are held out of the first publication package.
The current source build does not consume them or perform binary JAR substitution.

Reserve a dedicated, unused bridge/subnet/source/gateway and one external
forwarding interface/SNAT address. IPv4 forwarding, target routes and the
SNAT address must already exist on that host. Do not change global routing
sysctls or unrelated interfaces as an installation shortcut. Provide the
existing HTTPS server, trusted TLS certificate and separately reviewed proxy
integration. No RDP or guacd listener is published on a public interface.

Every protected path ancestor must be root-owned, deny group/other writes and
contain no symlink. Root inputs are bounded regular files. State and secrets
must remain off shared or user-writable storage.

| Path | Ownership/mode and purpose |
| --- | --- |
| `/opt/guacamole-portal` and `tools` | root:root, 0755; reviewed host Python source, no instance data |
| `/etc/guacamole-portal` | root:root, 0700; external catalog, network and release |
| `config.json`, `network.json`, `release.json` | root:root, 0600; literal single-link JSON inputs |
| `/var/lib/guacamole-portal` | root:root, 0700; external state root |
| `secrets` and its files | root:root, directory0700/files0600, regular single-link credentials |
| `data` and `data/pgdata` | numeric UID/GID2000, 0700; independently restored/migrated PG16 data |
| `data/prepared.json` | root:root, 0600; current catalog/data binding generated by runtime |
| `host` and `network-bootstrap` | root:root, 0700; launcher/bootstrap receipts and locks |
| `/var/lib/guacamole-portal-network` | root:root, 0700; separate firewall receipt/lock |
| `/run/guacamole-portal` | root:root, 0755; runtime-owned readiness directory |
| `/run/guacamole-portal/ready` | root:root, 0600; launcher-owned access marker |
| `/etc/apparmor.d/guacamole-portal` | root:root, 0644; reviewed enforcing profile source |
| `/etc/portal-rdp-transport` on the client | root:root, 0700; private key and pinned transport config |
| external backup/evidence cases | root:root, 0700 with private files; never source-controlled |

Treat UID/GID2000 (database), UID2001 (Java) and UID2002 (guacd) as numeric
container identities. Preserve them across copies. Do not recursively chown
the state tree: the prepared receipt, secrets and database have different owners.

## Build, transfer and admit the immutable image

Freeze the reviewed source revision and the complete official input cache.
Do not copy a private reference image into the new image or download arbitrary
replacement dependencies. The locked base image must already be present in
the build engine; building uses `--pull=never` and the locked package snapshot.
Use at most two native workers and one sequential image build. Private CI is
disabled; do not enable paid jobs, publish an image or create a public release.
First complete `source_build.py` with the selected checkout and locked Java25
toolchain. `SUCCESSFUL_CLIENT_BUILD` below names that new external work directory
with a successful `provenance.json` and its recorded WAR/modules/SQL artifacts.
The Maven cache and repository are explicit external directories; the JDK must
already be unpacked from the verified locked input. Use different new work
directories for source compilation, verification and image building.

```sh
python3 deploy/appliance/tools/source_build.py --checkout "$REVIEWED_CHECKOUT" --work "$SUCCESSFUL_CLIENT_BUILD" --java-home "$VERIFIED_JDK25_HOME" --maven-cache "$MAVEN_CACHE" --maven-repository "$MAVEN_REPOSITORY"
python3 deploy/appliance/tools/build_image.py verify --client-build "$SUCCESSFUL_CLIENT_BUILD" --inputs "$OFFICIAL_INPUT_CACHE" --work "$NEW_VERIFY_WORK"
sudo python3 deploy/appliance/tools/build_image.py build --client-build "$SUCCESSFUL_CLIENT_BUILD" --inputs "$OFFICIAL_INPUT_CACHE" --work "$NEW_BUILD_WORK" --tag localhost/private-portal:development
```

Retain the frozen source/input hashes, build log and successful build receipt.
The development tag is not an admission identity. Record `IMAGE_ID` as the full
`sha256:` ID from that receipt and `IMAGE_HEX` as its 64 lowercase hex digits.
Run the isolated image/auth, PostgreSQL and synthetic RDP fixtures described in
[tools/IMAGE-FIXTURE.md](tools/IMAGE-FIXTURE.md),
[RDP-ACCEPTANCE.md](RDP-ACCEPTANCE.md) and the tool registry. The network kernel
fixture is separately documented in [NETWORK-CONTRACT.md](NETWORK-CONTRACT.md).
Use new private evidence directories and verify each fixture's owned cleanup.

For another host, export only that admitted local image:

```sh
sudo python3 deploy/appliance/tools/export_image.py --image "$IMAGE_HEX" --directory "$NEW_IMAGE_EXPORT_CASE"
```

Transfer the OCI archive and receipt through the reviewed private channel.
On the destination, verify archive size/SHA256 against that receipt before
loading, then inspect the exact local image ID and amd64 architecture. Loading
an archive or resolving a tag does not itself prove its identity or acceptance.

```sh
sudo podman load --input "$VERIFIED_OCI_ARCHIVE"
sudo podman image inspect "$IMAGE_ID" --format '{{.Id}} {{.Architecture}}'
```

Retain the old immutable image and matching source/configuration for rollback.
Never rebuild a supposedly equivalent rollback image from an unpinned tag.

## Install reviewed host source before instance creation

Verify that every intended new source, profile and unit destination is absent,
including symlinks, or prove its dedicated ownership and use the stopped
upgrade procedure below. Install the exact reviewed host
modules and their matching units together; do not replace running source.

```sh
sudo install -d -o root -g root -m 0755 /opt/guacamole-portal/tools
sudo install -o root -g root -m 0644 deploy/appliance/host.py deploy/appliance/network.py deploy/appliance/network_service.py deploy/appliance/network_upgrade.py deploy/appliance/catalog.py /opt/guacamole-portal/
sudo install -o root -g root -m 0644 deploy/appliance/tools/prepare_instance.py deploy/appliance/tools/cold_copy.py deploy/appliance/tools/migrate_legacy.py deploy/appliance/tools/test_host_network.py deploy/appliance/tools/create_transport_identity.py deploy/appliance/tools/render_transport.py deploy/appliance/tools/install_transport_client.py deploy/appliance/tools/install_transport_server.py deploy/appliance/tools/test_transport_client.py deploy/appliance/tools/test_live.py deploy/appliance/tools/render_proxy.py deploy/appliance/tools/assemble_private_evidence.py deploy/appliance/tools/probe_rdp.py deploy/appliance/tools/run_rdp_probe.py /opt/guacamole-portal/tools/
sudo install -o root -g root -m 0644 deploy/appliance/guacamole-portal.apparmor /etc/apparmor.d/guacamole-portal
sudo apparmor_parser -r /etc/apparmor.d/guacamole-portal
sudo install -o root -g root -m 0644 deploy/appliance/guacamole-portal.service deploy/appliance/guacamole-portal-network.service /etc/systemd/system/
```

The installed tool names and their sibling modules matter.
`network_service.py` unconditionally imports `network_upgrade.py`; install it
even for an initial network preparation, before any upgrade is contemplated.
`prepare_instance.py` and `cold_copy.py` must be together;
`migrate_legacy.py` imports both those tools and the parent host modules.
Transport installers require sibling `render_transport.py`. Install the live
browser helper before its operator driver uses SSH. Preserve a private source
hash census; the image runtime remains inside the immutable image, not copied
over by these host-source steps. Check the loaded profile is enforcing.

The host launcher permits a release-selected compatible AppArmor profile, but
the current migration and network smoke helpers explicitly use
`guacamole-portal`. Use the provided profile for this recipe. Those helpers
and the immutable image HTTP listener currently require internal port8080;
set `host_backend_port` to8080. Arbitrary alternate names/ports are not covered.

## Prepare external catalog, credentials and network

Create reviewed root-private catalog/network files in a protected staging
directory. Use [examples/config.json](examples/config.json) for schema only;
replace every synthetic value externally. The catalog contains the existing
personal portal username, permitted target aliases, literal IPv4 endpoints,
per-target RDP usernames, NLA mode, exact certificate pins and separate password
filenames. An inaccessible account is not accepted merely because its socket
and certificate work. Schema2 supports mixed RDP/SSH targets with pinned host
keys and separate external application keys. The legacy preparation helper below
is RDP-only; mixed secret preparation and SSH/tmux installation/acceptance require
their separately reviewed procedures.

For a gateway-local RDP tunnel, list that exact gateway/port tuple in both the
catalog and `local_endpoints`. Other target tuples use the declared forwarding
interface/SNAT. Set `trusted_proxy_ipv4` only to the one verified actual proxy
peer, if required; it is not a broad private-network trust list. Review the
derived policy before any firewall mutation.

The supported legacy secret helper requires `/etc/guacamole-portal` and
`/var/lib/guacamole-portal` both to be entirely absent. Run it before bootstrap
or the host launcher creates the state root:

```sh
sudo python3 -B /opt/guacamole-portal/tools/prepare_instance.py --config "$REVIEWED_CONFIG" --network "$REVIEWED_NETWORK" --config-directory /etc/guacamole-portal --state-directory /var/lib/guacamole-portal --legacy-secrets "$LEGACY_SECRETS" --reuse-legacy-rdp-for-all
```

Use the reuse flag only after confirming that every selected Windows account
uses that same existing password. This is not a generic distinct-credential
installer. If passwords differ, provision the root-private namespace and each
independent file through a separately reviewed secret transfer; never copy the
shared legacy password to unverified targets to make this command applicable.
Keep credentials out of command arguments, shell history, logs and manifests.

`db-password` must match the copied cluster, with runtime's documented
16..512-character validation. Each target credential is 1..512 UTF-8 bytes;
spaces are significant and embedded LF/CR/NUL are forbidden. The legacy helper
normalizes at most one trailing LF for Windows credentials and creates distinct
files. Do not generate `portal-password` or enroll another identity on migration.
Retain preparation intent/result and verify ready status before continuing.

Stage the exact four-key provisional release from
[NETWORK-SERVICE.md](NETWORK-SERVICE.md): schema1, dedicated `podman_network`,
and SHA256 of the exact installed catalog/network bytes. It authorizes network
preparation only; no acceptance-evidence placeholder is needed.

```sh
sudo python3 -B /opt/guacamole-portal/network.py plan --config /etc/guacamole-portal/network.json --catalog /etc/guacamole-portal/config.json
sudo python3 -B /opt/guacamole-portal/network_service.py prepare
sudo python3 -B /opt/guacamole-portal/network_service.py check
sudo systemctl daemon-reload
sudo systemctl start guacamole-portal-network.service
```

Preparation refuses collisions, creates the managed network definition before
the kernel bridge, sets only that bridge's `route_localnet=1`, then applies and
checks the owned firewall. It never flushes a shared chain or edits a previous
appliance guard. Retain bootstrap/firewall receipts. Same-boot bridge recreation
requires an exact live ready policy; cold-boot recreation requires matching
prior ready receipts and all owned policy objects absent. Drift or interrupted
state is an operator review, not a reset/retry instruction.

Run a normal finite attachment/publication fixture before data promotion:

```sh
sudo python3 -B /opt/guacamole-portal/tools/test_host_network.py --image "$IMAGE_ID" --port "$UNUSED_LAB_LOOPBACK_PORT" --directory "$NEW_NETWORK_CASE"
```

Require `passed`, actual HTTP reply and verified cleanup. Its normal mode must
work with bootstrap settings; the historical discriminating sysctl mode is
diagnosis, not the installation acceptance route. After its last-container
cleanup, the bridge may disappear; normal `network_service.py boot` must
recreate it under the documented checks, without manual sysctl repair.

## Optional restricted peer transport

This host-side transport carries explicitly pinned RDP or SSH endpoints; browser
SSH/tmux requires separate runtime acceptance. For a remote target, create the dedicated client identity with
`tools/create_transport_identity.py`. Its fixed `/etc/portal-rdp-transport`
directory must be absent. It prints only the public key; retain the private key
on that client host. Stage the exact public-only schema from
`tools/render_transport.py`, including pinned client/server/listen/target
addresses and ports, bare Ed25519 client public key and server host public key.

On the pinned SSH server, the reviewed `install_transport_server.py --config
"$PUBLIC_TRANSPORT_CONFIG" --record "$NEW_SERVER_TRANSPORT_CASE" --admin-user
"$EXISTING_ADMIN_USER"` checks the host key, syntax and unchanged administrative
policy, backs up sshd configuration, then installs the restricted account and
reloads SSH. It refuses existing transport state, accounts or unreviewed Match
blocks. Keep an independent administrative connection and that exact backup.

On the client, feed only the public JSON to `install_transport_client.py` on
stdin. It requires the existing private identity, checks its public key/local
address, installs the network-dependent unit and reloads systemd, but does not
start the tunnel. Start it explicitly after network preparation. Use
`test_transport_client.py --directory "$NEW_CLIENT_TRANSPORT_CASE"` to confirm
public-key authentication and shell denial; this test disables all forwards
and does not prove Windows reachability. The actual tunnel and both RDP desktop
tests remain separate requirements. Never expose the gateway-local listener
to unrelated interfaces or broaden the SSH account's PermitOpen/MaxSessions.

Schema1 remains the exact singleton format used by the original installers.
Schema2 replaces the four top-level `listen_address`, `listen_port`,
`target_address`, `target_port` fields with `forwards`, a list of one to eight
objects containing exactly those four fields. All remaining top-level fields
are unchanged. Listeners must share one private bridge address; duplicate
listeners/endpoints, unknown fields and invalid addresses/ports fail. For example,
external synthetic schema2 forwarding objects can be:

```json
[
  {"listen_address":"10.55.0.1","listen_port":10473,"target_address":"192.168.50.10","target_port":3389},
  {"listen_address":"10.55.0.1","listen_port":10475,"target_address":"192.168.50.1","target_port":22}
]
```

The existing installers refuse updates; use the separate reviewed
`upgrade_transport_server.py` and `upgrade_transport_client.py` path for an
existing installation. Install both upgrade scripts beside the existing
`install_transport_server.py`, `render_transport.py` and `prepare_instance.py`,
with root ownership and no group/other writes; the latter's parent still needs
`catalog.py` and `network.py`. Source tests are inert:

```sh
python3 -B -m unittest discover -s deploy/appliance -p test_transport.py -v
sudo python3 -B -m unittest discover -s deploy/appliance/tools -p test_upgrade_transport.py -v
```

Prepare on each host using root-private, single-link mode0600 original and new
public configuration files under protected ancestry. A strict extension must
retain every old forward, bridge, source/peer address, port and public identity.
The existing installed files must match the original renderer exactly. Server
account, host key, global SSH configuration and unchanged administrative policy
are bound; client private-key metadata, public key, known host and network unit
are retained. Private key bytes are never read. Each CLI has a60-second bound
and shares one nonblocking host lock.

```sh
sudo python3 -B /opt/guacamole-portal/tools/upgrade_transport_server.py prepare --old-config "$OLD_PUBLIC_CONFIG" --new-config "$NEW_PUBLIC_CONFIG" --directory "$NEW_SERVER_CASE" --admin-user "$EXISTING_ADMIN_USER"
sudo python3 -B /opt/guacamole-portal/tools/upgrade_transport_client.py prepare --old-config "$OLD_PUBLIC_CONFIG" --new-config "$NEW_PUBLIC_CONFIG" --directory "$NEW_CLIENT_CASE"
```

Preparation creates new case files, exact candidate and original backups, and
`plan.json`; it changes no installed configuration. Review the complete diff,
original state, exact plan SHA256 and server syntax/effective policy before
apply. Keep an independent administrative connection. The operator separately
closes portal access, clears active sessions, stops the client transport through
its existing controller, and inhibits restarts. Restarting it interrupts every
forward on that connection, including the existing RDP endpoint.

For each host, supply a root-private external maintenance-review JSON containing
exactly `schema`1, `role` (`server` or `client`), `plan_sha256`, a nonempty ASCII
`deployment_reference` without whitespace, `portal_closed`:true,
`sessions_cleared`:true, and numeric UTC Unix `reviewed_at`/`expires_at` values.
It must be currently valid and span at most300seconds. These fields are explicit
operator attestations; the tool does not itself establish portal/session state.
Never manufacture a receipt from unobserved state. The client additionally
requires the existing loaded transport unit inactive with MainPID0.

```sh
sudo python3 -B /opt/guacamole-portal/tools/upgrade_transport_server.py apply --directory "$NEW_SERVER_CASE" --reviewed-plan-sha256 "$SERVER_PLAN_SHA256" --maintenance-review "$SERVER_MAINTENANCE_REVIEW"
sudo python3 -B /opt/guacamole-portal/tools/upgrade_transport_client.py apply --directory "$NEW_CLIENT_CASE" --reviewed-plan-sha256 "$CLIENT_PLAN_SHA256" --maintenance-review "$CLIENT_MAINTENANCE_REVIEW"
```

Apply rechecks original state, reviewed candidates/backups, administrative policy
and maintenance attestation. Attestation freshness is checked immediately before
each file mutation and final success; expiry after partial installation produces
a failed result and refuses replay. Apply atomically replaces each exact owned file with
its preserved owner/mode and fsyncs it. A durable once-only intent precedes host
replacement. Server files form a two-file update; failure may leave a partial
installed set, so keep access closed and preserve the case. Unknown/failed cases
are never replayed or automatically rolled back. Retain exact backups and review
any manual recovery independently. Neither wrapper reloads sshd/systemd, starts,
stops or restarts a service. Activation, pinned transport authentication,
endpoint acceptance and reopening the portal are separately reviewed maintenance
steps after both installed results are verified. File installation alone proves
neither loaded policy nor end-to-end SSH/tmux readiness.

## Backup legacy, independently restore, migrate and admit

Follow [MIGRATION.md](MIGRATION.md) for exact prerequisites and refusal behavior.
First observe existing Windows sessions, close old access through its reviewed
controller, stop its writers and automatic restarts, and preserve its original
data, secrets, image and proxy configuration. Do not kill an active desktop
blindly or remove `postmaster.pid` to manufacture a stopped state.

```sh
sudo python3 -B /opt/guacamole-portal/tools/cold_copy.py backup --source "$LEGACY_DATA" --service "$LEGACY_SERVICE" --container "$LEGACY_CONTAINER" --legacy-container-id "$LEGACY_CID" --directory "$NEW_BACKUP_CASE"
sudo python3 -B /opt/guacamole-portal/tools/cold_copy.py restore --backup "$NEW_BACKUP_CASE" --directory "$NEW_REHEARSAL_CASE" --for-migration
sudo python3 -B /opt/guacamole-portal/tools/migrate_legacy.py --image "$IMAGE_ID" --data "$NEW_REHEARSAL_DATA" --directory "$NEW_REHEARSAL_MIGRATION_CASE" --original-alias "$ORIGINAL_ALIAS"
```

`NEW_REHEARSAL_DATA` is the restored case's `data` directory. Verify the original
backup manifest and completed restore, preserved identity/TOTP/account census,
enrolled state, current alias census, immutable image and owned migration
cleanup. Migration runs network-disabled and publishes nothing. A failed SQL
target is evidence: start any further rehearsal from another independent
restore of the untouched backup, never from that failed destination.

For fixed-path promotion, restore again independently with `--for-migration`
and `--data-target /var/lib/guacamole-portal/data`; that target must be absent.
Run the same accepted migration against the resulting fixed data path with a
new migration case. Do not move a tested writable rehearsal into production
and call that an independent promotion restore. Do not recursively rewrite
ownership or manually manufacture `prepared.json`.

Replace the provisional release with the exact full schema in
[HOST-CONTRACT.md](HOST-CONTRACT.md), retaining its four network binding values.
Bind the exact local immutable image, installed catalog/network, enforcing
profile source, loopback backend port and a real protected acceptance evidence
file by SHA256. `assemble_private_evidence.py` can bind the documented private
primary receipts but explicitly leaves public, actual Windows NLA and SSH/tmux
admission pending. It cannot turn a failed desktop into acceptance. The host
checks file/hash bindings; the operator is responsible for the evidence scope.

Start the admitted service only after those reviewed inputs and prepared data
exist:

```sh
sudo systemctl start guacamole-portal.service
```

The launcher reruns network bootstrap before empty-bridge guards on each
application start, checks the exact image/mount/config/profile bindings, waits
for enrolled native health and the mandatory startup gate, then publishes its
own readiness marker. Never touch/create that marker manually. Loss of health
closes access and reconciles only the identified owned container.

## Private acceptance, proxy and public cutover

Use [LIVE-ACCEPTANCE.md](LIVE-ACCEPTANCE.md) for an explicit private operator
tunnel, fresh browser profile, existing native TOTP, selector/alias checks,
every Windows NLA desktop, reload, native logout and private sanitized evidence.
Respect the owner's existing sessions. Credential-free `probe_rdp.py` confirms
TCP/NLA negotiation and the TLS pin only; it does not authenticate a Windows
account or establish rendered-desktop acceptance.

Render proxy material with `tools/render_proxy.py --catalog
/etc/guacamole-portal/config.json --port "$BACKEND_LOOPBACK_PORT" --out
"$NEW_PROXY_STAGE"`. It writes `portal.conf` for the existing HTTPS server and
`rate-limit.conf` for nginx's HTTP scope. Review both and preserve the existing
server configuration before installation. The readiness gate must cover every
product route. The entire native `api/tokens` endpoint, including refresh, must
use the generated 6 requests/minute, burst10 limit. Preserve WebSocket/streamed
HTTP, cookie path, explicit alias behavior and unknown-alias404 semantics.
Validate nginx syntax before its reviewed reload; no RDP or guacd public port
is part of this change.

Every generated portal UI/authentication location explicitly sends CSP `frame-ancestors 'none'`,
`X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, no-store and
no-referrer, including redirects and errors. Verify effective response headers
and top-level native login rendering; a configuration-text check alone is not
a framing test. The exact static empty native resize document
`/desktop/app/app/element/templates/blank.html` alone uses `frame-ancestors 'self'`
and `SAMEORIGIN`, with GET/HEAD only and the same ready/no-store/nosniff guards.
Native Guacamole embeds that script-free, data-free document as an object;
blocking it can prevent resize callbacks and refreshed client connections.
No prefix, portal page, API response or client UI receives that exception.
Nginx location-level `add_header` replaces ordinary inherited
server/http headers: repeat any additional reviewed site policy, such as HSTS,
in those locations rather than assuming parent inheritance. The renderer does
not enable a host-wide HSTS or subdomain policy implicitly.

Use [PUBLIC-CUTOVER.md](PUBLIC-CUTOVER.md) for the reviewed staged
`tools/public_cutover.py` interface. Its source-level boundary tests do not
establish a live switch. Keep old public routing until actual browser evidence
passes for every intended RDP desktop, and operate within the owner's existing
deployment authorization. Publishing a repository, release or image requires
the separate owner acceptance specified for this private development stage.
After a reviewed switch, run the separate public HTTPS browser case through
nginx without bypassing its gate/rate limit. Preserve rollback until acceptance.

Enable the accepted units for boot only after their dependency graph and
restoration checks have passed. Each deployment's clean-host/full-reboot
acceptance must demonstrate profile loading, network/transport/app ordering, receipt recovery,
absence of unintended listeners, both real desktops, public readiness and
rollback. Record actual outcomes; enabling units is not that test.

## Upgrade and rollback

An image-only upgrade requires a new immutable build and the same relevant
fixture, restore, migration, native-auth and desktop checks. Close access,
inspect active sessions, stop the portal through systemd and confirm the
launcher cutoff completed for its exact old CID before replacing source or
release files. Preserve the old release/source/profile/proxy bytes, image,
secrets and an independently usable data backup. Install matching reviewed
source/units, reload systemd, stage reviewed hashes, start and repeat private
and public acceptance under the same authorization boundary.

Do not retarget the existing ready network receipt to another bridge, subnet,
catalog policy or port. Use [NETWORK-UPGRADE.md](NETWORK-UPGRADE.md) only for its
supported additive change with both genuine fixed app/transport services
loaded and stopped. A finite private transport fixture without that service
cannot use this controller; never create a dummy service or fabricate its plan.
For a separately reviewed fresh installation, stop all consumers, retain an
independent cold backup and the matching original selection, remove only the
exact owned old network/firewall objects as described below, and archive its
original receipts without editing them. Prepare the genuinely fresh network
with the new catalog/network bytes and provisional release, then select the
independently restored/migrated DATA, matching secrets and full release. This
manual boundary is not an additive-controller or promotion receipt. A catalog change also changes
the prepared data binding and requires an explicit accepted data migration;
restart is not a migration. PostgreSQL major upgrades are outside this recipe.

For a failed new installation, close its access and stop/cut off its exact
owned container. Reestablish the untouched old image/config/secrets/proxy on
its original legacy tree, or an independent exact legacy restore without
`--for-migration`. Verify existing TOTP and the original desktop before reopening.
Never run the old runtime on migrated data. For an in-place current-runtime
upgrade, restoring only the old image is safe only when the data format and
all bindings remain proven compatible; otherwise restore the complete matched
pre-upgrade set to a new target. No helper automatically decides this rollback.

## Current-format stopped backup and independent restore

For one reviewed maintenance window on the existing admitted installation,
see [CURRENT-BACKUP-WINDOW.md](CURRENT-BACKUP-WINDOW.md). Its separate staged
controller closes only the owned route, checks native session clearance, stops
the actual current service for a genuine cold backup and restores the unchanged
service. Stage/source tests do not authorize or prove an actual production run.

`cold_copy.py` accepts the current catalog `prepared.json` as well as the known
legacy singleton receipt. Current format requires exactly `schema`1,
`postgres_major`16, `guacamole`1.6.0, lowercase `config_sha256` and `connections`.
The mapping must contain one to32 valid catalog aliases and distinct positive
PostgreSQL integer IDs. The receipt must be root-owned, mode0600, regular,
single-link and at most16384bytes. Unknown formats and duplicate keys fail.

Close access, stop the exact service/container and every other data writer,
and inhibit automatic restarts externally. Record the exact immutable container
ID before stopping. The existing CLI option name `--legacy-container-id` also
pins a stopped current installation; all service/container/mount census,
ownership, complete manifest, deadline and no-overwrite checks still apply.
The helper never stops services or starts a database. Do not remove a PID file
to bypass its stopped-cluster check.

```sh
sudo python3 -B /opt/guacamole-portal/tools/cold_copy.py backup --source "$CURRENT_DATA" --service "$CURRENT_SERVICE" --container "$CURRENT_CONTAINER" --legacy-container-id "$CURRENT_CID" --directory "$NEW_CURRENT_BACKUP_CASE"
sudo python3 -B /opt/guacamole-portal/tools/cold_copy.py restore --backup "$NEW_CURRENT_BACKUP_CASE" --directory "$NEW_CURRENT_RESTORE_CASE"
```

An optional `--data-target` must name an independent absent destination.
Current restore retains the exact prepared receipt bytes and ownership.
`--for-migration` is legacy-only: a current backup is rejected before creating
a restore case or target. Never strip or recast the current receipt. Include
the matching catalog/release/profile/source/image identities, secrets and,
if needed, transport private identity as separate protected backup material.
Database backup contains TOTP and is secret. Do not print SQL, credentials,
individual TOTP derivatives or clipboard/desktop contents. Copying a live
`pgdata` directory is not a consistent backup.

Restore must independently verify that complete backup to a new empty target,
preserve exact preparation/config/secret bindings, start only one writer,
verify native existing TOTP and every intended desktop, and retain the source
backup untouched. Firewall/bootstrap receipts describe their original host;
never clone them to another host to claim ownership of its live objects. A
different-host network installation requires fresh reviewed preparation and
acceptance. Inert source tests verify physical copy and receipt boundaries;
fresh exact-image restore, native existing TOTP and target acceptance remain
required operational gates before claiming complete current recovery.

## Removal while preserving unrelated host services

Removal has no supported automatic firewall transaction. First close only this
portal's proxy routes and observe active sessions. Stop/disable its portal
unit, reconcile its exact CID with `host.py cutoff`, then stop/disable its RDP
transport if exclusively owned. Keep data, secrets, images, all receipts and
the independently verified backup until the owner explicitly retires them.
Stopping the oneshot deliberately leaves its guard and definition in place.

Before removing any network object, verify the immutable network ID, ownership
labels/receipt, exact bridge alias/address, absence of all Podman consumers and
attached peers, and the complete owned firewall/jump census. Do not flush a
shared INPUT/FORWARD/POSTROUTING chain, restore a whole firewall snapshot, delete
another appliance's guard, or change global `all`/`default` sysctls. Exact
owned jumps/chains/table and their receipts require a separately reviewed
ordered removal plan; do not improvise broad commands from this document.

Remove units/source/AppArmor profile only after no running owned process needs
them. Remove a tunnel server account/key/sshd Include only after verifying its
dedicated ownership and preserving administrative syntax/effective policy;
the installer has no uninstall API. Do not blindly restore a whole historical
sshd backup over later administrative changes. Review nginx and SSH syntax
before their reloads and verify unrelated services after cleanup. Source and
unit removal, credential destruction and evidence retirement are distinct
operator-authorized steps, not recursive directory deletion by an installer.

## Completion evidence still required

The bounded independent host lifecycle has passed with pre-enrolled synthetic
DATA: installed native authentication, stopped backup/independent restore,
matched rollback, reboot/recovery and exact owned removal while unrelated
services remain intact. Documented-command and missing-module defects found
in its frozen instructions were recorded and corrected. Prerequisite host
pinning was supplied externally; this is not a general host bootstrap installer.

The separate same-image actual Windows browser run passes over private
loopback, with its own deployment proofs and cleanup. Exact-image SSH/tmux and
same-image/cross-version restore fixtures remain separate evidence. The full
fresh-agent integrated public-transfer rehearsal, new-image production HTTPS
acceptance and wrong-certificate rejection are not complete. Generic fresh-user
enrollment and automatic network removal remain unsupported. The reviewed
manual removal used in the independent rehearsal is not a new uninstall API.
