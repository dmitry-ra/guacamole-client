# Portable personal portal appliance

This downstream fork builds one deployable image with the Guacamole web
application, guacd and PostgreSQL. Runtime data and credentials remain external.
Current development uses actual Apache main source and current Java LTS25.
Recorded acceptance below identifies a private baseline, not every future
source revision. New builds and changed migration paths require their own
exact source/image receipts; private evidence remains outside this tree.
It does not target an Apache contribution or old Java compatibility.

The earlier private preparation build was accepted with two actual Windows
desktops, SSH/tmux, native target selection and TOTP, plus independent stopped
backup/restore and migration. Those results describe that exact former image.
They do not accept this new main-based image. The current source build passes
the selected eleven-module Maven reactor and 58 Java tests on Temurin25.0.5;
native Angular portal selection also passes initial and continuation fixtures.
The current selected candidate also passes packaged HTTP/native TOTP and real
Angular browser checks, including initial login, chooser/direct links, invalid
links, saved-token reload and desktop/mobile/narrow login layout. Its isolated
native SSH/tmux checks pass correct-key access, wrong-key/host-key and forbidden
command denial, reconnect and retained process/counter continuity. Independent
same-image mixed backup/restore and old-image-to-current-image restore both pass
identity/TOTP/catalog preservation and restored browser SSH checks.

Full synthetic TLS two-target RDP and independent-target-failure acceptance also
pass: both native clients render distinct markers, beta failure leaves alpha
connected, and own logout, health and cleanup succeed. Earlier failures came
from retained backend-EOF slots in the test HTTP relay; correcting that fixture
required no product or image change. Diagnostic marker trials remain separate.
An independent clean-host rehearsal of this same image also passes genuine
installation, native TOTP/browser checks, stopped backup/independent restore,
matched rollback, real reboot and owned removal while preserving unrelated
services. That rehearsal used pre-enrolled synthetic DATA and documentation
endpoints; it did not exercise target desktop or SSH sessions.

A separate operator-run fresh installation of the same image passes both
actual Windows NLA desktops through the unmodified native browser driver:
CONNECTED/status0, nonblack canvases, concurrent clients under the same native
token, twenty-second stability holds, authenticated refresh and logout204.
Read-only WTS observations show the expected Windows sessions Active during
the holds and Disconnected afterwards. Browser/profile and finite tunnel
cleanup pass. A subsequent integrated run on that same clean VM passes both
actual Windows targets and a dedicated external synthetic SSH/tmux endpoint,
including reconnect, real portal reboot, stopped independent restore, matched
rollback and exact owned removal. The external tmux/counter process identities
remain unchanged across portal lifecycle operations. A separate intentional
first-route failure leaves the selected second desktop usable through refresh.
Matched native certificate controls also pass: changing only the pin rejects
the connection with the pinned certificate-not-trusted diagnostic; the correct
pin renders. Owned temporary diagnostic processes and all leases are removed.
These results accept the pre-enrolled, manually provisioned private lifecycle;
they do not implement fresh-user enrollment or a general host installer.
Published-main rebuild and new-image production HTTPS acceptance are separate
remaining actions; no former production receipt is relabeled.

Read RUNTIME-CONTRACT.md, NETWORK-CONTRACT.md, NETWORK-SERVICE.md and
HOST-CONTRACT.md for current interfaces. Developer fixtures and commands are
indexed in tools/README.md. Root configuration, credentials and actual evidence
are never part of this source tree. The optional trusted_proxy_ipv4 accepts one
exact proxy peer; forwarded client addresses are otherwise not trusted.

See [INSTALL.md](INSTALL.md) for external installation, upgrade, backup,
restore, rollback and removal steps, including the supported pre-enrolled DATA
route and the remaining capability and integrated acceptance limits.

Client baseline: Apache main a8daafeb38b60b0acb4059c5218e6d5bacfaeb8f.
Server baseline: Apache main bb1ba8ed1414ec6a239cea265d4e9c7e23b9c6a3.
These are selected, recorded commits, not moving refs during a build. The
upstream development version currently reports 1.6.1. No released 1.6.0 WAR,
binary dependency replacement or historical FreeRDP backport is consumed by
the new build. The existing deployment supplies behavior to preserve.

Public source transfer, fresh published-main builds and production HTTPS
acceptance each require their separate exact receipts. The documented installation
route uses independently restored pre-enrolled DATA, preserving existing TOTP;
generic fresh-user enrollment is not implemented. The integrated private run
uses a synthetic external SSH target and reviewed manual network replacement,
selection and removal; separate protocol fixtures retain their own scopes.

The catalog accepts one portal identity and one to 32 explicit targets. Schema1
is RDP-only; schema2 supports mixed RDP and SSH. Endpoints are literal IPv4
addresses. Each RDP target requires an exact SHA256 certificate fingerprint and
its own external password-file reference. Each SSH target requires a pinned
host public key and a separate external Ed25519 private-key file reference.
Unknown fields, duplicate JSON keys and invalid references are rejected. The
samples contain documentation-only addresses and synthetic trust material.
They hide target names before authentication by default. Set
`publish_target_labels` only when explicitly accepting a prelogin chooser;
authenticated clients still receive their authorized catalog after native TOTP.
This is disclosure reduction, not target authorization: direct aliases may be
guessed, and the supported portal has one identity authorized for its catalog.
Distinct Windows/SSH credentials do not create separate portal login identities.

```sh
chmod go-w deploy/appliance/examples/config.json
python3 deploy/appliance/catalog.py deploy/appliance/examples/config.json
python3 -m unittest discover -s deploy/appliance -p 'test_*.py' -v
```

These commands validate the source contract only; they do not create a live
portal or replace the packaged image and protocol acceptance gates.

Current-main source build (local preparation):

```sh
python3 deploy/appliance/tools/fetch_source_inputs.py --inputs /path/to/public-input-cache
python3 deploy/appliance/tools/source_build.py --help
python3 deploy/appliance/tools/build_image.py verify --client-build /path/to/successful-source-build --inputs /path/to/public-input-cache --work /path/to/new-private-build
sudo python3 deploy/appliance/tools/build_image.py build --client-build /path/to/successful-source-build --inputs /path/to/public-input-cache --work /path/to/new-private-build --tag localhost/private-portal:development
```

The input cache is checked against `source-inputs-lock.json`, including pinned
server source, Temurin25, Tomcat, PostgreSQL driver and bootstrap CA. Tomcat's
release signature remains verified. Git source archives are identified by their
selected commit and archive hash; they are not misrepresented as ASF-signed
releases. Offline image verification makes no network requests. Source Maven
builds resolve dependencies normally and record the exact resulting artifacts.
The image uses a pinned local Ubuntu base (`--pull=never`) and dated HTTPS
Ubuntu packages. It compiles current guacd with RDP and SSH, and packages the
receipt-bound source-built client WAR and authentication modules. Native and
downstream source snapshots have separate hashes; downstream tool changes do
not silently substitute a different native client. Native compile uses two
workers; image stages run sequentially. Java25 portal compilation and its
harness must pass inside the image build.
The root-owned runtime integrity manifest covers runtime modules, SQL, extension
JARs and source/dependency provenance. All credentials and endpoints remain
external. A built image alone is not end-to-end or migration acceptance.


Catalog schema2 supports mixed RDP/SSH; schema1 remains RDP-only. The synthetic
examples/config-ssh.json contains two RDP records and one pinned SSH target.
Existing RDP IDs/default and TOTP must survive the independently restored
upgrade rehearsal. Prepared DATA's historical Guacamole1.6.0 field identifies
the unchanged PostgreSQL schema, not the new running binary version. Exact
client/server/JDK identities are in source and image provenance.
