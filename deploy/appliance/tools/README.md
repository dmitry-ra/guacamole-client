# Appliance developer tools

- test_clipboard_images.cjs: exercises the actual Angular clipboard service,
  ManagedClient and focused-client directive against controlled browser and
  transport boundaries. PNG preference/bytes, text/permission fallback,
  asynchronous upload/key ordering, finite ACK failure, direct paste and client
  replacement cleanup are checked. Run `node tools/test_clipboard_images.cjs`.
  This does not establish real browser permission or Windows clipboard behavior.

- ../native/clipboard-image.c, patch_server.py and test-clipboard-image.c:
  explicitly identified downstream addition to the locked guacd source. PNG
  input is converted into a top-down 24-bit Windows CF_DIB with alpha composited
  on white. Header dimensions, decoded allocation and output size are bounded
  by the configured clipboard limit. The native image build runs malformed,
  truncated, large-IHDR and known-pixel controls under AddressSanitizer and
  UndefinedBehaviorSanitizer, then compiles the patched RDP library. The patch
  adds PNG-only chunk ACKs/overflow refusal required by BlobWriter. Source
  transformations require exact original contexts and fail on upstream drift.
  Text behavior is preserved; remote-to-local image clipboard and other rich
  clipboard formats are outside this change. The builder target is compile/test
  evidence only and contains no accepted web application.

- source_build.py and test_source_build.py: freeze the selected checkout's
  actual native source and build its WAR, PostgreSQL JDBC/TOTP/ban extensions
  and complete SQL schema with checksum-pinned Maven3.9.12 and JDK25. Native
  Maven/RAT source is separate from independently hashed downstream deploy/
  and AGENTS.md files; no analyzer is disabled. New external work directory,
  finite process-group deadline, one Maven worker, exact source/artifact hashes
  and success-only provenance status. Source build is not image, migration,
  browser or production acceptance; Maven repositories and network remain build
  inputs, and byte-identical repeated-build reproducibility is not established.

- install_terminal_target.py and test_install_terminal_target.py: staged exact-
  plan installation for an existing reviewed Unix account. Preserve and back up
  all authorized_keys bytes/metadata, install fixed root-owned renderer/config
  and dedicated user0700 socket directory, then append one source-restricted
  forced-command public key last. No private key, account/global sshd changes,
  authentication, tmux/service activation or replay. See ../TERMINAL-INSTALL.md
  for explicit manual known-unused/hash-matched rollback and trust limits.

- upgrade_network.py and test_upgrade_network.py: separate reviewed one-time
  additive gateway-local SSH firewall upgrade and explicit known-state rollback.
  Exact old/new source/config/receipt/boot bindings, fresh closed-session review,
  inactive units/empty owned bridge, atomic owned nft replacement and precise
  iptables insert/inverse operations preserve unrelated rules. Never changes
  services, resource definitions, config selection or DATA. Historical proof
  validation lives in ../network_upgrade.py with narrow bootstrap hooks; see
  ../NETWORK-UPGRADE.md. Inert tests do not establish live kernel acceptance.

- terminal_launcher.py and test_terminal_launcher.py: pure fixed-command SSH
  launcher renderer. Requires exact original command, clean environment/shell,
  explicit private tmux socket/config/session; never installs keys/accounts or
  touches existing tmux servers. Operator must protect files/socket parent and
  review account startup and disconnect cleanup policy before activation.
- prepare_terminal_key.py: root-only one-time external Ed25519 application-key
  preparation under a protected private secret directory. New paths and case,
  durable intent, bounded noninteractive ssh-keygen, exact private metadata and
  public/private pair check; outputs only public-key identity metadata. Does
  not add authorized keys, create an account, authenticate or activate access.

- probe_nginx_reload.py: finite isolated loopback nginx reload/status visibility
  fixture in a new private directory and unused laboratory port. Own process
  cleanup and status/timing receipts; no production nginx service or config
  changes, portal authentication or Windows access.

- update_target_secret.py and test_update_target_secret.py: root-only stopped-
  candidate replacement of one connection-specific mounted secret from bounded
  stdin. Exact config SHA/alias/username, host lock, inactive service and no owned
  container required; new durable intent, private prior-secret backup and atomic
  owner/mode-preserving replacement. No authentication or service start.
  See ../LOGIN-PROBE.md; inert tests exercise stale mapping and stdin boundaries.

- probe_login.py, run_login_probe.py and test_probe_login.py: explicit one-attempt
  empty-domain RDP login diagnostic through the exact running image guacd.
  Catalog username/NLA/endpoint/pin preserved; mounted target password stays in
  memory. New fsynced intent before dispatch, exact CID/image guard, no replay
  or reconnect, numeric status/display counts only. See ../LOGIN-PROBE.md.
  Inert tests cover protocol bounds, unchanged target parameters and durable
  intent/refusal; no Windows authentication during source tests.

- public_cutover.py and test_public_cutover.py: staged reversible RDP route
  transition with exact reviewed evidence, native session clearance, fresh
  replay holds, bounded no-auth GET convergence after reload, durable safe
  failure/rollback diagnostics, separate public browser acceptance and retained rollback.
  See ../PUBLIC-CUTOVER.md. A failed or proof-less browser result cannot stage
  a switch; the tool never changes Windows credentials or publishes a repository.

- probe_rdp.py and run_rdp_probe.py: finite credential-free TCP/X224 NLA negotiation and SHA256-pinned
  TLS check, run as guacd UID2002 inside an exact selected container. Source
  address and endpoint labels/IPv4/ports/pins are explicit external arguments.
  At most eight endpoints, one absolute per-endpoint deadline and a whole-run
  alarm; no CredSSP, credentials, desktop authentication or configuration writes.
  JSON reports each completed transport phase; failures exit nonzero.
  The runner streams the source into a full immutable existing CID through a
  fresh nonmultiplexed SSH connection, as UID2002, and preserves private evidence
  in a new explicit directory. No container or host configuration is changed.

- assemble_private_evidence.py: bind reviewed primary receipt hashes for private
  restored rehearsal only. Explicitly leaves public, Windows NLA and SSH/tmux
  admission pending; never creates a publication marker or changes a service.

- migrate_legacy.py: exact-image migration of an independently restored stopped
  PG16 tree, network disabled. Checks the full identity/TOTP/account-row digest
  before/after, enrolled state and final catalog census; removes its exact own
  container. Failed targets are retained and never retried as source backups.
- migrate_current.py: separate single-use SSH catalog append or isolated
  true-to-false prelogin-label transition of
  an independently normal-restored CURRENT tree. Preserves intact prior receipt,
  every existing RDP ID/parameter and account/TOTP rows; exact-image/source/
  restore binding, network-none isolation and verified owned cleanup. No live
  source, legacy receipt stripping, authentication or service changes. Isolated
  label privacy may archive only a verified completed historical SSH-append
  journal on the independent restored copy: exact four-file/intent/result/
  prior-current preparation binding, whole restore revalidation, durable
  single-use archival intent and atomic no-replace rename preserve all bytes
  and receipt hashes. Failed/incomplete/mismatched history and archive replay
  refuse. The native runtime module is unchanged. See
  ../MIGRATION.md; actual PostgreSQL/SSH acceptance remains an operator gate.
- test_current_cid.py and reconcile_current_cleanup.py: root-private case CID
  metadata checks accept Podman's nonsecret root0644 CID file while rejecting
  writable, foreign, linked or malformed files. Explicit single-use cleanup
  reconciliation binds a failed receipt and exact container ownership; it
  preserves that failed receipt and never accepts or replays the migration.
  test_reconcile_current_cleanup.py adds inert exact-ownership/PID, absence,
  replay, receipt-drift and original-error-preservation adversarial boundaries;
  all engine calls are mocked and only synthetic root /run files are used.
- test_current_image.py: root-only synthetic PG16 native append-transaction
  fixture in an exact local image. Prepares a new enrolled two-target cluster,
  shuts down and removes its exact producer, independently copies and hashes
  the complete cluster, migrates only the copy, and checks original bytes,
  preserved identity/TOTP, IDs and archived receipt. Uses network-none owned
  containers; keeps synthetic evidence/data outside Git. This is not the host
  migration-wrapper or production backup/restore acceptance. Create/use with
  `sudo python3 tools/test_current_image.py --image EXACT_SHA256 --directory NEW_ABSOLUTE_CASE`;
  no host configuration is changed, containers are removed by exact ownership,
  and retained synthetic case removal requires an explicit cleanup decision.
  `--mode hide-labels` instead uses an already mixed synthetic catalog and
  verifies label-only migration preserves the complete census, identity/TOTP,
  mapping and actual connection sequence state. Default remains append-ssh;
  each mode needs a new private case and the exact image containing its module.
- test_current_image_cleanup.py: inert uncertain-dispatch cleanup regressions,
  including absent CID files, wrong ownership and engine errors; original
  dispatch exceptions remain primary. No engine or native database calls.
- test_current_privacy_history.py: root-only real PG append then genuine normal
  stopped backup/independent restore and host-wrapper label-privacy regression.
  Requires an already installed inactive appliance service and loaded enforcing
  profile; never installs/alters them. Creates exact-owned network-none producers
  and a real stopped source-mount consumer for backup provenance, removes only
  those containers, retains original/backup/history bytes and checks actual
  restored census/identity/sequence. Use `--image EXACT_SHA256 --directory NEW_CASE
  --backup-service guacamole-portal.service --apparmor-profile LOADED_PROFILE`;
  retain evidence; case removal needs separate cleanup authority. No target
  authentication, live DATA, public route or production promotion claim.
- ../current_migration.py, ../test_current_migration.py and test_migrate_current.py:
  protocol-aware transaction guards, complete old/new census, old-receipt
  archive and finalize-after-verification, plus inert replay/identity/drift/
  cleanup and original-error-preservation tests. No actual PostgreSQL or host
  engine execution during these unit tests.
- test_migrate_legacy.py: mocked migration-controller boundary tests for exact
  container ownership, verified cleanup, terminal failure receipts and original
  error preservation. No engine, database or instance access occurs.
- close_current_for_upgrade.py and test_close_current_for_upgrade.py: reuse a
  fresh B window plan to close the exact route, persist native post503 census,
  stop only the current portal then its transport once, and leave original
  DATA/selection untouched. Separate reviewed pre-promotion fixed-original
  recovery starts the guarded app first, verifies fresh65s readiness, then
  fresh original transport and opens last; no mixed activation or automatic
  retry/recovery. Read-only reconciliation reports actual partial states.
  See ../CURRENT-UPGRADE-CLOSE.md; inert tests perform no host operations.

- current_backup_window.py and test_current_backup_window.py: staged once-only
  current-service cold backup window, exact installed/staged source and live
  deployment bindings, native sessions before/after bounded503 closure, genuine
  stopped-service/pinned-CID cold_copy dispatch and full manifest verification.
  Restores only the unchanged original service/DATA and snippet after fresh65s
  readiness/native health, with one empty challenge and no429 retry. Preserves
  primary errors, partial cases, transport and legacy state; read-only reconcile,
  no uncertain lifecycle replay or archive rollback. Tests mock all process,
  engine and HTTP activity. See ../CURRENT-BACKUP-WINDOW.md; actual review and
  production/independent restore acceptance remain separate gates.
- prepare_instance.py and cold_copy.py: new external instance files and opaque
  stopped/exclusive PG16 backup and independent restore with complete file
  manifests. Accept only known legacy or current catalog preparation receipts;
  current receipt bytes/ownership remain intact and --for-migration is legacy
  only. See ../MIGRATION.md for legacy and ../INSTALL.md for current recovery.
- test_migration_tools.py: inert synthetic filesystem and mocked service/engine
  boundaries, including both receipt formats, strict current mapping bounds,
  exact current restore and pre-copy rejection of current migration staging.
- test_live_telemetry.py: inert adversarial privacy and selected-client error
  boundaries for passive browser diagnostics; no browser, network or credentials.
- test_live.py: operator-invoked own-browser private/public Windows acceptance;
  root-only OTP helper derives a code inside the exact verified container.
  Separate root-only deployment proofs bind the ready CID/run/image and
  admitted release/config/network before and after the observed browser base.
  See ../LIVE-ACCEPTANCE.md; no key/code/token or desktop screenshots are saved.
  Optional --ssh-alias adds one expected catalog/selector entry while continuing
  to test only the two Windows desktops. It explicitly does not accept SSH.
- test_live_receipts.py: offline boundaries for exact before/after deployment
  identity, concurrent run/config changes, helper proof output and unexpected
  browser origins/paths. No browser, engine, SSH or authentication is invoked.

- test_host_network.py: finite owned-container check of the already installed
  bridge, AppArmor profile, loopback backend mapping and exact live firewall
  after real Podman attachment. No data/secrets mounted; verifies own cleanup.

- ../host.py: root-owned admitted appliance lifecycle and readiness supervisor;
  see HOST-CONTRACT.md. Never installs or migrates data by itself.
- ../network_service.py: explicit owned network/bridge bootstrap and conservative
  ordinary-boot verification; see NETWORK-SERVICE.md. No shared-rule flushing.

- test_transport_client.py: bounded real public-key authentication using the
  installed pinned client configuration, with all forwards disabled. Verifies
  that a harmless shell command is rejected by MaxSessions0; private intent,
  SSH diagnostics and receipt. Does not create a listener or contact Windows.

- install_transport_client.py: consume public-only JSON on stdin, verify the
  existing root-private identity/local address, install new pinned client files
  and a supervised unit requiring the product network service. Daemon reload
  only; never starts the tunnel and refuses any existing installation.

- upgrade_transport_server.py and upgrade_transport_client.py: separate root-only
  prepare/review/apply path for additive schema2 forwarding. Bind original files,
  account/key/peer/bridge and immutable plan hashes; retain private backups,
  validate sshd syntax/effective policy and client parse, require fresh external
  closed-portal/session-clearance review, and refuse replay or state drift.
  Client apply requires its exact transport unit already inactive. Neither tool
  activates, reloads or restarts a service. See ../INSTALL.md restricted transport.
- test_upgrade_transport.py: inert mocked-process and synthetic root filesystem
  tests for retained identity, exact original/candidate bindings, maintenance
  review, active-client refusal, partial failures, replay and effective SSH policy.

- export_image.py: rootful export of an exact local image to a new private OCI
  archive, bounded600seconds, with intent and SHA256/size receipt. No instance
  data, network transfer or destination loading; do not repeat an existing case.

- test_rdp.py: finite actual two-target synthetic TLS RDP/browser acceptance
  using a network-disabled image and exact Unix/namespace relays. See
  RDP-ACCEPTANCE.md; correct certificate pins, distinct canvases and independent
  target failure are checked. Windows NLA and wrong-pin denial remain separate.
  The optional --markers-only flag is a separate finite A/B diagnostic: both
  unchanged pixel thresholds, own logout/health and cleanup remain, but beta is
  never stopped and the receipt always retains passed=false. Only
  diagnostic_complete=true can indicate successful diagnostic completion; it
  is not full RDP or independent-failure acceptance. Last per-alias state,
  status, geometry and numeric marker counts are saved before threshold
  assertions, without desktop content. test_rdp_telemetry.py checks privacy,
  rejected values and diagnostic-mode propagation/admission boundaries.

  `python3 -m unittest discover -s deploy/appliance/tools -p test_rdp_telemetry.py -v`

- audit_guacd_handshake.py: finite passive diagnostic for the exact admitted
  synthetic fixture network namespace. It compares catalog parameters in the
  app-to-guacd handshake using in-memory equality checks and exports only safe
  phases, booleans and numeric status. No PCAP, raw protocol or secret values
  are written. Admission uses a private stdin line and a capture-ready barrier;
  the parent retains the pipe and owns fixture cleanup. Read
  [GUACD-HANDSHAKE-AUDIT.md](GUACD-HANDSHAKE-AUDIT.md) before use.
  test_audit_guacd_handshake.py exercises framing, reassembly, filtering and
  privacy boundaries without sockets or namespace operations. A successful
  handshake comparison is not RDP or browser acceptance.


- install_transport_server.py: explicitly pinned server installation of the
  tunnel-only Unix account and source-bound public key. Validates candidate
  sshd syntax/effective policy, preserves administrative policy and a global
  configuration backup, then reloads SSH. Root only, new intent/result directory,
  refuses existing account/directory or existing Match blocks. No automatic retry.

- test_image.py: bounded complete candidate-image startup, native TOTP and own
  Chromium/Angular selector acceptance with network disabled and private
  namespace relay. Includes desktop/mobile/narrow native login geometry and
  synthetic blank-login screenshots without injected CSS or owner data.
  See IMAGE-FIXTURE.md; no actual RDP success claim.
- test_network_namespace.py: isolated real nft/iptables TCP/SNAT/HTTP and negative
  traffic fixture. At most two CPUs, at most170seconds, new private evidence;
  no host networking changes. See NETWORK-CONTRACT.md.
- test_network_upgrade_namespace.py: real additive nft table transaction and
  exact iptables insertion/inverse rollback inside the same owned namespace/
  tmpfs/chroot harness. Rejects a semantic-error nft batch without changing the
  old guard; checks unchanged unrelated rules, old RDP TCP/SNAT/backend replies,
  added gateway TCP source bounds and real listener-census rollback refusal.
  At most two CPUs/170seconds, new root-private protected evidence; no host
  networking, systemd, Podman, actual SSH authentication or boot acceptance.
  See NETWORK-UPGRADE-FIXTURE.md.
- synthetic_rdp_targets.py: finite two-listener XRDP fixture on a pinned owned
  guest, with separate accounts/certificate and private beta mount namespace.
  See TARGET-FIXTURE.md. Original listener is preserved; accounts expire locked.

- create_transport_identity.py: client-host root-only creation of one dedicated
  Ed25519 identity at /etc/portal-rdp-transport, with intent/result receipts.
  Refuses every existing directory. The private key is never read or printed;
  output is its public key only. No SSH configuration, account or service change.

- render_proxy.py: render a gated nginx snippet and HTTP-scope authentication
  rate limit. The catalog default_target controls the landing redirect; each
  configured alias has its own explicit link. Unknown aliases return404. This
  tool never installs nginx configuration or creates the readiness marker.

- render_transport.py: render a source-address-bound tunnel-only SSH account
  configuration, pinned client host key and supervised `ssh -N` unit. Requires
  explicit external IPv4 endpoints and public keys. Schema1 singleton rendering
  remains compatible; exact schema2 accepts one to eight distinct forwards on
  one private bridge, with matching PermitOpen/key options and LocalForward.
  Never reads private keys,
  installs files, creates accounts, reloads sshd or opens a connection.

- Historical capture_reference.py and import_primitives.py are held out of the
  first publication package. They supported bounded source-only capture from
  the private preparation image and hash-verified process/PostgreSQL helper
  extraction. Neither is imported or required by the active current-source
  build, installation or fixtures.
- build_extension.py and test_build_extension.py: compile the portal provider
  and mandatory filter with Java25 against a successful source_build.py WAR
  receipt, plus the exact servlet API extracted from the Tomcat archive verified
  by source-inputs-lock.json. Run the existing inert Java provider harness and
  package both JARs with the source-built Guacamole version and actual browser
  resources. New external directory and hash receipt; no image, engine, runtime,
  database, production or network operations. The former --image mode is removed.

  `python3 deploy/appliance/tools/build_extension.py --client-build SOURCE_BUILD_DIRECTORY --tomcat-archive LOCKED_TOMCAT_ARCHIVE --java-home JDK25_HOME --directory NEW_EXTERNAL_DIRECTORY`

  `python3 -m unittest discover -s deploy/appliance/tools -p test_build_extension.py -v`

  The output directory contains synthetic test logs, extracted public libraries,
  compiled classes and JARs. Retain it for review, then explicitly remove that
  directory when evidence is no longer needed; it is never an installed service.

- build_image.py: verify current public inputs and successful source-built WAR
  provenance offline, freeze the reviewed source/input namespace, and build the
  single source image with at most two native workers. Compiles and tests Java25
  portal sources and packages browser resources,
  installs the mandatory WAR filter and writes a root-owned integrity census.
- Historical release_inputs.py, ../dependency_patch.py, ../images-lock.json
  and ../dependency-lock.json form one released1.6.0 inspection/fetch closure.
  It and ../freerdp_compat.py with ../GUACAMOLE-2328-1.6.0.patch are held out
  of the first publication package. The current source/image and SSH endpoint
  builders use source-inputs-lock.json and do not import the historical closure.
  If historical support is retained separately, keep that closure together.

- test_postgres.py: bounded actual PostgreSQL16 preparation/enrollment/migration
  and negative-drift fixture against an exact local image SHA. Runs only one
  owned rootful container, network disabled, at most two CPUs, tmpfs data/secrets,
  and read-only current appliance sources. Generates synthetic credentials in
  the container; never mounts instance data or external secrets. Uses an inner
  100-second alarm and an outer bounded wait, then verifies ownership before
  stopping/removing the container in finally. Writes a new private evidence
  directory; deliberately bypasses image integrity/config loading to test SQL
  integration only, and does not establish full image acceptance.

  `python3 deploy/appliance/tools/test_postgres.py --image EXACT_LOCAL_SHA256 --directory NEW_PRIVATE_DIRECTORY`

Use new private evidence directories outside the checkout. No live host bindings
or captured private evidence belong in Git. Bounded PR source checks may use
standard free public GitHub-hosted Linux runners with read-only permissions.
No paid/larger runners, private target access, deployment, cache/artifact or
image publication is part of those checks. Native build checks run only for
affected native/Java/build sources; available inert Python/Node checks run on
each component. Hosted checks do not replace private image/protocol acceptance.

- build_ssh_endpoint.py, test_build_ssh_endpoint.py, ssh-endpoint.Containerfile,
  test_ssh.py, ssh_fixture.py and test_ssh_fixture.py: separate pinned public-input
  endpoint image using source-inputs-lock.json (base, snapshot and bootstrap CA)
  and
  bounded network-none native guacd/OpenSSH/tmux fixture. Wrong host/app keys,
  NONE/forced-command refusal, exact pane PID/start/counter persistence and
  same-account default-socket sentinel preservation; synthetic keys remain in
  memory/container tmpfs. Exact owned cleanup, no host package/key/service
  changes. Not browser/JDBC or actual endpoint acceptance. See ../SSH-FIXTURE.md.

- test_mixed_image.py and test_mixed_boundaries.py: complete packaged schema2
  synthetic TOTP/JDBC/SSH browser fixture with an exact native-refusal receipt
  prerequisite. Three-alias UI/tree and original RDP routing, Java key injection,
  exact received UTF-8 hash, measured PTY resize, pane persistence, own logout204
  and verified cleanup. Nonroot sandboxed owned Chrome; no product module
  overlays, owner endpoints or logs/screenshots. See ../SSH-MIXED-FIXTURE.md.

- test_live_ssh.py and test_live_ssh_boundaries.py: separately operator-invoked
  SSH-only browser acceptance with exact three-entry JDBC protocol census,
  shared root OTP/deployment proofs, ordinary-user sandboxed own Chrome,
  refresh/disconnect/reconnect and logout204/profile cleanup. No terminal input,
  screenshots, keys/tokens or host pane identity claim. Source/unit preparation
  does not authorize invocation. See ../LIVE-SSH-ACCEPTANCE.md.

- promote_current.py and test_promote_current.py: reviewed stopped CURRENT
  DATA/file-only promotion with exact fresh cold-backup/normal-restore/migration
  lineage, original DATA inode retention, fixed operating-file allowlist,
  existing network/transport/terminal proof contracts and explicit partial-state
  rollback. No service, nginx, firewall, transport or authentication operations;
  no automatic recovery/replay or admission generation. Root-owned inert tests
  cover actual synthetic filesystem retention and expiry boundaries. See
  ../CURRENT-PROMOTION.md; independent source review is required before staging.

- test_mixed_restore.py and test_mixed_restore_boundaries.py: separate already-
  MIXED PG16 backup/normal-restore gate using actual stopped/exclusive cold_copy
  primitives and three retained independent DATA trees. Full identity/TOTP/
  census/prepared equality before restored authentication, separately handled
  synthetic secrets, restored-only exact-image native mixed browser and verified
  clean shutdown/cleanup. Optional --source-image uses an exact old producer
  image while --image remains the restored target; default is same-image.
  Both image roles are recorded and guarded independently. No fake systemd/
  production CLI receipt, owner endpoint
  or image/runtime changes. See ../MIXED-RESTORE-FIXTURE.md.


- ../web/browser/test-target-selection.py: focused current-main genuine Angular
  login/form rendering with actual portal JS/CSS and three synthetic aliases.
  Verifies exact lockfile dependency SHA512 values, uses a fresh sandboxed
  Chrome profile and loopback fixture, retains only explicitly requested
  external evidence. See ../web/README.md for invocation and scope limits;
  no full WAR, backend authentication or desktop acceptance claim.


- fetch_source_inputs.py and test_fetch_source_inputs.py: fetch only public
  inputs from source-inputs-lock.json into an explicit external directory.
  Existing matching files remain unchanged; different existing files, links,
  unsafe names and credential-bearing/non-HTTPS URLs are refused. Optional
  --cache reuses hash-matched Tomcat, bootstrap CA and PostgreSQL driver bytes
  (including the former dependencies/ driver layout). Server metadata is
  generated from the exact locked commit/archive hash. Downloads have byte,
  socket and elapsed-time limits; failed partials and failure receipts remain
  in a new fetch-attempt-* directory. No package installation, source build,
  image build or production action occurs. A ready_for_verification receipt
  means acquisition only: build_image.py verify checks the Tomcat signature
  against its locked fingerprint and freezes all inputs/artifacts separately.

  ```sh
  python3 deploy/appliance/tools/fetch_source_inputs.py --inputs /path/to/input-cache --cache /path/to/verified-public-cache
  python3 deploy/appliance/tools/build_image.py verify --inputs /path/to/input-cache --client-build /path/to/successful-source-build --work /path/to/new-image-work
  python3 -m unittest discover -s deploy/appliance/tools -p test_fetch_source_inputs.py -v
  ```

  The cache is optional; a bootstrap CA must match the reviewed lock, supplied
  either by that cache or /etc/ssl/certs/ca-certificates.crt. Private source-build
  artifacts come from source_build.py, never this public-input downloader.

- test_build_source_freeze.py: inert current-source/image handoff regressions.
  Native source namespace, hashes and executable bits are separate from the
  appliance source freeze. Artifact names/hashes and the complete SQL namespace
  must match the selected native source; the manifest version must match its
  Maven revision. Tests cover missing/extra/changed SQL, source drift, linked
  WAR files and receipt mutation after parsing. No source compilation, network
  or container execution occurs.

- test_browser_probe.cjs and test_browser_diagnostics.py: bounded, controlled
  own-Chrome CDP regressions for empty-canvas pixel reads and the real Angular
  portal invalid-target pending promise. The probe verifies the current exact
  Angular npm lockfile hash, uses synthetic canvases and inert navigation inputs,
  creates/removes only its own temporary browser profile/process group, and
  emits only synthetic state, pixel counts and exception classes. No application
  endpoint, authentication, credentials, screenshots or raw exception stacks.
  Run `node deploy/appliance/tools/test_browser_probe.cjs` and
  `python3 -m unittest discover -s deploy/appliance/tools -p test_browser_diagnostics.py -v`.
  No persistent artifact is created; Node22+ native fetch/WebSocket, Python3,
  tar and ordinary-user sandboxed /usr/bin/google-chrome are required.

- GuacamoleTwinProbe.java and TestGuacamoleTwinProbe.java: conditional synthetic
  Java handshake/reader diagnostic, prepared separately from packaged runtime
  sources. Uses the selected WAR's actual guacamole-common InetGuacamoleSocket
  (unchanged 15-second phase timeout), ConfiguredGuacamoleSocket and
  getReader().readInstruction() APIs. No HTTP, JDBC, browser renderer, product
  overlay, guest command, image build or lifecycle operation. Compile/parser
  success is not RDP acceptance. Operator invocation is a separate root-owned
  conditional step after reviewing the native exact-browser-profile replay.

  Compile both files with the existing JDK25 javac, `-cp` the exact selected
  packaged guacamole-common JAR and `-d` a new private external directory. Run
  TestGuacamoleTwinProbe using that directory and JAR on the classpath for inert
  parser/default/constraint checks; it never opens a socket. For a separately
  admitted diagnostic, invoke GuacamoleTwinProbe with no arguments, the same
  classes/JAR and packaged slf4j-api on its classpath, and redirect an external
  private input file to stdin. No downloads or installation are required.

  Input is at most 65536 bytes of UTF-8 Java Properties, with duplicate/unknown
  keys refused. Use standard Properties escaping for backslashes/newlines.
  Required keys: guacd.host (exactly 127.0.0.1), guacd.port (exactly 4822), client.width,
  client.height, client.dpi, client.timezone; media.audio.count,
  media.video.count, media.image.count and contiguous zero-based indexed MIME
  values (for example media.image.0). Explicit zero counts mean empty arrays.
  No media or geometry defaults are inferred. Copy the measured native replay's
  exact MIME values/order, 1100x800/DPI96 and timezone into this shared profile.
  Each distinct target has target.1.parameter.NAME / target.2.parameter.NAME;
  hostname must be exactly 127.0.0.1 for each; target ports must be distinct
  33389 and 33390 (either order). Each username must match p[ab][0-9a-f]{10},
  password must be nonempty, security must be tls, domain must be empty,
  enable-drive and enable-printing must both be false. Each cert-fingerprints
  must be one lowercase colon-delimited sha256 fingerprint (32 byte pairs).
  Only these target parameters plus resize-method, enable-font-smoothing and
  client-name are allowed. These constraints run before Guacamole library
  objects are constructed or sockets opened. Supply the complete reviewed
  synthetic catalog parameter sets in native replay order (Beta then Alpha).
  The parent harness must additionally bind exact CID/catalog/secret equality;
  syntactic constraints alone do not establish fixture provenance. No secrets
  in arguments, source, environment, logs or tracked fixtures. This helper
  cannot target arbitrary endpoints or serve as a production operator tool.

  Client1 reaches ready and a successfully echoed sync before client2 starts.
  Each ConfiguredGuacamoleSocket establishment has an independent 29-second
  socket-close watchdog; it is canceled at ready. Client1's reader stays alive
  during client2 establishment. Both readers echo sync timestamps and ACK every
  blob, discard payloads, and retain only numeric counts. All sockets close by
  65 seconds after input; a process watchdog halts by 75 seconds including input.
  No retry/reconnect. All library stdout/stderr is discarded before library
  initialization; only the captured original stdout emits numeric JSON.

  Stages: 0=not started, 1=TCP construction, 2=configured handshake,
  3=ready/reading, 4=sync acknowledged. Status is the numeric Guacamole status
  (512 for other errors); read timestamps, instruction/sync/blob/display counts,
  second-start timestamp and first-reader-alive are safe diagnostics. Result0
  means both sync readers remained alive after up to two seconds of overlap;
  result1 means incomplete, result2 means rejected input/control failure. These
  results do not verify guest logon, decoded desktop markers, browser rendering,
  independent failure isolation or production acceptance. Timed-out/closed
  readers can end with status0; assess stage/alive/counts together. No native
  decoder is present, and advertised media is replayed without browser decoding.

* `test_rdp.py --raw-web --markers-only --audit-handshake` adds the separately
  reviewed passive observer described in `GUACD-HANDSHAKE-AUDIT.md`. It requires
  the exact frozen collector hash, binds the owned CID/init identity/netns and
  mounted catalog/credential hashes, and waits for capture readiness before any
  browser authentication. Only whitelisted numeric/boolean JSON records persist.
  EOF closes observation before health probes and container removal; an external
  root-owned timeout bounds failed EOF cleanup. This remains a diagnostic: native
  catalog parameter equality and phase boundaries do not establish complete
  handshake equivalence, backend logon or full RDP acceptance.

  The private fixture's HTTP transport relay retains its eight-slot limit.
  Backend EOF cancels the remaining client-to-backend pipe and releases the
  slot; client half-close alone still allows the backend response to finish.
  `http-relay.json` records bounded connection ordinals, queued/active counts,
  fixed phase epochs and byte counts, never requests, URLs, headers or payloads.
  Child counts and child-exited timestamps refer to parent cleanup/reaping,
  not independently sampled operating-system exit times.
