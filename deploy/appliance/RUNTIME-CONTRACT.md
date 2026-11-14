# Runtime contract

Private implementation; live PostgreSQL and native-image acceptance remain
pending. The Python unit suite executes no PostgreSQL or deployment operations.
The separate tools/test_postgres.py harness executes isolated synthetic SQL
acceptance against a local PostgreSQL16 image, with owned-container cleanup.

Run `python3 /opt/homelab-web-rdp/runtime.py COMMAND` as container root.
Supported commands are `prepare`, `migrate --original-alias ALIAS`,
`migrate-current --previous-config PATH`, `serve`, and `health`. No command
changes network rules or probes configured target endpoints.
The image launcher must supply an isolated container network/egress policy,
read-only root filesystem, private tmpfs at `/run/web-rdp`, root-owned read-only
configuration and secret mounts, and a separate persistent `/data` mount.

`/config/config.json` accepts catalog schema version 1 (RDP only) or version 2
(explicit RDP/SSH protocol records). Existing schema-1 RDP input and native
connection parameters remain unchanged. The filesystem containing
this file must be read-only. Its parents and the file must be owned by root;
parents must not be writable by group/other. Configuration rejects final and
parent symlinks. `/secrets` has the same parent protection. Each credential is
a root-owned regular file with no group/other access and one hard link:
`db-password`, `portal-password` (new-data preparation only), and the distinct
secret filename of every target. Database and portal credentials contain
16 through 512 characters. RDP credentials contain 1 through 512 UTF-8 bytes,
preserving exact contents, and cannot contain newline, carriage return or NUL.
SSH credentials are separate multiline ASCII unencrypted single-key Ed25519
OpenSSH private keys of at most 16384 bytes. Encrypted keys/passphrases and
password fallback fields are not supported. Neither reader prints credential
values. Guacamole properties escape database-password metacharacters.

The image must install PostgreSQL 16 tools in `/usr/lib/postgresql/16/bin`,
Tomcat in `/opt/tomcat`, guacd in `/opt/guacamole/sbin/guacd`, Java25 LTS in
`/opt/java`, and the schema in
`/opt/homelab-web-rdp/schema/001-create-schema.sql`. Native executables and
libraries must match the reviewed clean-build manifest. Runtime modules,
extensions, library symlinks and the integrity manifest live beneath
`/opt/homelab-web-rdp`. The integrity manifest is a root-protected JSON object:
`{"schema":1,"files":{"runtime.py":"<64 lowercase hex SHA256>"}}`.
Entries are relative paths without `..`; each entry is checked before commands
run. The builder is responsible for including all mandatory source/JARs and
for binding the installed runtime into the immutable image digest.

`prepare` requires a completely empty `/data` directory owned by UID/GID 2000
with mode 0700. It loads only schema 001 and creates exactly one personal user,
without a stock administrator. Sorted target aliases get deterministic IDs.
The root-owned mode 0600 `/data/prepared.json` retains the historical
`guacamole` value `1.6.0` as the compatible PostgreSQL schema marker, not the
running application version. It binds PostgreSQL16, the exact configuration
hash and the alias-to-ID mapping. Source/image provenance identifies the
actual selected client/server and Java25 binaries.
Changing configuration requires an explicit migration procedure; restarting
with changed configuration fails closed.

`migrate` accepts a copied, stopped legacy PostgreSQL 16 cluster with no current
receipt. The caller must independently verify that it is an isolated copy;
the command cannot prove provenance. It validates the original singleton
connection, all parameters and permissions, exactly one active identity, and
confirmed valid TOTP before modifying any SQL state. The only legacy parameter
normalization is `${HOMELAB_WINDOWS_PASSWORD}` to the alias-specific token.
The human-readable original connection name becomes the alias. ID 1, account
rows and TOTP attributes are preserved. Additional aliases receive new IDs.
The migration does not execute schema or recreate users/roles. The copied
cluster's `guacamole` role must already match external `db-password`.
Failed rehearsals must be retried from a fresh stopped copy; do not use failed
migration destinations as rollback sources. Only external backup/restore
procedures should create that copy; this CLI currently has no backup/restore
or TOTP recovery commands.

`serve` requires either `WEB_RDP_PRODUCTION=1` with no fixture lease variables,
or both `WEB_RDP_DURATION_SECONDS` (positive, at most 600) and an absolute
`WEB_RDP_DEADLINE_EPOCH`. Fixture access ends at the earlier deadline. Runtime
must not be used as an authorization source for publication. The mandatory Java
filter retains the 65-second startup hold; runtime has no shortcut around it.

The Java provider receives `portal-user`, `portal-targets` (comma-separated
aliases), `portal-target-ALIAS-id`, `portal-target-ALIAS-protocol` (rdp/ssh),
and `portal-publish-target-labels`. Extension
priority is `portal, postgresql, totp, ban`. Target passwords are staged in
`/run/web-rdp/java/target-ALIAS-password`; SSH keys are separately staged at
`/run/web-rdp/java/target-ALIAS-private-key`. Both use UID/GID 2001, mode 0600
and single-link regular files. The Java provider reads only the selected alias
and dispatches the same protocol-specific byte/format bounds as the runtime.
RDP keeps PORTAL_TARGET_ALIAS_PASSWORD; SSH uses PORTAL_TARGET_ALIAS_PRIVATE_KEY.
Host selection checks file metadata/bounds only and never reads secret values. Stored JDBC
connection names are exactly aliases and credentials remain token placeholders.
No fallback administrator, group, sharing profile or system permission is
allowed. Health checks compare the complete connection parameter/permission
census with the registry, including connection proxy overrides and limits.

The optional `portal.trusted_proxy_ipv4` configures exactly one trusted reverse
proxy IPv4 address. When present, Tomcat installs RemoteIpValve with
`internalProxies` equal to that address with regex metacharacters escaped,
`remoteIpHeader=X-Forwarded-For` and `protocolHeader=X-Forwarded-Proto`. This
preserves per-client ban attribution behind the trusted proxy. With the field
absent, Tomcat installs no forwarded-header valve and uses the direct peer.
No subnet, default private-range trust, or arbitrary proxy regex is accepted.

`health` prints `database_ready`, `web_ready` and `enrolled` separately. A failed
RDP host does not close the portal. Web health does not by itself imply that the
65-second gate is open or native TOTP enrollment is complete. The external
acceptance controller must require the intended combination and independent
end-to-end browser/RDP evidence.

The supervisor owns separate Java and guacd process groups. Shutdown kills and
waits for all live group members even when a parent has already exited, then
stops PostgreSQL. Zombies are reaped by PID 1 during normal serving and do not
count as socket-owning live members. Unit tests create only their own process
groups and include an exited-parent/live-descendant regression.


## Mixed-protocol source contract and remaining native gates

Schema 2 RDP records retain exactly the schema-1 record shape, including explicit
`protocol: rdp`, `password_file` and SHA256 certificate fingerprint. Schema 2 SSH
records require `protocol: ssh`, IPv4 hostname, port, Linux username, `host_key`,
`private_key_file` and `command`, with optional label. Unknown fields, shared
secret filenames and password/passphrase/SFTP/recording overrides are rejected.
`command` is one canonical absolute launcher pathname without shell arguments.
`host_key` is one full canonical OpenSSH known-host entry bound to exactly that
endpoint (bracketed host:port for a nonstandard port), with a structurally checked
Ed25519 or ECDSA nistp256 public key. No wildcard, multi-host, hashed-host,
comment, digest-only pin or TOFU fallback is accepted. The configured key must
match the algorithm actually negotiated by native libssh2; native Guacamole
verifies the key after handshake and does not force its algorithm from the pin.

Each Target exposes protocol, secret_file, secret_parameter, secret_token and
secret_limit. RDP password_file/password_token compatibility properties retain
their old meanings and reject SSH use. SSH native parameters include the pinned
host-key, private-key token, fixed command and enable-sftp=false; no password,
passphrase or recording path is emitted. Runtime SQL and health census validate
actual protocol and the complete exact parameters/permissions for every ID.
Portal identity, TOTP policy and the mandatory startup hold remain unchanged.

`migrate-current` delegates to the separately reviewed current_migration module
on an independent stopped current-format restore; it must preserve every old
RDP ID/parameter, portal/default policy and identity/TOTP rows while appending
SSH. A separate narrow transition may only hide prelogin labels (true to false)
with no added targets and all other settings unchanged. That transition writes
no target/permission/sequence SQL; it retains the complete DB census and existing
identity/TOTP while updating the independently restored preparation binding.
No-op, reversal and combined visibility/target changes are rejected. It is
distinct from the legacy singleton migrator and does not authorize
in-place production mutation. Mixed image, actual SSH/key/host-pin/tmux/browser,
independently restored migration and RDP regression gates remain required; see
SSH-ACCEPTANCE.md. Unit/harness success is source-level evidence only.
