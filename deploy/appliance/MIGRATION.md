# Stopped legacy database migration and rollback

For extension of an already current catalog, use the separate CURRENT procedure
at the end of this document. Its restore keeps `prepared.json` intact; the
legacy `--for-migration` preparation below must not be used for that operation.

These tools prepare external files and copy a stopped PostgreSQL16 tree. They
do not stop or start a service, change a proxy or firewall, create a container,
contact a Windows endpoint, initialize a database, or create a portal identity.
The operator separately closes access and stops the old installation using its
reviewed controller. Observe active desktop sessions before doing so.

Run host helpers as root from a reviewed, root-protected installation. Place
`prepare_instance.py` and `cold_copy.py` together under its tools directory;
`catalog.py` and `network.py` must be in their parent directory. Never run a
helper against production merely to test its argument parsing. `--help` is
inert. All external source inputs, results and secrets stay outside Git.

First run the source fixture tests. Every service/engine inspection is mocked;
root tests only copy synthetic files in their own disposable `/run` directory.
Non-root execution skips the filesystem ownership cases.

```sh
sudo python3 -B -m unittest discover -s deploy/appliance/tools -p test_migration_tools.py -v
```

## Prepare a new external namespace

Review the two-target catalog and network JSON outside the checkout. Both
must be root-owned mode0600 regular single-link files with root-protected,
non-writable ancestry. Retain the existing portal username and exact original
target parameters, including certificate pin and RDP username. Each alias
requires a different password filename. Validate the intended forwarding and
gateway-local classification before closing the existing portal.

Preparation creates the two specified new directories with mode0700. The
standard destinations are `/etc/guacamole-portal` and
`/var/lib/guacamole-portal`. Both must be absent, including interrupted prior
attempts. Prepare before another helper creates the state root. Parents must
already exist, be root-owned and deny group/other writes; symlinks are rejected.

The following variables denote reviewed external paths, never secret values:

```sh
sudo python3 -B /opt/guacamole-portal/tools/prepare_instance.py \
  --config "$REVIEWED_CONFIG" --network "$REVIEWED_NETWORK" \
  --config-directory /etc/guacamole-portal \
  --state-directory /var/lib/guacamole-portal \
  --legacy-secrets "$LEGACY_SECRETS" --reuse-legacy-rdp-for-all
```

The explicit reuse flag is appropriate only after the operator confirms that
every configured Windows account uses the existing legacy RDP password.
`LEGACY_SECRETS` must be root-owned mode0700 and contain root-owned mode0600
single-link `db-password` and `rdp-password` files. Database password bytes are
copied unchanged, including an existing trailing LF. Validation matches the
runtime's removal of trailing LF characters and 16..512-character bound.
Windows passwords accept 1..512 UTF-8 bytes. At most one trailing LF is
removed; embedded LF, CR and NUL are rejected. Leading/trailing spaces remain
part of the password. Each target gets its own independent mode0600 file.
No password value, length, digest or derivative is logged or recorded.

The helper copies the reviewed configuration bytes unchanged and records
their hashes in `prepare-intent.json` and `prepare-result.json` in the new
state root. It does not create data, `portal-password` or a new login. Inspect
the result before continuing; a missing result or failed phase means an
incomplete attempt to preserve for review, never an invitation to replay.

## Close the old portal and make an opaque cold backup

Before closing, record the exact old immutable container ID and the existing
service/controller ownership in private operator evidence. Close proxy access
and stop the old installation through the separately reviewed legacy procedure.
Leave its original data and secrets in place for rollback. Do not remove a
`postmaster.pid` file to make this tool accept a potentially live cluster.

```sh
sudo python3 -B /opt/guacamole-portal/tools/cold_copy.py backup \
  --source "$LEGACY_DATA" --service "$LEGACY_SERVICE" \
  --container "$LEGACY_CONTAINER" --legacy-container-id "$LEGACY_CID" \
  --directory "$NEW_BACKUP_CASE"
```

`--legacy-container-id` is optional when the old container still exists and
is stopped. It is required when the old controller removes that container:
fresh `podman container exists` checks must independently return1 for both
the old name and pinned ID. An engine error never establishes absence. The
systemd unit must still be loaded, inactive/failed and have MainPID0. If an
old container remains, its exact name, full ID, stopped state and source data
mount are checked. Every container's mounts are inspected, including stopped
containers. Any overlapping consumer except that pinned stopped old container
is refused unless it is separately named with repeatable
`--allow-stopped-consumer FULL_CID`. This option acknowledges only an already
reviewed historical container, never a name or ID prefix. Every listed ID must
remain present, Runningfalse, PID0 and exited/stopped, with exactly one
overlapping bind source resolving to the exact data directory. Parent/subtree
binds, missing consumers, unknown or running states and unlisted overlaps are
refused. The intent records the explicit allowlist and each consumer's exact
ID, name, immutable image, stopped state and mount metadata plus its digest.
The complete selected metadata must remain identical after copying. No
container environment, command or secret contents are captured. Historical
containers and their evidence are retained. A symlinked bind source is
resolved before overlap comparison.

The data root and `pgdata` must be UID/GID2000 mode0700. `PG_VERSION` must
declare16; a postmaster PID file, tablespace symlink, hardlink, special file,
mount crossing or group/other-writable entry is rejected. The required legacy
mode0600 `prepared.json` can be UID0 or UID2000 and must contain exactly the
known singleton schema: `schema`, `postgres_major`, `guacamole`, `profile`,
`portal_username`, and `config_sha256`. Backup and ordinary restore also accept
the exact current catalog receipt, retaining it intact; `--for-migration`
accepts only legacy receipts. See [current recovery in INSTALL.md](INSTALL.md#current-format-stopped-backup-and-independent-restore)
for current receipt validation and restore requirements.

The new backup case is root-owned mode0700. It contains `intent.json`, the
complete copied `data` tree, a private `manifest.json`, and `result.json`.
`cp -a` preserves numeric ownership and modes without reading SQL contents.
The manifest covers every directory and file, metadata and full file SHA256.
Source and destination must match it exactly; stop/exclusivity checks repeat
after copying. The manifest hash is bound in the successful result. Cluster
hashes serve opaque integrity only and remain private; stdout contains no
manifest, database content, credentials or TOTP material.

The entire CLI operation has a600-second deadline. Unknown completion or
failure leaves the intent, failed result when possible, and partial copies
for review. It never overwrites a prior destination, deletes evidence, retries
an uncertain operation or performs lifecycle cleanup. Fixed safe inspection
diagnostics are included in stderr even for refusal before a case is created;
raw engine output and parser/decoding exception text are never printed.

Root remains the trusted operator. These checks do not prevent another root
process from starting a new database after inspection. Keep all other writers
and automatic service restarts closed throughout backup and rehearsal.

## Independently restore and migrate a disposable copy

```sh
sudo python3 -B /opt/guacamole-portal/tools/cold_copy.py restore \
  --backup "$NEW_BACKUP_CASE" --directory "$NEW_REHEARSAL_CASE" \
  --for-migration
```

Restore requires a successful backup result, verifies the complete original
backup against its bound manifest, and copies it into a separate new case.
The backup is never modified or mounted writable. After exact copy verification,
`--for-migration` moves only the old `prepared.json` to the new case's
`legacy-prepared.json`, outside its `data` directory. The original file and
metadata are preserved; its bytes and hash remain bound in the original
manifest. All other copied entries must still match exactly. Omitting the flag
restores an exact legacy tree suitable for old-runtime recovery instead.

Run the accepted immutable image's `runtime.py migrate --original-alias ALIAS`
against only `$NEW_REHEARSAL_CASE/data`, with read-only catalog and secrets,
read-only image root, required bounded tmpfs and process capabilities. The SQL
step needs no network and must publish no ports. The container must be pinned
by full immutable ID, have a new private intent/result, and be reconciled by
that exact ID after exit or timeout. The copy helper deliberately does not
construct this container or treat arbitrary successful command output as
migration acceptance. Follow `RUNTIME-CONTRACT.md` for mounts and runtime
requirements and `HOST-CONTRACT.md` for resource and process controls.

Migration validates the exact legacy singleton and confirmed TOTP before SQL
changes. It preserves original connection ID1, account rows and TOTP
attributes, normalizes the legacy password token to the original alias's
connection-specific token, and adds other aliases. It never initializes a
database or enrolls another identity. Keep all raw SQL/TOTP evidence private.

Then verify the restored copy with the accepted image, native existing TOTP,
each configured RDP target, alias URLs, login selector, certificate rejection,
independent target failure, proxy gate and shutdown. Also compare the existing
account identity and TOTP attribute bytes internally before/after migration
without printing or hashing their individual secret values. Record actual
results and artifact hashes externally. Copy success and a migration exit
code alone do not prove identity preservation or browser/RDP acceptance.

A failed migration is disposable evidence. Begin another rehearsal from a new
independent restore of the untouched backup; never retry against the failed
SQL destination or use it as a rollback source.

## Promote only after a successful rehearsal

Keep the old service/proxy closed. Restore again from the untouched backup
into a new case with `--for-migration`. For the fixed production data path,
the case and target can be independent:

```sh
sudo python3 -B /opt/guacamole-portal/tools/cold_copy.py restore \
  --backup "$NEW_BACKUP_CASE" --directory "$NEW_PROMOTION_CASE" \
  --data-target /var/lib/guacamole-portal/data --for-migration
```

The target must be absent. A prepared, empty or partially copied pre-existing
directory is refused. Run the same reviewed migration against this fresh copy,
then satisfy the full release admission in `HOST-CONTRACT.md`: reviewed image,
actual rehearsal evidence, exact config/network hashes, owned network,
enforcing profile, startup ordering, gated proxy and existing TOTP acceptance.
Only then open access. Preserve the old install and untouched backup until
operator acceptance establishes that rollback can be retired separately.

If promotion fails, close new proxy access and stop/reconcile its exact owned
container through the new launcher's cutoff procedure. Confirm no container
can write the old tree, restore the old proxy/controller release bindings,
and restart the original installation on its untouched original data. If that
original tree is unavailable, use a new exact restore without `--for-migration`
and the original config, secrets and immutable old image. Never point the old
runtime at migrated data. Verify native existing TOTP and the old RDP target
before reopening access. No helper performs that rollback automatically.

## Extend an independently restored CURRENT catalog

`current_migration.py` and `tools/migrate_current.py` are a separate source-only
procedure for appending SSH targets to the already current schema1 preparation
receipt format. Their inert tests pass; actual PostgreSQL, native SSH/tmux and
image acceptance remain separate operator gates. No existing RDP target is
normalized or rewritten. The previous catalog can be schema1 or schema2, but
its complete existing target parameters, labels, secret filenames, protocol,
portal username, default, label-publication flag and trusted proxy must stay
unchanged. The only additions allowed are SSH targets.

Close access and stop the current installation through its reviewed controller,
after checking desktop sessions. Preserve the original DATA, current config,
secrets, exact image and cold backup. Use normal cold restore, with no
`--for-migration`: the root-owned mode0600 current `prepared.json` must stay
byte-for-byte intact and match the restore manifest.

```sh
sudo python3 -B /opt/guacamole-portal/tools/cold_copy.py restore \
  --backup "$CURRENT_BACKUP_CASE" --directory "$CURRENT_RESTORE_CASE" \
  --data-target "$CURRENT_RESTORED_DATA"
```

Stage a new catalog externally by retaining the previous portal and all RDP
records and appending reviewed SSH records under schema2. Provide the exact
previous configuration bytes, not a reconstructed equivalent. Prepare the
separate root-private secret directory using the existing exact RDP credentials
and distinct prevalidated SSH application identities. Migration never reads or
prints target secret contents and does not change an account or authenticate
to a target. Existing external DB credentials must match the restored DB role.

Install reviewed `migrate_current.py`, `cold_copy.py` and `prepare_instance.py`
together in the protected tools directory, with the matching `catalog.py`,
`host.py`, `network.py` and `current_migration.py` in its parent. The exact
candidate image must include the reviewed current migration module in its
integrity manifest. The wrapper compares the module's actual image SHA256 to
the reviewed host source before starting PostgreSQL.

```sh
sudo python3 -B /opt/guacamole-portal/tools/migrate_current.py \
  --image "$EXACT_CURRENT_CANDIDATE_IMAGE" \
  --data "$CURRENT_RESTORED_DATA" \
  --previous-config "$EXACT_PREVIOUS_CONFIG" --config "$REVIEWED_EXTENDED_CONFIG" \
  --secrets "$REVIEWED_SECRET_DIRECTORY" \
  --restore-receipt "$CURRENT_RESTORE_CASE/result.json" \
  --expected-restore-sha256 "$REVIEWED_NORMAL_RESTORE_SHA256" \
  --directory "$NEW_CURRENT_MIGRATION_CASE" --apparmor-profile "$ENFORCING_PROFILE"
```

The wrapper requires the normal restore result, original completed backup and
both full manifests to agree. It verifies independent DATA identities, intact
current preparation bytes, stopped/exclusive mounts, exact old config hash and
append-only or isolated label-hiding mapping before dispatch. The fixed production DATA namespace and
any ancestor/descendant of the backup's original source DATA are rejected,
even when stopped and accompanied by an otherwise valid restore receipt.
It never mounts the source backup. A new
private fsynced intent binds the image, module/wrapper/inside source hashes,
restore and manifest hashes, old/new config hashes, old preparation hash and
restored DATA device/inode. Frozen old/new config copies are read-only in the
container; data and the separate secret mount cannot overlap them or the case.

The container has network disabled, read-only root, two CPUs, 1GiB memory with
equal total memory+swap, 192 PIDs, no-new-privileges, the explicit confined
AppArmor profile and only the established runtime capabilities. It starts only
PostgreSQL for migration; no Java, guacd or target connection is started.

The runtime entry point is `migrate-current --previous-config /config/previous.json`.
It requires the exact old receipt/mapping and complete old DB census, one
confirmed existing identity and TOTP enrollment. New SSH IDs start at
`max(existing IDs)+1`; sparse/noncontiguous RDP IDs retain their exact values.
One SQL transaction locks the catalog/identity/permission tables, checks the
entire pre-census, appends only new native SSH connection parameters and READ
permissions, checks the complete expected post-census and compares all entity,
account and TOTP rows through a temporary identity guard before COMMIT.
The guard never interpolates a TOTP key or password hash into the SQL text.
The sequence advances to the complete new maximum.

For an already configured catalog, the same wrapper also supports the single
privacy transition `publish_target_labels: true` to `false`, with zero added
targets. Every existing target record, ID, parameter, secret reference, username,
default and trusted proxy must remain unchanged. The transaction still locks
and verifies the full pre/post census and identity/TOTP guard, but skips all
target SQL, including sequence changes. Reverse/no-op/combined append-and-hide
requests are rejected. Native `test_current_image.py --mode hide-labels` must
pass against the exact rebuilt image before this path is used operationally.
Network ownership also binds catalog bytes: use an applicable genuine reviewed
network transition or the documented exact-owned fresh network preparation;
never edit a ready receipt to disguise a metadata change.

After COMMIT, the complete census, all original account/TOTP rows, enrollment
and database health are checked again. The exact old `prepared.json` and old
config are archived under root-private `/data/current-migration` before any SQL.
Only after these checks may `prepared.json` be atomically replaced and its new
config/mapping binding confirmed. Source backup and original DATA are untouched.

A fresh restore without a previous `current-migration` journal is accepted.
For the isolated label-hiding transition only, the host wrapper also accepts a
verified completed historical SSH-append journal. It first validates the whole
normal restore and untouched backup, then binds all four root-private journal
files to the prior intent, successful terminal result, prior archived catalog
and preparation, and the actual current preparation/IDs. It records a new
single-use wrapper intent before atomically moving that journal without
replacement to `current-migration-history` inside the independent restored
copy. All four original bytes/inodes and hashes are retained. The original
backup and production DATA are never changed by this archival.

The separate `current-migration-history-intent.json` burns a partial archival
attempt. Existing history/archive intent, failed, incomplete, linked, changed
or mismatched journals refuse. Append requests still cannot adopt a historical
journal. Every attempted destination remains single-use, including failures
before SQL, uncertain commits and terminal-storage failures. Never delete a
journal or reuse a failed target; restore a new independent copy instead.

Before using privacy after a historical append, run the real host-wrapper
regression with an exact local image, a genuinely installed inactive appliance
unit and loaded enforcing profile. It creates only synthetic data and owned
network-none producer/stopped-consumer containers; it does not install or alter
units/profiles, connect targets, or fabricate backup/restore receipts:

```sh
sudo python3 -B tools/test_current_privacy_history.py \
  --image "$EXACT_CURRENT_CANDIDATE_IMAGE" --directory "$NEW_HISTORY_FIXTURE_CASE" \
  --backup-service guacamole-portal.service --apparmor-profile "$ENFORCING_PROFILE"
```

The fixture performs an actual PG append, a normal stopped backup/independent
restore, the host privacy wrapper and a real PG census/identity/sequence check.
Retain its receipt and original/backup bytes. It is not target authentication,
host installation, public HTTPS acceptance or a production promotion proof.

Container cleanup requires the exact full CID, fresh name/run label, immutable
image and consistent running/PID state. Missing ownership never permits a blind
stop or removal. After removal only `podman container exists` return code1 proves
absence; code0 or125 fails. A durable terminal receipt requires both verified
migration and cleanup. Cleanup or receipt-storage errors do not replace the
original operation error. Only validated safe metadata and output byte counts/
hashes are recorded; raw container stdout/stderr are not retained or printed.
Completion JSON must have the exact documented migration schema, bounded typed
hashes/mappings and timestamps; unexpected debug/secret fields cannot enter the
receipt. Mounted secret metadata uses each protocol's size limit (512 bytes for
RDP, 16KiB for SSH keys) and at most4096 bytes for the DB secret, without reading
target credential contents.

```sh
python3 -B -m unittest discover -s deploy/appliance -p test_current_migration.py -v
python3 -B -m unittest discover -s deploy/appliance/tools -p test_migrate_current.py -v
```

Actual PostgreSQL fixture plan, for later operator execution:

1. In a new isolated owned image fixture, create a synthetic current two-RDP
   catalog with confirmed synthetic TOTP. Record the complete account/TOTP row
   digest, RDP mapping and complete parameter census; stop PostgreSQL cleanly.
2. Produce a current cold backup and two independent normal restores using the
   reviewed helpers, retaining the current preparation receipt. Never use live
   identities, credentials, host networking or Windows endpoints in this fixture.
3. Run this wrapper against one exact candidate image and the first restore,
   appending a synthetic pinned SSH target. Verify SQL transaction acceptance,
   unchanged old IDs/parameter bytes/account digest/TOTP rows, new ID at the old
   maximum plus one, exact READ permissions, archived old receipt and final
   native database health. Stop/remove the owned fixture and prove absence.
4. Repeat from the second independent restore, and compare the same preserved
   identity and mapping outcomes. Restore both catalog versions independently
   and confirm each preparation binding with its corresponding config/image.
5. Use fresh restores for negative cases: wrong old config/receipt hash, changed
   RDP parameters, admin/group/sharing drift, unconfirmed TOTP, ID overflow and
   a SQL failure. They must not finalize preparation or permit target replay.
   Include SSH command quoting and real pre/post SQL guards; source unit checks
   alone do not establish that PostgreSQL accepted the generated transaction.
6. Preserve actual source/image/restore/SQL/cleanup receipts externally. Native
   SSH key, host-pin rejection, tmux attachment/persistence, browser and public
   admission still require their own accepted fixtures before deployment.
