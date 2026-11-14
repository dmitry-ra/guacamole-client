# Stopped CURRENT DATA and file promotion

`tools/promote_current.py` stages, applies once, or explicitly rolls back one
reviewed stopped promotion. Source preparation and unit tests do not authorize
operator invocation. This tool never stops/starts services, operates nginx,
installs network/transport policy, authenticates to an endpoint, publishes a
readiness marker or manufactures admission evidence.

The only installation destinations are /etc/guacamole-portal/config.json,
network.json and release.json; /opt/guacamole-portal/{host.py,catalog.py,
network_service.py,network_upgrade.py}; and /var/lib/guacamole-portal/data.
Other files are not installed or deleted. A new explicit root-private case
holds archives, manifests, journals and retained DATA. Original file bytes,
owner/group/modes and DATA directory device/inode identity are bound by the plan.

Run from a separately frozen, root-protected source bundle containing the
reviewed new parsers and existing dependency tools, using Python -B. Imported
host/catalog/network-service/upgrade source paths must not be the operating
module destinations that this process will replace. The bundle hashes must
remain unchanged through rollback. Root ancestry, single-link regular files,
bounded reads and no-follow opens protect source/proof inputs. Existing host,
bootstrap and firewall locks are acquired in that order without creating locks.

The strict input JSON has these keys:

- schema: integer1; new_data: the independent restored/migrated DATA path.
- files: exactly config, network, release, host.py, catalog.py,
  network_service.py and network_upgrade.py. Each value is {path,sha256} for
  a separate reviewed root-protected source file. No destination override exists.
- migration, restore and backup: {path,sha256} for the actual CURRENT wrapper
  receipt.json, normal restore result.json and final stopped cold-backup
  result.json. Keep their complete original private case directories available.
- network_plan, transport_server_plan, transport_client_plan, terminal_plan:
  {path,sha256} for exact independently reviewed plan.json files. Server and
  terminal cases are protected copies of the complete HEL evidence archives;
  no private key is copied or read. Plans can precede their actual installation.
- primary_gates: exactly build, auth, native-ssh, mixed-browser and kernel,
  each an actual reviewed {path,sha256} primary receipt. Image-specific gates
  must match the new image and completed fixtures must pass with cleanup. Each
  role requires its actual producer scope/checks, not a generic passed flag;
  receipt hashes cannot be reused across roles. Mixed evidence must crosslink
  the exact native refusal receipt and prove exact BMP input, PTY resize,
  reconnect PID/start/counter, canvases and logout.

New release.json uses the existing strict host release schema. Physical
network/backend/AppArmor bindings must remain unchanged. Its protected
acceptance_evidence_path must contain externally reviewed JSON whose image_id
matches the new release, primary_receipts maps the above five names to their
exact hashes, and migration_receipt_sha256 matches the actual promotion-target
migration receipt. The promotion tool only validates/hash-binds this evidence;
it does not generate a review or relabel a pending gate as passed.

```
sudo python3 -B /absolute/protected-source/tools/promote_current.py stage \
  --inputs /absolute/private/inputs.json --expected-sha256 INPUT_JSON_SHA256 \
  --directory /absolute/new-private-promotion-case \
  --maintenance-review /absolute/private/stage-review.json
sudo python3 -B /absolute/protected-source/tools/promote_current.py apply \
  --directory /absolute/private-promotion-case --expected-sha256 PLAN_SHA256 \
  --maintenance-review /absolute/private/apply-review.json
sudo python3 -B /absolute/protected-source/tools/promote_current.py rollback \
  --directory /absolute/private-promotion-case --expected-sha256 PLAN_SHA256 \
  --maintenance-review /absolute/private/rollback-review.json
```

Each maintenance review is a root-private exact JSON object with schema1,
operation (promote-current-stage, promote-current-apply or rollback-current),
binding_sha256, portal_closed:true, sessions_cleared:true, closed_route and
session_census ({path,sha256}), reviewed_at and expires_at. Stage binds the input
JSON hash; apply/rollback bind the final plan hash. Timestamps must be finite,
current and valid for at most300seconds. The operator supplies fresh actual
closed-route/session evidence. Root must separately reread remote installed
file hashes through strict administrative SSH before authorizing the review;
the promotion tool performs no remote reads or readiness claims.

Before stage and each critical mutation, the fixed application and transport
units must already be loaded/inactive with PID0, readiness absent and no owned
candidate container remaining. Both DATA trees must be stopped/exclusive,
independent and on the case filesystem. The final stopped original's complete
manifest must equal the actual cold backup and backup tree. The independent
backup namespace cannot overlap either DATA tree, and original/backup/restored
directory identities must all differ. The independent
normal restore and completed CURRENT wrapper/journal must bind that backup,
original/new configs, new image, old IDs, unchanged identity/TOTP digest and new
prepared mapping. The append-only current_migration.plan contract is reused.
The root-owned migration journal is pinned below the intentionally PG-owned
DATA directory; symlinks and non-private journal members are refused.

Apply additionally requires the completed network proof through
network_upgrade.definition_binding, unchanged physical network/bridge identity,
the actual current new firewall policy/native guard check and matching ready
result. Transport results must bind their exact plans/candidate file hashes;
MAIN client files are reread locally. Copied HEL server/terminal results are
historical installation proofs only; they do not establish remote loaded policy,
transport activation or authentication. Both local units remain inactive.

A new fsynced apply intent precedes effects. Original DATA is renamed into
case/original-data, restored DATA is renamed to the fixed production path, then
only reviewed files are replaced atomically with original modes. A missing new
network_upgrade.py is installed root0600. Fresh review/stopped checks occur after
expensive guards, directly before renames/replacements and after final progress
fsync before success. Source/destination drift and stale consent stop further
effects. There is no automatic rollback or replay after an uncertain attempt.

Explicit rollback recognizes only the exact partial/complete DATA locations
and known old/new installed file states. Original DATA must still match its
entire archived manifest. A privately tested promoted cluster may legitimately
contain new WAL/history: its current full manifest is recorded and that DATA is
retained separately as case/promoted-data. Original DATA returns with the same
directory inode; original files return with exact bytes/owner/group/modes.
Recognized partial replacement temporaries are retained for audit; foreign
files/locations are refused. A newly added unreferenced root0600 module may
remain for audit. No DATA or foreign file is deleted.

After rollback, restore the original installed release/config/network selection
before invoking the separate network rollback tool, whose checkpoint binds the
old release SHA. Starting services, verifying transport/native sessions, private
and public browser gates and opening the route remain separate operator actions.

`test_promote_current.py` contains inert review/privacy/allowlist checks and
root-owned synthetic /run filesystem cases. All service/engine/network actions
are mocked; no real DATA, authentication or lifecycle operation occurs. Tests
exercise provenance, original inode/mode preservation, WAL retention, partial
renames/files, foreign-state refusal, no replay and clock-steered expiry during
engine checks, replacements and final progress durability.
