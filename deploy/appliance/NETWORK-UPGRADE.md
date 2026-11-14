# Reviewed additive SSH network upgrade

`tools/upgrade_network.py` is a separate root operator tool. It prepares a
reviewable plan, applies one narrowly additive firewall change, or explicitly
rolls back a known attempted change. It never changes config/release/catalog
files, DATA, secrets, accounts, routes, network definitions or service state.
No service reload, restart, activation or transport connection occurs.

Source-only unit acceptance is available. Actual isolated kernel transaction,
new listener exposure controls, mixed deployment, rollback and later-boot
acceptance remain operator gates; unit results do not establish them.

The starting point must be an existing unupgraded owned network and current-boot
ready firewall. The portal and transport units must already be inactive, the
readiness marker absent, no appliance containers remaining, and the exact
owned kernel bridge empty. Normal last-container teardown can remove the
kernel bridge; the operator must first use the existing reviewed bootstrap
procedure to restore it under the original selection. This tool does not
create or repair resources. All operations take the existing host, bootstrap
and firewall locks, in that order. Each CLI run has a 180-second deadline.

The destination catalog uses schema2 and appends SSH targets to an RDP-only
catalog. Every original target record and portal field must remain exactly
equal, including explicit versus omitted optional fields. Every other network
field stays equal. The only new network permissions are the appended SSH
targets' distinct gateway-local TCP tuples; existing tuples, forwarded
destinations, SNAT, interfaces, subnet, source, gateway and backend port stay
equal. A second successful extension is refused.

Install the reviewed `network_upgrade.py` beside `network_service.py` on the
host, and install the reviewed tool with its existing `prepare_instance.py`
helper. Preserve root ownership and non-writable ancestry. The small bootstrap
hooks depend on that new module; installing the hooks alone is incomplete.
This changes host tooling and does not require a runtime image rebuild.

Preparation, using external protected files and a new private case directory:

```sh
sudo python3 tools/upgrade_network.py prepare --directory /protected/new-case \
  --old-network /protected/original-network.json \
  --new-network /protected/candidate-network.json \
  --old-catalog /protected/original-catalog.json \
  --new-catalog /protected/candidate-catalog.json
```

The installed release and installed input bytes must still select the original
policy. Preparation checks actual ownership, receipt, current boot, native
firewall rules, independent guard and added-port listener absence. It archives
the exact original bootstrap/firewall receipts and both pairs of config bytes,
with private mode0600 and fsync. `plan.json` binds those hashes, source hashes,
network ID, boot IDs, release SHA, complete relevant shared-chain snapshots and
the precise insert commands. The nft replacement is syntax-checked only.

Independently review that plan and create an external root-private JSON review:

```json
{
  "schema": 1,
  "operation": "add-local-ssh",
  "plan_sha256": "EXACT_PLAN_SHA256",
  "portal_closed": true,
  "sessions_cleared": true,
  "closed_route": {"path": "/protected/installed-closed-route.conf", "sha256": "EXACT_SHA256"},
  "session_census": {"path": "/protected/after-close-census.json", "sha256": "EXACT_SHA256"},
  "reviewed_at": 1800000000,
  "expires_at": 1800000240
}
```

Times are Unix seconds; the review must already be effective and expire within
300 seconds of review. The reviewer must establish actual public route closure
before the native session census, clearance of owner sessions, and an inactive
candidate/transport. These are external operational facts, not inferred by this
tool from a config file or a process count. The tool checks the exact protected
evidence bytes and repeats actual inactive-service/empty-bridge checks and
approval freshness before every policy or ready-receipt replacement, including
between temporary receipt fsync and rename. It archives the reviewed evidence
for historical boot validation. Error/intent diagnostics can persist after
expiry; expiry never authorizes another policy mutation.

```sh
sudo python3 tools/upgrade_network.py apply --directory /protected/new-case \
  --plan-sha256 EXACT_PLAN_SHA256 --review /protected/fresh-review.json
```

Apply never replays an existing intent. Before the first permission insertion,
it atomically deletes and creates only the owned nft table in one transaction.
The new guard protects each added listener on every host interface and permits
only the exact appliance source through the exact bridge. It then inserts only
new input accepts and protected listener jumps, retaining every existing rule
and the full shared-chain remainder. It neither flushes nor rebuilds chains.
Unexpected guard/rule drift stops the attempt. Complete native policy
verification precedes ready receipts. Native stdout/stderr is never saved or
printed; terminal output contains fixed status/action/error class only.

`upgrade-proof.json` binds the original archive hashes, old and new selected
bindings, original network ID, historical boot IDs, exact reviewed plan and
maintenance evidence. Bootstrap's `definition_binding` retains the immutable
old network label and bridge alias; its ordinary `binding` selects the new
catalog/network/policy hashes. Bootstrap verifies the protected complete proof,
recomputes the strict extension and requires the original ready ownership and
firewall archives. There is no label adoption, unofficial engine state edit,
network recreation or receipt-only readiness shortcut. Ordinary boot still
checks the currently selected new policy. Later bridge recreation uses the
verified original alias, preserves the proof, and records a fresh current boot
and guard. Historical approval does not expire on reboot; archived evidence
must remain protected and intact. The live public route may reopen afterward.

After success, root must independently install/bind the new external selection,
review admission and activate/test transport and portal. During the interval
before that selection change, old selection and upgraded receipts deliberately
disagree and startup refuses. This tool cannot finish deployment on its own.

Rollback requires the original release selection still installed (or already
restored externally), a new fresh review for the same plan, inactive portal and
transport, an empty owned bridge, and a fresh native TCP socket census proving
every added port absent, including wildcard and IPv6 listeners. Never drop the
new guard while its added listener remains. No owner session is stopped here.

```sh
sudo python3 tools/upgrade_network.py rollback --directory /protected/new-case \
  --plan-sha256 EXACT_PLAN_SHA256 --review /protected/fresh-rollback-review.json
```

Only an exact known prefix of durable insertion intents, unchanged shared
rules, an exact owned receipt and a known guard can be rolled back. The tool
deletes only its exact inserted rules, checks added-port listener absence again,
then atomically restores the original guard. Only after exact original
physical/firewall verification does it durably restore original receipt bytes.
Backups, DATA and source files stay untouched. A failure after effect is
reconciled by fresh observation, never by reissuing the insertion. Unknown nft
outcome before its new hash was recorded, unrelated drift, a failed rollback or
interrupted attempt requires independent operator containment/review. Rollback
itself is single-use and never automatically retried. Terminal failure records
preserve the original exception even if diagnostic persistence also fails.

Inert checks (the second command uses synthetic root-owned files under /run;
all engine, service, socket, kernel and firewall calls are mocked):

```sh
python3 -m unittest discover -s deploy/appliance -p 'test_network_service.py'
sudo env PYTHONPATH=deploy/appliance:deploy/appliance/tools \
  python3 -m unittest deploy/appliance/tools/test_upgrade_network.py
```

Before operational approval, run the generated nft replacement and exact
iptables insert/inverse sequence in a new isolated network namespace. Verify
unrelated shared rules survive, the new listener is denied on unrelated host
interfaces/loopback, only its declared bridge/source can connect, expiry and
partial failure retain the guard, rollback refuses a lingering listener, and
normal/cold boot verify/recreate with historical proof and fresh guard receipts.
