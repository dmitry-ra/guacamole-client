# Dedicated network bootstrap

`network_service.py` supplies the host-network prerequisite for the portal and
the separately supervised RDP transport. It uses the unchanged `network.py`
policy implementation. It is not an installer, migration manager or removal
tool. Importing it performs no host action. Its tests mock every host command.

Install the reviewed `network_service.py`, `network_upgrade.py`, `host.py`,
`network.py` and `catalog.py` together under root-protected
`/opt/guacamole-portal`. The upgrade contract is an unconditional import even
for initial preparation. Install
`guacamole-portal-network.service` in the system service directory. The portal
and transport units must both require and start after this network unit. The
network unit orders itself after network-online, libvirtd and AppArmor, and
before both consumers. It remains active after successful completion; stopping
the unit does not delete the bridge, network or firewall policy. Normal Podman
last-container teardown can remove the kernel bridge. The host launcher must
therefore invoke `network_service.py boot` before its empty-bridge guards on
every start, including application restarts while this oneshot remains active.

Inputs remain the fixed protected files `/etc/guacamole-portal/config.json`,
`network.json` and `release.json`. The catalog and network schemas are described
in NETWORK-CONTRACT.md. All network names, interface names, addresses and
destination tuples come from those external files. No previous appliance
interface or firewall object is selected or changed.

Initial private setup may use this exact four-key provisional release:

```json
{
  "schema": 1,
  "podman_network": "portal-test",
  "config_sha256": "<64 lowercase hex>",
  "network_sha256": "<64 lowercase hex>"
}
```

The strict complete host release is also accepted. Bootstrap validates its
schema but does not open acceptance evidence, image, data, secrets or AppArmor
files. This permits private actual-RDP acceptance before admitting the host
launcher. Replacing the provisional release with a final release does not
change network ownership when these four values remain identical. The final
host launcher independently requires its complete admission contract.

The operator must stage protected inputs and review the network policy before
the first explicit preparation:

```sh
sudo python3 -B /opt/guacamole-portal/network.py plan --config /etc/guacamole-portal/network.json --catalog /etc/guacamole-portal/config.json
sudo python3 -B /opt/guacamole-portal/network_service.py prepare
sudo python3 -B /opt/guacamole-portal/network_service.py check
```

Preparation refuses an existing network with the declared name, an existing
declared kernel interface, another network using that interface or overlapping
subnet, existing owned firewall state, and every existing consumer or attached
bridge peer. A matching product label alone does not authorize adoption. It
creates one rootful Podman bridge network definition with the declared
interface/subnet/gateway, DNS disabled,
IPv6 disabled and `internal=false`. Its labels include `guacamole.portal=1`
and a binding digest. Network creation is issued once; its full immutable ID
is captured and checked. It then creates exactly the declared kernel bridge,
adds its one gateway/prefix and brings it up. An exact binding alias marks that
bridge. Creation sets only that declared bridge's IPv4 `route_localnet=1`,
required for the supported loopback publication path. Finally it invokes
`network.py apply` and `check`. No container is created or started. It changes
no global forwarding, `all` or `default` sysctl and no other host interface;
existing forwarding/route prerequisites still apply.

State is under `/var/lib/guacamole-portal/network-bootstrap`, root-owned mode
0700, with mode 0600 lock and receipts. A nonblocking exclusive lock serializes
prepare/boot. Read-only check takes a shared lock and creates nothing. Durable
atomic `intent` precedes the first mutation, `ready` follows exact checks, and
an exception records `failed` where storage remains available. Prior ready
receipt bytes are preserved in exclusive archives before a new attempt, with
their SHA256 recorded in the new intent. Failures retain existing objects
and evidence; no shared chain is flushed and no rollback is attempted. A
definite network-create failure additionally preserves up to 8192 bytes of
stderr, its full SHA256 and the network-only argv in a private diagnostic JSON
file. Raw stderr is never printed. Uncertain timeout results remain unresolved.

Ordinary service startup runs `boot`, which requires the exact ready bootstrap
receipt and existing immutable Podman definition. It never creates or adopts a
missing network definition. An absent kernel bridge may be recreated after
a valid changed boot identity, with a matching prior-boot ready firewall
receipt and every owned table, chain and jump absent. In the same boot, the
matching ready firewall receipt must instead retain the exact policy hash,
current boot identity and guard hash, and `network.verify` must verify every
live owned rule, guard and shared-jump order without requiring the absent link.
Same-boot missing, modified or partial firewall state cannot authorize link
recreation. These inspections run under the network module's shared lock;
the subsequent policy CLI
performs its own exclusive locked transaction and rechecks its prerequisites.
Existing links and network consumers are checked before mutation. Root and
privileged network managers remain trusted; service ordering excludes the
product consumers during this operation.

The bridge-recreation intent binds the exact archived prior bootstrap bytes
and exact firewall receipt bytes by SHA256, plus its inspection mode, boot,
policy hash and (for same-boot recreation) live guard hash. The network
definition, consumers and firewall proof are checked again immediately before
link creation. Changed proof fails the attempt rather than being accepted as
a new basis. No firewall mutation occurs before the bridge exists; the existing
policy is then applied/checked through the normal module lifecycle.

An existing bridge must have the exact ownership alias, address, bridge type,
UP flag and bridge-local `route_localnet=1`. A value of zero is drift and fails
inspection; existing interfaces are never silently retuned. The same policy
is then applied/checked through `network.py`, whose
separate receipt controls permitted cold-boot firewall recreation. Partial,
changed or same-boot missing firewall state is not repaired. Failed or interrupted
bootstrap receipts require operator inspection; never delete receipts and
retry blindly. No automated removal or partial-operation replay is provided.

Source review found that the namespace fixture sets bridge-local
`route_localnet=1`, while the original bootstrap omitted it and the tested
network manager skips setting it on an existing bridge. This closes a source
prerequisite gap. An actual same-container contrast established its HTTP
effect: direct backend HTTP succeeded with the bridge value zero, while
loopback-published HTTP failed; changing only this owned bridge value to one
made loopback-published HTTP succeed with the same container and unchanged
firewall policy. Cleanup passed. The deployment journal retains the private
primary receipt; unit tests alone do not establish this host outcome.

The original implementation created the addressed bridge before the managed
Podman definition. This order is incompatible with Podman 5.7.0's subnet
validation: [networkCreate](https://raw.githubusercontent.com/containers/podman/v5.7.0/vendor/go.podman.io/common/libnetwork/netavark/config.go)
obtains used subnets before validating the new network, and
[GetUsedSubnets](https://raw.githubusercontent.com/containers/podman/v5.7.0/vendor/go.podman.io/common/libnetwork/internal/util/util.go)
includes live host interface subnets. The corrected order creates the
definition while the bridge is absent, then materializes the bridge before
firewall installation. The original stderr was not retained, so this source
finding explains the likely failure mechanism rather than proving its message.

An operator who has reviewed that specific failed attempt may invoke the
separate bounded recovery command with the SHA256 of its exact receipt bytes:

```sh
sudo python3 -B /opt/guacamole-portal/network_service.py recover-failed-prepare --failed-receipt-sha256 REVIEWED_EXACT_RECEIPT_SHA256
```

This accepts only the original failed receipt schema, same boot and binding,
null network ID and definite RuntimeError. It requires no dedicated network
definition, no overlapping/foreign definition, no firewall receipt or owned
firewall objects, and the exact owned empty addressed bridge. It preserves the
original receipt bytes in an exclusive durable archive, records recovery intent,
then rechecks ownership, consumers, network absence and firewall absence. Only
then may it delete that declared bridge, create the network definition and
recreate the bridge before applying/checking policy. No other interface is
selected. It cannot recover uncertain timeouts, active consumers, different
configuration, partial firewall state, or another failed recovery. Recovery
failure retains its archive and unresolved state; do not replay it.

```sh
python3 -B -m unittest discover -s deploy/appliance -p test_network_service.py -v
```

The inert tests cover provisional/final release inputs, literal argv, mutation
order, existing-object collisions, foreign consumers, exact immutable network
ownership, changed-boot conditions, bounded stderr and hash-bound recovery
ordering/refusal. They do not
establish actual Podman/kernel behavior, service boot acceptance, AppArmor or
end-to-end RDP. Those remain deployment/rehearsal checks by the operator.

One separately reviewed additive RDP-to-SSH policy extension can retain the
original physical resource binding through a protected immutable upgrade proof.
The normal selected binding must still match the exact current catalog/network
bytes and policy; labels/alias use the verified original definition binding.
Ordinary receipts without this extension retain their existing behavior.
See NETWORK-UPGRADE.md for archives, boot validation and explicit rollback.
