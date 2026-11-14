# Isolated additive firewall transaction fixture

`tools/test_network_upgrade_namespace.py` exercises real nft/iptables kernel
commands, packets and rollback for the additive gateway SSH network extension.
It reuses the existing `test_network_namespace.py` outer unshare/chroot/tmpfs/
process-group harness and its peer/socket/probe roles. Every network/sysctl/
firewall mutation occurs only after the inherited network and mount namespace
IDs differ from the host and match the exact parent. Source is mounted read-only;
product state and links exist in the private tmpfs root and network namespaces.
The outer host network namespace is never inspected for rules or changed.

Use a new evidence directory under existing root-protected ancestry, outside
the checkout. The harness creates it root-owned mode0700 and never reuses it.
At most two CPUs, an inner145second alarm and outer170second wait are retained;
owned children are terminated/reaped and the outer namespace identities and
absent owned process group are independently checked after cleanup.

```sh
sudo python3 -B deploy/appliance/tools/test_network_upgrade_namespace.py --directory /root/new-portal-network-upgrade-case
```

Create/use requires existing local iproute2, nftables and iptables-nft tools,
root and permitted Linux namespace operations. No downloads, package/service
changes, production engine calls or authentication occur. Evidence remains in
the explicit private directory; deleting retained evidence is a separate owner
decision, not automatic cleanup. No host networking configuration is installed.

The synthetic old policy has two forwarded RDP TCP tuples and one gateway-local
RDP TCP tuple. The new catalog/network pass the actual `network_upgrade.extension`
validator and add one gateway-local SSH-designated TCP tuple on the same bridge.
The fixture calls the actual policy generator, guard transaction renderer,
insertion command/state derivation and verification helpers; kernel commands
are never mocked.

Required evidence includes:

- Positive pre-policy TCP/UDP/IPv6/listener controls, so later denial is causal.
- A real nft delete/recreate batch with a final semantic error leaves the old
  guard and exact iptables chains intact; old RDP/SNAT and backend replies work.
- Actual atomic owned-guard replacement and every precise iptables insertion
  match the derived intermediate chain states, preserving unrelated rules/table.
- The added gateway TCP listener accepts only the configured application source.
  Router-originated loopback-to-gateway, foreign bridge source and other-interface
  connections fail; application UDP and IPv6 to proven listeners fail.
- Existing RDP TCP/SNAT and direct/loopback-published chunked backend HTTP work
  before, during and after the upgrade; unrelated host listener access remains.
- The actual TCP listener census refuses rollback while the new listener exists,
  without changing rules. After stopping that owned listener, precise reverse
  full-specification deletions and atomic old-guard restoration reproduce the
  entire original chain snapshot and unrelated table. Old traffic still works.

`receipt.json` contains the inherited cleanup/namespace proof and kernel checks.
`upgrade-sources.json` additionally binds every contract/controller/harness source
hash and the exact kernel receipt SHA256; `sources_unchanged` must be true.
Accept the run only when both receipts and the command exit confirm success.
Failure logs and partial cases are retained for review and are never replayed.

This is kernel policy and transaction evidence only. The listener is synthetic
TCP/UDP JSON traffic, not native SSH authentication, an RDP desktop or tmux.
No actual systemd inactive/boot condition, Podman network lifecycle, installed
maintenance review or production upgrade proof is fabricated or claimed.
The production wrapper separately requires real stopped services/empty bridge,
fresh exact reviewed evidence and durable ownership/proof receipts. Unknown nft
after-effect dispatch remains a manual fail-closed case, not an automatic replay.
