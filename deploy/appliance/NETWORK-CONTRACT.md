# Private bridge host network contract

`network.py` plans, installs and checks a separate host firewall policy. It does
not create a bridge, a container, a route, a service, a forwarding sysctl or a
target listener. It never changes the previous appliance's network guard.
Instance configuration and catalog files remain outside the source tree.

The owner provisions a dedicated bridge with one appliance IPv4 address and
one host gateway address. No other workloads may share this bridge. The host
must already enable IPv4 forwarding and provide an up forwarding interface
with the configured SNAT address. Forwarded catalog endpoint routes must use
that interface. Targets inside the appliance bridge subnet are forbidden
except for explicit gateway-local endpoint tuples. The appliance must start
only after successful network apply/check. No active appliance may be attached
during initial policy installation.

The dedicated bridge must also have its own IPv4 `route_localnet=1` for the
supported host loopback publication path. `network.py` checks this prerequisite
without setting it. Bootstrap sets it only when creating the declared owned
bridge; a disabled value on an existing bridge is drift and fails checks.
Global `all`/`default` routing sysctls and other interfaces are outside this
operation.

## External configuration

Both `--config` and `--catalog` require absolute paths. Every directory and file
must be root owned and must deny group/other writes. Symlinks, duplicate JSON
keys, unknown fields, nonregular inputs and inputs over 128 KiB are rejected.
A root-controlled read-only configuration mount meets this contract if its
complete host path also meets these ownership requirements. Do not put inputs
under writable home or temporary directories.

Network schema 1 requires every field below. This example uses documentation
addresses; it does not describe an installation:

```json
{
  "schema_version": 1,
  "bridge": "portalb0",
  "subnet_ipv4": "192.0.2.0/29",
  "source_ipv4": "192.0.2.2",
  "gateway_ipv4": "192.0.2.1",
  "forward_interface": "uplink0",
  "snat_ipv4": "198.51.100.1",
  "host_backend_port": 8080,
  "local_endpoints": [{"hostname": "192.0.2.1", "port": 10222}]
}
```

Interface names use lowercase ASCII letters, digits and underscore, start with
a letter and contain at most 15 characters. Reserved/system bridge prefixes and
the previous appliance bridge are rejected. Source and gateway must be distinct
usable addresses in the canonical /24 through /30 subnet. Ports are integers
from 1 through 65535. Addresses are literal IPv4 unicast addresses, excluding
loopback, link-local, unspecified and all-ones broadcast addresses. There is
one forwarding interface and one explicit SNAT address.
`host_backend_port` is the appliance HTTP listener's internal TCP port. It does
not declare an appliance-initiated egress destination.

`Catalog.endpoints()` is the sole destination authority. `local_endpoints` is a
unique exact subset of those `(hostname, port)` tuples, with every hostname
equal to the configured gateway. An endpoint absent from the catalog cannot
be opened through the network file. All remaining catalog tuples use the
forwarding interface and SNAT. Classification is by the whole tuple, never a
host-wide allow. Network policy is TCP only; catalog protocol support remains
the catalog's responsibility.

Every gateway-local catalog TCP tuple is exclusive to the appliance. The exact
bridge, source IPv4 and ORIGINAL-direction new/established request must match;
traffic reaching that same gateway address and port through another host
interface or the host loopback path is dropped. This protects local forwarding
listeners from other routed guests and host-local callers. Other listener ports
and unrelated host interfaces retain their existing behavior.

## Policy and ownership

The fixed nftables table is `inet guacamole_portal_guard`. Its input and forward
base chains run at priority -150. Exact allowed IPv4 TCP tuples match source,
destination, port, interface and connection state. Replies to forwarded targets
require the exact reversed tuple and established state. Gateway-local input
permits only its exact tuples and new/established states. Every other packet
entering the bridge input path or entering/leaving the bridge forward path is
dropped, including UDP, IPv6, spoofed sources and unrelated established/related
connections. Traffic outside the appliance bridge and declared gateway-local
TCP tuples remains outside this policy. A later
network manager accept cannot reverse an earlier nftables drop.

Host-originated backend HTTP responses also traverse INPUT. Exact response
rules require the appliance source IPv4, configured backend source port,
established state and conntrack REPLY direction, with destination restricted to
the bridge gateway or `127.0.0.1`. Direct host connections use the gateway
destination; loopback publication through OUTPUT DNAT plus source rewrite uses
the loopback destination at the early INPUT hook. These rules preserve streamed
HTTP responses without permitting appliance-originated connections, including
already established ORIGINAL-direction connections using the backend source
port. Other host ingress addresses or publication methods require a separate
review and acceptance fixture.

Owned iptables/ip6tables chains use `GP_PORTAL_FWD`, `GP_PORTAL_IN` and the IPv4
`GP_PORTAL_NAT` chain. Their jumps must occupy the first positions of INPUT,
FORWARD and POSTROUTING, before libvirt reject or network manager accept rules.
IPv6 owned filter chains drop all traffic. IPv4 SNAT matches each forwarded
destination tuple separately. No shared chain is flushed, no complete ruleset
is restored and no old product chain or table is edited. Chain/table names and
state paths cannot be supplied through configuration. This version supports
one installation per host.

The fixed state directory is `/var/lib/guacamole-portal-network` (root, mode
0700), with mode 0600 `lock` and `state.json`. Apply obtains an exclusive
nonblocking lock. Check obtains a shared nonblocking lock and never creates a
directory, lock, receipt or firewall object. Both reject unsafe state ancestry.

After collision checks and an nft syntax preflight, apply durably records
`intent` before its first firewall mutation. It installs the independent deny
guard before creating accepts, records the normalized live guard hash, and
records `ready` only after exact rule, jump ordering, route and bridge checks.
Failures record `failed` and the exception type when receipt storage remains
available. A crash or storage failure can leave `intent`; this is unresolved
state. A receipt also contains the complete derived policy, its SHA256 and the
current kernel boot ID.

Repeated apply of an identical ready policy performs checks only. Missing,
partially installed, modified, differently configured or unresolved state is
never silently repaired or replaced. After a cold boot, apply can recreate an
identical previously ready policy only when its recorded valid boot ID differs
from the current boot ID and every owned table, chain and shared jump is absent.
It first preserves the exact old receipt in an exclusive mode 0600 archive,
syncs the archive, and then records a new intent with the current boot ID and
archive hash. Partial state, same-boot disappearance, missing boot identity,
different policy and unresolved receipts all require operator review. Check
never recreates anything. An existing
guard, owned chain or shared owned-prefix reference without the matching ready
receipt is a collision. Retain failed receipts and review live state before
operator recovery. This module does not provide removal or automatic rollback;
failure deliberately retains any installed deny guard. Root must explicitly
manage persistence and operator recovery. Firewall snapshots are not used as
automatic rollback input.

## Commands and Python API

```sh
sudo python3 deploy/appliance/network.py plan --config /etc/portal/network.json --catalog /etc/portal/catalog.json
sudo python3 deploy/appliance/network.py apply --config /etc/portal/network.json --catalog /etc/portal/catalog.json
sudo python3 deploy/appliance/network.py check --config /etc/portal/network.json --catalog /etc/portal/catalog.json
python3 -m unittest discover -s deploy/appliance -p test_network.py -v
```

`plan` reads only the two protected inputs and prints policy, policy hash, nft
source, planned argv arrays and fixed state directory as JSON. It executes no
host command and writes no state. A plan is review material, not host acceptance.
`apply` and `check` require root. Host tools are fixed `/usr/sbin/` executables,
with a fixed environment, no shell and a ten-second timeout per invocation.
Failures return a nonzero process exit. Success prints its policy hash.

Pure Python entry points are `parse_config(value) -> Config`,
`policy(config, catalog) -> dict`, `guard_text(policy) -> str`,
`plan(policy) -> dict`, and `digest(value) -> str`. A caller may obtain a policy
from protected files using `load_inputs(config_path, catalog_path)`. Importing
the module has no effects. Pure entry points perform no command execution,
network requests, secret reads or writes. `Config` and derived policy values
must come from these validators; do not construct or mutate them by hand.

Low-level `apply(policy)` and `check(policy)` are for an already root-validated,
locked caller with the fixed secure state directory. The CLI performs that
locking and directory validation. These functions do not themselves acquire a
lock. Runtime callers should invoke the CLI or provide the same lifecycle.

## Evidence and remaining acceptance

The unit suite is host inert. It interprets generated guard matches against
synthetic packets, exercises strict inputs, transaction receipts, collision
refusal, ordering, changed policy rejection and read-only check behavior. It
does not invoke nft, iptables, network namespaces, containers or production.

The separate kernel fixture is opt in:

```sh
sudo python3 -B deploy/appliance/tools/test_network_namespace.py --directory /absolute/new/private-evidence
```

It proves that both network and mount namespace inodes differ from its real
parent before any mount, link, sysctl or firewall mutation. It then makes mount
propagation private, builds a minimal tmpfs root with read-only system binaries
and source, and mounts the unchanged product state path only inside that root.
No mountpoint is created in the host's `/var/lib`. Three additional anonymous
peer network namespaces provide synthetic source, target and untrusted machines. They
use documentation addresses and no host interfaces, routes, firewall tables,
containers, instance files or secrets. Every peer is independently checked to
differ from the host/router namespaces. The process tree inherits at most two
CPUs, has a 145-second inner alarm and a 170-second outer deadline, and is
terminated/reaped in finally. If unshare is unavailable or denied, it fails
without falling back to host networking.

Kernel checks include positive controls before filtering, actual CLI
apply/check with iptables-nft/native nft, exact forwarded SNAT and local TCP,
direct and loopback-published chunked HTTP streams, rejection of an already
established ORIGINAL-direction connection with backend source port, denied
wrong tuples/UDP/IPv6/spoofing despite broader accepts, gateway-local listener
exclusivity against another ingress interface and host-local callers while
preserving unrelated listeners, shared reject ordering,
unprepared/drift checks and read-only ready reapply/check. IPv6 neighbors are
configured explicitly so negative controls cannot pass because discovery
failed. Receipts preserve source hashes, namespace proofs, results, tool
versions and cleanup verification in the new evidence directory. No private
receipt belongs in source control. Boot-ID recreation is unit tested with
synthetic identities; this fixture never changes the real host boot identity.

Before deployment, independently validate actual deployment network-manager
publication, boot ordering and receipt recovery on the restored appliance
fixture. Verify the
dedicated bridge has only the intended appliance peer and preserve the old
appliance's guard unchanged. Runtime startup and monitoring must enforce this
check; a root firewall reset after a successful check cannot be prevented by
this script. Root users and privileged network managers remain trusted.
