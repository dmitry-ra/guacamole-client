#!/usr/bin/env python3
"""Owned host firewall policy for an externally provisioned private bridge."""

import argparse
from dataclasses import asdict, dataclass
import fcntl
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import shlex
import stat
import subprocess
import time

import catalog

PREFIX = "GP_PORTAL"
NFT_TABLE = "guacamole_portal_guard"
STATE = Path("/var/lib/guacamole-portal-network")
LIMIT = 128 * 1024
BINARIES = {name: "/usr/sbin/" + name for name in
            ("nft", "iptables", "ip6tables", "ip")}


def ipv4(value):
    if not isinstance(value, str):
        raise ValueError("Literal IPv4 address required")
    address = ipaddress.IPv4Address(value)
    if (address.is_unspecified or address.is_multicast or address.is_loopback
            or address.is_link_local or str(address) == "255.255.255.255"):
        raise ValueError("Unicast, non-local IPv4 address required")
    return str(address)


def interface(value, bridge=False):
    if not isinstance(value, str) or not re.fullmatch(r"[a-z][a-z0-9_]{0,14}", value):
        raise ValueError("Literal interface name required")
    if value == "lo" or bridge and (value == "wrdp0" or re.match(
            r"(?:eth|en|wl|virbr|docker|podman|cni|tun|tap|veth|bond|team)", value)):
        raise ValueError("A separate product bridge is required")
    return value


def endpoint(value):
    catalog.fields(value, {"hostname", "port"})
    return ipv4(value["hostname"]), catalog.port(value["port"])


@dataclass(frozen=True)
class Config:
    bridge: str
    subnet_ipv4: str
    source_ipv4: str
    gateway_ipv4: str
    forward_interface: str
    snat_ipv4: str
    host_backend_port: int
    local_endpoints: tuple


def parse_config(value):
    catalog.fields(value, {"schema_version", "bridge", "subnet_ipv4", "source_ipv4",
                           "gateway_ipv4", "forward_interface", "snat_ipv4", "host_backend_port", "local_endpoints"})
    if type(value["schema_version"]) is not int or value["schema_version"] != 1:
        raise ValueError("Unsupported network configuration schema")
    bridge = interface(value["bridge"], bridge=True)
    forward = interface(value["forward_interface"])
    if bridge == forward:
        raise ValueError("Forwarding interface must differ from private bridge")
    if not isinstance(value["subnet_ipv4"], str):
        raise ValueError("Literal IPv4 subnet required")
    subnet = ipaddress.IPv4Network(value["subnet_ipv4"], strict=True)
    if not 24 <= subnet.prefixlen <= 30:
        raise ValueError("A dedicated /24 through /30 bridge subnet is required")
    source, gateway = ipv4(value["source_ipv4"]), ipv4(value["gateway_ipv4"])
    for address in (source, gateway):
        if (ipaddress.IPv4Address(address) not in subnet
                or ipaddress.IPv4Address(address) in (subnet.network_address, subnet.broadcast_address)):
            raise ValueError("Source and gateway must be usable bridge subnet addresses")
    if source == gateway:
        raise ValueError("Source and gateway must differ")
    local = value["local_endpoints"]
    if not isinstance(local, list) or len(local) > 32:
        raise ValueError("Bounded explicit local endpoint list required")
    local = tuple(sorted(endpoint(item) for item in local))
    if len(set(local)) != len(local) or any(host != gateway for host, _ in local):
        raise ValueError("Local endpoints must be unique bridge gateway tuples")
    return Config(bridge, str(subnet), source, gateway, forward,
                  ipv4(value["snat_ipv4"]), catalog.port(value["host_backend_port"]), local)


def protected_read(path, limit=LIMIT):
    """Traverse root-owned non-writable directories without following symlinks."""
    path = Path(path)
    if not path.is_absolute() or ".." in path.parts:
        raise ValueError("Absolute protected path required")
    descriptor = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
    try:
        for index, part in enumerate(path.parts[1:]):
            final = index == len(path.parts) - 2
            flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
            if not final:
                flags |= os.O_DIRECTORY
            child = os.open(part, flags, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
            meta = os.fstat(descriptor)
            if meta.st_uid != 0 or meta.st_mode & 0o022:
                raise ValueError("Root-owned, non-writable input ancestry required")
            if final and (not stat.S_ISREG(meta.st_mode) or meta.st_size > limit):
                raise ValueError("Bounded regular input required")
        data = os.read(descriptor, limit + 1)
        if len(data) > limit:
            raise ValueError("Input exceeds size limit")
        return data
    finally:
        os.close(descriptor)


def load_inputs(configuration, catalog_path):
    config = parse_config(json.loads(protected_read(configuration),
                                     object_pairs_hook=catalog.unique_object))
    targets = catalog.parse(json.loads(protected_read(catalog_path),
                                      object_pairs_hook=catalog.unique_object))
    return policy(config, targets)


def policy(config, targets):
    """Derive all permitted TCP destinations exclusively from Catalog.endpoints()."""
    all_endpoints = tuple(sorted({(ipv4(host), catalog.port(port))
                                  for host, port in targets.endpoints()}))
    if not 1 <= len(all_endpoints) <= 32:
        raise ValueError("Bounded nonempty catalog endpoints required")
    local = set(config.local_endpoints)
    if not local <= set(all_endpoints):
        raise ValueError("Local endpoints must be a catalog subset")
    forwarded = tuple(item for item in all_endpoints if item not in local)
    subnet = ipaddress.IPv4Network(config.subnet_ipv4)
    if any(ipaddress.IPv4Address(host) in subnet for host, _ in forwarded):
        raise ValueError("Bridge subnet endpoints require explicit gateway-local classification")
    source = config.source_ipv4 + "/32"
    fwd, inp, nat = (PREFIX + suffix for suffix in ("_FWD", "_IN", "_NAT"))
    forward_rules, input_rules, nat_rules = [], [], []
    # Host-originated direct and loopback-published backend connections return
    # through INPUT. Match conntrack REPLY direction as well as the exact port;
    # unrelated appliance-originated established connections remain denied.
    for destination in (config.gateway_ipv4, "127.0.0.1"):
        input_rules.append(["-i", config.bridge, "-s", source, "-d", destination + "/32",
                            "-p", "tcp", "-m", "tcp", "--sport", str(config.host_backend_port),
                            "-m", "conntrack", "--ctstate", "ESTABLISHED", "--ctdir", "REPLY",
                            "-j", "ACCEPT"])
    for host, port in forwarded:
        peer = host + "/32"
        forward_rules.extend([
            ["-i", config.bridge, "-s", source, "-o", config.forward_interface, "-d", peer,
             "-p", "tcp", "-m", "tcp", "--dport", str(port), "-m", "conntrack",
             "--ctstate", "NEW,ESTABLISHED", "-j", "ACCEPT"],
            ["-i", config.forward_interface, "-s", peer, "-o", config.bridge, "-d", source,
             "-p", "tcp", "-m", "tcp", "--sport", str(port), "-m", "conntrack",
             "--ctstate", "ESTABLISHED", "-j", "ACCEPT"]])
        nat_rules.append(["-s", source, "-d", peer, "-o", config.forward_interface,
                          "-p", "tcp", "-m", "tcp", "--dport", str(port),
                          "-j", "SNAT", "--to-source", config.snat_ipv4])
    for host, port in config.local_endpoints:
        input_rules.append(["-i", config.bridge, "-s", source, "-d", host + "/32",
                            "-p", "tcp", "-m", "tcp", "--dport", str(port), "-m",
                            "conntrack", "--ctstate", "NEW,ESTABLISHED", "--ctdir", "ORIGINAL",
                            "-j", "ACCEPT"])
    rules = [("iptables", "filter", fwd, forward_rules + [["-j", "DROP"]]),
             ("iptables", "filter", inp, input_rules + [["-j", "DROP"]]),
             ("iptables", "nat", nat, nat_rules + [["-j", "RETURN"]]),
             ("ip6tables", "filter", fwd, [["-j", "DROP"]]),
             ("ip6tables", "filter", inp, [["-j", "DROP"]])]
    jumps = []
    for binary in ("iptables", "ip6tables"):
        jumps.extend([(binary, "filter", "FORWARD", ["-i", config.bridge, "-j", fwd]),
                      (binary, "filter", "FORWARD", ["-o", config.bridge, "-j", fwd]),
                      (binary, "filter", "INPUT", ["-i", config.bridge, "-j", inp])])
    jumps.append(("iptables", "nat", "POSTROUTING",
                  ["-s", source, "-o", config.forward_interface, "-j", nat]))
    for host, port in config.local_endpoints:
        # A gateway listener is reachable through other host interfaces too.
        # Route every protected tuple through the exact appliance input ACL.
        jumps.append(("iptables", "filter", "INPUT",
                      ["-d", host + "/32", "-p", "tcp", "-m", "tcp", "--dport", str(port),
                       "-j", inp]))
    return json.loads(json.dumps({"schema_version": 1, "config": asdict(config),
                                 "endpoints": all_endpoints, "forwarded": forwarded,
                                 "rules": rules, "jumps": jumps}))


def guard_text(p):
    c = p["config"]
    bridge, source, forward = c["bridge"], c["source_ipv4"], c["forward_interface"]
    lines = [f"table inet {NFT_TABLE} {{",
             " chain input { type filter hook input priority -150; policy accept;"]
    for destination in (c["gateway_ipv4"], "127.0.0.1"):
        lines.append(f'  iifname "{bridge}" ip saddr {source} ip daddr {destination} '
                     f'tcp sport {c["host_backend_port"]} ct state established ct direction reply accept;')
    for host, port in c["local_endpoints"]:
        lines.append(f'  iifname "{bridge}" ip saddr {source} ip daddr {host} '
                     f'tcp dport {port} ct state new,established ct direction original accept;')
    for host, port in c["local_endpoints"]:
        # Scope this drop to the declared listener tuple, including traffic
        # arriving on unrelated interfaces or through the host loopback path.
        lines.append(f'  ip daddr {host} tcp dport {port} drop;')
    lines.extend([f'  iifname "{bridge}" drop;', " }",
                  " chain forward { type filter hook forward priority -150; policy accept;"])
    for host, port in p["forwarded"]:
        lines.extend([
            f'  iifname "{bridge}" oifname "{forward}" ip saddr {source} '
            f'ip daddr {host} tcp dport {port} ct state new,established accept;',
            f'  iifname "{forward}" oifname "{bridge}" ip saddr {host} '
            f'ip daddr {source} tcp sport {port} ct state established accept;'])
    lines.extend([f'  iifname "{bridge}" drop;', f'  oifname "{bridge}" drop;', " }", "}"])
    return "\n".join(lines) + "\n"


def run(args, check=True, input=None):
    executable = BINARIES[args[0]]
    return subprocess.run([executable, *args[1:]], check=check, input=input,
                          text=True, capture_output=True, timeout=10,
                          env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"})


def command(binary, table, *args):
    return [binary, "-w", "5", "-t", table, *args]


def chain_lines(binary, table, chain):
    result = run(command(binary, table, "-S", chain), check=False)
    if result.returncode:
        if result.returncode == 1 and ("No chain" in result.stderr or "does not exist" in result.stderr):
            return None
        raise RuntimeError("Cannot inspect firewall chain")
    return [shlex.split(line) for line in result.stdout.splitlines() if line]


def guard_hash():
    result = run(["nft", "-j", "list", "table", "inet", NFT_TABLE], check=False)
    if result.returncode:
        if result.returncode == 1 and ("No such file" in result.stderr or "does not exist" in result.stderr):
            return None
        raise RuntimeError("Cannot inspect independent guard")

    def clean(value):
        if isinstance(value, dict):
            return {k: clean(v) for k, v in value.items() if k not in {"handle", "metainfo"}}
        if isinstance(value, list):
            return [clean(v) for v in value if not isinstance(v, dict) or "metainfo" not in v]
        return value

    return digest(clean(json.loads(result.stdout)))


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def normalize(rule):
    head, rest = rule[:2], rule[2:]
    matches, remaining = {}, []
    index = 0
    while index < len(rest):
        key = rest[index]
        if key in ("-s", "-d", "-i", "-o", "-p"):
            if key in matches or index + 1 == len(rest):
                raise RuntimeError("Malformed firewall match")
            matches[key] = rest[index + 1]
            index += 2
        elif key == "--ctstate" and index + 1 < len(rest):
            remaining.extend([key, ",".join(sorted(rest[index + 1].split(",")))])
            index += 2
        else:
            remaining.append(key)
            index += 1
    return head + [part for key in ("-s", "-d", "-i", "-o", "-p") if key in matches
                   for part in (key, matches[key])] + remaining


def shared_groups(p):
    groups = {}
    for binary, table, chain, spec in p["jumps"]:
        groups.setdefault((binary, table, chain), []).append(["-A", chain, *spec])
    return groups


def verify(p, expected_guard):
    if not expected_guard or guard_hash() != expected_guard:
        raise RuntimeError("Missing or changed independent guard")
    for binary, table, chain, rules in p["rules"]:
        expected = [["-N", chain]] + [["-A", chain, *rule] for rule in rules]
        actual = chain_lines(binary, table, chain)
        if actual is None or list(map(normalize, actual)) != list(map(normalize, expected)):
            raise RuntimeError("Missing or changed owned chain: " + chain)
    for (binary, table, chain), expected in shared_groups(p).items():
        lines = chain_lines(binary, table, chain)
        if lines is None:
            raise RuntimeError("Missing shared chain")
        rules = [normalize(line) for line in lines if line[0] == "-A"]
        wanted = list(map(normalize, expected))
        if rules[:len(wanted)] != wanted or any(rules.count(line) != 1 for line in wanted):
            raise RuntimeError("Owned jumps must precede all shared rules exactly once")
        owned = [line for line in rules if any(PREFIX in token for token in line)]
        if owned != wanted:
            raise RuntimeError("Unexpected owned-prefix shared reference")


def verify_host(p):
    c = p["config"]
    bridge = json.loads(run(["ip", "-j", "-d", "link", "show", "dev", c["bridge"]]).stdout)
    if (len(bridge) != 1 or bridge[0].get("linkinfo", {}).get("info_kind") != "bridge"
            or "UP" not in bridge[0].get("flags", [])):
        raise RuntimeError("Configured bridge must already exist and be up")
    addresses = json.loads(run(["ip", "-j", "-4", "address", "show", "dev", c["bridge"]]).stdout)
    actual = {(item["local"], item["prefixlen"]) for link in addresses
              for item in link.get("addr_info", []) if item.get("family") == "inet"}
    expected = {(c["gateway_ipv4"], ipaddress.IPv4Network(c["subnet_ipv4"]).prefixlen)}
    if actual != expected:
        raise RuntimeError("Bridge IPv4 address differs from configuration")
    if Path('/proc/sys/net/ipv4/conf', c['bridge'], 'route_localnet').read_text().strip() != '1':
        raise RuntimeError("Bridge loopback routing prerequisite is disabled")
    forward = json.loads(run(["ip", "-j", "link", "show", "dev", c["forward_interface"]]).stdout)
    if len(forward) != 1 or "UP" not in forward[0].get("flags", []):
        raise RuntimeError("Forward interface must exist and be up")
    host_addresses = json.loads(run(["ip", "-j", "-4", "address", "show", "dev", c["forward_interface"]]).stdout)
    if c["snat_ipv4"] not in {item["local"] for link in host_addresses
                               for item in link.get("addr_info", [])}:
        raise RuntimeError("SNAT address must belong to forwarding interface")
    if p["forwarded"] and Path("/proc/sys/net/ipv4/ip_forward").read_text().strip() != "1":
        raise RuntimeError("IPv4 forwarding is disabled")
    for host in sorted({host for host, _ in p["forwarded"]}):
        route = json.loads(run(["ip", "-j", "route", "get", host, "from", c["source_ipv4"],
                               "iif", c["bridge"]]).stdout)
        if (len(route) != 1 or route[0].get("dev") != c["forward_interface"]
                or route[0].get("type", "unicast") != "unicast"):
            raise RuntimeError("Catalog endpoint route differs from forward interface")


def secure_directory(path):
    """Validate every ancestor of an existing root-owned state directory."""
    for parent in reversed((path, *path.parents)):
        meta = parent.lstat()
        if (not stat.S_ISDIR(meta.st_mode) or meta.st_uid != 0 or meta.st_mode & 0o022):
            raise RuntimeError("Unsafe network state ancestry")
    if stat.S_IMODE(path.stat().st_mode) != 0o700:
        raise RuntimeError("Private network state directory required")


def saved_state():
    secure_directory(STATE)
    path = STATE / "state.json"
    if not path.exists() and not path.is_symlink():
        return None
    data = protected_read(path)
    if stat.S_IMODE(path.lstat().st_mode) != 0o600:
        raise RuntimeError("Private network receipt required")
    return json.loads(data, object_pairs_hook=catalog.unique_object)


def save(receipt):
    temporary = STATE / "state.next"
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w") as stream:
        json.dump(receipt, stream, sort_keys=True)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, STATE / "state.json")
    fd = os.open(STATE, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def check(p):
    receipt = saved_state()
    if not receipt or receipt.get("phase") != "ready" or receipt.get("policy") != p:
        raise RuntimeError("Matching ready network receipt required")
    verify_host(p)
    verify(p, receipt.get("guard_hash"))


def plan(p):
    commands = [["nft", "-c", "-f", "-"], ["nft", "-f", "-"]]
    for binary, table, chain, rules in p["rules"]:
        commands.append(command(binary, table, "-N", chain))
        commands.extend(command(binary, table, "-A", chain, *rule) for rule in rules)
    for (binary, table, chain), jumps in shared_groups(p).items():
        for jump in reversed(jumps):
            commands.append(command(binary, table, "-I", chain, "1", *jump[2:]))
    return {"policy": p, "policy_hash": digest(p), "guard": guard_text(p),
            "commands": commands, "state_directory": str(STATE)}


def boot_id():
    value = Path("/proc/sys/kernel/random/boot_id").read_text().strip()
    if re.fullmatch(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", value) is None:
        raise RuntimeError("Cannot establish current boot identity")
    return value


def all_owned_absent(p):
    if guard_hash() is not None:
        return False
    if any(chain_lines(binary, table, chain) is not None
           for binary, table, chain, _ in p["rules"]):
        return False
    for binary, table, chain in shared_groups(p):
        lines = chain_lines(binary, table, chain)
        if lines is None or any(PREFIX in token for line in lines for token in line):
            return False
    return True


def archive_ready(previous):
    name = "ready-before-boot-" + previous["boot_id"] + "-" + str(time.time_ns()) + ".json"
    data = protected_read(STATE / "state.json")
    if json.loads(data, object_pairs_hook=catalog.unique_object) != previous:
        raise RuntimeError("Network receipt changed before boot archive")
    fd = os.open(STATE / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())
    fd = os.open(STATE, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)
    return {"filename": name, "sha256": hashlib.sha256(data).hexdigest()}


def apply(p):
    previous = saved_state()
    current_boot = boot_id()
    archived = None
    if previous is not None:
        if previous.get("phase") == "ready" and previous.get("policy") == p:
            try:
                check(p)
                return
            except RuntimeError:
                old_boot = previous.get("boot_id", "")
                if (not isinstance(old_boot, str)
                        or re.fullmatch(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", old_boot) is None
                        or old_boot == current_boot or not all_owned_absent(p)):
                    raise
                verify_host(p)
                archived = archive_ready(previous)
        else:
            raise RuntimeError("Unresolved or different network receipt; manual review required")
    verify_host(p)
    if guard_hash() is not None:
        raise RuntimeError("Independent guard collision")
    for binary, table, chain, _ in p["rules"]:
        if chain_lines(binary, table, chain) is not None:
            raise RuntimeError("Owned chain collision")
    for binary, table, chain in shared_groups(p):
        lines = chain_lines(binary, table, chain)
        if lines is None or any(PREFIX in token for line in lines for token in line):
            raise RuntimeError("Missing shared chain or owned-prefix collision")
    run(["nft", "-c", "-f", "-"], input=guard_text(p))
    receipt = {"phase": "intent", "policy": p, "policy_hash": digest(p),
               "boot_id": current_boot, "started_at": time.time()}
    if archived is not None:
        receipt["previous_ready_archive"] = archived
    save(receipt)
    try:
        # Install the independent deny guard before any shared chain accept.
        run(["nft", "-f", "-"], input=guard_text(p))
        receipt["guard_hash"] = guard_hash()
        save(receipt)
        for args in plan(p)["commands"][2:]:
            run(args)
        verify_host(p)
        verify(p, receipt["guard_hash"])
    except Exception as error:
        receipt.update(phase="failed", error_type=type(error).__name__)
        save(receipt)
        raise
    receipt.update(phase="ready", finished_at=time.time())
    save(receipt)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("plan", "apply", "check"))
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--catalog", type=Path, required=True)
    args = parser.parse_args()
    p = load_inputs(args.config, args.catalog)
    if args.command == "plan":
        print(json.dumps(plan(p), sort_keys=True))
        return
    if os.geteuid() != 0:
        raise RuntimeError("Root required for host firewall inspection and apply")
    if args.command == "apply":
        # Only the fixed product directory may be created. Check never creates it.
        for parent in reversed(STATE.parents):
            meta = parent.lstat()
            if (not stat.S_ISDIR(meta.st_mode) or meta.st_uid != 0 or meta.st_mode & 0o022):
                raise RuntimeError("Unsafe network state ancestry")
        STATE.mkdir(mode=0o700, exist_ok=True)
    secure_directory(STATE)
    lock_path = STATE / "lock"
    flags = os.O_NOFOLLOW | os.O_NONBLOCK | (os.O_RDWR | os.O_CREAT if args.command == "apply" else os.O_RDONLY)
    fd = os.open(lock_path, flags, 0o600)
    with os.fdopen(fd, "r+" if args.command == "apply" else "r") as lock:
        info = os.fstat(lock.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or stat.S_IMODE(info.st_mode) != 0o600:
            raise RuntimeError("Unsafe network lock")
        fcntl.flock(lock, (fcntl.LOCK_EX if args.command == "apply" else fcntl.LOCK_SH) | fcntl.LOCK_NB)
        (apply if args.command == "apply" else check)(p)
    print(json.dumps({"success": True, "policy_hash": digest(p)}))


if __name__ == "__main__":
    main()
