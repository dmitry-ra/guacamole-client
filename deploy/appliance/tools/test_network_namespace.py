#!/usr/bin/env python3
"""Bounded real-kernel network fixture, confined to new mount/network namespaces."""
import argparse
import hashlib
import http.client
import json
import os
from pathlib import Path
import selectors
import signal
import socket
import subprocess
import sys
import threading
import time

HERE = Path(__file__).resolve().parents[1]
CHECKOUT = HERE.parents[1] if len(HERE.parents) > 1 else HERE
SELF = Path(__file__).resolve()
TIMEOUT = 170


def namespace(kind, pid="self"):
    return os.stat(f"/proc/{pid}/ns/{kind}").st_ino


def run(args, **kwargs):
    return subprocess.run(list(map(str, args)), check=kwargs.pop("check", True),
                          capture_output=True, text=True, timeout=kwargs.pop("timeout", 10), **kwargs)


def deadline(signum, frame):
    raise TimeoutError("Network fixture deadline")


def listen():
    selector = selectors.DefaultSelector()
    for family, kind, port in ((socket.AF_INET, socket.SOCK_STREAM, 3389),
                                (socket.AF_INET, socket.SOCK_STREAM, 3390),
                                (socket.AF_INET, socket.SOCK_STREAM, 3391),
                                (socket.AF_INET, socket.SOCK_STREAM, 10222),
                                (socket.AF_INET, socket.SOCK_STREAM, 10223),
                                (socket.AF_INET, socket.SOCK_STREAM, 10224),
                                (socket.AF_INET, socket.SOCK_STREAM, 8080),
                                (socket.AF_INET, socket.SOCK_DGRAM, 3389),
                                (socket.AF_INET, socket.SOCK_DGRAM, 10222),
                                (socket.AF_INET6, socket.SOCK_STREAM, 3389),
                                (socket.AF_INET6, socket.SOCK_STREAM, 10222)):
        sock = socket.socket(family, kind)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        if family == socket.AF_INET6:
            sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
        sock.bind(("::" if family == socket.AF_INET6 else "0.0.0.0", port))
        if kind == socket.SOCK_STREAM:
            sock.listen(16)
        selector.register(sock, selectors.EVENT_READ, kind)
    print("ready", flush=True)
    while True:
        for key, _ in selector.select(1):
            sock = key.fileobj
            if key.data == socket.SOCK_STREAM:
                connection, peer = sock.accept()
                def respond(connection=connection, peer=peer, port=sock.getsockname()[1]):
                  with connection:
                    connection.settimeout(1)
                    if port == 10224:
                        connection.settimeout(30)
                        while data := connection.recv(4096):
                            connection.sendall(data)
                        return
                    if port == 8080:
                        request = b""
                        while b"\r\n\r\n" not in request:
                            request += connection.recv(4096)
                        connection.sendall(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Type: application/x-ndjson\r\n\r\n")
                    for sequence in range(3):
                        chunk = (json.dumps({"peer": peer[0], "sequence": sequence}) + "\n").encode()
                        connection.sendall((f"{len(chunk):x}\r\n".encode() + chunk + b"\r\n") if port == 8080 else chunk)
                        time.sleep(0.03)
                    if port == 8080:
                        connection.sendall(b"0\r\n\r\n")
                threading.Thread(target=respond, daemon=True).start()
            else:
                _, peer = sock.recvfrom(4096)
                sock.sendto(json.dumps({"peer": peer[0]}).encode(), peer)


def probe(arguments):
    family = socket.AF_INET6 if ":" in arguments.host else socket.AF_INET
    kind = socket.SOCK_DGRAM if arguments.protocol == "udp" else socket.SOCK_STREAM
    try:
        if arguments.http:
            connection = http.client.HTTPConnection(arguments.host, arguments.port, timeout=1.5)
            connection.request("GET", "/synthetic-stream")
            response = connection.getresponse()
            if response.status != 200 or response.getheader("Transfer-Encoding") != "chunked":
                raise RuntimeError("HTTP stream response invalid")
            responses = [json.loads(response.readline()) for _ in range(3)]
            connection.close()
            print(json.dumps({"connected": True, "responses": responses, "http_chunked": True}))
            return
        with socket.socket(family, kind) as sock:
            sock.settimeout(1.5)
            if arguments.source:
                sock.bind((arguments.source, 8080 if arguments.source_port else 0))
            sock.connect((arguments.host, arguments.port))
            if kind == socket.SOCK_DGRAM:
                sock.send(b"synthetic")
                data = sock.recv(4096)
                responses = [json.loads(data)]
            else:
                data = b""
                while data.count(b"\n") < 3:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    data += chunk
                responses = [json.loads(line) for line in data.splitlines()]
                if len(responses) != 3:
                    raise RuntimeError("Incomplete response stream")
        print(json.dumps({"connected": True, "responses": responses}))
    except (OSError, ValueError, RuntimeError) as error:
        print(json.dumps({"connected": False, "error": type(error).__name__}))


def persistent_client():
    """Preserve a source-port-8080 ORIGINAL connection across guard activation."""
    with socket.socket() as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        sock.settimeout(1.5)
        sock.bind(("192.0.2.2", 8080))
        sock.connect(("192.0.2.1", 10224))
        sock.sendall(b"before")
        if sock.recv(4096) != b"before":
            raise RuntimeError("Persistent baseline echo failed")
        print("ready", flush=True)
        if sys.stdin.readline().strip() != "probe":
            raise RuntimeError("Persistent probe command missing")
        sock.sendall(b"after")
        try:
            response = sock.recv(4096)
            print(json.dumps({"blocked": False, "response": response.decode()}), flush=True)
        except TimeoutError:
            print(json.dumps({"blocked": True}), flush=True)


def isolate(arguments):
    # These are the first operations after unshare. No mounts, links, sysctls or
    # firewall writes are allowed before both independently inherited IDs differ.
    proof = {"host_net": arguments.host_net, "host_mount": arguments.host_mount,
             "fixture_net": namespace("net"), "fixture_mount": namespace("mnt")}
    if (os.geteuid() != 0 or proof["fixture_net"] == proof["host_net"]
            or proof["fixture_mount"] == proof["host_mount"]
            or namespace("net", os.getppid()) != proof["host_net"]
            or namespace("mnt", os.getppid()) != proof["host_mount"]):
        raise RuntimeError("Namespace isolation proof failed before mutation")
    run(["mount", "--make-rprivate", "/"])
    root = arguments.directory / "root"
    run(["mount", "-t", "tmpfs", "-o", "size=64m,mode=0755,nosuid,nodev", "portal-fixture", root])
    for name in ("usr", "proc", "src", "etc", "etc/alternatives", "var", "var/lib", "run", "config", "tmp"):
        (root / name).mkdir(mode=0o755, exist_ok=True)
    for name in ("bin", "sbin", "lib", "lib64"):
        (root / name).symlink_to("usr/" + name)
    for source, target in ((Path("/usr"), root / "usr"), (HERE, root / "src")):
        run(["mount", "--bind", source, target])
        run(["mount", "-o", "remount,bind,ro", target])
    for name in ("iptables", "ip6tables"):
        (root / "etc/alternatives" / name).symlink_to("/usr/sbin/" + name + "-nft")
    run(["mount", "-t", "proc", "-o", "nosuid,nodev,noexec", "proc", root / "proc"])
    os.chroot(root)
    os.chdir("/")
    # The product path exists only in the private tmpfs root. Its own tmpfs
    # therefore cannot create a mountpoint in the host's /var/lib.
    Path("/var/lib/guacamole-portal-network").mkdir(mode=0o700)
    run(["mount", "-t", "tmpfs", "-o", "size=4m,mode=0700,nosuid,nodev,noexec",
         "portal-state", "/var/lib/guacamole-portal-network"])
    Path("/config/isolation.json").write_text(json.dumps(proof))
    return suite(proof)


def require_inner():
    if HERE != Path("/src") or os.geteuid() != 0:
        raise RuntimeError("Internal role requires isolated tmpfs root")
    proof = json.loads(Path("/config/isolation.json").read_text())
    if namespace("net") == proof["host_net"] or namespace("mnt") != proof["fixture_mount"]:
        raise RuntimeError("Internal role namespace proof failed")


def suite(proof):
    signal.signal(signal.SIGALRM, deadline)
    signal.alarm(145)
    processes, checks = [], []
    script = "/src/tools/test_network_namespace.py"
    python = "/usr/bin/python3"

    def start(args):
        process = subprocess.Popen(args, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        processes.append(process)
        selector = selectors.DefaultSelector()
        selector.register(process.stdout, selectors.EVENT_READ)
        if not selector.select(5):
            raise RuntimeError("Fixture child did not become ready")
        line = process.stdout.readline().strip()
        selector.close()
        if not line:
            raise RuntimeError("Fixture child startup failed: " + process.stderr.read(4096))
        return process, line

    def peer():
        process, line = start(["/usr/bin/unshare", "--net", python, "-B", "-S", script, "--hold"])
        inode = int(line)
        if inode in (proof["host_net"], proof["fixture_net"]):
            raise RuntimeError("Peer namespace isolation failed")
        return process.pid, inode

    def within(pid, *args):
        return ["/usr/bin/nsenter", "--net=/proc/" + str(pid) + "/ns/net", *map(str, args)]

    def ip(*args):
        run(["/usr/sbin/ip", *args])

    def peer_ip(pid, *args):
        run(within(pid, "/usr/sbin/ip", *args))

    def attempt(pid, host, port, expected, label, protocol="tcp", source=None, source_port=False, peer_address=None):
        args = [python, "-B", "-S", script, "--probe", "--host", host, "--port", str(port), "--protocol", protocol]
        if port in (8080, 10474):
            args += ["--http"]
        if source:
            args += ["--source", source]
        if source_port:
            args += ["--source-port"]
        result = json.loads(run(within(pid, *args) if pid else args).stdout)
        if result["connected"] != expected:
            print(json.dumps({"failed_probe": label,
                              "router_routes": run(["/usr/sbin/ip", "-6", "route"]).stdout,
                              "router_neighbours": run(["/usr/sbin/ip", "-6", "neigh"]).stdout,
                              "source_routes": run(within(source_pid, "/usr/sbin/ip", "-6", "route")).stdout}), file=sys.stderr)
            raise AssertionError(label + ": " + json.dumps(result))
        if peer_address and any(r["peer"] != peer_address for r in result["responses"]):
            raise AssertionError("SNAT source differs: " + json.dumps(result))
        checks.append({"check": label, "result": result})

    def controller(verb, expected=True):
        result = run([python, "-B", "-S", "/src/network.py", verb, "--config", "/config/network.json",
                      "--catalog", "/config/catalog.json"], check=False)
        if (result.returncode == 0) != expected:
            raise AssertionError("Controller " + verb + " unexpected result: " + result.stderr)
        return result

    try:
        source_pid, source_ns = peer()
        target_pid, target_ns = peer()
        untrusted_pid, untrusted_ns = peer()
        proof.update(source_net=source_ns, target_net=target_ns, untrusted_net=untrusted_ns)
        if len({source_ns, target_ns, untrusted_ns}) != 3:
            raise RuntimeError("Peer namespace collision")
        ip("link", "set", "lo", "up")
        ip("link", "add", "portalb0", "type", "bridge")
        ip("address", "add", "192.0.2.1/29", "dev", "portalb0")
        ip("-6", "address", "add", "2001:db8:1::1/64", "dev", "portalb0", "nodad")
        ip("link", "set", "portalb0", "up")
        for local, remote, pid in (("brpeer0", "src0", source_pid), ("uplink0", "dst0", target_pid),
                                   ("untrusted0", "other0", untrusted_pid)):
            ip("link", "add", local, "type", "veth", "peer", "name", remote)
            ip("link", "set", remote, "netns", str(pid))
            ip("link", "set", local, "up")
            peer_ip(pid, "link", "set", "lo", "up")
            peer_ip(pid, "link", "set", remote, "up")
        ip("link", "set", "brpeer0", "master", "portalb0")
        ip("address", "add", "198.51.100.1/24", "dev", "uplink0")
        ip("address", "add", "203.0.113.1/30", "dev", "untrusted0")
        peer_ip(untrusted_pid, "address", "add", "203.0.113.2/30", "dev", "other0")
        peer_ip(untrusted_pid, "route", "add", "default", "via", "203.0.113.1")
        ip("-6", "address", "add", "2001:db8:2::1/64", "dev", "uplink0", "nodad")
        for address in ("192.0.2.2/29", "192.0.2.3/29"):
            peer_ip(source_pid, "address", "add", address, "dev", "src0")
        peer_ip(source_pid, "-6", "address", "add", "2001:db8:1::2/64", "dev", "src0", "nodad")
        peer_ip(source_pid, "route", "add", "default", "via", "192.0.2.1")
        peer_ip(source_pid, "-6", "route", "add", "default", "via", "2001:db8:1::1")
        for address in ("198.51.100.7/24", "198.51.100.8/24"):
            peer_ip(target_pid, "address", "add", address, "dev", "dst0")
        peer_ip(target_pid, "-6", "address", "add", "2001:db8:2::7/64", "dev", "dst0", "nodad")
        peer_ip(target_pid, "route", "add", "default", "via", "198.51.100.1")
        peer_ip(target_pid, "-6", "route", "add", "default", "via", "2001:db8:2::1")
        def mac(pid, device):
            args = ["/usr/sbin/ip", "-j", "link", "show", "dev", device]
            return json.loads(run(within(pid, *args) if pid else args).stdout)[0]["address"]
        # Deterministic IPv6 controls do not depend on multicast discovery
        # startup, and retain established neighbors when the deny guard blocks ND.
        for pid, device, address, peer_mac in (
                (None, "portalb0", "2001:db8:1::2", mac(source_pid, "src0")),
                (None, "uplink0", "2001:db8:2::7", mac(target_pid, "dst0")),
                (source_pid, "src0", "2001:db8:1::1", mac(None, "portalb0")),
                (target_pid, "dst0", "2001:db8:2::1", mac(None, "uplink0"))):
            args = ["-6", "neigh", "replace", address, "lladdr", peer_mac,
                    "nud", "permanent", "dev", device]
            peer_ip(pid, *args) if pid else ip(*args)
        Path("/proc/sys/net/ipv4/ip_forward").write_text("1\n")
        Path("/proc/sys/net/ipv6/conf/all/forwarding").write_text("1\n")
        for pid in (None, source_pid, target_pid):
            args = [python, "-B", "-S", script, "--listen"]
            start(within(pid, *args) if pid else args)
        for host, port, protocol, label in (("198.51.100.7", 3391, "tcp", "baseline_wrong_port"),
                                           ("198.51.100.8", 3389, "tcp", "baseline_wrong_tuple"),
                                           ("192.0.2.1", 10223, "tcp", "baseline_local_wrong_port"),
                                           ("198.51.100.7", 3389, "udp", "baseline_udp"),
                                           ("2001:db8:2::7", 3389, "tcp", "baseline_ipv6")):
            attempt(source_pid, host, port, True, label, protocol)
        attempt(untrusted_pid, "192.0.2.1", 10222, True, "baseline_other_interface_gateway_listener")
        attempt(None, "192.0.2.1", 10222, True, "baseline_host_local_gateway_listener")
        # Model host loopback publication using OUTPUT DNAT and source rewrite.
        # All addresses/rules exist only inside this freshly proved namespace.
        Path("/proc/sys/net/ipv4/conf/portalb0/route_localnet").write_text("1\n")
        run(["/usr/sbin/iptables-nft", "-t", "nat", "-A", "OUTPUT", "-d", "127.0.0.1/32", "-p", "tcp", "--dport", "10474", "-j", "DNAT", "--to-destination", "192.0.2.2:8080"])
        run(["/usr/sbin/iptables-nft", "-t", "nat", "-A", "POSTROUTING", "-s", "127.0.0.1/32", "-d", "192.0.2.2/32", "-p", "tcp", "--dport", "8080", "-j", "SNAT", "--to-source", "192.0.2.1"])
        run(["/usr/sbin/nft", "-f", "-"], input='''table inet fixture_hook {
 chain input { type filter hook input priority -200; policy accept;
  ip saddr 192.0.2.2 tcp sport 8080 ip daddr 192.0.2.1 ct direction reply counter;
  ip saddr 192.0.2.2 tcp sport 8080 ip daddr 127.0.0.1 ct direction reply counter;
 }
}
''')
        attempt(None, "192.0.2.2", 8080, True, "baseline_direct_http_stream")
        attempt(None, "127.0.0.1", 10474, True, "baseline_published_loopback_http_stream")
        print(json.dumps({"actual_http_input_hooks": json.loads(run(["/usr/sbin/nft", "-j", "list", "table", "inet", "fixture_hook"]).stdout)}), file=sys.stderr)
        established, _ = start(within(source_pid, python, "-B", "-S", script, "--persistent-client"))
        checks.append({"check": "baseline_established_original_backend_source_port"})
        config = {"schema_version": 1, "bridge": "portalb0", "subnet_ipv4": "192.0.2.0/29",
                  "source_ipv4": "192.0.2.2", "gateway_ipv4": "192.0.2.1",
                  "forward_interface": "uplink0", "snat_ipv4": "198.51.100.1",
                  "host_backend_port": 8080,
                  "local_endpoints": [{"hostname": "192.0.2.1", "port": 10222}]}
        target = {"protocol": "rdp", "hostname": "198.51.100.7", "port": 3389,
                  "username": "synthetic", "certificate_fingerprint": "sha256:" + ":".join(["00"] * 32),
                  "password_file": "synthetic-secret"}
        catalog = {"schema_version": 1, "portal": {"username": "synthetic"},
                   "targets": {"desktop": target,
                               "second": {**target, "hostname": "198.51.100.8", "port": 3390},
                               "gateway": {**target, "hostname": "192.0.2.1", "port": 10222}}}
        for name, value in (("network", config), ("catalog", catalog)):
            Path("/config/" + name + ".json").write_text(json.dumps(value))
            Path("/config/" + name + ".json").chmod(0o600)
        controller("check", expected=False)
        if Path("/var/lib/guacamole-portal-network/lock").exists():
            raise AssertionError("Check created a lock")
        checks.append({"check": "unprepared_check_closed_without_writes"})
        # Shared rejects predate apply. Owned allow jumps must be inserted ahead.
        for binary in ("iptables-nft", "ip6tables-nft"):
            run(["/usr/sbin/" + binary, "-A", "FORWARD", "-j", "REJECT"])
        controller("apply")
        controller("check")
        checks.append({"check": "actual_apply_and_exact_canonicalized_check"})
        run(["/usr/sbin/iptables-nft", "-I", "INPUT", "1", "-j", "ACCEPT"])
        established.stdin.write("probe\n")
        established.stdin.flush()
        selector = selectors.DefaultSelector()
        selector.register(established.stdout, selectors.EVENT_READ)
        if not selector.select(5):
            raise RuntimeError("Established original probe timed out")
        result = json.loads(established.stdout.readline())
        selector.close()
        if not result.get("blocked"):
            raise AssertionError("Established ORIGINAL backend source port bypassed guard")
        established.wait(timeout=2)
        checks.append({"check": "deny_established_original_backend_source_port_after_broad_accept", "result": result})
        run(["/usr/sbin/iptables-nft", "-D", "INPUT", "-j", "ACCEPT"])
        controller("check")
        attempt(None, "192.0.2.2", 8080, True, "direct_http_stream_with_guard")
        attempt(None, "127.0.0.1", 10474, True, "published_loopback_http_stream_with_guard")
        attempt(source_pid, "198.51.100.7", 3389, True, "forward_exact_snat", peer_address="198.51.100.1")
        attempt(source_pid, "198.51.100.8", 3390, True, "second_exact_snat", peer_address="198.51.100.1")
        attempt(source_pid, "192.0.2.1", 10222, True, "gateway_exact_tcp")
        # A separate later native nft accept and a deliberately earlier shared
        # iptables accept cannot reverse the independent early guard's drops.
        run(["/usr/sbin/nft", "-f", "-"], input='''table inet fixture_later {
 chain input { type filter hook input priority 0; policy accept; accept; }
 chain forward { type filter hook forward priority 0; policy accept; accept; }
}
''')
        for chain in ("INPUT", "FORWARD"):
            run(["/usr/sbin/iptables-nft", "-I", chain, "1", "-j", "ACCEPT"])
        controller("check", expected=False)
        attempt(untrusted_pid, "192.0.2.1", 10222, False, "deny_other_interface_gateway_listener_despite_broad_accept")
        attempt(None, "192.0.2.1", 10222, False, "deny_host_local_gateway_listener_despite_broad_accept")
        attempt(source_pid, "192.0.2.1", 10222, False, "deny_wrong_bridge_source_gateway_listener",
                source="192.0.2.3")
        attempt(source_pid, "192.0.2.1", 10222, True, "appliance_gateway_listener_remains_allowed")
        attempt(untrusted_pid, "192.0.2.1", 10223, True, "unrelated_host_listener_other_interface_preserved")
        attempt(None, "192.0.2.1", 10223, True, "unrelated_host_local_listener_preserved")
        for host, port, protocol, source, label in (
                ("198.51.100.7", 3391, "tcp", None, "deny_wrong_port_after_broad_accept"),
                ("198.51.100.8", 3389, "tcp", None, "deny_wrong_tuple_after_broad_accept"),
                ("192.0.2.1", 10223, "tcp", None, "deny_local_wrong_port"),
                ("198.51.100.7", 3389, "udp", None, "deny_udp"),
                ("192.0.2.1", 10222, "udp", None, "deny_local_udp"),
                ("2001:db8:2::7", 3389, "tcp", None, "deny_ipv6_forward"),
                ("2001:db8:1::1", 10222, "tcp", None, "deny_ipv6_input"),
                ("198.51.100.7", 3389, "tcp", "192.0.2.3", "deny_spoofed_source")):
            attempt(source_pid, host, port, False, label, protocol, source)
        for chain in ("INPUT", "FORWARD"):
            run(["/usr/sbin/iptables-nft", "-D", chain, "-j", "ACCEPT"])
        controller("check")
        receipt = Path("/var/lib/guacamole-portal-network/state.json")
        before = receipt.read_bytes(), receipt.stat().st_mtime_ns, run(["/usr/sbin/nft", "-j", "list", "ruleset"]).stdout
        controller("apply")
        controller("check")
        after = receipt.read_bytes(), receipt.stat().st_mtime_ns, run(["/usr/sbin/nft", "-j", "list", "ruleset"]).stdout
        if before != after:
            raise AssertionError("Ready check/reapply mutated policy or receipt")
        checks.append({"check": "ready_reapply_and_check_read_only"})
        run(["/usr/sbin/nft", "add", "rule", "inet", "guacamole_portal_guard", "forward", "counter"])
        changed = run(["/usr/sbin/nft", "-j", "list", "ruleset"]).stdout
        controller("check", expected=False)
        if changed != run(["/usr/sbin/nft", "-j", "list", "ruleset"]).stdout:
            raise AssertionError("Drift check mutated rules")
        checks.append({"check": "guard_drift_rejected_without_repair"})
        return {"passed": True, "namespaces": proof, "checks": checks,
                "versions": {binary: run(["/usr/sbin/" + binary, "--version"]).stdout.strip()
                             for binary in ("nft", "iptables-nft", "ip6tables-nft")}}
    finally:
        for process in reversed(processes):
            if process.poll() is None:
                process.terminate()
        for process in reversed(processes):
            try:
                process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=2)
        signal.alarm(0)


def fixture(directory):
    if os.geteuid() != 0 or not directory.is_absolute() or directory == CHECKOUT or CHECKOUT in directory.parents:
        raise ValueError("Root and a new absolute evidence directory outside checkout required")
    os.umask(0o077)
    os.sched_setaffinity(0, set(sorted(os.sched_getaffinity(0))[:2]))
    directory.mkdir(mode=0o700)
    (directory / "root").mkdir(mode=0o700)
    sources = [HERE / "network.py", HERE / "catalog.py", SELF]
    hashes = {str(p.relative_to(HERE)): hashlib.sha256(p.read_bytes()).hexdigest() for p in sources}
    host_net, host_mount = namespace("net"), namespace("mnt")
    status = {"passed": False, "sources": hashes, "cleanup_verified": False,
              "cpu_affinity": sorted(os.sched_getaffinity(0)),
              "scope": "synthetic isolated kernel namespaces only"}
    started = time.monotonic()
    process = None
    try:
        process = subprocess.Popen(["/usr/bin/unshare", "--mount", "--net", "--propagation", "unchanged",
                                    sys.executable, "-B", "-S", str(SELF), "--isolate", "--directory", str(directory),
                                    "--host-net", str(host_net), "--host-mount", str(host_mount)],
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, start_new_session=True)
        stdout, stderr = process.communicate(timeout=TIMEOUT)
        (directory / "stdout.log").write_text(stdout)
        (directory / "stderr.log").write_text(stderr)
        status["exit_code"] = process.returncode
        if process.returncode:
            raise RuntimeError("Isolated network fixture failed; inspect private stderr.log")
        result = json.loads(stdout)
        if result.get("passed") is not True:
            raise RuntimeError("Fixture success receipt missing")
        if hashes != {str(p.relative_to(HERE)): hashlib.sha256(p.read_bytes()).hexdigest() for p in sources}:
            raise RuntimeError("Fixture sources changed during execution")
        status.update(passed=True, result=result)
    finally:
        if process is not None:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait(timeout=5)
            try:
                os.killpg(process.pid, 0)
            except ProcessLookupError:
                status["cleanup_verified"] = True
        if namespace("net") != host_net or namespace("mnt") != host_mount:
            raise RuntimeError("Outer namespaces changed")
        status["elapsed_seconds"] = round(time.monotonic() - started, 3)
        (directory / "receipt.json").write_text(json.dumps(status, indent=2) + "\n")
        if not status["cleanup_verified"]:
            raise RuntimeError("Fixture process group survived cleanup")
    print(json.dumps(status))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", type=Path)
    parser.add_argument("--isolate", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--hold", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--listen", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--probe", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--host-net", type=int)
    parser.add_argument("--host-mount", type=int)
    parser.add_argument("--host")
    parser.add_argument("--port", type=int)
    parser.add_argument("--protocol", choices=("tcp", "udp"), default="tcp")
    parser.add_argument("--source")
    parser.add_argument("--source-port", action="store_true")
    parser.add_argument("--http", action="store_true")
    parser.add_argument("--persistent-client", action="store_true", help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.hold or args.listen or args.probe or args.persistent_client:
        require_inner()
    if args.isolate:
        print(json.dumps(isolate(args)))
    elif args.hold:
        signal.alarm(150)
        print(namespace("net"), flush=True)
        signal.pause()
    elif args.listen:
        signal.alarm(150)
        listen()
    elif args.probe:
        probe(args)
    elif args.persistent_client:
        persistent_client()
    elif args.directory:
        fixture(args.directory)
    else:
        parser.error("--directory is required")


if __name__ == "__main__":
    main()
