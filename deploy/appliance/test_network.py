"""Host-inert validation and policy tests. No firewall tools are executed."""

import copy
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import network


def configuration():
    return {"schema_version": 1, "bridge": "portalb0", "subnet_ipv4": "192.0.2.0/29",
            "source_ipv4": "192.0.2.2", "gateway_ipv4": "192.0.2.1",
            "forward_interface": "uplink0", "snat_ipv4": "198.51.100.1",
            "host_backend_port": 8080,
            "local_endpoints": [{"hostname": "192.0.2.1", "port": 10222}]}


def target_catalog(endpoints=None):
    return SimpleNamespace(endpoints=lambda: endpoints or [
        ("198.51.100.7", 3389), ("198.51.100.8", 3390), ("192.0.2.1", 10222)])


def sample():
    return network.policy(network.parse_config(configuration()), target_catalog())


def nft_verdict(p, chain, **packet):
    """Interpret the generated guard's match subset, independently of policy()."""
    body = network.guard_text(p).split(" chain " + chain + " {")[1].split(" }")[0]
    for line in body.splitlines()[1:]:
        matches = re.findall(r'(iifname|oifname) "([a-z0-9_]+)"', line)
        matches += re.findall(r'ip (saddr|daddr) ([0-9.]+)', line)
        if any(packet.get(key) != value for key, value in matches):
            continue
        if " ip " in line and packet.get("family") != "ip":
            continue
        tcp = re.search(r'tcp (dport|sport) (\d+)', line)
        if tcp and (packet.get("protocol") != "tcp" or packet.get(tcp[1]) != int(tcp[2])):
            continue
        states = re.search(r'ct state ([a-z,]+)', line)
        if states and packet.get("state") not in states[1].split(","):
            continue
        direction = re.search(r'ct direction (original|reply)', line)
        if direction and packet.get("direction") != direction[1]:
            continue
        if " accept;" in line:
            return "accept"
        if " drop;" in line:
            return "drop"
    return "accept"


def packet(**changes):
    value = dict(family="ip", protocol="tcp", iifname="portalb0", oifname="uplink0",
                 saddr="192.0.2.2", daddr="198.51.100.7", sport=40000, dport=3389, state="new", direction="original")
    value.update(changes)
    return value


class ValidationTests(unittest.TestCase):
    def test_valid_and_exact_catalog_derivation(self):
        p = sample()
        self.assertEqual(p["forwarded"], [["198.51.100.7", 3389], ["198.51.100.8", 3390]])
        self.assertEqual(len(p["endpoints"]), 3)
        nat = next(rules for binary, table, _, rules in p["rules"] if table == "nat")
        self.assertEqual(len(nat), 3)
        self.assertTrue(all("SNAT" in rule for rule in nat[:-1]))
        self.assertFalse(any("10222" in rule for rule in nat))

    def test_invalid_fields_names_addresses_ports_and_subnets(self):
        variants = [("schema_version", True), ("bridge", "lo"), ("bridge", "wrdp0"),
                    ("bridge", "virbr0"), ("bridge", "eth0"), ("bridge", 'x" drop;'),
                    ("bridge", "UPPER"), ("bridge", "a" * 16),
                    ("forward_interface", "lo"), ("forward_interface", "portalb0"),
                    ("source_ipv4", "::1"), ("source_ipv4", "192.0.2.0"),
                    ("source_ipv4", "192.0.2.7"), ("source_ipv4", "192.0.2.1"),
                    ("source_ipv4", "127.0.0.1"), ("snat_ipv4", "0.0.0.0"),
                    ("snat_ipv4", "224.0.0.1"), ("snat_ipv4", "169.254.1.1"),
                    ("snat_ipv4", "255.255.255.255"), ("subnet_ipv4", "192.0.2.1/29"),
                    ("host_backend_port", True), ("host_backend_port", 0),
                    ("subnet_ipv4", "192.0.0.0/16"), ("subnet_ipv4", "192.0.2.0/31"),
                    ("local_endpoints", [{"hostname": "192.0.2.1", "port": True}]),
                    ("local_endpoints", [{"hostname": "192.0.2.1", "port": 65536}]),
                    ("local_endpoints", [{"hostname": "192.0.2.3", "port": 22}])]
        for key, invalid in variants:
            with self.subTest(key=key, invalid=invalid):
                value = configuration()
                value[key] = invalid
                with self.assertRaises(ValueError):
                    network.parse_config(value)
        for value in ({**configuration(), "extra": 1}, {"schema_version": 1}):
            with self.assertRaises(ValueError):
                network.parse_config(value)

    def test_local_must_be_unique_catalog_gateway_subset(self):
        config = configuration()
        config["local_endpoints"] *= 2
        with self.assertRaises(ValueError):
            network.parse_config(config)
        with self.assertRaises(ValueError):
            network.policy(network.parse_config(configuration()), target_catalog([("198.51.100.7", 3389)]))
        config = configuration()
        config["local_endpoints"] = []
        with self.assertRaises(ValueError):
            network.policy(network.parse_config(config), target_catalog())

    def test_duplicate_catalog_endpoints_are_deduplicated(self):
        config = configuration()
        config["local_endpoints"] = []
        p = network.policy(network.parse_config(config), target_catalog([("198.51.100.7", 3389)] * 2))
        self.assertEqual(p["endpoints"], [["198.51.100.7", 3389]])

    def test_protected_paths_reject_writable_ancestor_and_relative(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "input.json"
            path.write_text("{}")
            with self.assertRaises(ValueError):
                network.protected_read(path)
        for path in ("relative.json", "/etc/../etc/input.json"):
            with self.assertRaises(ValueError):
                network.protected_read(path)

    def test_protected_read_rejects_symlink_file_fifo_and_nonroot(self):
        real_fstat = os.fstat
        def pretend_protected_ancestors(fd):
            meta = real_fstat(fd)
            if stat.S_ISDIR(meta.st_mode):
                return SimpleNamespace(st_uid=0, st_mode=stat.S_IFDIR | 0o755)
            return meta
        with tempfile.TemporaryDirectory() as tmp, patch("network.os.fstat", side_effect=pretend_protected_ancestors):
            path = Path(tmp) / "input"
            path.write_text("{}")
            path.chmod(0o600)
            link = Path(tmp) / "link"
            link.symlink_to(path)
            with self.assertRaises(OSError):
                network.protected_read(link)
            fifo = Path(tmp) / "fifo"
            os.mkfifo(fifo)
            with self.assertRaises(ValueError):
                network.protected_read(fifo)
            with patch("network.os.fstat", return_value=SimpleNamespace(st_uid=1000, st_mode=stat.S_IFDIR | 0o755)):
                with self.assertRaises(ValueError):
                    network.protected_read(path)

    def test_load_rejects_duplicate_json_keys(self):
        with patch("network.protected_read", return_value=b'{"schema_version":1,"schema_version":1}'):
            with self.assertRaises(ValueError):
                network.load_inputs("/config", "/catalog")


class GuardTests(unittest.TestCase):
    def test_exact_forward_and_reverse_tuples(self):
        p = sample()
        self.assertEqual(nft_verdict(p, "forward", **packet()), "accept")
        self.assertEqual(nft_verdict(p, "forward", **packet(daddr="198.51.100.8", dport=3390)), "accept")
        reverse = packet(iifname="uplink0", oifname="portalb0", saddr="198.51.100.7",
                         daddr="192.0.2.2", sport=3389, state="established")
        self.assertEqual(nft_verdict(p, "forward", **reverse), "accept")
        for change in ({"state": "new"}, {"sport": 3390}, {"iifname": "other0"},
                       {"saddr": "198.51.100.8"}, {"daddr": "192.0.2.3"}):
            self.assertEqual(nft_verdict(p, "forward", **{**reverse, **change}), "drop")

    def test_unrelated_tcp_udp_ipv6_and_spoofing_dropped(self):
        p = sample()
        for change in ({"daddr": "203.0.113.9"}, {"dport": 22}, {"protocol": "udp"},
                       {"family": "ip6"}, {"saddr": "192.0.2.3"}, {"oifname": "other0"},
                       {"state": "related"}, {"state": "invalid"},
                       {"daddr": "198.51.100.8", "dport": 3389}):
            with self.subTest(change=change):
                self.assertEqual(nft_verdict(p, "forward", **packet(**change)), "drop")

    def test_local_input_allows_only_exact_tcp_gateway_tuple(self):
        p = sample()
        local = packet(daddr="192.0.2.1", dport=10222)
        self.assertEqual(nft_verdict(p, "input", **local), "accept")
        for change in ({"daddr": "198.51.100.7"}, {"dport": 22}, {"protocol": "udp"},
                       {"family": "ip6"}, {"saddr": "192.0.2.3"}, {"state": "related"}):
            self.assertEqual(nft_verdict(p, "input", **{**local, **change}), "drop")

    def test_early_drop_is_terminal_before_later_network_accept(self):
        p = sample()
        self.assertIn("hook forward priority -150", network.guard_text(p))
        self.assertIn("hook input priority -150", network.guard_text(p))
        for chain in ("input", "forward"):
            for denied in (packet(protocol="udp"), packet(family="ip6"), packet(dport=53)):
                early = nft_verdict(p, chain, **denied)
                later_shared_accept = "accept"
                verdict = "drop" if early == "drop" else later_shared_accept
                self.assertEqual(verdict, "drop")

    def test_unrelated_interfaces_remain_outside_owned_policy(self):
        self.assertEqual(nft_verdict(sample(), "forward", **packet(iifname="other0", oifname="other1")), "accept")

    def test_gateway_local_catalog_ports_are_exclusive_across_all_host_interfaces(self):
        p = sample()
        for ingress in ("lo", "uplink0", "untrusted0", "portalb0"):
            for source in ("203.0.113.2", "192.0.2.3", "192.0.2.2"):
                incoming = packet(iifname=ingress, saddr=source, daddr="192.0.2.1", dport=10222)
                expected = "accept" if ingress == "portalb0" and source == "192.0.2.2" else "drop"
                self.assertEqual(nft_verdict(p, "input", **incoming), expected)
        self.assertEqual(nft_verdict(p, "input", **packet(iifname="uplink0", saddr="203.0.113.2",
                                                         daddr="192.0.2.1", dport=10223)), "accept")
        self.assertEqual(nft_verdict(p, "input", **packet(daddr="192.0.2.1", dport=10222,
                                                         direction="reply")), "drop")
        # Exact host-backend REPLY traffic is still accepted before the listener
        # tuple drop even when the host chose that protected port as source.
        self.assertEqual(nft_verdict(p, "input", **packet(daddr="192.0.2.1", dport=10222,
                                                         sport=8080, state="established", direction="reply")), "accept")

    def test_host_backend_reply_is_exact_port_source_destination_and_direction(self):
        p = sample()
        for destination in ("192.0.2.1", "127.0.0.1"):
            reply = packet(daddr=destination, sport=8080, dport=41000,
                           state="established", direction="reply")
            self.assertEqual(nft_verdict(p, "input", **reply), "accept")
            for change in ({"direction": "original"}, {"state": "new"}, {"state": "related"},
                           {"sport": 8081}, {"saddr": "192.0.2.3"}, {"daddr": "198.51.100.1"},
                           {"family": "ip6"}, {"protocol": "udp"}):
                self.assertEqual(nft_verdict(p, "input", **{**reply, **change}), "drop")


class InspectionTests(unittest.TestCase):
    def setUp(self):
        self.p = sample()
        self.chains = {(b, t, c): [["-N", c]] + [["-A", c, *r] for r in rules]
                       for b, t, c, rules in self.p["rules"]}
        for key, jumps in network.shared_groups(self.p).items():
            self.chains[key] = [["-P", key[2], "ACCEPT"], *jumps,
                                ["-A", key[2], "-j", "LIBVIRT_TEST"]]

    def test_exact_ready_inspection_and_shared_order(self):
        with patch("network.guard_hash", return_value="guard"), patch("network.chain_lines", side_effect=lambda *key: self.chains[key]):
            network.verify(self.p, "guard")
            key = ("iptables", "filter", "FORWARD")
            self.chains[key].insert(1, ["-A", "FORWARD", "-j", "NETAVARK_ACCEPT"])
            with self.assertRaises(RuntimeError):
                network.verify(self.p, "guard")

    def test_changed_guard_and_duplicate_or_extra_owned_references_rejected(self):
        for variant in ("guard", "duplicate", "extra", "rule"):
            with self.subTest(variant=variant):
                chains = copy.deepcopy(self.chains)
                if variant == "duplicate":
                    chains[("iptables", "filter", "INPUT")].append(chains[("iptables", "filter", "INPUT")][1])
                if variant == "extra":
                    chains[("iptables", "filter", "INPUT")].append(["-A", "INPUT", "-j", "GP_PORTAL_UNKNOWN"])
                if variant == "rule":
                    chains[("iptables", "filter", "GP_PORTAL_FWD")].insert(1, ["-A", "GP_PORTAL_FWD", "-j", "ACCEPT"])
                with patch("network.guard_hash", return_value="changed" if variant == "guard" else "guard"), patch("network.chain_lines", side_effect=lambda *key: chains[key]):
                    with self.assertRaises(RuntimeError):
                        network.verify(self.p, "guard")

    def test_plan_is_pure_and_has_no_flush_or_delete(self):
        with patch("network.run", side_effect=AssertionError("Host command executed")):
            result = network.plan(self.p)
        self.assertEqual(result["commands"][0], ["nft", "-c", "-f", "-"])
        self.assertFalse(any(token in {"-F", "-X", "flush", "delete", "restore"}
                             for command in result["commands"] for token in command))
        self.assertNotIn("HL_WRDP", json.dumps(result))
        self.assertNotIn("homelab_web_rdp_single", json.dumps(result))

    def test_check_only_reads_and_requires_ready(self):
        for phase in (None, "intent", "failed"):
            receipt = None if phase is None else {"phase": phase, "policy": self.p}
            with patch("network.saved_state", return_value=receipt), patch("network.save", side_effect=AssertionError("write")), patch("network.run", side_effect=AssertionError("command")):
                with self.assertRaises(RuntimeError):
                    network.check(self.p)
        with patch("network.saved_state", return_value={"phase": "ready", "policy": self.p, "guard_hash": "g"}), patch("network.verify_host") as host, patch("network.verify") as verify, patch("network.save", side_effect=AssertionError("write")):
            network.check(self.p)
            host.assert_called_once_with(self.p)
            verify.assert_called_once_with(self.p, "g")

    def test_no_uncertain_repair_or_different_policy_replacement(self):
        for receipt in ({"phase": "failed", "policy": self.p},
                        {"phase": "intent", "policy": self.p},
                        {"phase": "ready", "policy": {}}):
            with patch("network.saved_state", return_value=receipt), patch("network.run", side_effect=AssertionError("mutation")):
                with self.assertRaises(RuntimeError):
                    network.apply(self.p)

    def test_transaction_installs_guard_before_accept_and_records_failure(self):
        receipts, commands = [], []
        def execute(args, **kwargs):
            commands.append(args)
            if "-N" in args:
                raise RuntimeError("synthetic failure")
            return SimpleNamespace(stdout="", returncode=0)
        def lines(binary, table, chain):
            return None if chain.startswith(network.PREFIX) else [["-P", chain, "ACCEPT"]]
        with patch("network.saved_state", return_value=None), patch("network.verify_host"), patch("network.guard_hash", side_effect=[None, "guard"]), patch("network.chain_lines", side_effect=lines), patch("network.run", side_effect=execute), patch("network.save", side_effect=lambda r: receipts.append(copy.deepcopy(r))):
            with self.assertRaises(RuntimeError):
                network.apply(self.p)
        self.assertEqual([r["phase"] for r in receipts], ["intent", "intent", "failed"])
        self.assertEqual(commands[1], ["nft", "-f", "-"])
        self.assertEqual(receipts[-1]["error_type"], "RuntimeError")

    def test_collision_does_not_write_intent_or_mutate(self):
        with patch("network.saved_state", return_value=None), patch("network.verify_host"), patch("network.guard_hash", return_value="existing"), patch("network.run", side_effect=AssertionError("mutation")), patch("network.save", side_effect=AssertionError("write")):
            with self.assertRaises(RuntimeError):
                network.apply(self.p)

    def test_host_checks_bridge_gateway_snat_and_target_routes(self):
        def execute(args, **kwargs):
            if args[1:4] == ["-j", "-d", "link"]:
                value = [{"flags": ["UP"], "linkinfo": {"info_kind": "bridge"}}]
            elif "address" in args:
                address = "192.0.2.1" if args[-1] == "portalb0" else "198.51.100.1"
                value = [{"addr_info": [{"family": "inet", "local": address, "prefixlen": 29}]}]
            elif "route" in args:
                value = [{"dev": "uplink0"}]
            else:
                value = [{"flags": ["UP"]}]
            return SimpleNamespace(stdout=json.dumps(value))
        paths = []
        def enabled(path):
            paths.append(str(path))
            return '1\n'
        with patch("network.run", side_effect=execute), patch.object(Path, "read_text", autospec=True, side_effect=enabled):
            network.verify_host(self.p)
        self.assertEqual(paths, ['/proc/sys/net/ipv4/conf/portalb0/route_localnet',
                                 '/proc/sys/net/ipv4/ip_forward'])
        for failure in ("bridge", "gateway", "snat", "route", "forward"):
            def broken(args, **kwargs):
                result = execute(args, **kwargs)
                value = json.loads(result.stdout)
                if failure == "bridge" and "-d" in args:
                    value[0]["linkinfo"]["info_kind"] = "dummy"
                elif failure == "gateway" and "address" in args and args[-1] == "portalb0":
                    value[0]["addr_info"][0]["local"] = "192.0.2.3"
                elif failure == "snat" and "address" in args and args[-1] == "uplink0":
                    value[0]["addr_info"][0]["local"] = "198.51.100.2"
                elif failure == "route" and "route" in args:
                    value[0]["dev"] = "other0"
                elif failure == "forward" and args[1:4] == ["-j", "link", "show"]:
                    value[0]["flags"] = []
                return SimpleNamespace(stdout=json.dumps(value))
            with self.subTest(failure=failure), patch("network.run", side_effect=broken), patch.object(Path, "read_text", return_value="1\n"):
                with self.assertRaises(RuntimeError):
                    network.verify_host(self.p)
        for disabled, expected in (('/proc/sys/net/ipv4/conf/portalb0/route_localnet', 'loopback routing'),
                                   ('/proc/sys/net/ipv4/ip_forward', 'IPv4 forwarding')):
            with self.subTest(disabled=disabled), patch("network.run", side_effect=execute), \
                 patch.object(Path, "read_text", autospec=True,
                              side_effect=lambda path: '0\n' if str(path) == disabled else '1\n'):
                with self.assertRaisesRegex(RuntimeError, expected):
                    network.verify_host(self.p)

    def test_ready_repeat_checks_without_mutation(self):
        receipt = {"phase": "ready", "policy": self.p}
        with patch("network.saved_state", return_value=receipt), patch("network.check") as check, patch("network.run", side_effect=AssertionError("mutation")):
            network.apply(self.p)
            check.assert_called_once_with(self.p)

    def test_new_boot_recreates_only_all_absent_same_policy_ready(self):
        old_boot = "00000000-0000-0000-0000-000000000001"
        new_boot = "00000000-0000-0000-0000-000000000002"
        previous = {"phase": "ready", "policy": self.p, "boot_id": old_boot}
        receipts = []
        def lines(binary, table, chain):
            return None if chain.startswith(network.PREFIX) else [["-P", chain, "ACCEPT"]]
        with patch("network.saved_state", return_value=previous), patch("network.boot_id", return_value=new_boot), patch("network.check", side_effect=RuntimeError("absent")), patch("network.all_owned_absent", return_value=True), patch("network.archive_ready", return_value={"filename": "old.json", "sha256": "a"}) as archive, patch("network.verify_host"), patch("network.guard_hash", side_effect=[None, "guard"]), patch("network.chain_lines", side_effect=lines), patch("network.run"), patch("network.verify"), patch("network.save", side_effect=lambda receipt: receipts.append(copy.deepcopy(receipt))):
            network.apply(self.p)
        archive.assert_called_once_with(previous)
        self.assertEqual([r["phase"] for r in receipts], ["intent", "intent", "ready"])
        self.assertEqual(receipts[0]["boot_id"], new_boot)
        self.assertEqual(receipts[0]["previous_ready_archive"]["filename"], "old.json")

    def test_boot_recreation_rejects_partial_same_boot_and_missing_identity(self):
        current = "00000000-0000-0000-0000-000000000002"
        for old_boot, absent in ((current, True), (None, True), ("bad", True),
                                 ("00000000-0000-0000-0000-000000000001", False)):
            previous = {"phase": "ready", "policy": self.p, "boot_id": old_boot}
            with self.subTest(old_boot=old_boot, absent=absent), patch("network.saved_state", return_value=previous), patch("network.boot_id", return_value=current), patch("network.check", side_effect=RuntimeError("missing or drifted")), patch("network.all_owned_absent", return_value=absent), patch("network.archive_ready", side_effect=AssertionError("archive")), patch("network.run", side_effect=AssertionError("mutation")):
                with self.assertRaises(RuntimeError):
                    network.apply(self.p)

    def test_all_absent_requires_no_table_chain_or_owned_shared_reference(self):
        def absent_lines(binary, table, chain):
            return None if chain.startswith(network.PREFIX) else [["-P", chain, "ACCEPT"]]
        with patch("network.guard_hash", return_value=None), patch("network.chain_lines", side_effect=absent_lines):
            self.assertTrue(network.all_owned_absent(self.p))
        with patch("network.guard_hash", return_value="guard"):
            self.assertFalse(network.all_owned_absent(self.p))
        with patch("network.guard_hash", return_value=None), patch("network.chain_lines", return_value=[["-N", "GP_PORTAL_FWD"]]):
            self.assertFalse(network.all_owned_absent(self.p))
        def leftover_jump(binary, table, chain):
            return None if chain.startswith(network.PREFIX) else [["-A", chain, "-j", "GP_PORTAL_UNKNOWN"]]
        with patch("network.guard_hash", return_value=None), patch("network.chain_lines", side_effect=leftover_jump):
            self.assertFalse(network.all_owned_absent(self.p))

    def test_boot_archive_preserves_original_receipt_exclusively(self):
        previous = {"phase": "ready", "boot_id": "00000000-0000-0000-0000-000000000001"}
        data = json.dumps(previous).encode()
        with tempfile.TemporaryDirectory() as tmp, patch("network.STATE", Path(tmp)), patch("network.protected_read", return_value=data), patch("network.time.time_ns", return_value=123):
            archived = network.archive_ready(previous)
            self.assertEqual((Path(tmp) / archived["filename"]).read_bytes(), data)
            self.assertEqual(stat.S_IMODE((Path(tmp) / archived["filename"]).stat().st_mode), 0o600)
            with self.assertRaises(FileExistsError):
                network.archive_ready(previous)

    def test_receipt_atomic_write_and_stale_temporary_refusal(self):
        with tempfile.TemporaryDirectory() as tmp, patch("network.STATE", Path(tmp)):
            network.save({"phase": "intent"})
            self.assertEqual(json.loads((Path(tmp) / "state.json").read_text()), {"phase": "intent"})
            self.assertEqual(stat.S_IMODE((Path(tmp) / "state.json").stat().st_mode), 0o600)
            (Path(tmp) / "state.next").write_text("stale")
            with self.assertRaises(FileExistsError):
                network.save({"phase": "ready"})
            self.assertEqual(json.loads((Path(tmp) / "state.json").read_text()), {"phase": "intent"})


class NamespaceFixtureSafetyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        path = Path(__file__).parent / "tools/test_network_namespace.py"
        spec = importlib.util.spec_from_file_location("namespace_fixture", path)
        cls.fixture = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.fixture)

    def test_unisolated_or_forged_parent_proof_rejected_before_commands(self):
        fixture = self.fixture
        arguments = SimpleNamespace(host_net=100, host_mount=200)
        for identities in ([100, 400], [300, 200], [300, 400, 999]):
            with self.subTest(identities=identities), patch.object(fixture.os, "geteuid", return_value=0), patch.object(fixture, "namespace", side_effect=identities), patch.object(fixture, "run", side_effect=AssertionError("mutation")):
                with self.assertRaises(RuntimeError):
                    fixture.isolate(arguments)

    def test_internal_socket_roles_refuse_host_checkout(self):
        with self.assertRaises(RuntimeError):
            self.fixture.require_inner()


if __name__ == "__main__":
    unittest.main()
