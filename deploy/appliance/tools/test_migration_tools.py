"""Synthetic filesystem tests; all service and container inspections are mocked."""

import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import cold_copy as cold
import prepare_instance as prepare


class PasswordTests(unittest.TestCase):
    def test_preserves_short_and_space_credentials_and_removes_only_one_lf(self):
        for raw, wanted in [(b"abc", b"abc"), (b" x ", b" x "), (b"abc\n", b"abc")]:
            self.assertEqual(prepare.windows_password(raw), wanted)

    def test_rejects_extra_lf_cr_nul_invalid_utf8_empty_and_oversize(self):
        for raw in (b"", b"\n", b"abc\n\n", b"a\r\n", b"a\0b", b"\xff", b"x" * 513):
            with self.subTest(raw_length=len(raw)), self.assertRaises((ValueError, UnicodeError)):
                prepare.windows_password(raw)

    def test_literal_paths_reject_relative_and_parent_escape(self):
        for value in ("relative", "/", "/var/lib/../etc"):
            with self.assertRaises(ValueError):
                prepare.literal(value)


class EngineInspectionTests(unittest.TestCase):
    cid = "a" * 64
    other = "b" * 64
    data = Path("/var/lib/synthetic-portal/data")

    def container(self, identifier=None, running=False):
        return {"Id": identifier or self.cid, "Name": "legacy-portal",
                "Image": "sha256:" + "c" * 64,
                "State": {"Running": running, "Pid": 123 if running else 0,
                          "Status": "running" if running else "exited"},
                "Mounts": [{"Type": "bind", "Source": str(self.data),
                            "Destination": "/data", "RW": True, "Options": ["rbind"]}]}

    def completed(self, output, code=0):
        return subprocess.CompletedProcess([], code, output.encode(), b"")

    def test_active_service_stops_before_any_data_or_engine_inspection(self):
        with patch.object(cold, "command", return_value=self.completed(
                "LoadState=loaded\nActiveState=active\nMainPID=123\n")), \
                patch.object(cold, "engine_json") as engine:
            with self.assertRaises(RuntimeError):
                cold.stopped_and_exclusive(self.data, "legacy.service", "legacy-portal")
            engine.assert_not_called()

    def test_missing_service_does_not_count_as_stopped(self):
        with patch.object(cold, "command", return_value=self.completed(
                "LoadState=not-found\nActiveState=inactive\nMainPID=0\n")):
            with self.assertRaises(RuntimeError):
                cold.stopped_and_exclusive(self.data, "legacy.service", "legacy-portal")

    def test_running_container_refused_even_when_service_inactive(self):
        with patch.object(cold, "command", return_value=self.completed(
                "LoadState=loaded\nActiveState=inactive\nMainPID=0\n")), \
                patch.object(cold, "engine_json", return_value=[self.container(running=True)]):
            with self.assertRaises(RuntimeError):
                cold.stopped_and_exclusive(self.data, "legacy.service", "legacy-portal")

    def test_other_stopped_container_mount_also_refused(self):
        def command(argv, timeout=10):
            if argv[0].endswith("systemctl"):
                return self.completed("LoadState=loaded\nActiveState=inactive\nMainPID=0\n")
            return self.completed(self.cid + "\n" + self.other + "\n")
        def engine(argv):
            return [self.container(self.other if argv[-1] == self.other else self.cid)]
        with patch.object(cold, "command", side_effect=command), \
                patch.object(cold, "engine_json", side_effect=engine):
            with self.assertRaisesRegex(RuntimeError, "another container mount"):
                cold.stopped_and_exclusive(self.data, "legacy.service", "legacy-portal")

    def test_pinned_stopped_legacy_binding_is_accepted(self):
        def command(argv, timeout=10):
            if argv[0].endswith("systemctl"):
                return self.completed("LoadState=loaded\nActiveState=inactive\nMainPID=0\n")
            return self.completed(self.cid + "\n")
        with patch.object(cold, "command", side_effect=command), \
                patch.object(cold, "engine_json", return_value=[self.container()]):
            self.assertEqual(cold.stopped_and_exclusive(
                self.data, "legacy.service", "legacy-portal"), self.cid)
            with self.assertRaisesRegex(RuntimeError, "identity changed"):
                cold.stopped_and_exclusive(self.data, "legacy.service", "legacy-portal", self.other)

    def test_parent_and_child_mounts_overlap_data(self):
        with patch.object(cold, "command", return_value=self.completed(self.other + "\n")):
            for source in (self.data.parent, self.data / "pgdata", self.data):
                entry = self.container(self.other)
                entry["Mounts"] = [{"Source": str(source)}]
                with patch.object(cold, "engine_json", return_value=[entry]):
                    with self.assertRaises(RuntimeError):
                        cold.stopped_and_exclusive(self.data)

    def test_absent_legacy_requires_pinned_id_and_two_fresh_absence_checks(self):
        queried = []
        def command(argv, timeout=10):
            queried.append(argv)
            if argv[0].endswith("systemctl"):
                return self.completed("LoadState=loaded\nActiveState=inactive\nMainPID=0\n")
            if "exists" in argv:
                return self.completed("", 1)
            return self.completed("")
        with patch.object(cold, "command", side_effect=command):
            with self.assertRaises(RuntimeError):
                cold.stopped_and_exclusive(self.data, "legacy.service", "legacy-portal")
            self.assertEqual(cold.stopped_and_exclusive(
                self.data, "legacy.service", "legacy-portal", self.cid), self.cid)
        self.assertIn(["/usr/bin/podman", "container", "exists", self.cid], queried)

    def test_engine_error_never_counts_as_absence(self):
        def command(argv, timeout=10):
            if argv[0].endswith("systemctl"):
                return self.completed("LoadState=loaded\nActiveState=inactive\nMainPID=0\n")
            return self.completed("", 125)
        with patch.object(cold, "command", side_effect=command):
            with self.assertRaises(RuntimeError):
                cold.stopped_and_exclusive(self.data, "legacy.service", "legacy-portal", self.cid)

    def test_explicit_stopped_consumer_is_bound_to_exact_metadata(self):
        entry = self.container(self.other)
        census = {}
        with patch.object(cold, "command", return_value=self.completed(self.other + "\n")), \
                patch.object(cold, "engine_json", return_value=[entry]):
            cold.stopped_and_exclusive(self.data, allowed_stopped=[self.other], census_out=census)
            cold.stopped_and_exclusive(self.data, allowed_stopped=[self.other], expected_consumers=census)
            self.assertEqual(census[self.other]["metadata"]["id"], self.other)
            self.assertEqual(len(census[self.other]["sha256"]), 64)
            entry["Name"] = "renamed-history"
            with self.assertRaisesRegex(cold.InspectionError, "metadata changed"):
                cold.stopped_and_exclusive(self.data, allowed_stopped=[self.other], expected_consumers=census)

    def test_allowed_consumer_must_be_present_full_id_and_correct_binding(self):
        with patch.object(cold, "command", return_value=self.completed(self.other + "\n")), \
                patch.object(cold, "engine_json", return_value=[self.container(self.other)]):
            with self.assertRaisesRegex(cold.InspectionError, "absent"):
                cold.stopped_and_exclusive(self.data, allowed_stopped=[self.cid])
            for ids in ([self.other[:12]], [self.other, self.other]):
                with self.assertRaises(ValueError):
                    cold.stopped_and_exclusive(self.data, allowed_stopped=ids)
        entry = self.container(self.other)
        entry["Mounts"][0]["Source"] = str(self.data.parent)
        with patch.object(cold, "command", return_value=self.completed(self.other + "\n")), \
                patch.object(cold, "engine_json", return_value=[entry]):
            with self.assertRaisesRegex(cold.InspectionError, "exact data bind"):
                cold.stopped_and_exclusive(self.data, allowed_stopped=[self.other])

    def test_allowed_consumer_running_pid_or_unknown_state_is_refused(self):
        for state in ({"Running": True, "Pid": 123, "Status": "running"},
                      {"Running": False, "Pid": 123, "Status": "exited"},
                      {"Running": False, "Pid": 0, "Status": "paused"},
                      {"Running": False, "Pid": False, "Status": "exited"}):
            entry = self.container(self.other)
            entry["State"] = state
            with self.subTest(state=state), \
                    patch.object(cold, "command", return_value=self.completed(self.other + "\n")), \
                    patch.object(cold, "engine_json", return_value=[entry]):
                with self.assertRaisesRegex(cold.InspectionError, "not stopped"):
                    cold.stopped_and_exclusive(self.data, allowed_stopped=[self.other])


@unittest.skipUnless(os.geteuid() == 0, "Run as root for synthetic UID2000 and protected ancestry")
class ProtectedFilesystemTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="portal-migration-test-", dir="/run")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        os.chmod(self.root, 0o700)

    def write(self, path, value):
        path.write_bytes(value)
        path.chmod(0o600)
        return path

    def inputs(self):
        config = json.loads((Path(__file__).parents[1] / "examples/config.json").read_text())
        network = {"schema_version": 1, "bridge": "portaltest", "subnet_ipv4": "198.18.0.0/24",
                   "source_ipv4": "198.18.0.2", "gateway_ipv4": "198.18.0.1",
                   "forward_interface": "eth0", "snat_ipv4": "192.0.2.1",
                   "host_backend_port": 8080, "local_endpoints": []}
        self.write(self.root / "config.json", json.dumps(config, indent=3).encode() + b"\n")
        self.write(self.root / "network.json", json.dumps(network).encode() + b"\n")
        secrets = self.root / "legacy-secrets"
        secrets.mkdir(mode=0o700)
        self.write(secrets / "db-password", b"synthetic-database-password\n")
        self.write(secrets / "rdp-password", b"abc")
        return config

    def prepare(self, explicit=True):
        prepare.prepare(self.root / "config.json", self.root / "network.json",
                        self.root / "new-config", self.root / "new-state",
                        self.root / "legacy-secrets", explicit)

    def cluster(self):
        data = self.root / "legacy-data"
        data.mkdir(mode=0o700)
        (data / "pgdata").mkdir(mode=0o700)
        for path in (data, data / "pgdata"):
            os.chown(path, 2000, 2000)
        self.write(data / "pgdata/PG_VERSION", b"16\n")
        self.write(data / "pgdata/base-file", b"synthetic opaque pages\0\n")
        old = {"schema": 1, "postgres_major": 16, "guacamole": "1.6.0",
               "profile": "synthetic", "portal_username": "operator", "config_sha256": "c" * 64}
        self.write(data / "prepared.json", json.dumps(old).encode())
        for path in (data / "pgdata/PG_VERSION", data / "pgdata/base-file", data / "prepared.json"):
            os.chown(path, 2000, 2000)
        return data

    def test_preparation_preserves_input_bytes_db_lf_and_separate_short_passwords(self):
        config = self.inputs()
        self.prepare()
        for name in ("config.json", "network.json"):
            self.assertEqual((self.root / "new-config" / name).read_bytes(),
                             (self.root / name).read_bytes())
        secrets = self.root / "new-state/secrets"
        self.assertEqual((secrets / "db-password").read_bytes(), b"synthetic-database-password\n")
        inodes = []
        for target in config["targets"].values():
            path = secrets / target["password_file"]
            self.assertEqual(path.read_bytes(), b"abc")
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            inodes.append(path.stat().st_ino)
        self.assertEqual(len(set(inodes)), len(inodes))
        self.assertFalse((secrets / "portal-password").exists())
        self.assertFalse((self.root / "new-state/data").exists())
        with self.assertRaises(ValueError):
            self.prepare()

    def test_preparation_requires_explicit_reuse_and_unique_secret_references(self):
        config = self.inputs()
        with self.assertRaisesRegex(ValueError, "Explicit"):
            self.prepare(False)
        self.assertFalse((self.root / "new-state").exists())
        config["targets"]["desktop-b"]["password_file"] = "desktop-a-password"
        self.write(self.root / "config.json", json.dumps(config).encode())
        with self.assertRaisesRegex(ValueError, "Distinct"):
            self.prepare()

    def test_preparation_rejects_symlink_secret_and_duplicate_json_key(self):
        self.inputs()
        (self.root / "legacy-secrets/alias").symlink_to("rdp-password")
        with self.assertRaises(OSError):
            prepare.private_bytes(self.root / "legacy-secrets/alias")
        self.write(self.root / "config.json", b'{"schema_version":1,"schema_version":1}')
        with self.assertRaises(ValueError):
            self.prepare()

    def test_unsafe_parent_symlink_and_group_writable_input_refused(self):
        bad = self.root / "bad"
        bad.mkdir(mode=0o777)
        bad.chmod(0o777)
        with self.assertRaises(ValueError):
            prepare.new_directory(bad / "child")
        (self.root / "link").symlink_to(self.root, target_is_directory=True)
        with self.assertRaises(ValueError):
            prepare.new_directory(self.root / "link/new")
        self.write(self.root / "input", b"anything").chmod(0o660)
        with self.assertRaises(ValueError):
            prepare.private_bytes(self.root / "input")

    def test_version_current_receipt_and_stale_pid_refused(self):
        data = self.cluster()
        cold.validate_cluster(data, True)
        self.write(data / "pgdata/PG_VERSION", b"15\n")
        with self.assertRaises(ValueError):
            cold.validate_cluster(data, True)
        self.write(data / "pgdata/PG_VERSION", b"16\n")
        self.write(data / "prepared.json", b'{"schema":1,"connections":{"desktop-a":1}}')
        with self.assertRaises(ValueError):
            cold.validate_cluster(data, True)
        self.write(data / "pgdata/postmaster.pid", b"123")
        with self.assertRaisesRegex(ValueError, "PID"):
            cold.validate_cluster(data)

    def current_receipt(self, data):
        value = {"schema": 1, "postgres_major": 16, "guacamole": "1.6.0",
                 "config_sha256": "d" * 64, "connections": {"desktop-a": 1, "shell-b": 7}}
        path = self.write(data / "prepared.json", json.dumps(value, indent=2).encode() + b"\n")
        os.chown(path, 0, 0)
        return value

    def test_current_receipt_strict_fields_versions_hash_aliases_and_mapping_bounds(self):
        data = self.cluster()
        value = self.current_receipt(data)
        path = data / "prepared.json"
        mutations = [{**value, "extra": 1}, {**value, "profile": "hybrid"},
                     {key: item for key, item in value.items() if key != "guacamole"},
                     {**value, "schema": True}, {**value, "schema": 2},
                     {**value, "postgres_major": True}, {**value, "postgres_major": 17},
                     {**value, "guacamole": "1.7.0"}, {**value, "config_sha256": "D" * 64},
                     {**value, "config_sha256": "d" * 63}]
        mappings = [None, [], {}, {"desktop-a": 1, "desktop-b": 1},
                    {"Bad-Alias": 1}, {"a" * 49: 1}, {"desktop-a": True},
                    {"desktop-a": 0}, {"desktop-a": -1}, {"desktop-a": 1.0},
                    {"desktop-a": "1"}, {"desktop-a": 2147483648},
                    {"desktop-" + str(i): i + 1 for i in range(33)}]
        mutations.extend({**value, "connections": mapping} for mapping in mappings)
        for changed in mutations:
            with self.subTest(value=changed), self.assertRaises(ValueError):
                self.write(path, json.dumps(changed).encode())
                cold.prepared_receipt(path)
        value["connections"] = {"desktop-" + str(i): i + 1 for i in range(32)}
        value["connections"]["desktop-31"] = 2147483647
        self.write(path, json.dumps(value).encode())
        self.assertEqual(cold.prepared_receipt(path), path.read_bytes())
        for raw in (b'{"schema":1,"schema":1}',
                    json.dumps(value).replace('"desktop-0": 1',
                        '"desktop-0": 1, "desktop-0": 2').encode(), b" " * 16385):
            self.write(path, raw)
            with self.assertRaises(ValueError):
                cold.prepared_receipt(path)

    def test_current_receipt_requires_root_private_single_link_regular_file(self):
        data = self.cluster()
        self.current_receipt(data)
        path = data / "prepared.json"
        os.chown(path, 2000, 2000)
        with self.assertRaises(ValueError):
            cold.prepared_receipt(path)
        os.chown(path, 0, 0)
        path.chmod(0o640)
        with self.assertRaises(ValueError):
            cold.prepared_receipt(path)
        path.chmod(0o600)
        os.link(path, data / "receipt-link")
        with self.assertRaises(ValueError):
            cold.prepared_receipt(path)
        (data / "receipt-symlink").symlink_to("prepared.json")
        with self.assertRaises(OSError):
            cold.prepared_receipt(data / "receipt-symlink")

    def test_current_backup_exact_independent_restore_and_migration_refusal(self):
        source = self.cluster()
        self.current_receipt(source)
        original = cold.manifest(source)
        backup, restored = self.root / "backup", self.root / "restored"
        with patch.object(cold, "stopped_and_exclusive", return_value="a" * 64):
            cold.perform("backup", backup, source, service="current.service", container="current")
            cold.perform("restore", restored, backup=backup)
            for target in (source, backup / "data", restored / "data"):
                self.assertEqual(cold.manifest(target), original)
                self.assertEqual((target / "prepared.json").read_bytes(),
                                 (source / "prepared.json").read_bytes())
            self.assertNotEqual((source / "pgdata/base-file").stat().st_ino,
                                (restored / "data/pgdata/base-file").stat().st_ino)
            self.assertFalse((restored / "legacy-prepared.json").exists())
            refused, target = self.root / "migration-refused", self.root / "new-data"
            with patch.object(cold, "copy_tree") as copier:
                with self.assertRaisesRegex(ValueError, "legacy"):
                    cold.perform("restore", refused, backup=backup,
                                 data_target=target, for_migration=True)
                copier.assert_not_called()
            self.assertFalse(refused.exists())
            self.assertFalse(target.exists())
            self.assertEqual(cold.manifest(backup / "data"), original)

    def test_backup_requires_receipt_for_both_known_formats(self):
        source = self.cluster()
        (source / "prepared.json").unlink()
        with patch.object(cold, "stopped_and_exclusive", return_value="a" * 64):
            with self.assertRaisesRegex(ValueError, "receipt required"):
                cold.perform("backup", self.root / "backup", source,
                             service="current.service", container="current")
        self.assertFalse((self.root / "backup").exists())

    def test_complete_manifest_detects_bytes_metadata_and_unsafe_entries(self):
        data = self.cluster()
        before = cold.manifest(data)
        self.write(data / "pgdata/base-file", b"changed opaque pages!\0\n")
        self.assertNotEqual(cold.manifest(data), before)
        (data / "pgdata/symlink").symlink_to("PG_VERSION")
        with self.assertRaises(ValueError):
            cold.manifest(data)

    def test_manifest_rejects_external_hardlinks_and_fifos(self):
        for unsafe in ("hardlink", "fifo"):
            with self.subTest(kind=unsafe):
                data = self.root / unsafe
                data.mkdir(mode=0o700)
                if unsafe == "hardlink":
                    external = self.write(self.root / "external", b"not cluster data")
                    os.link(external, data / "entry")
                else:
                    os.mkfifo(data / "entry", 0o600)
                with self.assertRaises(ValueError):
                    cold.manifest(data)

    def test_stopped_backup_independent_restore_and_legacy_receipt_archive(self):
        source = self.cluster()
        backup, restored = self.root / "backup", self.root / "restored"
        original = cold.manifest(source)
        with patch.object(cold, "stopped_and_exclusive", return_value="a" * 64):
            cold.perform("backup", backup, source, service="legacy.service", container="legacy")
            cold.perform("restore", restored, backup=backup, for_migration=True)
        self.assertEqual(cold.manifest(source), original)
        self.assertEqual(cold.manifest(backup / "data"), original)
        self.assertEqual((restored / "legacy-prepared.json").read_bytes(),
                         (source / "prepared.json").read_bytes())
        self.assertFalse((restored / "data/prepared.json").exists())
        self.assertNotEqual((source / "pgdata/base-file").stat().st_ino,
                            (restored / "data/pgdata/base-file").stat().st_ino)
        self.assertEqual((restored / "data").stat().st_uid, 2000)
        with self.assertRaises(ValueError):
            cold.perform("restore", restored, backup=backup)

    def test_changed_backup_and_preexisting_target_are_refused(self):
        source = self.cluster()
        backup = self.root / "backup"
        with patch.object(cold, "stopped_and_exclusive", return_value="a" * 64):
            cold.perform("backup", backup, source, service="legacy.service", container="legacy")
            existing = self.root / "existing-data"
            existing.mkdir(mode=0o700)
            self.write(existing / "prepared.json", b"do not overwrite")
            with self.assertRaises(ValueError):
                cold.perform("restore", self.root / "case", backup=backup, data_target=existing)
            self.assertEqual((existing / "prepared.json").read_bytes(), b"do not overwrite")
            self.write(backup / "data/pgdata/base-file", b"corruption")
            with self.assertRaisesRegex(ValueError, "complete manifest"):
                cold.perform("restore", self.root / "case2", backup=backup)
            self.assertFalse((self.root / "case2").exists())

    def test_stop_proof_precedes_cluster_read_and_failure_is_not_replayed(self):
        source = self.cluster()
        case = self.root / "case"
        with patch.object(cold, "stopped_and_exclusive", side_effect=RuntimeError("active")), \
                patch.object(cold, "validate_cluster") as reader:
            with self.assertRaises(RuntimeError):
                cold.perform("backup", case, source, service="legacy.service", container="legacy")
            reader.assert_not_called()
        with patch.object(cold, "stopped_and_exclusive", return_value="a" * 64), \
                patch.object(cold, "copy_tree", side_effect=TimeoutError):
            with self.assertRaises(TimeoutError):
                cold.perform("backup", case, source, service="legacy.service", container="legacy")
        self.assertEqual(json.loads((case / "result.json").read_text())["phase"], "failed")
        with self.assertRaises(ValueError):
            cold.perform("backup", case, source, service="legacy.service", container="legacy")

    def test_absent_pinned_legacy_id_survives_complete_backup_and_postcopy_recheck(self):
        source = self.cluster()
        case = self.root / "absent-backup"
        pinned = "a" * 64
        queries = []
        original_command = cold.command
        def synthetic_command(argv, timeout=10):
            queries.append(argv)
            if argv[0] == "/usr/bin/cp":
                return original_command(argv, timeout)
            if argv[0] == "/usr/bin/systemctl":
                output = b"LoadState=loaded\nActiveState=inactive\nMainPID=0\n"
                return subprocess.CompletedProcess(argv, 0, output, b"")
            return subprocess.CompletedProcess(argv, 1 if "exists" in argv else 0, b"", b"")
        with patch.object(cold, "command", side_effect=synthetic_command):
            cold.perform("backup", case, source, service="legacy.service", container="legacy",
                         legacy_container_id=pinned)
        receipt = json.loads((case / "result.json").read_text())
        self.assertEqual(receipt["phase"], "ready")
        self.assertEqual(receipt["legacy_cid"], pinned)
        self.assertEqual(queries.count(["/usr/bin/podman", "container", "exists", pinned]), 2)
        self.assertEqual(cold.manifest(source), cold.manifest(case / "data"))

    def test_allowed_historical_consumer_census_is_recorded_and_change_fails_backup(self):
        source = self.cluster()
        historical, legacy = "b" * 64, "a" * 64
        original_command, original_copy = cold.command, cold.copy_tree
        for changed in (False, True):
            case = self.root / ("changed-consumer" if changed else "stable-consumer")
            entry = {"Id": historical, "Name": "historical-run", "Image": "sha256:" + "c" * 64,
                     "State": {"Running": False, "Pid": 0, "Status": "exited"},
                     "Mounts": [{"Type": "bind", "Source": str(source),
                                 "Destination": "/data", "RW": True}]}
            def synthetic_command(argv, timeout=10):
                if argv[0] == "/usr/bin/cp":
                    return original_command(argv, timeout)
                if argv[0] == "/usr/bin/systemctl":
                    return subprocess.CompletedProcess(argv, 0,
                        b"LoadState=loaded\nActiveState=inactive\nMainPID=0\n", b"")
                return subprocess.CompletedProcess(argv, 1 if "exists" in argv else 0,
                    b"" if "exists" in argv else (historical + "\n").encode(), b"")
            def synthetic_copy(first, second):
                original_copy(first, second)
                if changed:
                    entry["Name"] = "changed-after-copy"
            with self.subTest(changed=changed), \
                    patch.object(cold, "command", side_effect=synthetic_command), \
                    patch.object(cold, "engine_json", return_value=[entry]), \
                    patch.object(cold, "copy_tree", side_effect=synthetic_copy):
                if changed:
                    with self.assertRaisesRegex(cold.InspectionError, "metadata changed"):
                        cold.perform("backup", case, source, service="legacy.service", container="legacy",
                                     legacy_container_id=legacy, allowed_stopped=[historical])
                else:
                    cold.perform("backup", case, source, service="legacy.service", container="legacy",
                                 legacy_container_id=legacy, allowed_stopped=[historical])
            intent = json.loads((case / "intent.json").read_text())
            result = json.loads((case / "result.json").read_text())
            self.assertEqual(intent["allowed_stopped_consumers"], [historical])
            self.assertEqual(intent["stopped_consumer_census"][historical]["metadata"]["name"],
                             "historical-run")
            self.assertEqual(result["phase"], "failed" if changed else "ready")


if __name__ == "__main__":
    unittest.main()
