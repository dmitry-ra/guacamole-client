#!/usr/bin/env python3
"""Copy stopped PG16 data to a new backup, or independently restore that backup."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import stat
import subprocess
import sys
import time

import prepare_instance as files

ENV = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"}
MAX_FILES = 200000


class InspectionError(RuntimeError):
    """Fixed diagnostic text only; never constructed from external output."""


def command(argv, timeout=10):
    result = subprocess.run(argv, capture_output=True, timeout=timeout, env=ENV)
    if len(result.stdout) > 16 * 1024 * 1024:
        raise InspectionError("Engine response exceeds bound")
    return result


def engine_json(argv):
    result = command(["/usr/bin/podman", *argv])
    if result.returncode:
        raise InspectionError("Cannot independently inspect container engine")
    return json.loads(result.stdout)


def overlaps(first, second):
    return first == second or first in second.parents or second in first.parents


def mounts_for(container):
    mounts = container.get("Mounts")
    if not isinstance(mounts, list):
        raise InspectionError("Missing container mount census")
    for mount in mounts:
        source = mount.get("Source")
        if not isinstance(source, str) or not source.startswith("/") or ".." in Path(source).parts:
            raise InspectionError("Uninspectable container mount source")
        # Resolve aliases to catch bind sources reached through another symlink.
        yield Path(source).resolve()


def stopped_and_exclusive(data, service=None, container=None, expected_cid=None,
                          allowed_stopped=(), expected_consumers=None, census_out=None):
    """Read-only host checks; no stop/start/create/remove command exists here."""
    data = files.literal(data)
    if (len(allowed_stopped) > 32 or len(set(allowed_stopped)) != len(allowed_stopped)
            or any(not isinstance(cid, str) or not re.fullmatch(r"[a-f0-9]{64}", cid)
                   for cid in allowed_stopped)):
        raise ValueError("Distinct full stopped-consumer IDs required; maximum32")
    consumers = {}
    if bool(service) != bool(container):
        raise ValueError("Both legacy service and container required together")
    legacy_cid = None
    legacy_absent = False
    if service:
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.@-]*\.service", service):
            raise ValueError("Literal service name required")
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]*", container):
            raise ValueError("Literal container name required")
        result = command(["/usr/bin/systemctl", "show", service, "--no-pager",
                          "--property=LoadState,ActiveState,MainPID"])
        properties = dict(line.split("=", 1) for line in result.stdout.decode().splitlines())
        if (result.returncode or properties.get("LoadState") != "loaded"
                or properties.get("ActiveState") not in {"inactive", "failed"}
                or properties.get("MainPID") != "0"):
            raise InspectionError("Legacy service is not independently confirmed stopped")
        if expected_cid is not None and not re.fullmatch(r"[a-f0-9]{64}", expected_cid):
            raise ValueError("Exact legacy container ID required")
        existence = command(["/usr/bin/podman", "container", "exists", container])
        if existence.returncode == 1 and expected_cid is not None:
            pinned = command(["/usr/bin/podman", "container", "exists", expected_cid])
            if pinned.returncode != 1:
                raise InspectionError("Legacy container absence not independently established")
            legacy_cid, legacy_absent = expected_cid, True
        elif existence.returncode == 0:
            old = engine_json(["container", "inspect", container])
            if not isinstance(old, list) or len(old) != 1:
                raise InspectionError("Ambiguous legacy container")
            old = old[0]
            legacy_cid = old.get("Id")
            if (not isinstance(legacy_cid, str) or not re.fullmatch(r"[a-f0-9]{64}", legacy_cid)
                    or old.get("Name", "").lstrip("/") != container
                    or old.get("State", {}).get("Running") is not False
                    or old.get("State", {}).get("Status") not in {"exited", "stopped"}
                    or old.get("State", {}).get("Pid") != 0
                    or data not in set(mounts_for(old))):
                raise InspectionError("Legacy stopped container/data binding not established")
            if expected_cid is not None and legacy_cid != expected_cid:
                raise InspectionError("Legacy container identity changed during copy")
        else:
            raise InspectionError("Legacy absence requires an externally pinned full container ID")
    if legacy_cid in allowed_stopped:
        raise ValueError("Historical consumer allowlist must exclude the legacy production ID")
    result = command(["/usr/bin/podman", "ps", "-aq", "--no-trunc"])
    if result.returncode:
        raise InspectionError("Cannot enumerate all container mounts")
    identifiers = result.stdout.decode().splitlines()
    if (len(set(identifiers)) != len(identifiers) or len(identifiers) > 4096
            or any(not re.fullmatch(r"[a-f0-9]{64}", item) for item in identifiers)):
        raise InspectionError("Invalid or excessive container census")
    if legacy_cid and not legacy_absent and legacy_cid not in identifiers:
        raise InspectionError("Legacy container disappeared during inspection")
    if not set(allowed_stopped) <= set(identifiers):
        raise InspectionError("An explicitly allowed stopped consumer is absent")
    for identifier in identifiers:
        entries = engine_json(["container", "inspect", identifier])
        if (not isinstance(entries, list) or len(entries) != 1
                or entries[0].get("Id") != identifier):
            raise InspectionError("Container census identity changed")
        entry = entries[0]
        sources = list(mounts_for(entry))
        overlapping = [source for source in sources if overlaps(data, source)]
        state = entry.get("State", {})
        stopped = (state.get("Running") is False and type(state.get("Pid")) is int
                   and state["Pid"] == 0 and state.get("Status") in {"exited", "stopped"})
        if identifier in allowed_stopped:
            if not stopped or overlapping != [data]:
                raise InspectionError("Allowed historical consumer is not stopped on the exact data bind")
            name, image = entry.get("Name"), entry.get("Image")
            if (not isinstance(name, str) or not re.fullmatch(r"/?[A-Za-z0-9][A-Za-z0-9_.-]*", name)
                    or not isinstance(image, str) or not re.fullmatch(r"(?:sha256:)?[a-f0-9]{64}", image)):
                raise InspectionError("Allowed historical consumer identity metadata is incomplete")
            mounts = []
            for mount, source in zip(entry["Mounts"], sources):
                if source == data and mount.get("Type") != "bind":
                    raise InspectionError("Allowed historical consumer requires an exact data bind")
                mounts.append({key: mount.get(key) for key in
                               ("Type", "Source", "Destination", "RW", "Options", "Propagation")})
            metadata = {"id": identifier, "name": name, "image_id": image,
                        "state": {"running": False, "pid": 0, "status": state["Status"]},
                        "mounts": mounts}
            consumers[identifier] = {"metadata": metadata, "sha256": hashlib.sha256(
                json.dumps(metadata, sort_keys=True, separators=(",", ":")).encode()).hexdigest()}
        elif overlapping and (legacy_absent or identifier != legacy_cid or not stopped):
            raise InspectionError("Data has another container mount, including a stopped consumer")
    if expected_consumers is not None and consumers != expected_consumers:
        raise InspectionError("Allowed historical consumer metadata changed during copy")
    if census_out is not None:
        census_out.update(consumers)
    return legacy_cid


def pg_directory(path):
    meta = path.lstat()
    if (not stat.S_ISDIR(meta.st_mode) or meta.st_uid != 2000 or meta.st_gid != 2000
            or stat.S_IMODE(meta.st_mode) != 0o700):
        raise ValueError("PG data requires UID/GID2000 mode0700")


def read_member(path, limit=16384):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        meta = os.fstat(stream.fileno())
        if not stat.S_ISREG(meta.st_mode) or meta.st_nlink != 1 or meta.st_size > limit:
            raise ValueError("Bounded regular cluster metadata required")
        raw = stream.read(limit + 1)
    if len(raw) > limit:
        raise ValueError("Cluster metadata exceeds bound")
    return raw, meta


def legacy_receipt(path):
    raw, meta = read_member(path)
    value = json.loads(raw, object_pairs_hook=files.catalog.unique_object)
    if (meta.st_uid not in {0, 2000} or stat.S_IMODE(meta.st_mode) != 0o600
            or not isinstance(value, dict)
            or set(value) != {"schema", "postgres_major", "guacamole", "profile",
                              "portal_username", "config_sha256"}
            or type(value["schema"]) is not int or value["schema"] != 1
            or type(value["postgres_major"]) is not int or value["postgres_major"] != 16
            or value["guacamole"] != "1.6.0"
            or not isinstance(value["profile"], str) or not value["profile"]
            or not isinstance(value["portal_username"], str) or not value["portal_username"]
            or not isinstance(value["config_sha256"], str)
            or not re.fullmatch("[a-f0-9]{64}", value["config_sha256"])):
        raise ValueError("Only the known legacy prepared receipt is eligible")
    return raw


def prepared_receipt(path):
    """Accept only the known legacy or current catalog preparation formats."""
    raw, meta = read_member(path)
    value = json.loads(raw, object_pairs_hook=files.catalog.unique_object)
    if isinstance(value, dict) and "profile" in value:
        return legacy_receipt(path)
    if (meta.st_uid != 0 or stat.S_IMODE(meta.st_mode) != 0o600
            or not isinstance(value, dict)
            or set(value) != {"schema", "postgres_major", "guacamole",
                              "config_sha256", "connections"}
            or type(value["schema"]) is not int or value["schema"] != 1
            or type(value["postgres_major"]) is not int or value["postgres_major"] != 16
            or value["guacamole"] != "1.6.0"
            or not isinstance(value["config_sha256"], str)
            or not re.fullmatch("[a-f0-9]{64}", value["config_sha256"])):
        raise ValueError("Only known legacy or current prepared receipts are eligible")
    mapping = value["connections"]
    if not isinstance(mapping, dict) or not 1 <= len(mapping) <= 32:
        raise ValueError("Current receipt requires one to32 connections")
    identifiers = set()
    for name, identifier in mapping.items():
        files.catalog.alias(name)
        if (type(identifier) is not int or not 1 <= identifier <= 2147483647
                or identifier in identifiers):
            raise ValueError("Distinct positive PostgreSQL integer connection IDs required")
        identifiers.add(identifier)
    return raw


def validate_cluster(data, require_legacy=False, require_receipt=False):
    files.protected_directory(data.parent)
    pg_directory(data)
    pg_directory(data / "pgdata")
    version, meta = read_member(data / "pgdata/PG_VERSION", 8)
    if version not in {b"16", b"16\n"} or meta.st_uid != 2000 or meta.st_mode & 0o077:
        raise ValueError("Stopped PostgreSQL16 cluster required")
    pid = data / "pgdata/postmaster.pid"
    if pid.exists() or pid.is_symlink():
        raise ValueError("Postmaster PID file present; investigate stopped state externally")
    receipt = data / "prepared.json"
    if receipt.exists() or receipt.is_symlink():
        (legacy_receipt if require_legacy else prepared_receipt)(receipt)
    elif require_legacy or require_receipt:
        raise ValueError("Protected preparation receipt required")


def manifest(data, seconds=600):
    deadline = time.monotonic() + seconds
    entries = {}
    device = data.lstat().st_dev

    def visit(path):
        if time.monotonic() >= deadline or len(entries) >= MAX_FILES:
            raise RuntimeError("Cluster census exceeded time or entry bound")
        meta = path.lstat()
        if meta.st_dev != device or meta.st_mode & 0o022:
            raise ValueError("Cluster mount boundaries or writable entries refused")
        name = str(path.relative_to(data))
        info = {"uid": meta.st_uid, "gid": meta.st_gid,
                "mode": stat.S_IMODE(meta.st_mode)}
        if stat.S_ISDIR(meta.st_mode):
            info["type"] = "directory"
            entries[name] = info
            for child in sorted(path.iterdir()):
                visit(child)
        elif stat.S_ISREG(meta.st_mode) and meta.st_nlink == 1:
            info.update(type="file", size=meta.st_size)
            digest = hashlib.sha256()
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
            with os.fdopen(fd, "rb") as stream:
                before = os.fstat(stream.fileno())
                if (before.st_dev, before.st_ino) != (meta.st_dev, meta.st_ino):
                    raise RuntimeError("Cluster entry changed while opening")
                while block := stream.read(1024 * 1024):
                    if time.monotonic() >= deadline:
                        raise RuntimeError("Cluster hashing exceeded deadline")
                    digest.update(block)
                after = os.fstat(stream.fileno())
                if (before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (
                        after.st_size, after.st_mtime_ns, after.st_ctime_ns):
                    raise RuntimeError("Cluster entry changed while hashing")
            info["sha256"] = digest.hexdigest()
            entries[name] = info
        else:
            raise ValueError("Cluster symlinks, hardlinks and special files refused")
    visit(data)
    return {"schema": 1, "entries": entries}


def copy_tree(source, target):
    if overlaps(source, target):
        raise ValueError("Independent source and destination required")
    files.protected_directory(target.parent)
    if target.exists() or target.is_symlink():
        raise ValueError("New data destination required; never overwrite or replay")
    target.mkdir(mode=0o700)  # Atomically reserve this destination against another invocation.
    result = command(["/usr/bin/cp", "-a", "--", str(source) + "/.", str(target)], timeout=600)
    if result.returncode:
        raise RuntimeError("Cold copy failed; preserve incomplete destination for review")
    # Flush only this copy, never unrelated host filesystems.
    for parent, directories, names in os.walk(target, followlinks=False):
        for name in names:
            fd = os.open(Path(parent) / name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
            try:
                os.fsync(fd)
            finally:
                os.close(fd)
        files.fsync_directory(parent)
    files.fsync_directory(target.parent)


def perform(operation, directory, source=None, backup=None, service=None, container=None,
            data_target=None, for_migration=False, legacy_container_id=None, allowed_stopped=()):
    directory = files.literal(directory)
    files.protected_directory(directory.parent)
    if directory.exists() or directory.is_symlink():
        raise ValueError("New case directory required; unresolved cases are never replayed")
    if operation == "backup":
        if not service or not container or source is None or data_target or for_migration:
            raise ValueError("Backup requires explicit source, service and container only")
        source = files.literal(source)
        files.protected_directory(source.parent)
        if overlaps(source, directory):
            raise ValueError("Backup case must be independent of source")
        consumers = {}
        cid = stopped_and_exclusive(source, service, container, legacy_container_id,
                                    allowed_stopped=allowed_stopped, census_out=consumers)
        validate_cluster(source, require_receipt=True)
        expected = manifest(source)
    elif operation == "restore":
        if source or service or container or legacy_container_id or allowed_stopped or backup is None:
            raise ValueError("Restore requires a completed backup case only")
        backup = files.literal(backup)
        files.protected_directory(backup, private=True)
        if overlaps(backup, directory):
            raise ValueError("Restore case must be independent of backup")
        result = json.loads(files.private_bytes(backup / "result.json", 16384),
                            object_pairs_hook=files.catalog.unique_object)
        if result.get("operation") != "backup" or result.get("phase") != "ready":
            raise ValueError("Completed cold backup result required")
        source = backup / "data"
        stopped_and_exclusive(source)
        validate_cluster(source, require_legacy=for_migration, require_receipt=True)
        raw = files.private_bytes(backup / "manifest.json", 64 * 1024 * 1024)
        if hashlib.sha256(raw).hexdigest() != result.get("manifest_sha256"):
            raise ValueError("Backup manifest binding mismatch")
        expected = json.loads(raw, object_pairs_hook=files.catalog.unique_object)
        if manifest(source) != expected:
            raise ValueError("Backup tree differs from its complete manifest")
        cid = None
        consumers = {}
    else:
        raise ValueError("Unknown operation")
    target = files.literal(data_target) if data_target else directory / "data"
    if data_target:
        files.protected_directory(target.parent)
        if overlaps(target, directory) or overlaps(target, source):
            raise ValueError("External target must be independent of case and source")
    if target.exists() or target.is_symlink():
        raise ValueError("New target required; prepared or interrupted destination refused")
    stopped_and_exclusive(target)
    files.new_directory(directory)
    intent = {"schema": 1, "operation": operation, "started_at": time.time(),
              "source": str(source), "target": str(target), "legacy_cid": cid,
              "for_migration": for_migration, "allowed_stopped_consumers": sorted(allowed_stopped),
              "stopped_consumer_census": consumers}
    files.json_new(directory / "intent.json", intent)
    try:
        copy_tree(source, target)
        if manifest(source) != expected or manifest(target) != expected:
            raise ValueError("Source or destination tree changed during copy")
        stopped_and_exclusive(source, service, container, cid, allowed_stopped=allowed_stopped,
                              expected_consumers=consumers)
        stopped_and_exclusive(target)
        raw = (json.dumps(expected, sort_keys=True) + "\n").encode("ascii")
        files.write_new(directory / "manifest.json", raw)
        if for_migration:
            legacy_receipt(target / "prepared.json")
            # Preserve old receipt outside /data; runtime must create its own.
            os.rename(target / "prepared.json", directory / "legacy-prepared.json")
            files.fsync_directory(target)
            files.fsync_directory(directory)
            actual = manifest(target)
            wanted = {"schema": 1, "entries": {k: v for k, v in expected["entries"].items()
                                               if k != "prepared.json"}}
            if actual != wanted:
                raise ValueError("Migration staging changed unexpected cluster entries")
        files.json_new(directory / "result.json", {
            **intent, "phase": "ready", "finished_at": time.time(),
            "manifest_sha256": hashlib.sha256(raw).hexdigest(),
            "legacy_receipt_archived": for_migration})
    except Exception as error:
        files.json_new(directory / "result.json", {
            **intent, "phase": "failed", "error_type": type(error).__name__})
        raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=("backup", "restore"))
    parser.add_argument("--directory", type=Path, required=True)
    parser.add_argument("--source", type=Path)
    parser.add_argument("--backup", type=Path)
    parser.add_argument("--service")
    parser.add_argument("--container")
    parser.add_argument("--legacy-container-id", help="Full ID pinned before external legacy shutdown")
    parser.add_argument("--allow-stopped-consumer", action="append", default=[],
                        help="Reviewed full historical CID; must retain exact stopped data bind")
    parser.add_argument("--data-target", type=Path)
    parser.add_argument("--for-migration", action="store_true")
    args = parser.parse_args()
    if os.geteuid() != 0:
        raise RuntimeError("Root required")
    def expired(signum, frame):
        raise TimeoutError("Cold copy operation exceeded600seconds")
    signal.signal(signal.SIGALRM, expired)
    signal.alarm(600)
    perform(args.operation, args.directory, args.source, args.backup, args.service,
            args.container, args.data_target, args.for_migration, args.legacy_container_id,
            args.allow_stopped_consumer)
    signal.alarm(0)
    print(json.dumps({"success": True, "operation": args.operation}))


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        failure = {"success": False, "error_type": type(error).__name__}
        if isinstance(error, InspectionError):
            failure["reason"] = str(error)
        print(json.dumps(failure), file=sys.stderr)
        sys.exit(1)
