#!/usr/bin/env python3
"""Create a new private instance namespace from external reviewed inputs only."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import catalog
import network


def literal(path):
    path = Path(path)
    if not path.is_absolute() or ".." in path.parts or path == Path("/"):
        raise ValueError("Literal absolute non-root path required")
    return path


def protected_directory(path, private=False):
    path = literal(path) if Path(path) != Path("/") else Path("/")
    for parent in reversed((path, *path.parents)):
        meta = parent.lstat()
        if not stat.S_ISDIR(meta.st_mode) or meta.st_uid != 0 or meta.st_mode & 0o022:
            raise ValueError("Root-protected directory ancestry required")
    if private and stat.S_IMODE(path.lstat().st_mode) != 0o700:
        raise ValueError("Private directory mode0700 required")


def new_directory(path):
    path = literal(path)
    protected_directory(path.parent)
    path.mkdir(mode=0o700)  # No exist_ok: interrupted work is never replayed.
    fsync_directory(path.parent)


def fsync_directory(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def write_new(path, data):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())
    fsync_directory(Path(path).parent)


def json_new(path, value):
    write_new(path, (json.dumps(value, sort_keys=True) + "\n").encode("ascii"))


def private_bytes(path, limit=1024):
    path = literal(path)
    protected_directory(path.parent)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        meta = os.fstat(stream.fileno())
        if (not stat.S_ISREG(meta.st_mode) or meta.st_uid != 0 or meta.st_nlink != 1
                or stat.S_IMODE(meta.st_mode) != 0o600 or meta.st_size > limit):
            raise ValueError("Bounded root-private single-link input required")
        value = stream.read(limit + 1)
    if len(value) > limit:
        raise ValueError("Input exceeds bound")
    return value


def windows_password(raw):
    # Legacy readers stripped a line terminator. Only one LF is normalized.
    value = raw[:-1] if raw.endswith(b"\n") else raw
    if not 1 <= len(value) <= 512 or any(c in value for c in (b"\r", b"\n", b"\0")):
        raise ValueError("Invalid Windows credential length or encoding")
    value.decode("utf-8")
    return value


def prepare(config, network_config, config_directory, state_directory, legacy_secrets,
            reuse_legacy_rdp_for_all=False):
    config_directory, state_directory = map(literal, (config_directory, state_directory))
    if (config_directory == state_directory or config_directory in state_directory.parents
            or state_directory in config_directory.parents):
        raise ValueError("Separate configuration and state namespaces required")
    for path in (config_directory, state_directory):
        protected_directory(path.parent)
        if path.exists() or path.is_symlink():
            raise ValueError("New instance paths required; never replay preparation")
    config_raw = private_bytes(config, 128 * 1024)
    network_raw = private_bytes(network_config, 128 * 1024)
    registry = catalog.parse(json.loads(config_raw, object_pairs_hook=catalog.unique_object))
    policy = network.parse_config(json.loads(network_raw, object_pairs_hook=catalog.unique_object))
    network.policy(policy, registry)  # Pure validation, no host/firewall operation.
    references = [target.password_file for target in registry.targets]
    if len(set(references)) != len(references) or set(references) & {"db-password", "portal-password"}:
        raise ValueError("Distinct per-target credential filenames required")
    if not reuse_legacy_rdp_for_all:
        raise ValueError("Explicit --reuse-legacy-rdp-for-all required for shared legacy credential")
    legacy_secrets = literal(legacy_secrets)
    protected_directory(legacy_secrets, private=True)
    db = private_bytes(legacy_secrets / "db-password", 4096)
    # Match runtime.secret exactly for validation; copy the original bytes.
    db_text = db.decode("utf-8").rstrip("\n")
    if not 16 <= len(db_text) <= 512 or any(c in db_text for c in "\r\n\0"):
        raise ValueError("Invalid legacy database credential")
    rdp = windows_password(private_bytes(legacy_secrets / "rdp-password", 513))
    new_directory(state_directory)
    intent = {"schema": 1, "operation": "prepare-instance", "started_at": time.time(),
              "config_directory": str(config_directory), "state_directory": str(state_directory),
              "config_sha256": hashlib.sha256(config_raw).hexdigest(),
              "network_sha256": hashlib.sha256(network_raw).hexdigest(),
              "shared_legacy_rdp_explicit": True}
    json_new(state_directory / "prepare-intent.json", intent)
    try:
        new_directory(config_directory)
        write_new(config_directory / "config.json", config_raw)
        write_new(config_directory / "network.json", network_raw)
        new_directory(state_directory / "secrets")
        write_new(state_directory / "secrets/db-password", db)
        for reference in references:
            write_new(state_directory / "secrets" / reference, rdp)
        # No portal-password, account creation, data or prepared receipt.
        json_new(state_directory / "prepare-result.json", {
            **intent, "phase": "ready", "finished_at": time.time(), "target_count": len(references)})
    except Exception as error:
        json_new(state_directory / "prepare-result.json", {
            **intent, "phase": "failed", "error_type": type(error).__name__})
        raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--network", type=Path, required=True)
    parser.add_argument("--config-directory", type=Path, required=True)
    parser.add_argument("--state-directory", type=Path, required=True)
    parser.add_argument("--legacy-secrets", type=Path, required=True)
    parser.add_argument("--reuse-legacy-rdp-for-all", action="store_true")
    args = parser.parse_args()
    if os.geteuid() != 0:
        raise RuntimeError("Root required")
    prepare(args.config, args.network, args.config_directory, args.state_directory,
            args.legacy_secrets, args.reuse_legacy_rdp_for_all)
    print(json.dumps({"success": True, "operation": "prepare-instance"}))


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        print(json.dumps({"success": False, "error_type": type(error).__name__}), file=sys.stderr)
        sys.exit(1)
