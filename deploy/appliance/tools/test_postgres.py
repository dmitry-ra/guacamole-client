#!/usr/bin/env python3
"""Bounded isolated PostgreSQL16 SQL fixture; never mount instance data/secrets."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import signal
import subprocess
import sys
import time

HERE = Path(__file__).resolve().parents[1]
LABEL = 'org.dmitryra.portal.pg-fixture'


def inside():
    source_paths = (HERE/'runtime.py', HERE/'lifecycle.py', HERE/'catalog.py', Path(__file__))
    source_hashes = {str(p.relative_to(HERE)): hashlib.sha256(p.read_bytes()).hexdigest() for p in source_paths}
    sys.path.insert(0, str(HERE))
    import catalog
    import lifecycle as life
    import runtime

    def expired(signum, frame):
        raise TimeoutError('Synthetic SQL fixture deadline')
    signal.signal(signal.SIGALRM, expired)
    signal.alarm(100)
    os.umask(0o077)
    os.chown('/data', 2000, 2000)
    os.chmod('/data', 0o700)
    full = catalog.load(HERE/'examples/config.json')
    first = full.targets[0]
    single = catalog.Catalog(full.username, first.alias, False, (first,))
    for name in ('db-password', 'portal-password'):
        runtime.write_private(Path('/secrets')/name, secrets.token_urlsafe(32))
    for target in full.targets:
        runtime.write_private(Path('/secrets')/target.password_file, 'synthetic-short')
    checked = []
    try:
        runtime.prepare(single, 'synthetic-single')
        mapping = runtime.check_cluster(single, 'synthetic-single')
        assert mapping == {first.alias: 1}
        assert runtime.database_health(single, mapping)
        assert not runtime.enrolled(single)
        checked.append('prepare_single_no_default_admin_unenrolled')
        life.pg_sql("INSERT INTO guacamole_user_attribute SELECT user_id,'guac-totp-key-secret','AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' FROM guacamole_user; INSERT INTO guacamole_user_attribute SELECT user_id,'guac-totp-key-confirmed','true' FROM guacamole_user;")
        assert runtime.enrolled(single)
        checked.append('synthetic_enrollment')
        identity_query = "SELECT json_build_object('users',(SELECT json_agg(row_to_json(u)) FROM guacamole_user u),'entities',(SELECT json_agg(row_to_json(e)) FROM guacamole_entity e),'attributes',(SELECT json_agg(row_to_json(a) ORDER BY attribute_name) FROM guacamole_user_attribute a));"
        before = life.pg_sql(identity_query)
        # Convert only synthetic local fixture to legacy shape. No live copies
        # or original data are read; this exercises SQL compatibility only.
        life.pg_sql("UPDATE guacamole_connection SET connection_name='Synthetic legacy desktop' WHERE connection_id=1; UPDATE guacamole_connection_parameter SET parameter_value='${HOMELAB_WINDOWS_PASSWORD}' WHERE connection_id=1 AND parameter_name='password';")
        life.shutdown()
        life.PROCESSES.clear()
        (Path('/data')/'prepared.json').unlink()
        runtime.migrate(full, 'synthetic-multiple', first.alias)
        mapping = runtime.check_cluster(full, 'synthetic-multiple')
        assert mapping[first.alias] == 1 and len(mapping) == len(full.targets)
        assert runtime.database_health(full, mapping)
        assert runtime.enrolled(full)
        assert life.pg_sql(identity_query) == before
        checked.append('migrate_preserves_user_password_totp_and_id1')
        checked.append('multiple_target_exact_census')
        mutations = [
            ("UPDATE guacamole_connection_parameter SET parameter_value='192.0.2.99' WHERE connection_id=1 AND parameter_name='hostname';", "UPDATE guacamole_connection_parameter SET parameter_value="+life.sql(first.hostname)+" WHERE connection_id=1 AND parameter_name='hostname';", 'parameter_drift'),
            ("UPDATE guacamole_connection SET proxy_hostname='192.0.2.99' WHERE connection_id=1;", "UPDATE guacamole_connection SET proxy_hostname=NULL WHERE connection_id=1;", 'proxy_override'),
            ("INSERT INTO guacamole_connection_permission SELECT entity_id,1,'ADMINISTER' FROM guacamole_entity;", "DELETE FROM guacamole_connection_permission WHERE permission='ADMINISTER';", 'connection_admin'),
            ("INSERT INTO guacamole_system_permission SELECT entity_id,'ADMINISTER' FROM guacamole_entity;", "DELETE FROM guacamole_system_permission;", 'system_admin'),
            ("INSERT INTO guacamole_connection(connection_name,protocol) VALUES('unexpected','rdp');", "DELETE FROM guacamole_connection WHERE connection_name='unexpected';", 'extra_connection'),
            ("INSERT INTO guacamole_entity(name,type) VALUES('unexpected','USER_GROUP');", "DELETE FROM guacamole_entity WHERE name='unexpected';", 'extra_group_entity'),
            ("INSERT INTO guacamole_sharing_profile(sharing_profile_name,primary_connection_id) VALUES('unexpected',1);", "DELETE FROM guacamole_sharing_profile;", 'sharing_profile'),
        ]
        for mutation, undo, label in mutations:
            life.pg_sql(mutation)
            try:
                runtime.database_health(full, mapping)
            except RuntimeError:
                checked.append('reject_' + label)
            else:
                raise AssertionError('Drift accepted: ' + label)
            finally:
                life.pg_sql(undo)
            assert runtime.database_health(full, mapping)
        assert source_hashes == {str(p.relative_to(HERE)): hashlib.sha256(p.read_bytes()).hexdigest() for p in source_paths}, 'Sources changed during fixture'
        print(json.dumps({'sources': source_hashes, 'passed': True, 'scope': 'synthetic SQL only; not full image acceptance', 'checks': checked, 'postgres': life.pg_sql('SHOW server_version;').strip()}))
    finally:
        life.shutdown()
        signal.alarm(0)


def podman(*args, **kwargs):
    return subprocess.run(['sudo', '-n', 'podman', *map(str, args)],
                          check=True, timeout=kwargs.pop('timeout', 15),
                          capture_output=True, text=True, **kwargs)


def fixture(image, directory):
    if re.fullmatch('[0-9a-f]{64}', image) is None:
        raise ValueError('Exact local image SHA required')
    os.umask(0o077)
    directory.mkdir(mode=0o700)
    token = secrets.token_hex(16)
    name = 'portal-pg16-fixture-' + token[:16]
    cid = None
    status = {'image': image, 'scope': 'synthetic SQL only', 'cleanup_verified': False}
    command = ['run', '-d', '--name', name, '--label', LABEL+'='+token,
               '--pull=never', '--network=none', '--read-only', '--pids-limit=96',
               '--memory=512m', '--cpus=2',
               '--tmpfs', '/tmp:rw,nosuid,nodev,size=32m',
               '--tmpfs', '/data:rw,nosuid,nodev,size=256m',
               '--tmpfs', '/run/web-rdp:rw,nosuid,nodev,size=32m',
               '--tmpfs', '/secrets:rw,nosuid,nodev,size=1m',
               '--mount', 'type=bind,src='+str(HERE)+',dst=/source,ro',
               '--entrypoint=python3', image, '-B', '/source/tools/test_postgres.py', '--inside']
    try:
        inspected = json.loads(podman('image', 'inspect', image).stdout)[0]
        if inspected['Id'].removeprefix('sha256:') != image:
            raise RuntimeError('Local image identity mismatch')
        cid = podman(*command, timeout=30).stdout.strip()
        if re.fullmatch('[0-9a-f]{64}', cid) is None:
            raise RuntimeError('Invalid container identity')
        result = podman('wait', cid, timeout=120).stdout.strip()
        logs = podman('logs', cid)
        (directory/'stdout.log').write_text(logs.stdout)
        (directory/'stderr.log').write_text(logs.stderr)
        status['exit_code'] = int(result)
        if result != '0':
            raise RuntimeError('Synthetic PostgreSQL fixture failed')
        outcome = json.loads(logs.stdout)
        if outcome.get('passed') is not True:
            raise RuntimeError('Missing successful fixture result')
        status['sources'] = outcome['sources']
        status['result'] = outcome
    finally:
        # Name is freshly generated; additionally require our secret ownership
        # label and exact image before stopping/removing this one container.
        found = podman('ps', '-a', '--filter', 'name=^'+name+'$', '--format', '{{.ID}}').stdout.strip()
        if found:
            owned = json.loads(podman('inspect', name).stdout)[0]
            if owned['Config']['Labels'].get(LABEL) != token or owned['Image'].removeprefix('sha256:') != image or (cid and owned['Id'] != cid):
                raise RuntimeError('Container cleanup ownership mismatch')
            podman('stop', '--time', '5', owned['Id'], timeout=12)
            podman('rm', owned['Id'])
        if podman('ps', '-a', '--filter', 'name=^'+name+'$', '--format', '{{.ID}}').stdout.strip():
            raise RuntimeError('Fixture container survived cleanup')
        status['cleanup_verified'] = True
        (directory/'receipt.json').write_text(json.dumps(status, indent=2)+'\n')
    print(json.dumps(status))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--inside', action='store_true', help=argparse.SUPPRESS)
    parser.add_argument('--image')
    parser.add_argument('--directory', type=Path)
    args = parser.parse_args()
    if args.inside:
        if HERE != Path('/source') or os.geteuid() != 0:
            raise RuntimeError('Inside mode requires isolated fixture container')
        inside()
    else:
        if not args.image or not args.directory:
            parser.error('--image and --directory are required')
        fixture(args.image, args.directory)


if __name__ == '__main__':
    main()
