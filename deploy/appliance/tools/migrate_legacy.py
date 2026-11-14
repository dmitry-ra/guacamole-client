#!/usr/bin/env python3
"""Migrate only an independently restored stopped cluster; preserve identity."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import secrets
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import catalog
import host
import cold_copy

LABEL = 'guacamole.portal.migration'
INSIDE = '''import hashlib,json,signal,sys
signal.alarm(100)
sys.path.insert(0,'/opt/homelab-web-rdp')
import runtime
import lifecycle as life
runtime.integrity()
registry,digest=runtime.configuration()
query="SELECT json_build_object('entities',(SELECT json_agg(row_to_json(e) ORDER BY entity_id) FROM guacamole_entity e),'users',(SELECT json_agg(row_to_json(u) ORDER BY user_id) FROM guacamole_user u),'attributes',(SELECT json_agg(row_to_json(a) ORDER BY user_id,attribute_name) FROM guacamole_user_attribute a));"
def identity():
 return hashlib.sha256(json.dumps(json.loads(life.pg_sql(query)),sort_keys=True).encode()).hexdigest()
try:
 life.start_pg()
 before=identity()
 if not runtime.enrolled(registry):raise RuntimeError('Existing confirmed identity required')
 life.shutdown();life.PROCESSES.clear()
 runtime.migrate(registry,digest,sys.argv[1])
 after=identity()
 mapping=runtime.check_cluster(registry,digest)
 if before!=after or not runtime.enrolled(registry) or not runtime.database_health(registry,mapping):raise RuntimeError('Migration identity or health changed')
 print(json.dumps({'migrated':True,'identity_unchanged':True,'identity_sha256':after,'enrolled':True,'connections':mapping}))
finally:life.shutdown()
'''


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image', required=True)
    parser.add_argument('--data', type=Path, required=True)
    parser.add_argument('--directory', type=Path, required=True)
    parser.add_argument('--original-alias', required=True)
    args = parser.parse_args()
    if os.geteuid() != 0:
        raise RuntimeError('Root operator required')
    image = host.image_id(args.image)
    catalog.alias(args.original_alias)
    cold_copy.stopped_and_exclusive(args.data)
    cold_copy.validate_cluster(args.data)
    if (args.data/'prepared.json').exists():
        raise RuntimeError('Restore must archive the legacy preparation receipt')
    host.directory(args.directory.parent)
    os.umask(0o077)
    args.directory.mkdir(mode=0o700)
    run_id = secrets.token_hex(16)
    result = {'image': image, 'data': str(args.data), 'run_id': run_id,
              'source_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
              'config_sha256': hashlib.sha256(host.network.protected_read(host.CONFIG)).hexdigest(),
              'passed': False, 'cleanup_verified': False}
    host.write(args.directory/'intent.json', result)
    cidfile = args.directory/'cid'
    argv = ['run', '--pull=never', '--name=portal-migration-'+run_id[:12],
            '--label='+LABEL+'='+run_id, '--cidfile='+str(cidfile),
            '--read-only', '--network=none', '--cpus=2', '--memory=1g', '--memory-swap=1g',
            '--pids-limit=192', '--cap-drop=all', *['--cap-add='+c for c in
                ('SETUID','SETGID','CHOWN','DAC_OVERRIDE','FOWNER','KILL')],
            '--security-opt=no-new-privileges', '--security-opt=apparmor=guacamole-portal',
            '--tmpfs=/tmp:rw,nosuid,nodev,size=64m,mode=1777',
            '--tmpfs=/run:rw,nosuid,nodev,size=64m,mode=755',
            '--volume='+str(args.data)+':/data:rw',
            '--volume='+str(host.CONFIG.parent)+':/config:ro',
            '--volume='+str(host.PERSIST/'secrets')+':/secrets:ro',
            '--entrypoint=python3', image, '-B', '-c', INSIDE, args.original_alias]
    migration_error = cleanup_error = receipt_error = None
    migration_verified = False
    try:
        response = host.engine(*argv, timeout=120, check=False)
        with (args.directory/'stderr.log').open('xb') as output:
            output.write(response.stderr[:65536])
        with (args.directory/'stdout.log').open('xb') as output:
            output.write(response.stdout[:65536])
        if response.returncode != 0:
            raise RuntimeError('Migration failed; preserve target and restore a new copy')
        result['migration'] = json.loads(response.stdout)
        if result['migration'].get('migrated') is not True:
            raise RuntimeError('Migration completion unconfirmed')
        migration_verified = True
    except BaseException as error:
        result['error_type'] = type(error).__name__
        migration_error = error
    try:
        result['cleanup_phase'] = 'confirm_cid'
        if not cidfile.exists():
            raise RuntimeError('Migration container ID unconfirmed; refuse to claim cleanup')
        cid = host.identifier(cidfile.read_text().strip())
        result['container_id'] = cid
        result['cleanup_phase'] = 'verify_ownership'
        value = host.one(host.engine('inspect', cid).stdout)
        if (value.get('Id') != cid or host.inspected_image(value.get('Image')) != image
                or value.get('Config', {}).get('Labels', {}).get(LABEL) != run_id):
            raise RuntimeError('Foreign migration container; refuse cleanup')
        running = value.get('State', {}).get('Running')
        if type(running) is not bool:
            raise RuntimeError('Migration container running state unconfirmed')
        if running:
            result['cleanup_phase'] = 'stop'
            host.engine('stop', '--time=10', cid, timeout=15)
        result['cleanup_phase'] = 'remove'
        host.engine('rm', cid)
        result['cleanup_phase'] = 'verify_absence'
        absence = host.engine('container', 'exists', cid, check=False).returncode
        result['cleanup_exists_returncode'] = absence
        if absence != 1:
            raise RuntimeError('Migration container absence unconfirmed after cleanup')
        result['cleanup_verified'] = True
        result['cleanup_phase'] = 'verified'
    except BaseException as error:
        cleanup_error = error
        result['cleanup_error_type'] = type(error).__name__
    result['passed'] = migration_verified and migration_error is None and result['cleanup_verified']
    result['phase'] = 'passed' if result['passed'] else 'failed'
    if migration_error is None and cleanup_error is not None:
        result['error_type'] = type(cleanup_error).__name__
    try:
        host.write(args.directory/'receipt.json', result)
    except BaseException as error:
        receipt_error = error
    # Cleanup and receipt failures must never replace the original migration error.
    primary_error = migration_error or cleanup_error or receipt_error
    if primary_error is not None:
        if receipt_error is not None and receipt_error is not primary_error:
            primary_error.add_note('Terminal receipt write failed: ' + type(receipt_error).__name__)
        raise primary_error
    print(json.dumps(result))


if __name__ == '__main__':
    main()
