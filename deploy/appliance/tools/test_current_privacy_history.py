#!/usr/bin/env python3
"""Real PG append, normal backup/restore and host-wrapper privacy history gate.

Requires a genuinely installed, inactive appliance service and confined image.
Never creates a unit/profile or fabricates backup/restore provenance.
All DATA/configuration/credentials are fresh synthetic material outside fixed
production namespaces. Only an operator may execute this root-only fixture.
"""
import argparse
import copy
import json
import os
from pathlib import Path
import re
import secrets

import cold_copy
import migrate_current
import prepare_instance as files
import test_current_image as native



VERIFY = """import hashlib,json,sys
sys.path.insert(0,'/opt/homelab-web-rdp')
import runtime,current_migration
import lifecycle as life
try:
 runtime.integrity()
 registry,digest=runtime.configuration()
 mapping=runtime.check_cluster(registry,digest)
 assert registry.publish_target_labels is False
 life.start_pg()
 census=json.loads(life.pg_sql(runtime.snapshot_query(),app=True))
 runtime.validate_snapshot(registry,mapping,census)
 identity=json.loads(life.pg_sql(current_migration.IDENTITY_QUERY,app=True))
 assert runtime.enrolled(registry)
 print(json.dumps({'census_sha256':hashlib.sha256(json.dumps(current_migration.normalize(census),sort_keys=True).encode()).hexdigest(),
  'identity_sha256':hashlib.sha256(json.dumps(identity,sort_keys=True).encode()).hexdigest(),
  'sequence':life.pg_sql('SELECT last_value,is_called FROM guacamole_connection_connection_id_seq;',app=True)}))
finally:life.shutdown()
"""


def configurations():
    examples=Path(__file__).resolve().parents[1]/'examples'
    before=json.loads((examples/'config.json').read_bytes())
    appended=json.loads((examples/'config-ssh.json').read_bytes())
    # A historical synthetic chooser, independent of public private defaults.
    before['portal']['publish_target_labels']=True
    appended['portal']['publish_target_labels']=True
    private=copy.deepcopy(appended)
    private['portal']['publish_target_labels']=False
    return tuple((json.dumps(value,sort_keys=True)+'\n').encode()
                 for value in (before,appended,private))


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image',required=True)
    parser.add_argument('--directory',required=True,type=Path)
    parser.add_argument('--backup-service',required=True)
    parser.add_argument('--apparmor-profile',required=True)
    args=parser.parse_args()
    assert os.geteuid()==0 and re.fullmatch('[a-f0-9]{64}',args.image)
    # These names refer to an existing documented installation; no unit changes.
    assert re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.@-]*\.service',args.backup_service)
    directory=files.literal(args.directory)
    files.protected_directory(directory.parent)
    assert not os.path.lexists(directory)
    os.umask(0o077);files.new_directory(directory)
    receipt={'schema':1,'image':args.image,'passed':False,
             'scope':'synthetic real PG append then genuine normal cold backup/restore and privacy wrapper; no target authentication or production DATA'}
    try:
        original=directory/'original';original.mkdir(mode=0o700);os.chown(original,2000,2000)
        secrets_path=directory/'secrets';files.new_directory(secrets_path)
        for name in ('db-password','portal-password','desktop-a-password','desktop-b-password','terminal-c-key'):
            files.write_new(secrets_path/name,secrets.token_urlsafe(32).encode())
        before,appended,private=configurations()
        initial=directory/'initial-config';files.new_directory(initial)
        append=directory/'append-config';files.new_directory(append)
        privacy=directory/'privacy-config';files.new_directory(privacy)
        files.write_new(initial/'config.json',before)
        files.write_new(append/'previous.json',before)
        files.write_new(append/'config.json',appended)
        files.write_new(privacy/'previous.json',appended)
        files.write_new(privacy/'config.json',private)
        native.run_owned(args.image,directory,original,initial,secrets_path,native.PREPARE,'prepare')
        appended_result=native.run_owned(args.image,directory,original,append,secrets_path,native.MIGRATE,'append')
        assert appended_result['migrated'] and appended_result['identity_unchanged']
        original_manifest=cold_copy.manifest(original)
        original_history={name:(original/migrate_current.current_migration.JOURNAL/name).read_bytes()
                          for name in migrate_current.HISTORY_FILES}
        backup=directory/'backup'
        # Genuine stopped source binding, created without starting portal services.
        token=secrets.token_hex(16);name='portal-current-pg-'+token
        try:
            response=native.engine('run','--pull=never','--name='+name,
                '--label='+native.LABEL+'='+token,'--cidfile='+str(directory/'guard-cid'),
                '--network=none','--read-only','--memory=32m','--memory-swap=32m',
                '--cpus=1','--pids-limit=16','--cap-drop=all',
                '--security-opt=no-new-privileges','--security-opt=apparmor='+args.apparmor_profile,
                '--volume='+str(original)+':/data:ro','--entrypoint=/bin/true',args.image,
                timeout=30,check=False)
            assert response.returncode==0
            cold_copy.perform('backup',backup,source=original,
                              service=args.backup_service,container=name)
        finally:
            native.cleanup_owned(args.image,directory,'guard',name,token)
        restored=directory/'restore'
        cold_copy.perform('restore',restored,backup=backup)
        restore_result=restored/'result.json'
        output=migrate_current.perform('sha256:'+args.image,restored/'data',
            privacy/'previous.json',privacy/'config.json',secrets_path,restore_result,
            native.digest(restore_result.read_bytes()),directory/'privacy-attempt',args.apparmor_profile)
        assert output['passed'] and output['cleanup_verified']
        assert output['migration']['connections']==appended_result['connections']
        assert output['migration']['identity_sha256']==appended_result['identity_sha256']
        for name,raw in original_history.items():
            assert (restored/'data'/migrate_current.HISTORY/name).read_bytes()==raw
            assert output['prior_journal_archive']['files'][name]==native.digest(raw)
        verified=native.run_owned(args.image,directory,restored/'data',privacy,secrets_path,VERIFY,'verify')
        for key in ('census_sha256','identity_sha256','sequence'):
            assert verified[key]==appended_result[key]
        assert cold_copy.manifest(original)==original_manifest
        assert cold_copy.manifest(backup/'data')==original_manifest
        cold_copy.stopped_and_exclusive(restored/'data')
        receipt.update(passed=True,cleanup_verified=True,original_unchanged=True,
                       backup_unchanged=True,history_bytes_retained=True,
                       migration_receipt=str(directory/'privacy-attempt/receipt.json'))
    except BaseException as error:
        receipt['failure_type']=type(error).__name__
        raise
    finally:
        files.json_new(directory/'receipt.json',receipt)
    print(json.dumps(receipt,sort_keys=True))


if __name__=='__main__':main()
