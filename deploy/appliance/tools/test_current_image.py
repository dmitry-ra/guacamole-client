#!/usr/bin/env python3
"""Native PG16 CURRENT append or label-privacy migration on an independent synthetic cold copy.

This is not the host migration wrapper or a production backup receipt. All
cluster data and credentials are newly generated synthetic fixture material.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import subprocess
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import cold_copy

ROOT = '/opt/homelab-web-rdp'
LABEL = 'org.dmitryra.portal.current-pg-fixture'
PREPARE = '''import json,sys
sys.path.insert(0,'/opt/homelab-web-rdp')
import runtime
import lifecycle as life
import current_migration
import hashlib
try:
 runtime.integrity()
 registry,digest=runtime.configuration()
 runtime.prepare(registry,digest)
 life.pg_sql("INSERT INTO guacamole_user_attribute SELECT user_id,'guac-totp-key-secret','AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' FROM guacamole_user; INSERT INTO guacamole_user_attribute SELECT user_id,'guac-totp-key-confirmed','true' FROM guacamole_user;")
 assert runtime.enrolled(registry)
 mapping={t.alias:i for i,t in enumerate(registry.targets,1)}
 census=json.loads(life.pg_sql(runtime.snapshot_query(),app=True))
 identity=json.loads(life.pg_sql(current_migration.IDENTITY_QUERY,app=True))
 print(json.dumps({'prepared':True,'connections':mapping,
  'census_sha256':hashlib.sha256(json.dumps(current_migration.normalize(census),sort_keys=True).encode()).hexdigest(),
  'identity_sha256':hashlib.sha256(json.dumps(identity,sort_keys=True).encode()).hexdigest(),
  'sequence':life.pg_sql('SELECT last_value,is_called FROM guacamole_connection_connection_id_seq;',app=True)}))
finally:life.shutdown()
'''
MIGRATE = '''import json,sys
sys.path.insert(0,'/opt/homelab-web-rdp')
import runtime
import lifecycle as life
import current_migration
import hashlib
try:
 runtime.integrity()
 registry,digest=runtime.configuration()
 result=current_migration.migrate(registry,digest,'/config/previous.json')
 assert result['identity_unchanged'] and result['enrolled']
 census=json.loads(life.pg_sql(runtime.snapshot_query(),app=True))
 result['census_sha256']=hashlib.sha256(json.dumps(current_migration.normalize(census),sort_keys=True).encode()).hexdigest()
 result['sequence']=life.pg_sql('SELECT last_value,is_called FROM guacamole_connection_connection_id_seq;',app=True)
 result['labels_hidden']=registry.publish_target_labels is False
 print(json.dumps(result))
finally:life.shutdown()
'''


def engine(*args, timeout=180, check=True):
    return subprocess.run(['podman', *map(str,args)], capture_output=True,
                          timeout=timeout, check=check)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def private(path, raw):
    with path.open('xb') as stream:
        stream.write(raw)
    path.chmod(0o600)


def run_owned(image, directory, data, bundle, secret_dir, payload, stage):
    token=secrets.token_hex(16)
    name='portal-current-pg-'+token
    cid=None
    result=None
    primary_error=None
    try:
        result=engine('run','--pull=never','--name='+name,
            '--label='+LABEL+'='+token,'--cidfile='+str(directory/(stage+'-cid')),
            '--network=none','--read-only','--cpus=2','--memory=1g',
            '--memory-swap=1g','--pids-limit=192',
            '--tmpfs=/tmp:rw,nosuid,nodev,size=64m',
            '--tmpfs=/run/web-rdp:rw,nosuid,nodev,size=64m',
            '--volume='+str(data)+':/data:rw',
            '--volume='+str(bundle)+':/config:ro',
            '--volume='+str(secret_dir)+':/secrets:ro',
            '--entrypoint=python3',image,'-B','-c',payload,check=False)
        cid=(directory/(stage+'-cid')).read_text().strip()
        assert re.fullmatch('[a-f0-9]{64}',cid)
        assert result.returncode==0, stage+' native process failed'
        assert len(result.stdout)<32768
        value=json.loads(result.stdout)
        return value
    except BaseException as error:
        primary_error=error
        raise
    finally:
        try:
            cleanup_owned(image,directory,stage,name,token)
        except BaseException as error:
            if primary_error is None:raise
            primary_error.add_note('Owned fixture cleanup failed: '+type(error).__name__)


def cleanup_owned(image,directory,stage,name,token):
    path=directory/(stage+'-cid')
    cid=path.read_text().strip() if path.exists() else None
    if cid is not None:assert re.fullmatch('[a-f0-9]{64}',cid)
    selected=cid or name
    exists=engine('container','exists',selected,check=False).returncode
    assert exists in (0,1), 'Container absence unconfirmed'
    if exists==0:
        inspected=json.loads(engine('inspect',selected).stdout)[0]
        actual=inspected['Id']
        assert re.fullmatch('[a-f0-9]{64}',actual) and (cid is None or actual==cid)
        assert inspected['Image'].removeprefix('sha256:')==image
        assert inspected['Name'].lstrip('/')==name and inspected['Config']['Labels'][LABEL]==token
        if inspected['State']['Running']:
            engine('stop','--time=10',actual,timeout=15)
        engine('rm',actual)
        assert engine('container','exists',actual,check=False).returncode==1
    assert engine('container','exists',name,check=False).returncode==1



def fixture_configuration(mode, examples):
    """Return only the reviewed append or mixed-catalog label-only transition."""
    if mode == 'append-ssh':
        return ((examples/'config.json').read_bytes(), (examples/'config-ssh.json').read_bytes())
    if mode == 'hide-labels':
        historical = json.loads((examples/'config-ssh.json').read_bytes())
        # Explicit historical synthetic state; public defaults remain private.
        historical['portal']['publish_target_labels'] = True
        before = (json.dumps(historical, sort_keys=True)+'\n').encode()
        after = json.loads(before)
        after['portal']['publish_target_labels'] = False
        return before, (json.dumps(after, sort_keys=True)+'\n').encode()
    raise ValueError('Unsupported native migration fixture mode')


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image',required=True)
    parser.add_argument('--directory',required=True,type=Path)
    parser.add_argument('--mode',choices=('append-ssh','hide-labels'),default='append-ssh',
                        help='Use hide-labels only with an image containing the reviewed privacy migration')
    args=parser.parse_args()
    assert os.geteuid()==0
    assert re.fullmatch('[a-f0-9]{64}',args.image)
    directory=args.directory.absolute()
    assert '..' not in directory.parts and not directory.exists()
    cold_copy.files.protected_directory(directory.parent)
    os.umask(0o077)
    directory.mkdir(mode=0o700)
    receipt={'schema':1,'image':args.image,'passed':False,'cleanup_verified':False,
        'mode':args.mode,
        'scope':'synthetic independent cold copy, real PG16 migration transaction and identity census; no host wrapper, production DATA, transport or SSH acceptance'}
    try:
        source=directory/'original';source.mkdir(mode=0o700)
        os.chown(source,2000,2000)
        secret_dir=directory/'secrets';secret_dir.mkdir(mode=0o700)
        for name in ('db-password','portal-password','desktop-a-password','desktop-b-password'):
            private(secret_dir/name,secrets.token_urlsafe(32).encode())
        before=directory/'old-config';before.mkdir(mode=0o700)
        after=directory/'new-config';after.mkdir(mode=0o700)
        examples=Path(__file__).resolve().parents[1]/'examples'
        old_raw,new_raw=fixture_configuration(args.mode,examples)
        private(before/'config.json',old_raw)
        private(after/'previous.json',old_raw)
        private(after/'config.json',new_raw)
        prepared=run_owned(args.image,directory,source,before,secret_dir,PREPARE,'prepare')
        assert not (source/'pgdata/postmaster.pid').exists()
        cold_copy.stopped_and_exclusive(source)
        original=cold_copy.manifest(source)
        restored=directory/'restored'
        cold_copy.copy_tree(source,restored)
        assert cold_copy.manifest(restored)==original
        assert source.stat().st_ino!=restored.stat().st_ino
        cold_copy.stopped_and_exclusive(restored)
        result=run_owned(args.image,directory,restored,after,secret_dir,MIGRATE,'migrate')
        assert cold_copy.manifest(source)==original
        assert result['migrated'] and result['phase']=='ready'
        assert result['connections']=={'desktop-a':1,'desktop-b':2,'terminal-c':3}
        if args.mode=='hide-labels':
            assert result['labels_hidden']
            assert result['connections']==prepared['connections']
            assert result['census_sha256']==prepared['census_sha256']
            assert result['identity_sha256']==prepared['identity_sha256']
            assert result['sequence']==prepared['sequence']
        assert result['identity_unchanged'] and result['enrolled']
        assert (restored/'current-migration/previous-prepared.json').read_bytes()==(source/'prepared.json').read_bytes()
        assert not (restored/'pgdata/postmaster.pid').exists()
        cold_copy.stopped_and_exclusive(restored)
        receipt.update(passed=True,cleanup_verified=True,
            identity_sha256=result['identity_sha256'],connections=result['connections'],
            previous_prepared_sha256=result['previous_prepared_sha256'],
            current_migration_sha256=digest((Path(__file__).resolve().parents[1]/'current_migration.py').read_bytes()),
            original_unchanged=True,prior_prepared_archived=True,
            label_only_census_unchanged=args.mode=='hide-labels',
            label_only_sequence_unchanged=args.mode=='hide-labels')
    except BaseException as error:
        receipt['failure_type']=type(error).__name__
        raise
    finally:
        private(directory/'receipt.json',(json.dumps(receipt,indent=2)+'\n').encode())
    print(json.dumps(receipt))


if __name__=='__main__':main()
