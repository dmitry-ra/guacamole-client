#!/usr/bin/env python3
"""Single-use CURRENT restore migration wrapper; no service or network changes."""
import argparse
import ctypes
import hashlib
import json
import math
import os
from pathlib import Path
import re
import secrets
import stat
import sys

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import catalog
import current_migration
import host
import cold_copy
import prepare_instance as files

LABEL = 'guacamole.portal.current-migration'
RESULT_KEYS = {'schema','phase','started_at','previous_config_sha256','config_sha256',
    'previous_prepared_sha256','previous_connections','connections','migrated','identity_unchanged',
    'enrolled','identity_sha256','finished_at','current_migration_sha256'}
INSIDE = '''import hashlib,json,signal,sys
signal.alarm(150)
sys.path.insert(0,'/opt/homelab-web-rdp')
import runtime
import current_migration
import lifecycle as life
error=None;result=None
try:
 runtime.integrity()
 source=hashlib.sha256(runtime.protected_read(runtime.ROOT/'current_migration.py')).hexdigest()
 if source!=sys.argv[1]:raise RuntimeError('Reviewed current migration source differs from image')
 registry,digest=runtime.configuration()
 result=current_migration.migrate(registry,digest,'/config/previous.json')
 result['current_migration_sha256']=source
except BaseException as exc:error=exc
try:life.shutdown()
except BaseException as exc:
 if error is None:error=exc
 else:error.add_note('PostgreSQL cleanup failed: '+type(exc).__name__)
if error is not None:
 print(json.dumps({'failed':True,'error_type':type(error).__name__}),file=sys.stderr)
 sys.exit(1)
print(json.dumps(result,sort_keys=True))
'''


def require(value,reason):
    if not value:raise RuntimeError(reason)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def data_identity(path):
    cold_copy.pg_directory(path)
    value=path.lstat()
    return {'device':value.st_dev,'inode':value.st_ino}


def validate_restore(data,receipt_path,expected):
    """Normal restore only; never strip or silently recreate prepared.json."""
    host.identifier(expected)
    require(not cold_copy.overlaps(data,host.PERSIST/'data'),
            'CURRENT migration cannot use the fixed production DATA namespace')
    if os.path.lexists(host.PERSIST/'data'):
        require(data_identity(data)!=data_identity(host.PERSIST/'data'),
                'CURRENT migration cannot alias the fixed production DATA identity')
    raw=files.private_bytes(receipt_path,16384)
    require(sha(raw)==expected,'Exact reviewed normal-restore receipt required')
    receipt=json.loads(raw,object_pairs_hook=catalog.unique_object)
    require(type(receipt.get('schema')) is int and receipt['schema']==1
            and receipt.get('operation')=='restore' and receipt.get('phase')=='ready'
            and receipt.get('for_migration') is False and receipt.get('legacy_receipt_archived') is False
            and receipt.get('target')==str(data),'Completed normal CURRENT restore required')
    source=files.literal(receipt['source'])
    require(source.name=='data' and not cold_copy.overlaps(source.parent,data),
            'Backup case and migration target must be independent')
    files.protected_directory(source.parent)
    require(data_identity(source)!=data_identity(data),'Backup and restored DATA share one identity')
    manifest_raw=files.private_bytes(receipt_path.parent/'manifest.json',64*1024*1024)
    require(sha(manifest_raw)==receipt.get('manifest_sha256'),'Restore manifest binding changed')
    manifest=json.loads(manifest_raw,object_pairs_hook=catalog.unique_object)
    backup=json.loads(files.private_bytes(source.parent/'result.json',16384),object_pairs_hook=catalog.unique_object)
    require(backup.get('operation')=='backup' and backup.get('phase')=='ready'
            and backup.get('target')==str(source) and backup.get('manifest_sha256')==sha(manifest_raw)
            and sha(files.private_bytes(source.parent/'manifest.json',64*1024*1024))==sha(manifest_raw),
            'Original completed backup and manifest must remain available')
    original=files.literal(backup['source'])
    require(not cold_copy.overlaps(original,data),'Migration target overlaps the original backup source DATA')
    if os.path.lexists(original):
        require(data_identity(original)!=data_identity(data),'Migration target aliases the original DATA identity')
    cold_copy.validate_cluster(source,require_receipt=True)
    cold_copy.validate_cluster(data,require_receipt=True)
    prepared=cold_copy.prepared_receipt(data/'prepared.json')
    value=json.loads(prepared,object_pairs_hook=catalog.unique_object)
    require('connections' in value and 'profile' not in value,'CURRENT preparation receipt required')
    require(manifest.get('schema')==1 and isinstance(manifest.get('entries'),dict)
            and manifest['entries'].get('prepared.json',{}).get('sha256')==sha(prepared),
            'Intact prepared.json must match the normal restore manifest')
    require(cold_copy.manifest(data)==manifest,'Restored DATA differs from complete normal-restore manifest')
    require(cold_copy.manifest(source)==manifest,'Original backup differs from its complete manifest')
    cold_copy.stopped_and_exclusive(source)
    return {'receipt_sha256':expected,'manifest_sha256':sha(manifest_raw),
            'source':str(source),'original_source':str(original),'source_identity':data_identity(source),
            'data_identity':data_identity(data),'prepared_sha256':sha(prepared)},prepared



HISTORY = 'current-migration-history'
HISTORY_INTENT = HISTORY+'-intent.json'
HISTORY_FILES = {'intent.json', 'result.json', 'previous-config.json', 'previous-prepared.json'}
INTENT_KEYS = {'schema','phase','started_at','previous_config_sha256','config_sha256',
               'previous_prepared_sha256','previous_connections','connections'}


def journal_bytes(data, name=current_migration.JOURNAL):
    """Read the exact completed journal through one no-follow directory FD."""
    fd = os.open(data/name, os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:
        meta = os.fstat(fd)
        require(meta.st_uid == 0 and meta.st_gid == 0 and stat.S_IMODE(meta.st_mode) == 0o700,
                'Root-private prior journal required')
        require(set(os.listdir(fd)) == HISTORY_FILES, 'Exact four-file prior journal required')
        result = {}
        for name in sorted(HISTORY_FILES):
            child = os.open(name, os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK, dir_fd=fd)
            with os.fdopen(child,'rb') as stream:
                info = os.fstat(stream.fileno())
                require(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and info.st_gid == 0
                        and info.st_nlink == 1 and stat.S_IMODE(info.st_mode) == 0o600
                        and 0 < info.st_size <= 65536, 'Bounded root-private journal file required')
                raw = stream.read(65537)
                require(len(raw) == info.st_size and os.fstat(stream.fileno()) == info,
                        'Prior journal changed during read')
                result[name] = raw
        return result, (meta.st_dev,meta.st_ino)
    finally: os.close(fd)


def completed_history(data, previous, registry, prepared, added):
    """Only a proven completed SSH append may precede flag-only privacy."""
    require(not os.path.lexists(data/HISTORY) and not os.path.lexists(data/HISTORY_INTENT),
            'Existing journal archive or archival attempt cannot be reused')
    if not os.path.lexists(data/current_migration.JOURNAL): return None
    require(not added and previous.publish_target_labels is True and registry.publish_target_labels is False,
            'Attempted CURRENT migration target cannot be reused outside flag-only privacy')
    raw, identity = journal_bytes(data)
    values = {name:json.loads(value,object_pairs_hook=catalog.unique_object) for name,value in raw.items()}
    intent,result = values['intent.json'],values['result.json']
    require(isinstance(intent,dict) and set(intent)==INTENT_KEYS
            and isinstance(result,dict) and set(result)==RESULT_KEYS-{'current_migration_sha256'},
            'Exact prior intent and native result schema required')
    require(type(intent['schema']) is int and intent['schema']==1 and intent['phase']=='intent'
            and type(result['schema']) is int and result['schema']==1 and result['phase']=='ready'
            and all(result[key] is True for key in ('migrated','identity_unchanged','enrolled')),
            'Completed successful prior migration required')
    require(all(result[key]==intent[key] for key in INTENT_KEYS-{'phase'}),
            'Prior intent and completion differ')
    require(all(type(result[k]) in (int,float) and math.isfinite(result[k]) for k in ('started_at','finished_at'))
            and type(intent['started_at']) in (int,float) and 0<result['started_at']<=result['finished_at'],
            'Finite typed prior completion timestamps required')
    host.identifier(result['identity_sha256'])
    require(all(isinstance(result[key],dict) and all(type(i) is int for i in result[key].values())
                for key in ('previous_connections','connections')), 'Typed prior connection mappings required')
    old_registry = catalog.parse(values['previous-config.json'])
    old_prepared = values['previous-prepared.json']
    require(isinstance(old_prepared,dict) and old_prepared=={
        'schema':1,'postgres_major':16,'guacamole':'1.6.0',
        'config_sha256':sha(raw['previous-config.json']), 'connections':result['previous_connections']}
        and type(old_prepared['schema']) is int and type(old_prepared['postgres_major']) is int
        and isinstance(old_prepared['connections'],dict)
        and all(type(i) is int for i in old_prepared['connections'].values()),
        'Archived prior config and preparation binding differs')
    mapping, appended = current_migration.plan(old_registry,previous,result['previous_connections'])
    current = json.loads(prepared,object_pairs_hook=catalog.unique_object)
    require(appended and mapping==result['connections']==current['connections']
            and result['config_sha256']==current['config_sha256']
            and result['previous_config_sha256']==sha(raw['previous-config.json'])
            and result['previous_prepared_sha256']==sha(raw['previous-prepared.json']),
            'Prior completed append does not bind current preparation')
    return {'archive':HISTORY,'files':{name:sha(value) for name,value in raw.items()},
            'directory_identity':list(identity)}


def archive_history(data, proof):
    require(not os.path.lexists(data/HISTORY), 'Existing journal archive cannot be reused')
    raw,identity = journal_bytes(data)
    require(list(identity)==proof['directory_identity']
            and {name:sha(value) for name,value in raw.items()}==proof['files'],
            'Prior journal changed before archival')
    # Linux host-only atomic no-replace: even an empty archive may not be overwritten.
    rename = ctypes.CDLL(None,use_errno=True).renameat2
    rename.argtypes = [ctypes.c_int,ctypes.c_char_p,ctypes.c_int,ctypes.c_char_p,ctypes.c_uint]
    rename.restype = ctypes.c_int
    if rename(-100,os.fsencode(data/current_migration.JOURNAL),-100,os.fsencode(data/HISTORY),1):
        code=ctypes.get_errno()
        raise OSError(code,os.strerror(code))
    files.fsync_directory(data)
    archived,archived_identity=journal_bytes(data,HISTORY)
    require(list(archived_identity)==proof['directory_identity']
            and {name:sha(value) for name,value in archived.items()}==proof['files'],
            'Archived journal verification failed')


def container_args(image,data,bundle,secrets_path,case,run_id,profile,module_hash):
    host.image_id(image);host.identifier(run_id,32);host.identifier(module_hash)
    require(isinstance(profile,str) and re.fullmatch('[a-z][a-z0-9_.-]{0,95}',profile)
            and profile!='unconfined','Explicit confined AppArmor profile required')
    return ['run','--pull=never','--name=portal-current-migration-'+run_id[:16],
        '--label='+LABEL+'='+run_id,'--cidfile='+str(case/'cid'),
        '--read-only','--network=none','--cpus=2','--memory=1g','--memory-swap=1g','--pids-limit=192',
        '--cap-drop=all',*['--cap-add='+cap for cap in ('SETUID','SETGID','CHOWN','DAC_OVERRIDE','FOWNER','KILL')],
        '--security-opt=no-new-privileges','--security-opt=apparmor='+profile,
        '--tmpfs=/tmp:rw,nosuid,nodev,size=64m,mode=1777','--tmpfs=/run:rw,nosuid,nodev,size=64m,mode=755',
        '--volume='+str(data)+':/data:rw','--volume='+str(bundle)+':/config:ro',
        '--volume='+str(secrets_path)+':/secrets:ro','--entrypoint=python3',image,'-B','-c',INSIDE,module_hash]


def owned(cid,image,run_id):
    value=host.one(host.engine('inspect',cid).stdout)
    require(value.get('Id')==cid and host.inspected_image(value.get('Image'))==image
            and value.get('Name','').lstrip('/')=='portal-current-migration-'+run_id[:16]
            and value.get('Config',{}).get('Labels',{}).get(LABEL)==run_id,
            'Foreign current-migration container; refuse cleanup')
    require(type(value.get('State',{}).get('Running')) is bool,'Migration running state is unknown')
    state=value['State']
    require(type(state.get('Pid')) is int and (state['Pid']>0 if state['Running'] else state['Pid']==0),
            'Migration running/PID state is inconsistent')
    return value


def read_cid(case):
    """Podman creates a nonsecret0644 CID file even under a private case."""
    files.protected_directory(case,private=True)
    fd=os.open(case/'cid',os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    with os.fdopen(fd,'rb') as stream:
        info=os.fstat(stream.fileno())
        require(stat.S_ISREG(info.st_mode) and info.st_uid==0 and info.st_nlink==1
                and stat.S_IMODE(info.st_mode) in (0o600,0o644) and info.st_size<=65,
                'Bounded root-owned nonwritable CID file required')
        raw=stream.read(66)
    require(re.fullmatch(b'[a-f0-9]{64}\\n?',raw) is not None,'Exact full Podman CID required')
    return raw.decode('ascii').rstrip('\n')


def cleanup(case,image,run_id,result):
    result['cleanup_phase']='confirm_cid'
    cid=read_cid(case)
    result['container_id']=cid
    result['cleanup_phase']='verify_ownership'
    value=owned(cid,image,run_id)
    if value['State']['Running']:
        result['cleanup_phase']='stop'
        host.engine('stop','--time=10',cid,timeout=15)
        value=owned(cid,image,run_id)
        require(value['State']['Running'] is False,'Migration shutdown unconfirmed')
    result['cleanup_phase']='remove'
    host.engine('rm',cid)
    result['cleanup_phase']='verify_absence'
    code=host.engine('container','exists',cid,check=False).returncode
    result['cleanup_exists_returncode']=code
    require(type(code) is int and code==1,'Migration container absence requires exact exists return code1')
    result['cleanup_phase']='verified';result['cleanup_verified']=True


def perform(image,data,previous_config,config,secrets_path,restore_receipt,expected_restore,case,profile):
    image=host.image_id(image)
    data,previous_config,config,secrets_path,restore_receipt,case=map(files.literal,
        (data,previous_config,config,secrets_path,restore_receipt,case))
    require(not os.path.lexists(case),'New current-migration evidence directory required')
    for first,second in ((data,case),(data,secrets_path),(data,config.parent),(data,previous_config.parent)):
        require(not cold_copy.overlaps(first,second),'Independent DATA/config/secrets/case namespaces required')
    files.protected_directory(case.parent)
    files.protected_directory(secrets_path,private=True)
    cold_copy.stopped_and_exclusive(data)
    restore,old_raw=validate_restore(data,restore_receipt,expected_restore)
    require(not cold_copy.overlaps(case,Path(restore['source']).parent),
            'Migration evidence must not modify the original backup namespace')
    previous_raw=host.network.protected_read(previous_config)
    config_raw=host.network.protected_read(config)
    previous=catalog.parse(json.loads(previous_raw,object_pairs_hook=catalog.unique_object))
    registry=catalog.parse(json.loads(config_raw,object_pairs_hook=catalog.unique_object))
    old_value=json.loads(old_raw,object_pairs_hook=catalog.unique_object)
    require(old_value['config_sha256']==sha(previous_raw),'Previous config differs from intact prepared receipt')
    mapping,added=current_migration.plan(previous,registry,old_value['connections'])
    require(sha(previous_raw)!=sha(config_raw),'Changed catalog required')
    history=completed_history(data,previous,registry,old_raw,added)
    source=Path(current_migration.__file__).absolute()
    module_hash=sha(host.network.protected_read(source))
    wrapper_hash=sha(host.network.protected_read(Path(__file__).absolute()))
    inspected=host.one(host.engine('image','inspect',image).stdout)
    require(host.inspected_image(inspected.get('Id'))==image and inspected.get('Architecture')=='amd64',
            'Exact local amd64 migration image required')
    for target in registry.targets:
        name=getattr(target,'secret_file',None)
        if name is None:name=target.password_file
        meta=(secrets_path/name).lstat()
        require(stat.S_ISREG(meta.st_mode) and meta.st_uid==0 and meta.st_nlink==1
                and stat.S_IMODE(meta.st_mode)==0o600 and 0<meta.st_size<=target.secret_limit,
                'Root-private distinct target secret files required')
    db=(secrets_path/'db-password').lstat()
    require(stat.S_ISREG(db.st_mode) and db.st_uid==0 and db.st_nlink==1 and stat.S_IMODE(db.st_mode)==0o600
            and 0<db.st_size<=4096,
            'Root-private database secret required')
    run_id=secrets.token_hex(16)
    files.new_directory(case)
    result={'schema':1,'operation':'migrate-current','image':image,'data':str(data),'run_id':run_id,
        'source_sha256':wrapper_hash,'current_migration_sha256':module_hash,'inside_sha256':sha(INSIDE.encode()),
        'previous_config_sha256':sha(previous_raw),'config_sha256':sha(config_raw),
        'restore':restore,'expected_connections':mapping,'added_aliases':added,
        'passed':False,'cleanup_verified':False,'phase':'intent','prior_journal_archive':history}
    host.write(case/'intent.json',result)
    migration_error=cleanup_error=receipt_error=None
    verified=False
    try:
        if history is not None:
            # The original restore manifest is checked BEFORE changing any path.
            cold_copy.stopped_and_exclusive(data)
            validate_restore(data,restore_receipt,expected_restore)
            current_migration.json_new(data/HISTORY_INTENT,{
                'schema':1,'phase':'intent','case':str(case),'run_id':run_id,
                'image':image,'restore_sha256':expected_restore,'history':history})
            archive_history(data,history)
            host.write(case/'history-archived.json',history)
        bundle=case/'config';files.new_directory(bundle)
        files.write_new(bundle/'config.json',config_raw)
        files.write_new(bundle/'previous.json',previous_raw)
        cold_copy.stopped_and_exclusive(data)
        require(data_identity(data)==restore['data_identity']
                and sha(cold_copy.prepared_receipt(data/'prepared.json'))==restore['prepared_sha256'],
                'Restored DATA or prior receipt changed before dispatch')
        response=host.engine(*container_args(image,data,bundle,secrets_path,case,run_id,profile,module_hash),
                             timeout=180,check=False)
        result['command_returncode']=response.returncode
        result['stdout_bytes']=len(response.stdout);result['stderr_bytes']=len(response.stderr)
        result['stdout_sha256']=sha(response.stdout);result['stderr_sha256']=sha(response.stderr)
        require(response.returncode==0 and len(response.stdout)<=32768,'CURRENT migration failed; restore a fresh target')
        value=json.loads(response.stdout,object_pairs_hook=catalog.unique_object)
        require(isinstance(value,dict) and set(value)==RESULT_KEYS
                and type(value['schema']) is int and value['schema']==1,
                'Exact safe CURRENT migration result schema required')
        require(value.get('phase')=='ready' and value.get('migrated') is True
                and value.get('identity_unchanged') is True and value.get('enrolled') is True
                and value.get('connections')==mapping and value.get('config_sha256')==sha(config_raw)
                and value.get('previous_config_sha256')==sha(previous_raw)
                and value.get('previous_prepared_sha256')==restore['prepared_sha256']
                and value.get('current_migration_sha256')==module_hash,
                'Exact CURRENT migration completion unconfirmed')
        require(value['previous_connections']==old_value['connections']
                and all(type(i) is int for i in value['previous_connections'].values())
                and all(type(i) is int for i in value['connections'].values())
                and all(type(value[k]) in (int,float) and math.isfinite(value[k]) for k in ('started_at','finished_at'))
                and 0<value['started_at']<=value['finished_at'],
                'Typed prior mapping and actual completion timestamps required')
        host.identifier(value.get('identity_sha256'))
        result['migration']={key:value[key] for key in RESULT_KEYS};verified=True
    except BaseException as error:
        migration_error=error;result['error_type']=type(error).__name__
    try:cleanup(case,image,run_id,result)
    except BaseException as error:
        cleanup_error=error;result['cleanup_error_type']=type(error).__name__
    if verified and cleanup_error is None:
        try:
            cold_copy.stopped_and_exclusive(data)
            cold_copy.validate_cluster(data,require_receipt=True)
            expected={'schema':1,'postgres_major':16,'guacamole':'1.6.0','config_sha256':sha(config_raw),'connections':mapping}
            require(json.loads(cold_copy.prepared_receipt(data/'prepared.json'),object_pairs_hook=catalog.unique_object)==expected,
                    'Post-cleanup preparation receipt differs from verified migration')
            require(data_identity(data)==restore['data_identity'],'Restored DATA identity changed during migration')
            if history is not None:
                archived,identity=journal_bytes(data,HISTORY)
                require(list(identity)==history['directory_identity']
                        and {name:sha(raw) for name,raw in archived.items()}==history['files'],
                        'Retained history changed during native migration')
        except BaseException as error:
            migration_error=error;result['error_type']=type(error).__name__
    result['passed']=verified and migration_error is None and cleanup_error is None and result['cleanup_verified']
    result['phase']='ready' if result['passed'] else 'failed'
    if migration_error is None and cleanup_error is not None:result['error_type']=type(cleanup_error).__name__
    try:host.write(case/'receipt.json',result)
    except BaseException as error:receipt_error=error
    primary=migration_error or cleanup_error or receipt_error
    if primary is not None:
        if receipt_error is not None and receipt_error is not primary:
            primary.add_note('Terminal receipt write failed: '+type(receipt_error).__name__)
        raise primary
    return result


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image',required=True)
    for name in ('data','previous-config','config','secrets','restore-receipt','directory'):
        parser.add_argument('--'+name,required=True,type=Path)
    parser.add_argument('--expected-restore-sha256',required=True)
    parser.add_argument('--apparmor-profile',required=True)
    args=parser.parse_args()
    require(os.geteuid()==0,'Root operator required')
    os.umask(0o077)
    result=perform(args.image,args.data,args.previous_config,args.config,args.secrets,
                   args.restore_receipt,args.expected_restore_sha256,args.directory,args.apparmor_profile)
    print(json.dumps({'passed':result['passed'],'cleanup_verified':result['cleanup_verified'],
                      'image':result['image'],'phase':result['phase']}))


if __name__=='__main__':
    try:main()
    except BaseException as error:
        print('CURRENT migration failed: '+type(error).__name__,file=sys.stderr)
        raise SystemExit(1)
