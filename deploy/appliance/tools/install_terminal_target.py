#!/usr/bin/env python3
"""Stage and install one restricted public SSH key for an existing Unix account."""
import argparse
import base64
import contextlib
import fcntl
import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import signal
import stat
import struct
import sys
import time

import prepare_instance as files
import terminal_launcher

LAUNCHER = Path('/usr/local/libexec/portal-tmux')
CONFIG_ROOT = Path('/etc/guacamole-portal-terminal')
DATA_ROOT = Path('/var/lib/guacamole-portal-terminal')
TMUX_CONFIG = 'set-option -g update-environment ""\n'
PLAN_KEYS = {'schema', 'operation', 'config_sha256', 'sources', 'baseline', 'files', 'prepared_at'}


def sha(raw): return hashlib.sha256(raw).hexdigest()
def load(raw): return json.loads(raw, object_pairs_hook=files.catalog.unique_object)


def metadata(info, directory=False):
    names = ('st_dev','st_ino','st_uid','st_gid','st_mode')
    if not directory: names += ('st_size','st_mtime_ns','st_ctime_ns','st_nlink')
    return {name: getattr(info,name) for name in names}


def configuration(raw):
    value=load(raw)
    if (not isinstance(value,dict) or set(value)!={'schema','username','from_addresses','public_key_path','session'}
            or type(value['schema']) is not int or value['schema']!=1
            or not isinstance(value['username'],str) or re.fullmatch('[a-z_][a-z0-9_-]{0,31}',value['username']) is None
            or not isinstance(value['session'],str) or re.fullmatch('[a-z][a-z0-9-]{0,31}',value['session']) is None
            or not isinstance(value['from_addresses'],list) or not 1<=len(value['from_addresses'])<=8):
        raise ValueError('Exact bounded terminal target configuration required')
    addresses=[files.network.ipv4(address) for address in value['from_addresses']]
    if addresses!=sorted(set(addresses)) or addresses!=value['from_addresses']:
        raise ValueError('Distinct sorted exact trusted source IPv4 addresses required')
    files.literal(value['public_key_path'])
    return value


def public_key(raw):
    """Read only a public Ed25519 identity; reject options/private key material."""
    text=raw.decode('ascii')
    if len(raw)>4096 or '\r' in text or '\0' in text or len(text.splitlines())!=1:
        raise ValueError('One bounded public key line required')
    parts=text.split()
    if len(parts)<2 or parts[0]!='ssh-ed25519' or any(ord(c)<32 or ord(c)>126 for c in text.rstrip('\n')):
        raise ValueError('Bare Ed25519 public key required')
    blob=base64.b64decode(parts[1],validate=True)
    if blob[:19]!=struct.pack('>I',11)+b'ssh-ed25519'+struct.pack('>I',32) or len(blob)!=51:
        raise ValueError('Exact Ed25519 public key blob required')
    if base64.b64encode(blob).decode()!=parts[1]: raise ValueError('Canonical public key encoding required')
    return 'ssh-ed25519 '+parts[1]


def key_input(path):
    raw=files.network.protected_read(path,4096)
    info=Path(path).lstat()
    if info.st_nlink!=1: raise ValueError('Single-link protected public key required')
    return raw, metadata(info)


def account(value):
    row=pwd.getpwnam(value['username'])
    if (row.pw_name!=value['username'] or row.pw_uid<=0 or row.pw_gid<=0
            or row.pw_shell not in ('/bin/bash','/usr/bin/bash')):
        raise ValueError('Existing non-root account with reviewed bash shell required')
    terminal_launcher.absolute(row.pw_dir)
    home=Path(row.pw_dir)
    files.protected_directory(home.parent)
    directories={}
    for path in (home,home/'.ssh'):
        info=path.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid!=row.pw_uid or info.st_mode&0o022:
            raise ValueError('Existing non-writable account home and SSH directory required')
        directories[str(path)]=metadata(info,True)
    return {'username':row.pw_name,'uid':row.pw_uid,'gid':row.pw_gid,'home':row.pw_dir,
            'shell':row.pw_shell,'directories':directories}


@contextlib.contextmanager
def ssh_directory(state):
    """Pin both account directories with no-follow descriptors."""
    home=Path(state['home'])
    fd=os.open(home,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:
        if metadata(os.fstat(fd),True)!=state['directories'][str(home)]:
            raise ValueError('Account home identity changed')
        ssh=os.open('.ssh',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fd)
        try:
            if metadata(os.fstat(ssh),True)!=state['directories'][str(home/'.ssh')]:
                raise ValueError('SSH directory identity changed')
            yield ssh
        finally: os.close(ssh)
    finally: os.close(fd)


def authorized(state):
    with ssh_directory(state) as parent:
        fd=os.open('authorized_keys',os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=parent)
        with os.fdopen(fd,'rb') as stream:
            info=os.fstat(stream.fileno())
            if (not stat.S_ISREG(info.st_mode) or info.st_uid not in (0,state['uid']) or info.st_nlink!=1
                    or stat.S_IMODE(info.st_mode) not in (0o600,0o644) or info.st_size>128*1024):
                raise ValueError('Bounded existing regular authorized_keys with safe metadata required')
            raw=stream.read(128*1024+1)
            if len(raw)>128*1024 or b'\0' in raw: raise ValueError('Bounded authorized_keys text required')
    return raw,metadata(info)


def paths():
    return (LAUNCHER,CONFIG_ROOT,DATA_ROOT)


def baseline(value):
    state=account(value)
    auth,auth_meta=authorized(state)
    public,public_meta=key_input(value['public_key_path'])
    key=public_key(public)
    if key.split()[1].encode() in auth.split():
        raise ValueError('Application public key already occurs in authorized_keys')
    for path in paths():
        if os.path.lexists(path): raise ValueError('New absent product paths required')
    files.protected_directory(CONFIG_ROOT.parent); files.protected_directory(DATA_ROOT.parent)
    libexec=LAUNCHER.parent
    if os.path.lexists(libexec):
        files.protected_directory(libexec)
        library=metadata(libexec.lstat(),True)
    else:
        files.protected_directory(libexec.parent); library=None
    return {'account':state,'authorized_keys':auth_meta,'authorized_keys_sha256':sha(auth),
            'public_key':public_meta,'public_key_sha256':sha(public),'libexec':library},auth,public,key


def sources():
    result={str(path):sha(files.network.protected_read(path,256*1024)) for path in
        (Path(__file__).resolve(),Path(terminal_launcher.__file__).resolve(),
         Path(files.__file__).resolve(),Path(files.network.__file__).resolve(),Path(files.catalog.__file__).resolve())}
    for binary in ('/usr/bin/tmux','/bin/bash','/bin/sh','/usr/bin/env'):
        path=Path(binary).resolve()
        result[str(path)]=native_hash(path)
    return result


def native_hash(path):
    # Modern coreutils multicall executables can exceed 8MiB. Keep a bounded
    # regular-file read while accepting their ordinary packaged size.
    raw=files.network.protected_read(path,32*1024*1024)
    if not path.stat().st_mode&0o001:raise ValueError('Root-protected executable prerequisite required')
    return sha(raw)


def rendered(value, state, key, original):
    launcher=terminal_launcher.render(launcher=str(LAUNCHER),socket=str(DATA_ROOT/'tmux/socket'),
        config=str(CONFIG_ROOT/'tmux.conf'),home=state['home'],username=state['username'],session=value['session']).encode('ascii')
    options='from="'+','.join(value['from_addresses'])+'",restrict,pty,command="'+str(LAUNCHER)+'"'
    line=(options+' '+key+' guacamole-portal-terminal\n').encode('ascii')
    appended=original+(b'' if not original or original.endswith(b'\n') else b'\n')+line
    return {'launcher':launcher,'tmux.conf':TMUX_CONFIG.encode('ascii'),'authorized_keys-new':appended}


def prepare(directory, config_path):
    raw=files.private_bytes(config_path,16384); value=configuration(raw)
    snapshot,auth,public,key=baseline(value)
    products=rendered(value,snapshot['account'],key,auth)
    files.new_directory(directory)
    files.json_new(directory/'prepare-intent.json',{'schema':1,'operation':'install-terminal-target'})
    files.write_new(directory/'lock',b'')
    artifacts={'config.json':raw,'authorized_keys-backup':auth,'public-key':public,**products}
    for name,data in artifacts.items():files.write_new(directory/name,data)
    if baseline(value)[0]!=snapshot:raise ValueError('Original state changed during preparation')
    files.json_new(directory/'plan.json',{'schema':1,'operation':'install-terminal-target',
        'config_sha256':sha(raw),'baseline':snapshot,'sources':sources(),
        'files':{name:sha(data) for name,data in artifacts.items()},'prepared_at':time.time()})


def create_directory(path, uid=0, gid=0, mode=0o755):
    files.protected_directory(path.parent)
    path.mkdir(mode=mode)
    fd=os.open(path,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:os.fchown(fd,uid,gid);os.fchmod(fd,mode);os.fsync(fd)
    finally:os.close(fd)
    files.fsync_directory(path.parent)


def create_file(path,raw,mode):
    files.protected_directory(path.parent)
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,mode)
    with os.fdopen(fd,'wb') as stream:
        os.fchmod(stream.fileno(),mode);stream.write(raw);stream.flush();os.fsync(stream.fileno())
    files.fsync_directory(path.parent)


def installed(products,state):
    for path,wanted,mode in ((LAUNCHER,products['launcher'],0o755),(CONFIG_ROOT/'tmux.conf',products['tmux.conf'],0o644)):
        raw=files.network.protected_read(path)
        info=path.lstat()
        if raw!=wanted or info.st_uid!=0 or info.st_gid!=0 or info.st_nlink!=1 or stat.S_IMODE(info.st_mode)!=mode:
            raise ValueError('Owned installed launcher/config changed')
    for path,uid,gid,mode in ((CONFIG_ROOT,0,0,0o755),(DATA_ROOT,0,0,0o755),
                              (DATA_ROOT/'tmux',state['uid'],state['gid'],0o700)):
        info=path.lstat()
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid!=uid or info.st_gid!=gid or stat.S_IMODE(info.st_mode)!=mode):
            raise ValueError('Owned product directory changed')
    if (set(path.name for path in CONFIG_ROOT.iterdir())!={'tmux.conf'}
            or set(path.name for path in DATA_ROOT.iterdir())!={'tmux'}
            or any((DATA_ROOT/'tmux').iterdir())):
        raise ValueError('Terminal product paths must remain exact and unused during installation')


def append_last(directory, reviewed_sha, value, snapshot, products):
    state=snapshot['account']
    if account(value)!=state:raise ValueError('Account changed before authorization')
    installed(products,state)
    with ssh_directory(state) as parent:
        old,meta=authorized(state)
        if sha(old)!=snapshot['authorized_keys_sha256'] or meta!=snapshot['authorized_keys']:
            raise ValueError('authorized_keys changed before authorization')
        name='.authorized_keys.portal-'+reviewed_sha[:16]
        fd=os.open(name,os.O_RDWR|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=parent)
        try:
            raw=products['authorized_keys-new']
            with os.fdopen(os.dup(fd),'wb') as stream:
                stream.write(raw);stream.flush()
            os.fchown(fd,meta['st_uid'],meta['st_gid']);os.fchmod(fd,stat.S_IMODE(meta['st_mode']));os.fsync(fd)
            old_again,meta_again=authorized(state)
            if old_again!=old or meta_again!=meta or account(value)!=state:
                raise ValueError('Original authorization/account drift before atomic append')
            installed(products,state)
            info=os.stat(name,dir_fd=parent,follow_symlinks=False)
            os.lseek(fd,0,os.SEEK_SET)
            if metadata(info)!=metadata(os.fstat(fd)) or os.read(fd,len(raw)+1)!=raw:
                raise ValueError('Authorization temporary changed')
            os.replace(name,'authorized_keys',src_dir_fd=parent,dst_dir_fd=parent)
            os.fsync(parent)
        finally:os.close(fd)
    actual,actual_meta=authorized(state)
    if actual!=products['authorized_keys-new'] or any(actual_meta[key]!=meta[key] for key in ('st_uid','st_gid','st_mode')):
        raise ValueError('Final authorization could not be verified')


def apply(directory,reviewed_sha):
    files.protected_directory(directory,private=True)
    raw=files.private_bytes(directory/'plan.json',256*1024)
    if not isinstance(reviewed_sha,str) or re.fullmatch('[0-9a-f]{64}',reviewed_sha) is None or sha(raw)!=reviewed_sha:
        raise ValueError('Exact independently reviewed plan SHA required')
    plan=load(raw)
    if (not isinstance(plan,dict) or set(plan)!=PLAN_KEYS or type(plan['schema']) is not int or plan['schema']!=1
            or plan['operation']!='install-terminal-target' or plan['sources']!=sources()
            or set(plan['files'])!={'config.json','authorized_keys-backup','public-key','launcher','tmux.conf','authorized_keys-new'}):
        raise ValueError('Exact staged plan and source bindings required')
    if any(os.path.lexists(directory/name) for name in ('apply-intent.json','result.json')):
        raise ValueError('Attempted terminal installation is never replayed')
    artifacts={name:files.private_bytes(directory/name,256*1024) for name in plan['files']}
    if any(sha(data)!=plan['files'][name] for name,data in artifacts.items()) or sha(artifacts['config.json'])!=plan['config_sha256']:
        raise ValueError('Staged artifact changed')
    value=configuration(artifacts['config.json'])
    snapshot,auth,public,key=baseline(value)
    if snapshot!=plan['baseline'] or auth!=artifacts['authorized_keys-backup'] or public!=artifacts['public-key']:
        raise ValueError('Original account/key/authorization/path state changed')
    products=rendered(value,snapshot['account'],key,auth)
    if any(products[name]!=artifacts[name] for name in products):raise ValueError('Rendered products changed')
    try:
        files.json_new(directory/'apply-intent.json',{'schema':1,'plan_sha256':reviewed_sha,'started_at':time.time()})
        if baseline(value)[0]!=snapshot:raise ValueError('Original changed after intent')
        if snapshot['libexec'] is None:create_directory(LAUNCHER.parent)
        create_directory(CONFIG_ROOT);create_directory(DATA_ROOT)
        create_directory(DATA_ROOT/'tmux',snapshot['account']['uid'],snapshot['account']['gid'],0o700)
        create_file(LAUNCHER,products['launcher'],0o755)
        create_file(CONFIG_ROOT/'tmux.conf',products['tmux.conf'],0o644)
        # Authorization is the last installed effect. Earlier partial failures
        # leave access unchanged, retain evidence and never authorize replay.
        append_last(directory,reviewed_sha,value,snapshot,products)
        files.json_new(directory/'result.json',{'schema':1,'phase':'installed','plan_sha256':reviewed_sha,
            'authorized_keys_sha256':sha(products['authorized_keys-new']),'authenticated':False,'finished_at':time.time()})
    except BaseException as error:
        try:files.json_new(directory/'result.json',{'schema':1,'phase':'failed','error_type':type(error).__name__,
            'plan_sha256':reviewed_sha,'finished_at':time.time()})
        except BaseException:pass
        raise


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action',choices=('prepare','apply'))
    parser.add_argument('--directory',type=Path,required=True)
    parser.add_argument('--config',type=Path)
    parser.add_argument('--plan-sha256')
    args=parser.parse_args()
    if os.geteuid()!=0:raise ValueError('Root required')
    directory=files.literal(args.directory)
    signal.signal(signal.SIGALRM,lambda *_:(_ for _ in ()).throw(TimeoutError('Deadline')));signal.alarm(60)
    signal.signal(signal.SIGTERM,lambda *_:(_ for _ in ()).throw(InterruptedError('Terminated')))
    if args.action=='prepare':
        if args.config is None:raise ValueError('External config required')
        prepare(directory,args.config)
    else:
        fd=os.open(directory/'lock',os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
        with os.fdopen(fd) as lock:
            info=os.fstat(lock.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_uid!=0 or info.st_nlink!=1 or stat.S_IMODE(info.st_mode)!=0o600:
                raise ValueError('Protected case lock required')
            fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
            apply(directory,args.plan_sha256)
    print(json.dumps({'success':True,'action':args.action,'authenticated':False}))


if __name__=='__main__':
    try:main()
    except BaseException as error:
        print(json.dumps({'success':False,'error_type':type(error).__name__}),file=sys.stderr);sys.exit(1)
