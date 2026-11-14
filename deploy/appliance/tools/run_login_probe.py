#!/usr/bin/env python3
"""Reserve one durable intent and stream a single login probe to an exact CID."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import subprocess
import time

REMOTE = r'''
import json,re,subprocess,sys
source=sys.stdin.buffer.read(65537)
if len(source)>65536: raise SystemExit(2)
cid,image,alias,username=sys.argv[1:]
p=subprocess.run(['/usr/bin/podman','inspect','--type=container',cid],capture_output=True,timeout=8,check=True)
v=json.loads(p.stdout)
if len(v)!=1: raise SystemExit(2)
v=v[0];labels=v.get('Config',{}).get('Labels',{})
if (v.get('Id')!=cid or v.get('Name','').lstrip('/')!='guacamole-portal'
    or v.get('Image','').removeprefix('sha256:')!=image
    or labels.get('guacamole.portal')!='1' or not re.fullmatch('[0-9a-f]{32}',labels.get('guacamole.portal.run',''))
    or v.get('State',{}).get('Running') is not True): raise SystemExit(2)
p=subprocess.run(['/usr/bin/podman','exec','-i','--user','0',cid,'/usr/bin/python3','-B','-',
    '--alias',alias,'--expected-username',username],input=source,capture_output=True,timeout=35)
if len(p.stdout)>4096: raise SystemExit(2)
sys.stdout.buffer.write(p.stdout)
raise SystemExit(p.returncode)
'''


def write(path, value):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(json.dumps(value, sort_keys=True).encode() + b'\n')
        stream.flush()
        os.fsync(stream.fileno())


def sync(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def response(value):
    required = {'schema', 'uid', 'domain_empty', 'single_connection', 'full_browser_acceptance',
                'stage', 'outcome', 'status', 'instructions', 'display_instructions', 'display_payload_characters'}
    if not isinstance(value, dict) or set(value) not in (required, required | {'error_type'}):
        raise ValueError('Probe response fields invalid')
    if (type(value['schema']) is not int or value['schema'] != 1 or type(value['uid']) is not int or value['uid'] != 0
            or value['domain_empty'] is not True or value['single_connection'] is not True
            or value['full_browser_acceptance'] is not False
            or value['stage'] not in {'validate', 'guacd_socket', 'select', 'credential_connect', 'observe'}
            or value['outcome'] not in {'probe_failure', 'guacd_error', 'display_activity', 'timeout', 'eof'}):
        raise ValueError('Probe response contract invalid')
    for key, maximum in [('instructions',10000), ('display_instructions',10000), ('display_payload_characters',16*1024*1024)]:
        if type(value[key]) is not int or not 0 <= value[key] <= maximum:
            raise ValueError('Probe response count invalid')
    if value['status'] is not None and (type(value['status']) is not int or not 0 <= value['status'] <= 65535):
        raise ValueError('Probe response status invalid')
    if value.get('error_type') not in (None, 'ValueError', 'RuntimeError', 'ProtocolError', 'UnicodeDecodeError',
                                     'OSError', 'ConnectionRefusedError', 'PermissionError', 'FileNotFoundError'):
        raise ValueError('Probe response error category invalid')
    if value['outcome'] == 'guacd_error' and value['status'] is None:
        raise ValueError('Numeric error status missing')
    if value['display_instructions'] > value['instructions']:
        raise ValueError('Display count exceeds instruction count')
    if value['outcome'] == 'display_activity' and (value['display_instructions'] == 0
            or value['status'] is not None or value['stage'] != 'observe'):
        raise ValueError('Display activity contract invalid')
    return value


def run(args):
    if (not re.fullmatch('[a-z][a-z0-9_-]{0,63}', args.ssh_host)
            or not re.fullmatch('[a-f0-9]{64}', args.container)
            or not re.fullmatch('[a-f0-9]{64}', args.expected_image)
            or not re.fullmatch('[a-z][a-z0-9-]{0,47}', args.alias)
            or not re.fullmatch('[A-Za-z0-9][A-Za-z0-9_.@-]{0,63}', args.expected_username)
            or not re.fullmatch('[A-Za-z0-9:_./-]{1,128}', args.authorization)):
        raise ValueError('Explicit literal operator bindings required')
    if not args.directory.is_absolute() or '..' in args.directory.parts:
        raise ValueError('New absolute private evidence directory required')
    payload = Path(__file__).with_name('probe_login.py').read_bytes()
    if len(payload) > 65536:
        raise ValueError('Source exceeds bound')
    os.umask(0o077)
    args.directory.mkdir(mode=0o700)
    receipt = dict(schema=1, phase='intent', started_at=time.time(), container_id=args.container,
                   image_id='sha256:'+args.expected_image, alias=args.alias, expected_username=args.expected_username,
                   domain_empty=True, authorization=args.authorization, source_sha256=hashlib.sha256(payload).hexdigest(),
                   full_browser_acceptance=False, passed=False)
    write(args.directory/'intent.json', receipt)
    # All durable reservations precede even starting SSH; every existing case
    # is refused, including failed/uncertain results. Never replay an intent.
    sync(args.directory)
    sync(args.directory.parent)
    command = ['/usr/bin/ssh', '-T', '-oBatchMode=yes', '-oStrictHostKeyChecking=yes', '-oConnectTimeout=10',
               '-oControlMaster=no', '-oControlPath=none', '-oControlPersist=no', args.ssh_host,
               shlex.join(['sudo','-n','/usr/bin/python3','-c',REMOTE,args.container,args.expected_image,
                           args.alias,args.expected_username])]
    try:
        result = subprocess.run(command, input=payload, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                timeout=55, check=False)
        receipt['returncode'] = result.returncode
        if len(result.stdout) > 4096:
            raise ValueError('Output exceeds bound')
        receipt['response'] = response(json.loads(result.stdout))
        receipt['phase'] = 'complete'
        receipt['passed'] = result.returncode == 0 and receipt['response']['outcome'] == 'display_activity'
    except Exception as error:
        receipt.update(phase='failed', error_type=type(error).__name__)
    receipt['finished_at'] = time.time()
    write(args.directory/'result.json', receipt)
    sync(args.directory)
    print(json.dumps(receipt, sort_keys=True))
    return 0 if receipt['passed'] else 1


def main():
    p = argparse.ArgumentParser(description=__doc__)
    for name in ('ssh-host','container','expected-image','alias','expected-username','authorization'):
        p.add_argument('--'+name, required=True)
    p.add_argument('--directory', type=Path, required=True)
    return run(p.parse_args())


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except Exception as error:
        print(json.dumps({'passed': False, 'error_type': type(error).__name__}))
        raise SystemExit(1)
