#!/usr/bin/env python3
"""Create one new external Ed25519 application key; never install access."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import time

import prepare_instance as files


def generate(directory, secret):
    if os.geteuid()!=0:raise RuntimeError('Root required')
    directory,secret=map(files.literal,(directory,secret))
    files.protected_directory(secret.parent,private=True)
    public=secret.with_name(secret.name+'.pub')
    if os.path.lexists(secret) or os.path.lexists(public):
        raise RuntimeError('New application key paths required; reconcile any prior attempt')
    files.new_directory(directory)
    files.json_new(directory/'intent.json',{'schema':1,'secret_path':str(secret),
        'operation':'new Ed25519 application identity only','started_at':time.time()})
    result={'schema':1,'ready':False,'access_installed':False,'secret_path':str(secret)}
    try:
        subprocess.run(['/usr/bin/ssh-keygen','-q','-t','ed25519','-N','',
            '-C','portal application identity','-f',str(secret)],
            stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,
            check=True,timeout=20)
        os.chmod(secret,0o600);os.chmod(public,0o600)
        for path in (secret,public):
            meta=path.lstat()
            if not stat.S_ISREG(meta.st_mode) or meta.st_uid!=0 or meta.st_nlink!=1:
                raise RuntimeError('Unexpected generated key metadata')
            with path.open('rb') as stream:os.fsync(stream.fileno())
        raw=files.private_bytes(secret,16384)
        pub=files.private_bytes(public,4096)
        derived=subprocess.run(['/usr/bin/ssh-keygen','-y','-f',str(secret)],
            stdin=subprocess.DEVNULL,capture_output=True,check=True,timeout=10).stdout
        if not raw.startswith(b'-----BEGIN OPENSSH PRIVATE KEY-----\n') or pub.split()[:2]!=derived.split()[:2]:
            raise RuntimeError('Generated key pair verification failed')
        files.fsync_directory(secret.parent)
        result.update(ready=True,algorithm='ssh-ed25519',
            public_key_sha256=hashlib.sha256(b' '.join(pub.split()[:2])).hexdigest(),
            finished_at=time.time())
    except BaseException as error:
        result.update(error_type=type(error).__name__,finished_at=time.time())
        try:files.json_new(directory/'result.json',result)
        except BaseException as receipt_error:
            error.add_note('Key preparation failure receipt: '+type(receipt_error).__name__)
        raise
    files.json_new(directory/'result.json',result)
    return result


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--directory',required=True,type=Path)
    parser.add_argument('--secret',required=True,type=Path)
    args=parser.parse_args()
    print(json.dumps(generate(args.directory,args.secret)))


if __name__=='__main__':main()
