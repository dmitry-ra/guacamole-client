#!/usr/bin/env python3
"""One explicit owned-container cleanup; never change a failed migration receipt."""
import argparse
import hashlib
import os
from pathlib import Path
import signal
import time

import migrate_current as migration


def reconcile(directory,expected):
    migration.require(os.geteuid()==0,'Root operator required')
    raw=migration.files.private_bytes(directory/'receipt.json',32768)
    migration.require(hashlib.sha256(raw).hexdigest()==migration.host.identifier(expected),
        'Exact reviewed failed receipt required')
    old=migration.json.loads(raw,object_pairs_hook=migration.catalog.unique_object)
    migration.require(old.get('operation')=='migrate-current' and old.get('phase')=='failed'
        and old.get('passed') is False and old.get('cleanup_verified') is False,
        'Only failed incomplete migration cleanup may be reconciled')
    image=migration.host.image_id(old.get('image'))
    run_id=migration.host.identifier(old.get('run_id'),32)
    intent=directory/'cleanup-reconciliation-intent.json'
    migration.files.json_new(intent,{'schema':1,'prior_receipt_sha256':expected,
        'image':image,'run_id':run_id,'started_at':time.time()})
    result={'schema':1,'prior_receipt_sha256':expected,'migration_accepted':False,
        'cleanup_verified':False,'image':image,'run_id':run_id}
    try:
        migration.cleanup(directory,image,run_id,result)
        migration.require(migration.files.private_bytes(directory/'receipt.json',32768)==raw,
            'Original failed migration receipt changed')
    except BaseException as error:
        result['error_type']=type(error).__name__
        try:migration.files.json_new(directory/'cleanup-reconciliation.json',result)
        except BaseException as receipt_error:error.add_note(type(receipt_error).__name__)
        raise
    result['finished_at']=time.time()
    migration.files.json_new(directory/'cleanup-reconciliation.json',result)
    return result


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--directory',required=True,type=Path)
    parser.add_argument('--expected-receipt-sha256',required=True)
    args=parser.parse_args()
    signal.signal(signal.SIGALRM,lambda *_:(_ for _ in ()).throw(TimeoutError('Cleanup deadline')))
    signal.alarm(60)
    result=reconcile(migration.files.literal(args.directory),args.expected_receipt_sha256)
    print(migration.json.dumps(result))


if __name__=='__main__':main()
