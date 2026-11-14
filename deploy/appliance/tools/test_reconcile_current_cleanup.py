"""Inert explicit cleanup reconciliation; no engine/database/host operations."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import reconcile_current_cleanup as reconcile

migration = reconcile.migration
IMAGE = 'sha256:'+'a'*64
CID = 'b'*64
RUN = 'c'*32


@unittest.skipUnless(os.geteuid()==0, 'Synthetic private case ownership requires root')
class ReconcileTests(unittest.TestCase):
    def setUp(self):
        temporary=tempfile.TemporaryDirectory(prefix='portal-current-cleanup-',dir='/run')
        self.addCleanup(temporary.cleanup)
        self.case=Path(temporary.name);self.case.chmod(0o700)
        self.old={'schema':1,'operation':'migrate-current','phase':'failed','passed':False,
            'cleanup_verified':False,'image':IMAGE,'run_id':RUN,'command_returncode':0,
            'migration':{'phase':'ready','identity_unchanged':True,'enrolled':True},
            'debug':'SYNTHETIC_PRIVATE_OLD_PAYLOAD'}
        self.raw=(json.dumps(self.old,sort_keys=True)+'\n').encode()
        migration.files.write_new(self.case/'receipt.json',self.raw)
        self.digest=migration.sha(self.raw)
        (self.case/'cid').write_bytes((CID+'\n').encode());(self.case/'cid').chmod(0o644)
        self.calls=[];self.running=False;self.foreign=None;self.absence=1;self.failure=None;self.receipt_drift=False
        patcher=patch.object(migration.host,'engine',side_effect=self.engine)
        patcher.start();self.addCleanup(patcher.stop)

    def engine(self,*args,**kwargs):
        self.calls.append(args)
        if self.failure and args[0]==self.failure[0]:raise self.failure[1]
        if args[0]=='inspect':
            value={'Id':CID,'Image':IMAGE,'Name':'portal-current-migration-'+RUN[:16],
                'Config':{'Labels':{migration.LABEL:RUN}},
                'State':{'Running':self.running,'Pid':4321 if self.running else 0}}
            if self.foreign=='id':value['Id']='d'*64
            if self.foreign=='image':value['Image']='sha256:'+'d'*64
            if self.foreign=='name':value['Name']='existing-unrelated-container'
            if self.foreign=='label':value['Config']['Labels'][migration.LABEL]='d'*32
            if self.foreign=='pid':value['State']['Pid']=False
            return subprocess.CompletedProcess(args,0,json.dumps([value]).encode(),b'')
        if args[0]=='stop':self.running=False
        elif args[0]=='rm':
            if self.receipt_drift:(self.case/'receipt.json').write_bytes(b'CONCURRENT RECEIPT CHANGE')
        elif args[:2]==('container','exists'):
            return subprocess.CompletedProcess(args,self.absence,b'',b'')
        else:raise AssertionError('Forbidden engine operation in reconciliation')
        return subprocess.CompletedProcess(args,0,b'',b'')

    def run_reconcile(self):return reconcile.reconcile(self.case,self.digest)

    def result(self):return json.loads((self.case/'cleanup-reconciliation.json').read_bytes())

    def test_success_keeps_failed_receipt_exact_and_never_accepts_migration(self):
        value=self.run_reconcile()
        self.assertTrue(value['cleanup_verified']);self.assertFalse(value['migration_accepted'])
        self.assertEqual(value['container_id'],CID)
        self.assertEqual(value['cleanup_exists_returncode'],1)
        self.assertEqual((self.case/'receipt.json').read_bytes(),self.raw)
        self.assertEqual([args[0] for args in self.calls],['inspect','rm','container'])
        self.assertNotIn('SYNTHETIC_PRIVATE_OLD_PAYLOAD',json.dumps(value))
        intent=json.loads((self.case/'cleanup-reconciliation-intent.json').read_bytes())
        self.assertEqual(intent['prior_receipt_sha256'],self.digest)
        count=len(self.calls)
        with self.assertRaises(FileExistsError):self.run_reconcile()
        self.assertEqual(len(self.calls),count)

    def test_running_owned_container_is_rechecked_after_stop(self):
        self.running=True
        self.run_reconcile()
        self.assertEqual([args[0] for args in self.calls],['inspect','stop','inspect','rm','container'])
        self.assertEqual(self.calls[1],('stop','--time=10',CID))

    def test_wrong_reviewed_hash_or_nonfailed_receipt_cannot_dispatch(self):
        with self.assertRaises(RuntimeError):reconcile.reconcile(self.case,'0'*64)
        self.assertEqual(self.calls,[])
        self.assertFalse((self.case/'cleanup-reconciliation-intent.json').exists())
        for changed in ({'phase':'ready'},{'passed':True},{'cleanup_verified':True},{'operation':'other'},
                        {'passed':0},{'cleanup_verified':0}):
            raw=json.dumps({**self.old,**changed}).encode();(self.case/'receipt.json').write_bytes(raw)
            with self.subTest(changed=changed),self.assertRaises(RuntimeError):
                reconcile.reconcile(self.case,migration.sha(raw))
        self.assertEqual(self.calls,[])

    def test_each_foreign_identity_or_unknown_pid_refuses_stop_and_remove(self):
        # Each failure has its own new case: never replay a prior attempted one.
        for field in ('id','image','name','label','pid'):
            sub=self.case/field;sub.mkdir(mode=0o700)
            migration.files.write_new(sub/'receipt.json',self.raw)
            migration.files.write_new(sub/'cid',CID.encode())
            self.foreign=field;self.calls=[]
            with self.subTest(field=field),self.assertRaises(RuntimeError):reconcile.reconcile(sub,self.digest)
            self.assertEqual([args[0] for args in self.calls],['inspect'])
            result=json.loads((sub/'cleanup-reconciliation.json').read_bytes())
            self.assertFalse(result['cleanup_verified']);self.assertFalse(result['migration_accepted'])
            self.assertEqual((sub/'receipt.json').read_bytes(),self.raw)

    def test_absence_zero_engine_error_or_boolean_never_confirms_cleanup(self):
        for code in (0,125,True):
            sub=self.case/('code-'+str(code));sub.mkdir(mode=0o700)
            migration.files.write_new(sub/'receipt.json',self.raw)
            migration.files.write_new(sub/'cid',CID.encode())
            self.absence=code
            with self.subTest(code=code),self.assertRaisesRegex(RuntimeError,'exact exists return code1'):
                reconcile.reconcile(sub,self.digest)
            result=json.loads((sub/'cleanup-reconciliation.json').read_bytes())
            self.assertFalse(result['cleanup_verified']);self.assertFalse(result['migration_accepted'])

    def test_missing_cid_cannot_inspect_another_container(self):
        (self.case/'cid').unlink()
        with self.assertRaises(FileNotFoundError):self.run_reconcile()
        self.assertEqual(self.calls,[])
        self.assertFalse(self.result()['cleanup_verified'])
        self.assertEqual((self.case/'receipt.json').read_bytes(),self.raw)

    def test_primary_engine_error_survives_reconciliation_receipt_error(self):
        original=TimeoutError('Synthetic original remove timeout')
        self.failure=('rm',original)
        write=migration.files.json_new
        def json_new(path,value):
            if path.name=='cleanup-reconciliation.json':raise OSError('Synthetic secondary disk failure')
            return write(path,value)
        with patch.object(migration.files,'json_new',side_effect=json_new):
            with self.assertRaises(TimeoutError) as caught:self.run_reconcile()
        self.assertIs(caught.exception,original)
        self.assertEqual((self.case/'receipt.json').read_bytes(),self.raw)
        self.assertTrue((self.case/'cleanup-reconciliation-intent.json').exists())
        with self.assertRaises(FileExistsError):self.run_reconcile()

    def test_concurrent_original_receipt_change_is_not_overwritten_or_accepted(self):
        self.receipt_drift=True
        with self.assertRaisesRegex(RuntimeError,'receipt changed'):self.run_reconcile()
        self.assertEqual((self.case/'receipt.json').read_bytes(),b'CONCURRENT RECEIPT CHANGE')
        value=self.result()
        self.assertTrue(value['cleanup_verified']);self.assertFalse(value['migration_accepted'])
        self.assertEqual(value['error_type'],'RuntimeError')


if __name__=='__main__':unittest.main()
