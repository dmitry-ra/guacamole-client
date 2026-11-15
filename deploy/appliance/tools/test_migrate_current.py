"""Host-inert CURRENT migration controller and restore-provenance boundaries."""
import copy
import json
import os
from pathlib import Path
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import migrate_current as migration
from test_current_migration import configurations

IMAGE='sha256:'+'a'*64
CID='b'*64
RUN='c'*32


class RestoreTests(unittest.TestCase):
    def setUp(self):
        self.data=Path('/var/lib/portal-restored/data')
        self.case=Path('/var/lib/portal-restored')
        self.source=Path('/var/lib/portal-backup/data')
        old,_=configurations()
        self.prepared=json.dumps({'schema':1,'postgres_major':16,'guacamole':'1.6.0',
            'config_sha256':migration.sha(json.dumps(old).encode()),'connections':{'desktop-a':7,'desktop-b':42}}).encode()
        self.manifest={'schema':1,'entries':{'prepared.json':{'sha256':migration.sha(self.prepared)}}}
        self.manifest_raw=json.dumps(self.manifest).encode()
        self.receipt={'schema':1,'operation':'restore','phase':'ready','for_migration':False,
            'legacy_receipt_archived':False,'source':str(self.source),'target':str(self.data),
            'manifest_sha256':migration.sha(self.manifest_raw)}
        self.backup={'schema':1,'operation':'backup','phase':'ready','target':str(self.source),
            'source':'/var/lib/original-catalog/data',
            'manifest_sha256':migration.sha(self.manifest_raw)}
        patch.object(migration.files,'protected_directory').start()
        patch.object(migration.cold_copy,'validate_cluster').start()
        patch.object(migration.cold_copy,'stopped_and_exclusive').start()
        patch.object(migration.cold_copy,'prepared_receipt',return_value=self.prepared).start()
        patch.object(migration.cold_copy,'manifest',return_value=self.manifest).start()
        patch.object(migration,'data_identity',side_effect=lambda p:{'device':1,'inode':2 if p==self.data else 3}).start()
        patch.object(migration.files,'private_bytes',side_effect=self.read).start()
        patch.object(migration.os.path,'lexists',return_value=False).start()
        patch.object(migration.host,'engine',side_effect=AssertionError('No container operation in restore validation')).start()
        self.addCleanup(patch.stopall)

    def read(self,path,*args):
        if path==self.case/'result.json':return json.dumps(self.receipt).encode()
        if path==self.source.parent/'result.json':return json.dumps(self.backup).encode()
        if path.name=='manifest.json':return self.manifest_raw
        raise AssertionError('Unexpected proof input')

    def validate(self):
        raw=json.dumps(self.receipt).encode()
        return migration.validate_restore(self.data,self.case/'result.json',migration.sha(raw))

    def test_intact_normal_restore_and_original_backup_both_match(self):
        proof,raw=self.validate()
        self.assertEqual(raw,self.prepared)
        self.assertEqual(proof['prepared_sha256'],migration.sha(self.prepared))
        self.assertEqual(proof['data_identity'],{'device':1,'inode':2})
        self.assertEqual(migration.cold_copy.manifest.call_args_list[0].args[0],self.data)
        self.assertEqual(migration.cold_copy.manifest.call_args_list[1].args[0],self.source)

    def test_legacy_migration_staging_failed_restore_or_changed_target_refused(self):
        for key,value in [('for_migration',True),('legacy_receipt_archived',True),('phase','failed'),
                          ('target','/var/lib/other/data'),('operation','backup')]:
            original=dict(self.receipt);self.receipt[key]=value
            with self.subTest(key=key),self.assertRaises(RuntimeError):self.validate()
            self.receipt=original

    def test_data_or_backup_manifest_drift_and_shared_identity_refused(self):
        migration.cold_copy.manifest.return_value={'changed':True}
        with self.assertRaisesRegex(RuntimeError,'Restored DATA differs'):self.validate()
        migration.cold_copy.manifest.side_effect=[self.manifest,{'changed':True}]
        with self.assertRaisesRegex(RuntimeError,'Original backup differs'):self.validate()
        migration.data_identity.side_effect=lambda p:{'device':1,'inode':2}
        with self.assertRaisesRegex(RuntimeError,'share one identity'):self.validate()

    def test_exact_restore_sha_and_intact_current_receipt_are_mandatory(self):
        with self.assertRaisesRegex(RuntimeError,'Exact reviewed normal-restore'):
            migration.validate_restore(self.data,self.case/'result.json','0'*64)
        migration.cold_copy.prepared_receipt.return_value=b'{"profile":"legacy"}'
        with self.assertRaisesRegex(RuntimeError,'CURRENT preparation'):self.validate()

    def test_data_must_not_be_anywhere_inside_backup_namespace(self):
        self.receipt['target']=str(self.source.parent/'another-data')
        self.data=self.source.parent/'another-data'
        with self.assertRaisesRegex(RuntimeError,'Backup case and migration target'):self.validate()

    def test_production_and_original_data_namespaces_are_never_migration_targets(self):
        for path in (migration.host.PERSIST/'data',migration.host.PERSIST/'data/child',
                     Path('/var/lib/original-catalog/data'),Path('/var/lib/original-catalog')):
            self.data=path;self.receipt['target']=str(path)
            with self.subTest(path=path),self.assertRaisesRegex(RuntimeError,'production DATA|original backup source'):
                self.validate()

    def test_bind_alias_of_production_or_original_data_identity_is_refused(self):
        production=migration.host.PERSIST/'data'
        migration.os.path.lexists.side_effect=lambda p:p==production
        migration.data_identity.side_effect=lambda p:{'device':1,'inode':2}
        with self.assertRaisesRegex(RuntimeError,'alias the fixed production'):self.validate()
        original=Path(self.backup['source'])
        migration.os.path.lexists.side_effect=lambda p:p==original
        migration.data_identity.side_effect=lambda p:{'device':1,'inode':3 if p==self.source else 2}
        with self.assertRaisesRegex(RuntimeError,'aliases the original DATA'):self.validate()


class ControllerTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name);self.data=self.root/'data';self.data.mkdir()
        self.case=self.root/'attempt';self.configs=self.root/'configs';self.configs.mkdir()
        self.secrets=self.root/'secrets';self.secrets.mkdir()
        self.old_path=self.configs/'previous.json';self.new_path=self.configs/'config.json'
        old,new=configurations();self.old_raw=json.dumps(old).encode();self.new_raw=json.dumps(new).encode()
        self.mapping={'desktop-a':7,'desktop-b':42,'terminal-c':43}
        self.old_prepared=json.dumps({'schema':1,'postgres_major':16,'guacamole':'1.6.0',
            'config_sha256':migration.sha(self.old_raw),'connections':{'desktop-a':7,'desktop-b':42}}).encode()
        self.prepared=self.old_prepared
        for target in migration.catalog.parse(new).targets:(self.secrets/target.secret_file).write_bytes(b'synthetic-not-read')
        (self.secrets/'db-password').write_bytes(b'synthetic-not-read')
        self.restore={'source':'/var/lib/synthetic-backup/data','prepared_sha256':migration.sha(self.old_prepared),
                      'data_identity':{'device':1,'inode':2}}
        self.calls=[];self.receipts={};self.events=[]
        self.module_hash=migration.sha(b'reviewed-module')
        self.running=False;self.absence=1;self.foreign=None;self.exec_error=None;self.cleanup_error=None
        self.write_cid=True;self.command_code=0;self.raw_output=None;self.result_changes={}
        self.addCleanup(patch.stopall)
        old_umask=os.umask(0o077);self.addCleanup(os.umask,old_umask)
        patch.object(migration.files,'protected_directory').start()
        patch.object(migration.host,'directory').start()
        patch.object(migration.cold_copy,'stopped_and_exclusive').start()
        patch.object(migration.cold_copy,'validate_cluster').start()
        patch.object(migration.cold_copy,'prepared_receipt',side_effect=lambda p:self.prepared).start()
        patch.object(migration,'validate_restore',return_value=(self.restore,self.old_prepared)).start()
        patch.object(migration,'data_identity',return_value={'device':1,'inode':2}).start()
        patch.object(migration.secrets,'token_hex',return_value=RUN).start()
        patch.object(migration.host.network,'protected_read',side_effect=self.protected).start()
        patch.object(migration.files,'private_bytes',side_effect=lambda p,*args:Path(p).read_bytes()).start()
        patch.object(migration.host,'write',side_effect=self.write).start()
        patch.object(migration.host,'engine',side_effect=self.engine).start()
        original=Path.lstat
        def root_secrets(path):
            info=original(path)
            if path.parent==self.secrets:
                return SimpleNamespace(st_uid=0,st_nlink=1,st_mode=0o100600,st_size=info.st_size)
            return info
        patch.object(Path,'lstat',root_secrets).start()

    def protected(self,path,*args,**kwargs):
        if path==self.old_path:return self.old_raw
        if path==self.new_path:return self.new_raw
        if path.name=='current_migration.py':return b'reviewed-module'
        if path.name=='migrate_current.py':return b'reviewed-wrapper'
        raise AssertionError('Unexpected protected input')

    def write(self,path,value):
        self.receipts[path.name]=copy.deepcopy(value);self.events.append(path.name)
        path.write_text(json.dumps(value))

    def engine(self,*argv,**kwargs):
        self.calls.append(argv)
        if argv[:2]==('image','inspect'):
            return subprocess.CompletedProcess(argv,0,json.dumps([{'Id':IMAGE,'Architecture':'amd64'}]).encode(),b'')
        if argv[0]=='run':
            self.assertIn('intent.json',self.receipts)
            self.events.append('dispatch')
            if self.write_cid:(self.case/'cid').write_text(CID+'\n')
            if self.exec_error:raise self.exec_error
            value={'schema':1,'phase':'ready','started_at':1,'finished_at':2,
                'previous_connections':{'desktop-a':7,'desktop-b':42},
                'migrated':True,'identity_unchanged':True,'enrolled':True,
                'connections':self.mapping,'config_sha256':migration.sha(self.new_raw),
                'previous_config_sha256':migration.sha(self.old_raw),
                'previous_prepared_sha256':self.restore['prepared_sha256'],
                'current_migration_sha256':self.module_hash,'identity_sha256':'d'*64}
            value.update(self.result_changes)
            self.prepared=json.dumps({'schema':1,'postgres_major':16,'guacamole':'1.6.0',
                'config_sha256':migration.sha(self.new_raw),'connections':self.mapping}).encode()
            return subprocess.CompletedProcess(argv,self.command_code,
                self.raw_output if self.raw_output is not None else json.dumps(value).encode(),b'SYNTHETIC_PRIVATE_STDERR')
        if self.cleanup_error and argv[0]==self.cleanup_error[0]:raise self.cleanup_error[1]
        if argv[0]=='inspect':
            value={'Id':CID,'Image':IMAGE,'Name':'portal-current-migration-'+RUN[:16],
                   'Config':{'Labels':{migration.LABEL:RUN}},'State':{'Running':self.running,'Pid':123 if self.running else 0}}
            if self.foreign=='id':value['Id']='e'*64
            if self.foreign=='image':value['Image']='sha256:'+'e'*64
            if self.foreign=='name':value['Name']='foreign'
            if self.foreign=='label':value['Config']['Labels'][migration.LABEL]='foreign'
            if self.foreign=='pid':value['State']['Pid']=False
            return subprocess.CompletedProcess(argv,0,json.dumps([value]).encode(),b'')
        if argv[0]=='stop':self.running=False
        if argv[0]=='container':return subprocess.CompletedProcess(argv,self.absence,b'',b'')
        if argv[0] in ('stop','rm'):return subprocess.CompletedProcess(argv,0,b'',b'')
        raise AssertionError('Unexpected engine command')

    def perform(self):
        return migration.perform(IMAGE,self.data,self.old_path,self.new_path,self.secrets,
            self.root/'restore.json','f'*64,self.case,'portal-test')

    def test_success_fsyncs_intent_freezes_configs_and_confirms_exact_absence(self):
        self.running=True;result=self.perform()
        self.assertTrue(result['passed']);self.assertTrue(result['cleanup_verified'])
        self.assertEqual(result['cleanup_exists_returncode'],1)
        self.assertLess(self.events.index('intent.json'),self.events.index('dispatch'))
        self.assertEqual((self.case/'config/config.json').read_bytes(),self.new_raw)
        self.assertEqual((self.case/'config/previous.json').read_bytes(),self.old_raw)
        self.assertTrue(any(c[:2]==('stop','--time=10') for c in self.calls))
        self.assertNotIn('SYNTHETIC_PRIVATE_STDERR',json.dumps(self.receipts))
        self.assertFalse((self.case/'stderr.log').exists());self.assertFalse((self.case/'stdout.log').exists())

    def test_resource_network_readonly_mount_and_source_bounds(self):
        self.perform();argv=next(c for c in self.calls if c[0]=='run')
        for arg in ('--network=none','--read-only','--cpus=2','--memory=1g','--memory-swap=1g',
                    '--pids-limit=192','--cap-drop=all','--security-opt=no-new-privileges','--security-opt=apparmor=portal-test'):
            self.assertIn(arg,argv)
        self.assertIn('--volume='+str(self.case/'config')+':/config:ro',argv)
        self.assertIn('--volume='+str(self.secrets)+':/secrets:ro',argv)
        self.assertFalse(any(self.restore['source'] in arg for arg in argv))
        self.assertEqual(argv[-1],self.module_hash)

    def test_absence_zero_or_engine_error_is_failed_terminal(self):
        for code in (0,125):
            with self.subTest(code=code):
                self.case=self.root/('attempt-'+str(code));self.absence=code
                self.prepared=self.old_prepared
                with self.assertRaisesRegex(RuntimeError,'absence requires'):self.perform()
                self.assertFalse(self.receipts['receipt.json']['passed'])
                self.assertFalse(self.receipts['receipt.json']['cleanup_verified'])
                self.assertEqual(self.receipts['receipt.json']['cleanup_phase'],'verify_absence')

    def test_foreign_or_unknown_pid_consumer_never_stopped_or_removed(self):
        for field in ('id','image','name','label','pid'):
            self.case=self.root/('attempt-'+field);self.foreign=field;self.calls=[];self.prepared=self.old_prepared
            with self.subTest(field=field),self.assertRaises(RuntimeError):self.perform()
            self.assertFalse(any(c[0] in ('stop','rm') for c in self.calls))
            self.assertFalse(self.receipts['receipt.json']['cleanup_verified'])

    def test_missing_cid_cannot_claim_cleanup_or_choose_another_container(self):
        self.write_cid=False
        with self.assertRaises(FileNotFoundError):self.perform()
        self.assertEqual(self.receipts['receipt.json']['cleanup_phase'],'confirm_cid')
        self.assertFalse(any(c[0] in ('inspect','stop','rm') for c in self.calls))

    def test_primary_error_survives_cleanup_and_terminal_receipt_failures(self):
        primary=ValueError('Synthetic original operation failure')
        self.exec_error=primary;self.cleanup_error=('rm',OSError('Synthetic cleanup failure'))
        original=self.write
        def write(path,value):
            if path.name=='receipt.json':
                self.receipts[path.name]=copy.deepcopy(value);raise OSError('Synthetic terminal failure')
            original(path,value)
        migration.host.write.side_effect=write
        with self.assertRaises(ValueError) as caught:self.perform()
        self.assertIs(caught.exception,primary)
        self.assertEqual(self.receipts['receipt.json']['error_type'],'ValueError')
        self.assertEqual(self.receipts['receipt.json']['cleanup_error_type'],'OSError')
        self.assertTrue(any('Terminal receipt write failed' in n for n in primary.__notes__))

    def test_malformed_or_secret_stdout_is_not_saved_and_never_accepted(self):
        self.raw_output=b'SYNTHETIC_SECRET_PAYLOAD'
        with self.assertRaises(json.JSONDecodeError):self.perform()
        self.assertNotIn('SYNTHETIC_SECRET_PAYLOAD',json.dumps(self.receipts))
        self.assertIs(self.receipts['receipt.json']['passed'],False)
        self.assertIs(self.receipts['receipt.json']['cleanup_verified'],True)

    def test_valid_json_extra_secret_or_oversized_allowed_field_cannot_be_persisted(self):
        for index,changes in enumerate(({'debug_secret':'SYNTHETIC_SECRET_PAYLOAD'},
                                       {'identity_sha256':'SYNTHETIC_SECRET_PAYLOAD'*100},
                                       {'started_at':True})):
            self.case=self.root/('unsafe-result-'+str(index));self.prepared=self.old_prepared
            self.result_changes=changes
            with self.subTest(changes=list(changes)),self.assertRaises((RuntimeError,ValueError)):self.perform()
            self.assertNotIn('SYNTHETIC_SECRET_PAYLOAD',json.dumps(self.receipts))
            self.assertNotIn('migration',self.receipts['receipt.json'])
            self.assertIs(self.receipts['receipt.json']['passed'],False)

    def test_typed_target_and_database_secret_size_limits_fail_before_dispatch(self):
        for index,(name,size) in enumerate((('desktop-a-password',513),('terminal-c-key',16385),('db-password',4097))):
            path=self.secrets/name;old=path.read_bytes();path.write_bytes(b'x'*size)
            self.case=self.root/('oversized-secret-'+str(index))
            with self.subTest(name=name),self.assertRaisesRegex(RuntimeError,'secret'):self.perform()
            self.assertFalse(any(c[0]=='run' for c in self.calls))
            path.write_bytes(old)

    @unittest.skipUnless(os.geteuid()==0,'Actual root-private journal metadata test')
    def test_privacy_archives_only_after_normal_manifest_validation_and_durable_intent(self):
        import shutil
        template=HistoryTests();template.setUp();self.addCleanup(template.doCleanups)
        _,current=configurations();hidden=copy.deepcopy(current)
        hidden['portal']['publish_target_labels']=False
        self.old_raw=json.dumps(current).encode();self.new_raw=json.dumps(hidden).encode()
        self.old_prepared=template.prepared;self.prepared=self.old_prepared
        self.restore['prepared_sha256']=migration.sha(self.old_prepared)
        migration.validate_restore.return_value=(self.restore,self.old_prepared)
        self.result_changes={'previous_connections':self.mapping}
        shutil.copytree(template.journal,self.data/migration.current_migration.JOURNAL)
        original_engine=self.engine
        def engine(*args,**kwargs):
            if args[0]=='run':
                self.assertEqual(migration.validate_restore.call_count,2)
                self.assertIn('intent.json',self.receipts)
                self.assertTrue((self.data/migration.HISTORY_INTENT).exists())
                for name,raw in template.raw.items():
                    self.assertEqual((self.data/migration.HISTORY/name).read_bytes(),raw)
            return original_engine(*args,**kwargs)
        migration.host.engine.side_effect=engine
        result=self.perform()
        self.assertTrue(result['passed'])
        self.assertEqual(result['prior_journal_archive']['files'],
                         {name:migration.sha(raw) for name,raw in template.raw.items()})
        self.assertTrue((self.case/'history-archived.json').exists())

    def test_existing_attempt_or_current_journal_cannot_replay(self):
        self.case.mkdir()
        with self.assertRaisesRegex(RuntimeError,'New current-migration'):self.perform()
        migration.host.engine.assert_not_called()
        self.case=self.root/'new-case';(self.data/migration.current_migration.JOURNAL).mkdir()
        with self.assertRaisesRegex(RuntimeError,'cannot be reused'):self.perform()
        migration.host.engine.assert_not_called()


@unittest.skipUnless(os.geteuid()==0,'Actual root-private journal metadata test')
class HistoryTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.data=Path(self.temp.name)/'data';self.data.mkdir(mode=0o700)
        self.journal=self.data/migration.current_migration.JOURNAL;self.journal.mkdir(mode=0o700)
        old,current=configurations()
        self.previous=migration.catalog.parse(current)
        hidden=copy.deepcopy(current);hidden['portal']['publish_target_labels']=False
        self.registry=migration.catalog.parse(hidden)
        old_raw=json.dumps(old).encode();current_raw=json.dumps(current).encode()
        self.mapping={'desktop-a':7,'desktop-b':42,'terminal-c':43}
        old_prepared=json.dumps({'schema':1,'postgres_major':16,'guacamole':'1.6.0',
            'config_sha256':migration.sha(old_raw),'connections':{'desktop-a':7,'desktop-b':42}}).encode()
        self.prepared=json.dumps({'schema':1,'postgres_major':16,'guacamole':'1.6.0',
            'config_sha256':migration.sha(current_raw),'connections':self.mapping}).encode()
        intent={'schema':1,'phase':'intent','started_at':1,
            'previous_config_sha256':migration.sha(old_raw),'config_sha256':migration.sha(current_raw),
            'previous_prepared_sha256':migration.sha(old_prepared),
            'previous_connections':{'desktop-a':7,'desktop-b':42},'connections':self.mapping}
        result={**intent,'phase':'ready','migrated':True,'identity_unchanged':True,'enrolled':True,
                'identity_sha256':'a'*64,'finished_at':2}
        self.raw={'intent.json':json.dumps(intent).encode(),'result.json':json.dumps(result).encode(),
                  'previous-config.json':old_raw,'previous-prepared.json':old_prepared}
        self.reset()

    def reset(self):
        for name,raw in self.raw.items():
            path=self.journal/name;path.write_bytes(raw);path.chmod(0o600)

    def proof(self):
        return migration.completed_history(self.data,self.previous,self.registry,self.prepared,[])

    def test_completed_append_archived_by_rename_with_all_four_bytes_and_inodes_retained(self):
        proof=self.proof()
        identities={name:(self.journal/name).stat().st_ino for name in self.raw}
        migration.archive_history(self.data,proof)
        self.assertFalse(self.journal.exists())
        for name,raw in self.raw.items():
            path=self.data/migration.HISTORY/name
            self.assertEqual(path.read_bytes(),raw)
            self.assertEqual(path.stat().st_ino,identities[name])
            self.assertEqual(proof['files'][name],migration.sha(raw))
        with self.assertRaisesRegex(RuntimeError,'archive.*cannot'):self.proof()

    def test_missing_extra_failed_or_unbound_prior_journal_is_refused_without_changes(self):
        result=json.loads(self.raw['result.json'])
        variants=[{'phase':'failed'},{'enrolled':False},{'identity_unchanged':False},
                  {'finished_at':True},{'finished_at':float('inf')},{'started_at':True},
                  {'config_sha256':'b'*64},{'previous_prepared_sha256':'b'*64},
                  {'connections':{'desktop-a':7,'desktop-b':42,'terminal-c':44}},
                  {'identity_sha256':'invalid'}]
        for changes in variants:
            (self.journal/'result.json').write_text(json.dumps({**result,**changes}))
            with self.subTest(changes=changes),self.assertRaises((RuntimeError,ValueError)):self.proof()
            self.assertFalse((self.data/migration.HISTORY).exists())
        self.reset();(self.journal/'result.json').unlink()
        with self.assertRaisesRegex(RuntimeError,'four-file'):self.proof()
        self.reset();(self.journal/'extra').write_text('retained')
        with self.assertRaisesRegex(RuntimeError,'four-file'):self.proof()

    def test_archive_or_append_replay_and_changed_journal_are_refused(self):
        with self.assertRaisesRegex(RuntimeError,'outside flag-only'):
            migration.completed_history(self.data,self.previous,self.registry,self.prepared,['new'])
        proof=self.proof()
        (self.journal/'intent.json').write_text('{}')
        with self.assertRaisesRegex(RuntimeError,'changed before archival'):
            migration.archive_history(self.data,proof)
        self.assertTrue(self.journal.exists())
        self.reset();(self.data/migration.HISTORY).mkdir()
        with self.assertRaisesRegex(RuntimeError,'archive.*cannot'):self.proof()
        with self.assertRaisesRegex(RuntimeError,'archive cannot'):migration.archive_history(self.data,proof)

    def test_atomic_archive_never_replaces_even_empty_destination_created_after_check(self):
        proof=self.proof();(self.data/migration.HISTORY).mkdir()
        with patch.object(migration.os.path,'lexists',return_value=False):
            with self.assertRaises(FileExistsError):migration.archive_history(self.data,proof)
        self.assertTrue(self.journal.exists())
        self.assertEqual(list((self.data/migration.HISTORY).iterdir()),[])

    def test_prior_archival_intent_burns_destination_even_without_completed_rename(self):
        (self.data/migration.HISTORY_INTENT).write_text('{}')
        with self.assertRaisesRegex(RuntimeError,'archival attempt cannot'):self.proof()
        self.assertTrue(self.journal.exists())

    def test_symlink_hardlink_and_nonprivate_metadata_are_refused(self):
        target=self.journal/'previous-config.json'
        raw=target.read_bytes();target.chmod(0o644)
        with self.assertRaisesRegex(RuntimeError,'root-private'):self.proof()
        target.chmod(0o600);linked=self.data/'linked';os.link(target,linked)
        with self.assertRaisesRegex(RuntimeError,'single|root-private'):self.proof()
        linked.unlink();target.unlink();outside=self.data/'outside';outside.write_bytes(raw);outside.chmod(0o600)
        target.symlink_to(outside)
        with self.assertRaises(OSError):self.proof()

    def test_previous_archived_config_or_prepared_and_current_prepared_must_all_bind(self):
        for name in ('previous-config.json','previous-prepared.json','intent.json'):
            raw=json.loads(self.raw[name])
            raw['unexpected']='changed'
            (self.journal/name).write_text(json.dumps(raw))
            with self.subTest(name=name),self.assertRaises((RuntimeError,ValueError)):self.proof()
            self.reset()
        current=json.loads(self.prepared);current['config_sha256']='f'*64
        with self.assertRaisesRegex(RuntimeError,'current preparation'):
            migration.completed_history(self.data,self.previous,self.registry,json.dumps(current).encode(),[])


class NativeHistoryPreparationTests(unittest.TestCase):
    def test_native_history_inputs_exercise_real_append_then_only_visibility_change(self):
        import test_current_privacy_history as fixture
        before,appended,hidden=map(json.loads,fixture.configurations())
        self.assertTrue(before['portal']['publish_target_labels'])
        self.assertTrue(appended['portal']['publish_target_labels'])
        self.assertFalse(hidden['portal']['publish_target_labels'])
        hidden['portal']['publish_target_labels']=True
        self.assertEqual(hidden,appended)
        old,current=map(migration.catalog.parse,(before,appended))
        ids={target.alias:i for i,target in enumerate(old.targets,1)}
        mapping,added=migration.current_migration.plan(old,current,ids)
        self.assertEqual(added,['terminal-c'])
        self.assertEqual(mapping,{'desktop-a':1,'desktop-b':2,'terminal-c':3})
        compile(fixture.VERIFY,'native-history-verify','exec')


if __name__=='__main__':unittest.main()
