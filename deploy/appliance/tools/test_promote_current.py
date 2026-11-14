"""Inert strict review boundaries and real synthetic filesystem transactions."""
import contextlib
import json
import os
from pathlib import Path
import tempfile
import time
import shutil
import unittest
from unittest.mock import patch

import promote_current as tool
REAL_PROVENANCE = tool.provenance
REAL_REVIEW = tool.review


class Reviews(unittest.TestCase):
    def review(self):
        return dict(schema=1,operation='promote-current-apply',binding_sha256='a'*64,
            portal_closed=True,sessions_cleared=True,closed_route={'path':'/proof','sha256':'b'*64},
            session_census={'path':'/sessions','sha256':'c'*64},reviewed_at=100,expires_at=200)

    def test_fresh_exact_review_checks_protected_evidence(self):
        with patch.object(tool.time,'time',return_value=150),patch.object(tool,'read_ref',return_value=b'proof') as read:
            self.assertEqual(tool.review(json.dumps(self.review()).encode(),'promote-current-apply','a'*64),self.review())
            self.assertEqual(read.call_count,2)

    def test_expired_wrong_action_open_route_and_nonfinite_refused(self):
        for change in [dict(expires_at=150),dict(operation='rollback-current'),dict(binding_sha256='b'*64),
                       dict(portal_closed=False),dict(sessions_cleared=False),dict(reviewed_at=True),
                       dict(expires_at=float('inf')),dict(extra_secret='SECRET')]:
            value=dict(self.review(),**change)
            with patch.object(tool.time,'time',return_value=150),patch.object(tool,'read_ref') as read:
                with self.assertRaises((ValueError,TypeError)):tool.review(json.dumps(value).encode(),'promote-current-apply','a'*64)
                read.assert_not_called()

    def test_write_destination_allowlist_rejects_foreign_path_before_creation(self):
        with patch.object(tool.files,'write_new') as write:
            with self.assertRaises(ValueError):tool.replace_file(Path('/etc/foreign'),b'SECRET',{},lambda:None,Path('/case'))
            write.assert_not_called()


class PrimaryAdmission(unittest.TestCase):
    def evidence(self):
        image='sha256:'+'a'*64
        refs={k:{'path':'/private/'+k,'sha256':tool.sha(k.encode())} for k in tool.GATES}
        auth=dict(image=image,passed=True,cleanup_verified=True,fixture_sha256='b'*64,installed_integrity_sha256='c'*64,
            scope='clean candidate image startup, native HTTP/TOTP and real Angular browser; no RDP endpoint acceptance',
            health=dict(database_ready=True,web_ready=True,enrolled=True),checks=[
                'packaged_WAR_startup_hold_and_username_optional_alias_no_password',
                'native_TOTP_challenge_wrong_valid_and_replay_denial','native_authorized_two_connection_tree_and_own_API_logout',
                'real_Angular_dynamic_alias_dropdown_overrides_link_through_native_TOTP',
                'real_Angular_both_selector_URIs_existing_native_token','own_browser_native_logout',
                'packaged_runtime_integrity_configuration_and_enrolled_health'])
        before=dict(sentinel=dict(pid=1,start=2),process=dict(pid=3,start=4,counter=5))
        after=dict(sentinel=dict(pid=1,start=2),process=dict(pid=3,start=4,counter=9))
        checks={k:True for k in ('ssh_plugin_loadable','none_denied','command_denied','same_process_counter_progress_sentinel_unchanged')}
        checks.update(wrong_pin=dict(outcome='guacd_error',status=512),wrong_appkey=dict(outcome='guacd_error',status=769))
        checks.update({k:dict(outcome='display_activity',status=None,display_instructions=10) for k in ('first_connect','reconnect')})
        native=dict(image=image,passed=True,cleanup_verified=True,phase='complete',
            scope='synthetic native SSH; not browser or JDBC acceptance',checks=checks,process_before=before,process_after=after)
        digest=tool.sha('synthetic \u0442\u0435\u0441\u0442 \u03bb \u754c'.encode())
        mixed=dict(image=image,passed=True,cleanup_verified=True,phase='complete',own_logout_204=True,
            scope='complete packaged mixed TOTP/JDBC/SSH browser; RDP alias routing only',
            native_refusal_sha256=refs['native-ssh']['sha256'],tree=[['1','desktop-a'],['2','desktop-b'],['3','terminal-c']],
            unicode_input_sha256=digest,unicode_input_mechanism='native Guacamole BMP keyboard events',
            terminal_disconnected=before,terminal_reconnected=after,
            terminal_before_resize={'process':dict(rows=45,cols=125,input_sha256=digest)},
            terminal_after_resize={'process':dict(rows=31,cols=93,input_sha256=digest)})
        mixed.update({k:dict(width=800,height=600,nonblack=1200) for k in ('first_canvas','resized_canvas','reconnect_canvas')})
        kernel=dict(passed=True,cleanup_verified=True,scope='synthetic isolated kernel namespaces only',result=dict(
            passed=True,scope='real isolated kernel transactions and packets; no systemd/Podman boot or SSH authentication',
            old_guard_sha256='b'*64,new_guard_sha256='c'*64,checks=[{'check':k} for k in (
                'real_invalid_nft_batch_preserves_old_guard_and_chains','real_guard_and_exact_insertions_preserve_unrelated_rules',
                'added_ssh_gateway_allows_only_app_tuple','real_listener_census_refuses_rollback_without_kernel_mutation',
                'real_reverse_spec_deletion_and_atomic_old_guard_restore')]))
        return image,refs,{'build':dict(schema=1,image_id=image,sources={'source':'b'*64},base_image='pinned',apt_snapshot='snapshot'),
                           'auth':auth,'native-ssh':native,'mixed-browser':mixed,'kernel':kernel}

    def execute(self,refs,values,image):
        with patch.object(tool,'read_ref',side_effect=lambda ref:json.dumps(values[Path(ref['path']).name]).encode()):
            return tool.primary_gates(refs,image)

    def test_distinct_actual_producer_contracts_are_accepted(self):
        image,refs,values=self.evidence()
        self.assertEqual(set(self.execute(refs,values,image)),tool.GATES)

    def test_auth_only_receipt_cannot_substitute_for_native_ssh_mixed_or_kernel(self):
        for role in ('native-ssh','mixed-browser','kernel'):
            image,refs,values=self.evidence();values[role]=values['auth']
            with self.assertRaises(ValueError):self.execute(refs,values,image)

    def test_same_receipt_hash_cannot_be_reused_across_roles(self):
        image,refs,values=self.evidence();refs['native-ssh']['sha256']=refs['auth']['sha256']
        with self.assertRaises(tool.Refused):self.execute(refs,values,image)

    def test_missing_pty_input_or_native_refusal_crosslink_is_refused(self):
        for key,value in [('unicode_input_sha256','0'*64),('native_refusal_sha256','0'*64),('terminal_after_resize',{})]:
            image,refs,values=self.evidence();values['mixed-browser'][key]=value
            with self.assertRaises(ValueError):self.execute(refs,values,image)


@unittest.skipUnless(os.geteuid()==0,'Real inert protected filesystem cases require root')
class Transactions(unittest.TestCase):
    def setUp(self):
        self.directory=tempfile.TemporaryDirectory(prefix='portal-promote-inert-',dir='/run')
        self.root=Path(self.directory.name);self.root.chmod(0o700)
        self.stack=contextlib.ExitStack();self.addCleanup(self.stack.close);self.addCleanup(self.directory.cleanup)
        self.persist=self.root/'persist';self.persist.mkdir(mode=0o700)
        self.installed=self.root/'installed';self.installed.mkdir(mode=0o700)
        self.etc=self.root/'etc';self.etc.mkdir(mode=0o700)
        self.case=self.root/'case';self.case.mkdir(mode=0o700)
        for name,value in [('PERSIST',self.persist),('ROOT',self.installed),('CONFIG',self.etc/'config.json'),
                           ('NETWORK',self.etc/'network.json'),('RELEASE',self.etc/'release.json')]:
            self.stack.enter_context(patch.object(tool.host,name,value))
        self.stack.enter_context(patch.object(tool,'stopped'))
        self.stack.enter_context(patch.object(tool,'review',return_value={}))
        self.stack.enter_context(patch.object(tool,'sources',return_value={'synthetic':'a'*64}))
        self.stack.enter_context(patch.object(tool,'provenance',return_value={}))
        self.stack.enter_context(patch.object(tool,'external_guards'))
        self.stack.enter_context(patch.object(tool.cold_copy,'stopped_and_exclusive'))
        self.stack.enter_context(patch.object(tool.cold_copy,'validate_cluster'))
        self.old_raw={};self.new_raw={};self.old_meta={};self.spec={'new_data':str(self.root/'restored'),'files':{}}
        source=self.root/'source';source.mkdir(mode=0o700)
        for key,path in tool.destinations().items():
            self.old_raw[key]=('old-'+key).encode();self.new_raw[key]=('new-'+key).encode()
            path.write_bytes(self.old_raw[key]);path.chmod(0o640)
            self.old_meta[key]=tool.metadata(path)
            original=source/key;original.write_bytes(self.new_raw[key]);original.chmod(0o600)
            self.spec['files'][key]={'path':str(original),'sha256':tool.sha(self.new_raw[key])}
        self.mapping={'desktop-a':1,'desktop-b':2,'terminal-c':3}
        self.old_data=self.persist/'data';self.new_data=Path(self.spec['new_data'])
        for path,kind in [(self.old_data,'old'),(self.new_data,'new')]:
            path.mkdir(mode=0o700);os.chown(path,2000,2000)
            (path/'payload').write_bytes(kind.encode());(path/'payload').chmod(0o600)
            prepared={'schema':1,'postgres_major':16,'guacamole':'1.6.0',
                'config_sha256':tool.sha(self.new_raw['config']) if kind=='new' else '0'*64,
                'connections':self.mapping if kind=='new' else {'desktop-a':1,'desktop-b':2}}
            (path/'prepared.json').write_text(json.dumps(prepared));(path/'prepared.json').chmod(0o600)
        self.old_identity=tool.migrate_current.data_identity(self.old_data)
        self.new_identity=tool.migrate_current.data_identity(self.new_data)
        self.old_manifest=tool.cold_copy.manifest(self.old_data);self.new_manifest=tool.cold_copy.manifest(self.new_data)
        for label,value in [('old',self.old_manifest),('new',self.new_manifest)]:tool.files.json_new(self.case/(label+'_manifest.json'),value)
        self.plan={'sources':{'synthetic':'a'*64},'old_files':self.old_meta,
            'new_files':{k:tool.sha(v) for k,v in self.new_raw.items()},
            'lineage':{'old_identity':self.old_identity,'new_identity':self.new_identity,'connections':self.mapping}}
        self.stack.enter_context(patch.object(tool,'read_case',return_value=(self.plan,self.spec,self.old_raw,self.new_raw)))
        self.review=self.root/'review.json';self.review.write_bytes(b'{}');self.review.chmod(0o600)

    def run_operation(self,rollback=False):return tool.run(self.case,'a'*64,self.review,rollback)

    def test_complete_promotion_and_rollback_preserve_inodes_modes_and_changed_new_tree(self):
        self.assertEqual(self.run_operation()['phase'],'promoted-stopped')
        self.assertEqual(tool.migrate_current.data_identity(self.old_data),self.new_identity)
        self.assertEqual(tool.migrate_current.data_identity(self.case/'original-data'),self.old_identity)
        (self.old_data/'payload').write_bytes(b'legitimate new WAL/history')
        self.assertEqual(self.run_operation(True)['phase'],'rolled-back')
        self.assertEqual(tool.migrate_current.data_identity(self.old_data),self.old_identity)
        self.assertEqual(tool.cold_copy.manifest(self.old_data),self.old_manifest)
        self.assertEqual((self.case/'promoted-data/payload').read_bytes(),b'legitimate new WAL/history')
        for key,path in tool.destinations().items():
            self.assertEqual(path.read_bytes(),self.old_raw[key]);self.assertEqual(path.stat().st_mode&0o777,0o640)

    def test_interruption_between_renames_recovers_only_original_and_retains_restored_source(self):
        rename=tool.os.rename
        def interrupt(source,target):
            if source==self.new_data:raise InterruptedError('synthetic interruption')
            return rename(source,target)
        with patch.object(tool.os,'rename',side_effect=interrupt):
            with self.assertRaises(InterruptedError):self.run_operation()
        self.assertFalse(self.old_data.exists());self.assertTrue(self.new_data.exists())
        self.assertEqual(self.run_operation(True)['phase'],'rolled-back')
        self.assertEqual(tool.migrate_current.data_identity(self.old_data),self.old_identity)
        self.assertEqual(tool.migrate_current.data_identity(self.new_data),self.new_identity)

    def test_foreign_file_blocks_rollback_before_intent_or_data_moves(self):
        self.run_operation();tool.host.CONFIG.write_bytes(b'foreign change')
        with self.assertRaises(ValueError):self.run_operation(True)
        self.assertFalse((self.case/'rollback-intent.json').exists())
        self.assertEqual(tool.migrate_current.data_identity(self.old_data),self.new_identity)
        self.assertTrue((self.case/'original-data').exists())

    def test_apply_and_rollback_intents_are_never_replayed(self):
        self.run_operation()
        with self.assertRaises(ValueError):self.run_operation()
        self.run_operation(True)
        with self.assertRaises(ValueError):self.run_operation(True)

    def test_preexisting_temporary_refuses_before_data_move(self):
        temp=tool.host.CONFIG.with_name(tool.host.CONFIG.name+'.promote-current-next')
        temp.write_bytes(b'foreign temporary');temp.chmod(0o600)
        with self.assertRaises(ValueError):self.run_operation()
        self.assertFalse((self.case/'apply-intent.json').exists())
        self.assertEqual(tool.migrate_current.data_identity(self.old_data),self.old_identity)

    def test_partial_owned_file_temporary_is_retained_before_rollback(self):
        replace=tool.replace_file
        def interrupted(path,raw,meta,check,case):
            if path==tool.host.ROOT/'host.py':
                tool.files.write_new(path.with_name(path.name+'.promote-current-next'),raw)
                raise InterruptedError('synthetic partial write')
            return replace(path,raw,meta,check,case)
        with patch.object(tool,'replace_file',side_effect=interrupted):
            with self.assertRaises(InterruptedError):self.run_operation()
        self.assertEqual(self.run_operation(True)['phase'],'rolled-back')
        self.assertEqual((self.case/'retained-temp-host.py').read_bytes(),self.new_raw['host.py'])
        self.assertEqual(tool.migrate_current.data_identity(self.old_data),self.old_identity)

    def test_review_expiry_after_first_rename_stops_before_second_and_can_explicitly_rollback(self):
        def expired(*args):
            if (self.case/'original-data').exists() and self.new_data.exists():
                raise tool.Refused('Fresh exact closed-route/session review required')
        with patch.object(tool,'review',side_effect=expired):
            with self.assertRaises(tool.Refused):self.run_operation()
        self.assertFalse(self.old_data.exists());self.assertTrue(self.new_data.exists())
        outcome=json.loads((self.case/'result.json').read_bytes())
        self.assertEqual(outcome['failure_phase'],'promoting_restored')
        self.assertEqual(outcome['failure_reason'],'Fresh exact closed-route/session review required')
        self.assertEqual(self.run_operation(True)['phase'],'rolled-back')
        self.assertEqual(tool.migrate_current.data_identity(self.old_data),self.old_identity)

    def test_new_unreferenced_helper_remains_private_for_audit_after_rollback(self):
        path=tool.destinations()['network_upgrade.py'];path.unlink()
        self.old_raw.pop('network_upgrade.py');self.plan['old_files']['network_upgrade.py']=None
        self.run_operation();self.run_operation(True)
        self.assertEqual(path.read_bytes(),self.new_raw['network_upgrade.py'])
        self.assertEqual(path.stat().st_mode&0o777,0o600)

    def test_foreign_data_location_refuses_before_rollback_intent(self):
        self.run_operation()
        foreign=Path(self.spec['new_data']);foreign.mkdir(mode=0o700);os.chown(foreign,2000,2000)
        with self.assertRaises(ValueError):self.run_operation(True)
        self.assertFalse((self.case/'rollback-intent.json').exists())
        self.assertEqual(tool.migrate_current.data_identity(self.old_data),self.new_identity)
        self.assertTrue((self.case/'original-data').exists());self.assertTrue(foreign.exists())

    def clock_review(self):
        closed=self.root/'closed';closed.write_bytes(b'closed');closed.chmod(0o600)
        sessions=self.root/'sessions';sessions.write_bytes(b'empty');sessions.chmod(0o600)
        value=dict(schema=1,operation='promote-current-apply',binding_sha256='a'*64,
            portal_closed=True,sessions_cleared=True,reviewed_at=100,expires_at=200,
            closed_route={'path':str(closed),'sha256':tool.sha(closed.read_bytes())},
            session_census={'path':str(sessions),'sha256':tool.sha(sessions.read_bytes())})
        self.review.write_text(json.dumps(value))

    def test_expiry_during_engine_census_blocks_immediately_following_data_rename(self):
        self.clock_review();clock=[150]
        def census(*args):
            progress=self.case/'progress.json'
            if progress.exists() and json.loads(progress.read_bytes())['phase']=='retaining_original':clock[0]=201
        with patch.object(tool,'review',side_effect=REAL_REVIEW),patch.object(tool.time,'time',side_effect=lambda:clock[0]), \
             patch.object(tool.cold_copy,'stopped_and_exclusive',side_effect=census):
            with self.assertRaises(tool.Refused):self.run_operation()
        self.assertEqual(tool.migrate_current.data_identity(self.old_data),self.old_identity)
        self.assertFalse((self.case/'original-data').exists())

    def test_expiry_during_last_temporary_guard_blocks_operating_file_replace(self):
        self.clock_review();clock=[150]
        path=tool.host.ROOT/'host.py';temporary=path.with_name(path.name+'.promote-current-next')
        def census(*args):
            if temporary.exists() and temporary.stat().st_mode&0o777==0o640:clock[0]=201
        with patch.object(tool,'review',side_effect=REAL_REVIEW),patch.object(tool.time,'time',side_effect=lambda:clock[0]), \
             patch.object(tool.cold_copy,'stopped_and_exclusive',side_effect=census):
            with self.assertRaises(tool.Refused):self.run_operation()
        self.assertEqual(path.read_bytes(),self.old_raw['host.py'])
        self.assertTrue(temporary.exists())

    def test_expiry_during_final_progress_fsync_cannot_emit_success_receipt(self):
        self.clock_review();clock=[150];write=tool.host.write
        def progress(path,value):
            write(path,value)
            if value.get('phase')=='promoted-stopped':clock[0]=201
        with patch.object(tool,'review',side_effect=REAL_REVIEW),patch.object(tool.time,'time',side_effect=lambda:clock[0]), \
             patch.object(tool.host,'write',side_effect=progress):
            with self.assertRaises(tool.Refused):self.run_operation()
        result=json.loads((self.case/'result.json').read_bytes())
        self.assertEqual(result['phase'],'failed');self.assertEqual(result['failure_phase'],'promoted-stopped')

    def lineage_graph(self):
        old=(Path(tool.catalog.__file__).parent/'examples/config.json').read_bytes()
        new=(Path(tool.catalog.__file__).parent/'examples/config-ssh.json').read_bytes()
        old_value={'schema':1,'postgres_major':16,'guacamole':'1.6.0',
            'config_sha256':tool.sha(old),'connections':{'desktop-a':1,'desktop-b':2}}
        old_prepared=json.dumps(old_value).encode()
        (self.old_data/'prepared.json').write_bytes(old_prepared)
        new_prepared=dict(old_value,config_sha256=tool.sha(new),connections=self.mapping)
        (self.new_data/'prepared.json').write_text(json.dumps(new_prepared))
        backup=self.root/'backup';backup.mkdir(mode=0o700)
        copied=backup/'data';shutil.copytree(self.old_data,copied);os.chown(copied,2000,2000)
        saved=tool.cold_copy.manifest(self.old_data)
        tool.files.json_new(backup/'manifest.json',saved)
        checksum=tool.sha((backup/'manifest.json').read_bytes())
        tool.files.json_new(backup/'result.json',dict(operation='backup',phase='ready',source=str(self.old_data),
            target=str(copied),manifest_sha256=checksum))
        restore=self.root/'restore-case';restore.mkdir(mode=0o700)
        tool.files.write_new(restore/'manifest.json',(backup/'manifest.json').read_bytes())
        tool.files.json_new(restore/'result.json',dict(operation='restore',phase='ready',for_migration=False,
            legacy_receipt_archived=False,target=str(self.new_data),source=str(copied),manifest_sha256=checksum))
        proof=dict(schema=1,phase='ready',started_at=100,finished_at=101,previous_config_sha256=tool.sha(old),
            config_sha256=tool.sha(new),previous_prepared_sha256=tool.sha(old_prepared),
            previous_connections=old_value['connections'],connections=self.mapping,migrated=True,identity_unchanged=True,
            enrolled=True,identity_sha256='b'*64,current_migration_sha256='c'*64)
        journal=self.new_data/tool.current_migration.JOURNAL;journal.mkdir(mode=0o700)
        tool.files.write_new(journal/'previous-prepared.json',old_prepared)
        tool.files.write_new(journal/'previous-config.json',old)
        tool.files.json_new(journal/'result.json',{k:v for k,v in proof.items() if k!='current_migration_sha256'})
        migration=self.root/'migration-case';migration.mkdir(mode=0o700)
        restore_sha=tool.sha((restore/'result.json').read_bytes())
        lineage=dict(receipt_sha256=restore_sha,manifest_sha256=checksum,source=str(copied),
            original_source=str(self.old_data),source_identity=tool.migrate_current.data_identity(copied),
            data_identity=self.new_identity,prepared_sha256=tool.sha(old_prepared))
        result=dict(schema=1,operation='migrate-current',phase='ready',passed=True,cleanup_verified=True,
            data=str(self.new_data),previous_config_sha256=tool.sha(old),config_sha256=tool.sha(new),
            image='sha256:'+'a'*64,restore=lineage,migration=proof,
            expected_connections=self.mapping,added_aliases=['terminal-c'],current_migration_sha256='c'*64)
        tool.files.json_new(migration/'receipt.json',result)
        spec=dict(new_data=str(self.new_data))
        for name,path in [('backup',backup/'result.json'),('restore',restore/'result.json'),('migration',migration/'receipt.json')]:
            spec[name]={'path':str(path),'sha256':tool.sha(path.read_bytes())}
        return spec,{'config':old},{'config':new,'release':json.dumps({'image_id':'sha256:'+'a'*64}).encode()}

    def test_actual_full_lineage_parser_accepts_root_journal_under_pg_owned_data(self):
        spec,old,new=self.lineage_graph()
        value=REAL_PROVENANCE(spec,old,new)
        self.assertEqual(value['old_identity'],self.old_identity)
        self.assertEqual(value['connections'],self.mapping)

    def test_changed_final_original_or_backup_refuses_stale_migration(self):
        spec,old,new=self.lineage_graph()
        (self.old_data/'payload').write_bytes(b'later production WAL')
        with self.assertRaises(ValueError):REAL_PROVENANCE(spec,old,new)

    def test_changed_identity_proof_or_archived_old_config_is_refused(self):
        spec,old,new=self.lineage_graph()
        path=self.new_data/tool.current_migration.JOURNAL/'previous-config.json'
        path.write_bytes(b'foreign config')
        with self.assertRaises(ValueError):REAL_PROVENANCE(spec,old,new)

    def test_backup_data_must_not_alias_original_identity(self):
        spec,old,new=self.lineage_graph();identity=tool.migrate_current.data_identity
        backup=Path(spec['backup']['path']).parent/'data'
        with patch.object(tool.migrate_current,'data_identity',side_effect=lambda p:self.old_identity if p==backup else identity(p)):
            with self.assertRaisesRegex(tool.Refused,'distinct identities'):REAL_PROVENANCE(spec,old,new)

    def test_backup_case_cannot_be_original_parent_even_with_matching_json(self):
        spec,old,new=self.lineage_graph()
        original=Path(spec['backup']['path']);copied=self.persist/'result.json'
        copied.write_bytes(original.read_bytes());copied.chmod(0o600)
        spec['backup']={'path':str(copied),'sha256':tool.sha(copied.read_bytes())}
        with self.assertRaisesRegex(tool.Refused,'Cold backup namespace'):REAL_PROVENANCE(spec,old,new)


if __name__=='__main__':unittest.main()
