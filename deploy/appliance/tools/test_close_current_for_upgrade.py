"""Inert exact-current shutdown tests; all host/engine/HTTP actions are mocked."""
from copy import deepcopy
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import close_current_for_upgrade as close


@unittest.skipUnless(os.geteuid() == 0, 'Synthetic root-private case requires root')
class ShutdownTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='portal-upgrade-close-', dir='/run')
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name); self.case = self.root/'case'; self.case.mkdir(mode=0o700)
        self.snippet = self.root/'snippet.conf'; self.snippet.write_bytes(b'ORIGINAL'); self.snippet.chmod(0o600)
        self.cfg = {'schema': 1, 'snippet_path': str(self.snippet), 'public_base': 'https://portal.example.invalid/desktop/app/',
                    'legacy_unit': 'legacy-portal.service'}
        self.record = {'container_id':'a'*64,'run_id':'b'*32,'image_id':'sha256:'+'c'*64,
                       'release_sha256':'d'*64,'phase':'ready'}
        self.current = deepcopy(self.record); self.portal = 'active'; self.transport = 'active'
        self.clock = 1000; self.loaded = 200; self.count = 1; self.exists = 1; self.events = []
        self.fresh_transport = False
        self.selected = {'release':{'image_id':self.record['image_id'],'backend_loopback_port':10080},'release_sha256':'d'*64,
            'data_identity':[1,2],'prepared_sha256':'1'*64,'secrets_identity':[1,3],'authentication_fields':['username']}
        self.expected_transport = self.service(close.pc.TRANSPORT)
        self.expected_legacy = self.service(self.cfg['legacy_unit'])
        self.fixed_binding = {**deepcopy(self.selected),
            'preserved_units':{close.pc.TRANSPORT:self.expected_transport,self.cfg['legacy_unit']:self.expected_legacy},
            'portal_unit':{key:self.service(close.pc.NEW_UNIT)[key] for key in ('LoadState','FragmentPath','UnitFileState')},
            'sources':{'source':'e'*64},'transport_identity':{'inode':17},'nginx_scope_sha256':'f'*64,'snippet_mode':0o600}
        self.plan = {'schema':1,'phase':'staged','snapshot':{'record':deepcopy(self.record),'binding':self.fixed_binding},
            'files':{'original-snippet.conf':close.host.sha(b'ORIGINAL')},'at':900}
        self.digest='9'*64
        def forbidden(*args, **kwargs): raise AssertionError('Actual host/engine/HTTP operation forbidden')
        for target, name in ((close.host,'command'),(close.pc.urllib.request,'build_opener')):
            self.patch(target,name,side_effect=forbidden)
        self.patch(close,'source_sha',return_value='8'*64)
        self.patch(close.time,'time',side_effect=lambda:self.clock)
        self.patch(close.time,'monotonic',side_effect=lambda:self.clock)
        self.patch(close.time,'sleep',side_effect=lambda duration:setattr(self,'clock',self.clock+duration))
        self.patch(close.window,'load_case',return_value=(self.cfg,self.plan))
        self.patch(close.window,'snapshot',side_effect=lambda cfg:deepcopy(self.plan['snapshot']))
        self.patch(close.window,'unchanged',side_effect=self.unchanged)
        self.patch(close,'selection_binding',side_effect=lambda:deepcopy(self.selected))
        self.patch(close.window,'source_hashes',return_value={'source':'e'*64})
        self.patch(close.window,'transport_identity',return_value={'inode':17})
        self.patch(close.window,'nginx_scope',return_value='f'*64)
        self.patch(close.window.cold_copy,'stopped_and_exclusive')
        self.patch(close.window.cold_copy,'validate_cluster')
        self.patch(close.pc,'service',side_effect=self.service)
        self.patch(close.pc,'candidate',side_effect=lambda:deepcopy(self.current))
        self.patch(close.pc,'no_sessions',side_effect=lambda cid:self.events.append(('sessions',cid)))
        self.patch(close.pc,'run',side_effect=self.command)
        self.patch(close.pc,'replace',side_effect=self.replace)
        self.patch(close.pc,'restore_file',side_effect=lambda case,name,path,allowed:self.restore_file(path,allowed))
        self.patch(close.pc,'wait_public_status',side_effect=self.wait)
        self.patch(close.pc,'public_status',side_effect=lambda *a,**k:self.loaded)
        self.patch(close.host,'engine',side_effect=self.engine)
        self.patch(close.host,'private_json',side_effect=lambda path:json.loads(Path(path).read_bytes())
            if Path(path).name == 'progress.json' else deepcopy(self.current))
        self.patch(close.host,'owned',side_effect=lambda *a:None if self.portal=='inactive' else {'State':{'Running':True}})
        self.patch(close.host,'authentication_ready',return_value=True)
        self.review_path=self.root/'review.json'
        self.write_review()

    def patch(self,target,name,**kwargs):
        patcher=patch.object(target,name,**kwargs);value=patcher.start();self.addCleanup(patcher.stop);return value

    def write_review(self,**changes):
        value={'schema':1,'scope':'one current upgrade shutdown','plan_sha256':self.digest,
            'shutdown_source_sha256':'8'*64,'operator_reference':'operator:final-window',
            'allow_fixed_original_recovery':True,'reviewed_at':999,'expires_at':1299}
        value.update(changes);self.review_path.write_text(json.dumps(value));self.review_path.chmod(0o600)

    def service(self,unit):
        state = self.portal if unit == close.pc.NEW_UNIT else self.transport if unit == close.pc.TRANSPORT else 'inactive'
        fresh = unit == close.pc.TRANSPORT and self.fresh_transport
        return {'LoadState':'loaded','ActiveState':state,'SubState':'running' if state=='active' else 'dead',
            'MainPID':('60' if fresh else '50') if state=='active' else '0',
            'InvocationID':('6'*32 if fresh else '7'*32) if state=='active' else '',
            'FragmentPath':'/etc/systemd/system/'+unit,'UnitFileState':'enabled' if unit!=self.cfg.get('legacy_unit') else 'disabled'}

    def unchanged(self,*args):
        close.require(self.transport=='active','Transport changed before own stop')
        close.require(self.selected=={key:self.fixed_binding[key] for key in self.selected},'Original selection changed')

    def command(self,argv,timeout=10):
        self.events.append(tuple(argv))
        if argv[0] == close.host.PODMAN:
            self.assertEqual(argv[1:3],['exec',self.record['container_id']])
            return subprocess.CompletedProcess(argv,0,json.dumps({'guacd_processes':self.count}).encode(),b'')
        if argv == [close.pc.NGINX,'-t']: pass
        elif argv == [close.pc.SYSTEMCTL,'reload','nginx.service']:self.loaded=503 if self.snippet.read_bytes()==close.pc.CLOSED else 200
        elif argv == [close.pc.SYSTEMCTL,'stop',close.pc.NEW_UNIT]:
            self.portal='inactive';self.current['phase']='stopped'
        elif argv == [close.pc.SYSTEMCTL,'stop',close.pc.TRANSPORT]:self.transport='inactive'
        elif argv == [close.pc.SYSTEMCTL,'start',close.pc.NEW_UNIT]:
            self.portal='active';start=self.clock;self.clock+=70
            self.current={**self.record,'container_id':'1'*64,'run_id':'2'*32,'at':start,'ready_at':self.clock}
        elif argv == [close.pc.SYSTEMCTL,'start',close.pc.TRANSPORT]:
            self.transport='active';self.fresh_transport=True
        else:raise AssertionError('Unrequested mutation target')
        return subprocess.CompletedProcess(argv,0,b'',b'')

    def engine(self,*args,**kwargs):
        if args[:2]==('container','exists'):
            self.assertEqual(args[2],self.record['container_id']);return subprocess.CompletedProcess(args,self.exists,b'',b'')
        if args[0]=='ps':return subprocess.CompletedProcess(args,0,b'',b'')
        raise AssertionError('Unexpected engine action')

    def replace(self,path,raw,allowed):
        self.assertEqual(path,self.snippet);self.assertIn(close.host.sha(path.read_bytes()),allowed)
        path.write_bytes(raw);self.events.append(('route-closed',))

    def restore_file(self,path,allowed):
        self.assertIn(close.host.sha(path.read_bytes()),allowed)
        path.write_bytes(b'ORIGINAL');self.events.append(('route-original',))

    def wait(self,base,expected,state=None):
        self.assertEqual(base,self.cfg['public_base']);self.assertEqual(self.loaded,expected)
        self.events.append(('observed',expected))

    def run_close(self):return close.run(self.case,self.digest,self.review_path)

    def test_shutdown_closes_censuses_stops_exact_portal_then_transport_once(self):
        result=self.run_close()
        self.assertEqual(result['phase'],'stopped');self.assertFalse(result['activated'])
        stop_portal=(close.pc.SYSTEMCTL,'stop',close.pc.NEW_UNIT)
        stop_transport=(close.pc.SYSTEMCTL,'stop',close.pc.TRANSPORT)
        self.assertEqual(self.events.count(stop_portal),1);self.assertEqual(self.events.count(stop_transport),1)
        self.assertLess(self.events.index(('observed',503)),self.events.index(stop_portal))
        self.assertLess(self.events.index(stop_portal),self.events.index(stop_transport))
        census=json.loads((self.case/'session-census.json').read_bytes())
        self.assertEqual((census['container_id'],census['run_id'],census['guacd_processes'],census['at']),
            (self.record['container_id'],self.record['run_id'],1,1000))
        self.assertTrue(census['closed_before_census'])
        self.assertEqual((self.portal,self.transport,self.loaded),('inactive','inactive',503))
        self.assertTrue(all(self.cfg['legacy_unit'] not in args and 'start' not in args for args in self.events))
        before=list(self.events)
        with self.assertRaises(close.pc.Refused):self.run_close()
        self.assertEqual(self.events,before)

    def test_postclose_active_or_invalid_native_count_never_stops_anything(self):
        for value in (2,0,True):
            sub=self.root/str(value);sub.mkdir(mode=0o700);self.case=sub;self.count=value
            self.snippet.write_bytes(b'ORIGINAL');self.loaded=200;self.events=[]
            with self.subTest(value=value),self.assertRaises(close.pc.Refused):self.run_close()
            self.assertFalse(any('stop' in event for event in self.events))
            self.assertEqual((self.portal,self.transport),('active','active'))
            self.assertEqual(self.loaded,503)

    def test_expiry_after_syntax_does_not_reload_or_stop_and_never_auto_recovers(self):
        def command(argv,timeout=10):
            value=self.command(argv,timeout)
            if argv[0]==close.pc.NGINX:self.clock=1300
            return value
        close.pc.run.side_effect=command
        with self.assertRaises(close.pc.Refused):self.run_close()
        self.assertFalse(any('stop' in event or 'reload' in event or 'start' in event for event in self.events))
        self.assertEqual(self.loaded,200)
        value=close.reconcile(self.case,self.digest)
        self.assertEqual(value['route'],'closed');self.assertEqual(value['observed_public_status'],200)
        self.assertTrue(value['no_actions_performed'])

    def test_expiry_after_portal_stop_does_not_stop_transport(self):
        def command(argv,timeout=10):
            value=self.command(argv,timeout)
            if argv==[close.pc.SYSTEMCTL,'stop',close.pc.NEW_UNIT]:self.clock=1300
            return value
        close.pc.run.side_effect=command
        with self.assertRaises(close.pc.Refused):self.run_close()
        self.assertEqual((self.portal,self.transport),('inactive','active'))
        self.assertEqual(sum('stop' in event for event in self.events),1)

    def test_uncertain_portal_stop_is_not_replayed_and_transport_stays_active(self):
        original=TimeoutError('Synthetic uncertain portal stop')
        def command(argv,timeout=10):
            value=self.command(argv,timeout)
            if argv==[close.pc.SYSTEMCTL,'stop',close.pc.NEW_UNIT]:raise original
            return value
        close.pc.run.side_effect=command
        with self.assertRaises(TimeoutError) as caught:self.run_close()
        self.assertIs(caught.exception,original)
        self.assertEqual((self.portal,self.transport),('inactive','active'))
        before=list(self.events);value=close.reconcile(self.case,self.digest)
        self.assertFalse(value['container_present']);self.assertEqual(self.events,before)
        with self.assertRaises(close.pc.Refused):self.run_close()

    def test_uncertain_transport_stop_is_observed_without_replaying_or_starting(self):
        original=TimeoutError('Synthetic uncertain transport stop')
        def command(argv,timeout=10):
            value=self.command(argv,timeout)
            if argv==[close.pc.SYSTEMCTL,'stop',close.pc.TRANSPORT]:raise original
            return value
        close.pc.run.side_effect=command
        with self.assertRaises(TimeoutError):self.run_close()
        before=list(self.events);value=close.reconcile(self.case,self.digest)
        self.assertTrue(value['no_actions_performed']);self.assertEqual(value['transport']['ActiveState'],'inactive')
        self.assertEqual(self.events,before)

    def test_unknown_cid_absence_stops_no_transport(self):
        self.exists=125
        with self.assertRaisesRegex(close.pc.Refused,'exists returncode1'):self.run_close()
        self.assertEqual(self.transport,'active')

    def test_stopped_transport_source_or_selected_data_drift_is_never_accepted(self):
        self.run_close()
        close.window.source_hashes.return_value={'changed':'e'*64}
        with self.assertRaisesRegex(close.pc.Refused,'sources'):close.reconcile(self.case,self.digest)
        close.window.source_hashes.return_value={'source':'e'*64}
        self.selected['data_identity']=[2,7]
        with self.assertRaisesRegex(close.pc.Refused,'DATA identity'):close.reconcile(self.case,self.digest)

    def test_review_wrong_scope_source_hash_or_stale_plan_prevents_intent(self):
        for changes in ({'scope':'one current backup window'},{'shutdown_source_sha256':'0'*64},
                        {'expires_at':999},{'allow_fixed_original_recovery':False}):
            self.write_review(**changes)
            with self.subTest(changes=changes),self.assertRaises(close.pc.Refused):self.run_close()
            self.assertFalse((self.case/'upgrade-close.intent.json').exists())
        self.write_review();close.window.snapshot.side_effect=lambda cfg:{'foreign':'snapshot'}
        with self.assertRaises(close.pc.Refused):self.run_close()
        self.assertEqual(self.events,[])

    def test_primary_stop_error_survives_failed_diagnostic_write(self):
        original=TimeoutError('Synthetic original stop')
        def command(argv,timeout=10):
            if argv==[close.pc.SYSTEMCTL,'stop',close.pc.NEW_UNIT]:raise original
            return self.command(argv,timeout)
        close.pc.run.side_effect=command
        write=close.files.json_new
        def json_new(path,value):
            if path.name=='upgrade-close.failure.json':raise OSError('Synthetic secondary failure')
            return write(path,value)
        with patch.object(close.files,'json_new',side_effect=json_new):
            with self.assertRaises(TimeoutError) as caught:self.run_close()
        self.assertIs(caught.exception,original)
        self.assertTrue((self.case/'upgrade-close.intent.json').exists())

    def prepare_recovery(self):
        self.run_close()
        self.recovery_case=self.root/'recovery'
        self.recovery_sha=close.stage_recovery(self.case,self.digest,self.recovery_case)
        self.write_review(scope='one fixed original recovery',recovery_plan_sha256=self.recovery_sha)

    def recover(self):return close.recover(self.case,self.digest,self.recovery_case,self.recovery_sha,self.review_path)

    def test_reviewed_fixed_original_recovery_starts_app_first_then_fresh_transport_and_opens_last(self):
        self.prepare_recovery();before=len(self.events)
        result=self.recover();events=self.events[before:]
        app=(close.pc.SYSTEMCTL,'start',close.pc.NEW_UNIT)
        transport=(close.pc.SYSTEMCTL,'start',close.pc.TRANSPORT)
        self.assertEqual(events.count(app),1);self.assertEqual(events.count(transport),1)
        self.assertLess(events.index(app),events.index(transport))
        self.assertLess(events.index(transport),events.index(('route-original',)))
        self.assertEqual((self.portal,self.transport,self.loaded),('active','active',200))
        self.assertTrue(result['original_restored']);self.assertFalse(result['activated_mixed'])
        self.assertEqual(result['fresh_transport']['InvocationID'],'6'*32)
        self.assertEqual(result['restored_deployment']['container_id'],'1'*64)
        close.host.authentication_ready.assert_called_once()
        prior=list(self.events)
        with self.assertRaises((close.pc.Refused,ValueError)):self.recover()
        self.assertEqual(prior,self.events)

    def test_recovery_cannot_stage_after_controller_replacement_or_changed_original_data(self):
        self.run_close();self.current['container_id']='3'*64
        with self.assertRaisesRegex(close.pc.Refused,'controller identity'):close.stage_recovery(self.case,self.digest,self.root/'recovery')
        self.current=deepcopy(self.record);self.current['phase']='stopped';self.selected['data_identity']=[8,9]
        with self.assertRaisesRegex(close.pc.Refused,'DATA identity'):close.stage_recovery(self.case,self.digest,self.root/'recovery')

    def test_recovery_rejects_wrong_scope_wrong_plan_or_source_before_start(self):
        self.prepare_recovery();before=list(self.events)
        self.write_review()
        with self.assertRaises((close.pc.Refused,ValueError)):self.recover()
        self.assertFalse(any('start' in event for event in self.events[len(before):]))
        self.write_review(scope='one fixed original recovery',recovery_plan_sha256='0'*64)
        with self.assertRaises(close.pc.Refused):self.recover()
        self.assertFalse((self.recovery_case/'recovery.intent.json').exists())
        close.source_sha.return_value='5'*64
        with self.assertRaises(close.pc.Refused):self.recover()

    def test_recovery_false_short_hold_or_wrong_image_never_starts_transport_or_opens(self):
        self.prepare_recovery()
        def command(argv,timeout=10):
            value=self.command(argv,timeout)
            if argv==[close.pc.SYSTEMCTL,'start',close.pc.NEW_UNIT]:self.current['ready_at']=1001
            return value
        close.pc.run.side_effect=command
        with self.assertRaisesRegex(close.pc.Refused,'65second'):self.recover()
        self.assertEqual((self.transport,self.loaded),('inactive',503))
        self.assertFalse(close.host.authentication_ready.called)

    def test_recovery_uncertain_app_start_never_retries_or_starts_transport(self):
        self.prepare_recovery();original=TimeoutError('Synthetic uncertain original start')
        def command(argv,timeout=10):
            value=self.command(argv,timeout)
            if argv==[close.pc.SYSTEMCTL,'start',close.pc.NEW_UNIT]:raise original
            return value
        close.pc.run.side_effect=command
        with self.assertRaises(TimeoutError):self.recover()
        self.assertEqual((self.transport,self.loaded),('inactive',503))
        before=list(self.events)
        result=close.reconcile_recovery(self.case,self.digest,self.recovery_case,self.recovery_sha)
        self.assertTrue(result['no_actions_performed']);self.assertEqual(result['current']['run_id'],'2'*32)
        self.assertEqual(before,self.events)
        with self.assertRaises(close.pc.Refused):self.recover()

    def test_recovery_fresh_transport_identity_required_before_challenge_and_open(self):
        self.prepare_recovery()
        def command(argv,timeout=10):
            value=self.command(argv,timeout)
            if argv==[close.pc.SYSTEMCTL,'start',close.pc.TRANSPORT]:self.fresh_transport=False
            return value
        close.pc.run.side_effect=command
        with self.assertRaisesRegex(close.pc.Refused,'Fresh original transport'):self.recover()
        self.assertEqual(self.loaded,503);self.assertFalse(close.host.authentication_ready.called)

    def test_recovery_failed_empty_challenge_never_retried_or_reopens(self):
        self.prepare_recovery();close.host.authentication_ready.return_value=False
        with self.assertRaisesRegex(close.pc.Refused,'challenge'):self.recover()
        close.host.authentication_ready.assert_called_once();self.assertEqual(self.loaded,503)
        with self.assertRaises(close.pc.Refused):self.recover()
        close.host.authentication_ready.assert_called_once()

    def test_recovery_expiry_after_app_start_leaves_closed_without_transport_start(self):
        self.prepare_recovery()
        def command(argv,timeout=10):
            value=self.command(argv,timeout)
            if argv==[close.pc.SYSTEMCTL,'start',close.pc.NEW_UNIT]:self.clock=1300;self.current['ready_at']=1300
            return value
        close.pc.run.side_effect=command
        with self.assertRaises(close.pc.Refused):self.recover()
        self.assertEqual((self.transport,self.loaded),('inactive',503))

    def test_review_expiry_during_source_read_cannot_authorize_shutdown(self):
        def source():
            self.clock=1300
            return '8'*64
        close.source_sha.side_effect=source
        with self.assertRaisesRegex(close.pc.Refused,'expired during source'):self.run_close()
        self.assertFalse((self.case/'upgrade-close.intent.json').exists());self.assertEqual(self.events,[])

    def test_shutdown_final_status_expiry_does_not_publish_stopped_success(self):
        calls=[0]
        def wait(base,expected,state=None):
            self.wait(base,expected,state);calls[0]+=1
            if calls[0]==2:self.clock=1300
        close.pc.wait_public_status.side_effect=wait
        with self.assertRaises(close.pc.Refused):self.run_close()
        self.assertEqual((self.portal,self.transport),('inactive','inactive'))
        self.assertFalse((self.case/'upgrade-close.result.json').exists())

    def test_recovery_final_status_expiry_does_not_publish_restored_success(self):
        self.prepare_recovery()
        def wait(base,expected,state=None):
            self.wait(base,expected,state)
            if expected==200:self.clock=1300
        close.pc.wait_public_status.side_effect=wait
        with self.assertRaises(close.pc.Refused):self.recover()
        self.assertEqual(self.loaded,200)
        self.assertFalse((self.recovery_case/'recovery.result.json').exists())


if __name__=='__main__':unittest.main()
