"""Inert transaction tests. No host service, nginx, browser or Podman is run."""
import copy
import contextlib
import io
import json
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import public_cutover as cutover

IMAGE = 'sha256:'+'a'*64
OLD_CID = 'b'*64
PRIVATE_CID = 'c'*64
PUBLIC_CID = 'd'*64
OLD_RUN = 'e'*32
PRIVATE_RUN = 'f'*32
PUBLIC_RUN = '1'*32
DRIVER = '2'*64
PLAN_SHA = '3'*64
CASE = Path('/var/lib/portal-cutover/case-a')


def config():
    return {'schema':1, 'legacy_unit':'legacy-portal.service', 'legacy_container':'legacy-portal',
        'legacy_label':'example.legacy', 'legacy_record_path':'/run/legacy-portal/instance.json',
        'legacy_ready_path':'/run/legacy-portal-public/ready', 'legacy_data_path':'/var/lib/legacy-portal/data',
        'snippet_path':'/etc/nginx/snippets/example-portal.conf',
        'rate_limit_path':'/etc/nginx/conf.d/portal-limit.conf',
        'public_base':'https://portal.example.invalid/desktop/app/',
        'private_base':'http://127.0.0.1:10080/guacamole/',
        'private_review':{'path':'/var/lib/review/review.json', 'sha256':'4'*64},
        'private_windows':{'path':'/var/lib/acceptance/private.json', 'sha256':'5'*64},
        'browser_driver_sha256':DRIVER, 'session_clearance_reference':'operator-session-check-1',
        'private_windows_review_reference':'operator-two-real-Windows-1'}


def registry():
    value = json.loads((Path(__file__).parents[1]/'examples/config.json').read_text())
    return cutover.catalog.parse(value)


def private_deployment():
    return cutover.deployment(release(),'0'*64,PRIVATE_CID,PRIVATE_RUN)


def browser(public=False):
    desktops = [{'alias':alias, 'client_id':str(i+1), 'state':'CONNECTED', 'status':0,
                 'width':800, 'height':600, 'nonblack':20000} for i,alias in enumerate(['desktop-a','desktop-b'])]
    return {'schema':1, 'passed':True, 'phase':'complete', 'expected_image':IMAGE[7:],
        'driver_sha256':DRIVER, 'checks':sorted(cutover.BROWSER_CHECKS),
        'own_logout_204':True, 'owned_chrome_group_cleanup':True, 'owned_profile_removed':True,
        'desktops':desktops, 'refresh':{k:v for k,v in desktops[-1].items() if k not in ('alias','client_id')},
        'started_at':1000, 'finished_at':1020,
        'observed_base':config()['public_base'] if public else config()['private_base'],
        'deployment_before':cutover.deployment(release(),'f'*64,PUBLIC_CID,PUBLIC_RUN) if public else private_deployment(),
        'deployment_after':cutover.deployment(release(),'f'*64,PUBLIC_CID,PUBLIC_RUN) if public else private_deployment()}


def validate(receipt):
    return cutover.validate_browser(receipt,IMAGE,['desktop-a','desktop-b'],DRIVER,
                                    config()['private_base'],private_deployment())


def release():
    return {'schema':1, 'image_id':IMAGE, 'config_sha256':'6'*64, 'network_sha256':'7'*64,
        'apparmor_profile_sha256':'8'*64, 'backend_loopback_port':10080,
        'acceptance_evidence_path':config()['private_review']['path'],
        'acceptance_evidence_sha256':config()['private_review']['sha256']}


def plan():
    return {'schema':1, 'snapshot':{'release':release(), 'release_sha256':'0'*64,
        'old':{'container_id':OLD_CID, 'image_id':IMAGE}, 'legacy_backend_port':10079,
        'new_container_id':PRIVATE_CID, 'new_run_id':PRIVATE_RUN, 'sources':{},
        'candidate_data_identity':[1,2], 'legacy_data_identity':[1,3],
        'units':{u:{'UnitFileState':'enabled' if u=='legacy-portal.service' else 'disabled'}
                 for u in ('legacy-portal.service', cutover.NEW_UNIT, cutover.TRANSPORT)}},
        'files':{'old-snippet.conf':'9'*64, 'new-snippet.conf':'a'*64,
                 'closed-snippet.conf':cutover.host.sha(cutover.CLOSED),
                 'old-release.json':'b'*64, 'new-rate.conf':cutover.host.sha(cutover.RATE)}}


class Inert(unittest.TestCase):
    def setUp(self):
        patch.object(cutover.host, 'command', side_effect=AssertionError('Unexpected host call')).start()
        patch.object(cutover.host, 'engine', side_effect=AssertionError('Unexpected engine call')).start()
        patch.object(cutover.urllib.request, 'build_opener', side_effect=AssertionError('Unexpected HTTP')).start()
        self.addCleanup(patch.stopall)


class ValidationTests(Inert):
    def test_policy_binding_sibling_drift_refuses_original_plan(self):
        changed = {}
        holder = {}
        def read(path):
            if path == CASE/'plan.json':
                return holder['plan']
            return changed.get(str(path), str(path).encode())
        with patch.object(cutover.host, 'ROOT', Path('/installed')), \
                patch.object(cutover.network, 'protected_read', side_effect=read), \
                patch.object(cutover.host, 'directory'), \
                patch.object(cutover.host, 'read_json', return_value=config()):
            sources = cutover.source_hashes()
            self.assertIn('/installed/network_upgrade.py', sources)
            holder['plan'] = json.dumps({'schema': 1, 'files': {},
                'snapshot': {'sources': sources}}).encode()
            expected = cutover.host.sha(holder['plan'])
            cutover.load_case(CASE, expected)
            changed['/installed/network_upgrade.py'] = b'changed policy binding code'
            with self.assertRaisesRegex(cutover.Refused, 'Reviewed source or unit changed'):
                cutover.load_case(CASE, expected)

    def test_external_configuration_strict_paths_https_and_independent_data(self):
        self.assertEqual(cutover.parse_config(config()), config())
        wrong = [('schema',True), ('legacy_unit',cutover.NEW_UNIT), ('legacy_label','bad;command'),
            ('legacy_data_path',str(cutover.host.PERSIST/'data')), ('snippet_path','/etc/passwd'),
            ('rate_limit_path','/etc/nginx/conf.d/../bad.conf'), ('public_base','http://portal.example.invalid/desktop/app/'),
            ('public_base','https://user:password@portal.example.invalid/desktop/app/'),
            ('private_windows_review_reference',''), ('session_clearance_reference','not reviewed\n')]
        for key,value in wrong:
            with self.subTest(key=key), self.assertRaises((cutover.Refused, ValueError)):
                cutover.parse_config({**config(),key:value})
        with self.assertRaises(ValueError): cutover.parse_config({**config(),'extra':True})

    def test_actual_two_windows_result_and_cleanup_required(self):
        validate(browser())
        changes = [('passed',False), ('phase','failed'), ('expected_image','f'*64),
            ('driver_sha256','f'*64), ('own_logout_204',False), ('owned_profile_removed',False),
            ('checks',['native_username_TOTP']), ('desktops',browser()['desktops'][:1])]
        for key,value in changes:
            with self.subTest(key=key), self.assertRaises(cutover.Refused):
                validate({**browser(),key:value})
        for field,value in [('state','DISCONNECTED'),('status',1),('status',False),('nonblack',10000),('client_id','1')]:
            receipt=browser();receipt['desktops'][1][field]=value
            with self.subTest(field=field), self.assertRaises(cutover.Refused):
                validate(receipt)

    def test_two_actual_aliases_can_be_tested_in_either_order(self):
        receipt=browser();receipt['desktops'].reverse();validate(receipt)

    def test_browser_origin_and_all_deployment_proof_fields_are_bound(self):
        for field in private_deployment():
            for side in ('deployment_before','deployment_after'):
                receipt=browser();receipt[side][field]='wrong'
                with self.subTest(field=field,side=side),self.assertRaisesRegex(cutover.Refused,'deployment proof'):
                    validate(receipt)
        receipt=browser();receipt['observed_base']=config()['public_base']
        with self.assertRaisesRegex(cutover.Refused,'browser origin'):validate(receipt)
        receipt=browser();del receipt['deployment_before']
        with self.assertRaises(cutover.Refused):validate(receipt)

    def test_private_rehearsal_alone_never_admits_pending_windows(self):
        cfg=config();reg=registry()
        primaries={n+'.json':cutover.host.sha(b'{}') for n in cutover.PRIMARY_NAMES}
        review={'schema':1,'scope':'private restored rehearsal only','public_admitted':False,
                'image_id':IMAGE,'primary_receipts':primaries}
        with patch.object(cutover,'read_artifact',side_effect=[review,{**browser(),'passed':False}]), \
             patch.object(cutover.network,'protected_read',return_value=b'{}'):
            with self.assertRaisesRegex(cutover.Refused,'Complete actual two-Windows'):
                cutover.admission_candidate(cfg,release(),reg,{},private_deployment())

    def test_admission_candidate_binds_primaries_and_keeps_operator_review_pending(self):
        primaries={n+'.json':cutover.host.sha(b'{}') for n in cutover.PRIMARY_NAMES}
        review={'schema':1,'scope':'private restored rehearsal only','public_admitted':False,
                'image_id':IMAGE,'primary_receipts':primaries}
        with patch.object(cutover,'read_artifact',side_effect=[review,browser()]), \
             patch.object(cutover.network,'protected_read',return_value=b'{}'):
            draft=cutover.admission_candidate(config(),release(),registry(),{'/opt/portal/host.py':'a'*64},private_deployment())
        self.assertIs(draft['public_rdp_admitted'],False)
        self.assertIs(draft['ssh_tmux_admitted'],False)
        self.assertEqual(draft['actual_windows_private'],config()['private_windows'])
        self.assertEqual(draft['host_sources'],{'/opt/portal/host.py':'a'*64})
        self.assertEqual(draft['primary_receipts'],primaries)

    def test_tampered_primary_receipt_refused(self):
        review={'schema':1,'scope':'private restored rehearsal only','public_admitted':False,
                'image_id':IMAGE,'primary_receipts':{n+'.json':'1'*64 for n in cutover.PRIMARY_NAMES}}
        with patch.object(cutover,'read_artifact',return_value=review), \
             patch.object(cutover.network,'protected_read',return_value=b'changed'):
            with self.assertRaisesRegex(cutover.Refused,'Primary rehearsal bytes changed'):
                cutover.admission_candidate(config(),release(),registry(),{},private_deployment())

    def test_session_probe_refuses_live_or_missing_guacd_without_stopping(self):
        for count in (0,2,5):
            with patch.object(cutover,'run',return_value=SimpleNamespace(stdout=json.dumps({'guacd_processes':count}).encode())) as run:
                with self.assertRaises(cutover.Refused):cutover.no_sessions(PRIVATE_CID)
                self.assertEqual(run.call_count,1)
                self.assertEqual(run.call_args.args[0][1:3],['exec',PRIVATE_CID])

    def test_exact_native_probe_parses_real_nul_separators_and_counts_child(self):
        class Process:
            def __init__(self,pid,raw):self.name=str(pid);self.raw=raw
            def __truediv__(self,name):return SimpleNamespace(read_bytes=lambda:self.raw)
        processes=[Process(1,b'python3\0runtime.py\0'), Process(20,b'/opt/guacamole/sbin/guacd\0-f\0-b\0127.0.0.1\0'),
                   Process(21,b'/opt/guacamole/sbin/guacd\0-f\0'),Process(30,b'java\0private-arg\0')]
        import pathlib
        output=io.StringIO()
        with patch.object(pathlib,'Path',return_value=SimpleNamespace(iterdir=lambda:processes)),contextlib.redirect_stdout(output):
            exec(compile(cutover.SESSION_PROBE,'exact-native-session-probe','exec'),{})
        self.assertEqual(json.loads(output.getvalue()),{'guacd_processes':2})

    def test_native_probe_permission_error_cannot_hide_a_session(self):
        def denied():raise PermissionError('uninspectable native process')
        class Process:
            name='1'
            def __truediv__(self,name):return SimpleNamespace(read_bytes=denied)
        import pathlib
        with patch.object(pathlib,'Path',return_value=SimpleNamespace(iterdir=lambda:[Process()])):
            with self.assertRaises(PermissionError):
                exec(compile(cutover.SESSION_PROBE,'exact-native-session-probe','exec'),{})

    def test_running_candidate_must_match_selected_release_before_use(self):
        record={'phase':'ready','image_id':'sha256:'+'b'*64,'release_sha256':'0'*64,
                'container_id':PRIVATE_CID,'run_id':PRIVATE_RUN}
        with patch.object(cutover.host,'private_json',return_value=record), \
             patch.object(cutover.host,'selection',return_value=(release(),None,('0'*64,))), \
             patch.object(cutover.host,'owned') as owned:
            with self.assertRaisesRegex(cutover.Refused,'match admitted image'):cutover.candidate()
            owned.assert_not_called()


class SwitchTests(Inert):
    def harness(self):
        self.events=[];self.writes={};self.state={};self.current_plan=plan()
        patch.object(cutover,'load_case',return_value=(config(),self.current_plan)).start()
        patch.object(cutover,'snapshot',return_value=self.current_plan['snapshot']).start()
        patch.object(cutover.os.path,'lexists',return_value=False).start()
        patch.object(cutover.catalog,'parse',return_value=registry()).start()
        patch.object(cutover,'admission_candidate',return_value={'public_rdp_admitted':False,'aliases':['desktop-a','desktop-b']}).start()
        def read_json(path):
            if path==CASE/'admission-candidate.json':return {'public_rdp_admitted':False,'aliases':['desktop-a','desktop-b']}
            return {}
        patch.object(cutover.host,'read_json',side_effect=read_json).start()
        patch.object(cutover.network,'protected_read',side_effect=lambda path:self.writes.get(str(path),b'{}')).start()
        patch.object(cutover,'json_new',side_effect=lambda p,v:self.writes.update({str(p):json.dumps(v).encode()})).start()
        patch.object(cutover,'write_new',side_effect=lambda p,v,**kw:self.events.append('rate-install')).start()
        def progress(case,state,phase):
            state['phase']=phase;state['at']=100
            self.events.append(phase);self.state=state
        patch.object(cutover,'progress',side_effect=progress).start()
        patch.object(cutover,'replace',side_effect=lambda path,*args:self.events.append('replace:'+path.name)).start()
        patch.object(cutover,'reload_nginx',side_effect=lambda:self.events.append('nginx-test-reload')).start()
        patch.object(cutover,'public_status',side_effect=[503,200]).start()
        patch.object(cutover,'no_sessions',side_effect=lambda cid:self.events.append('sessions:'+cid[0])).start()
        patch.object(cutover,'run',side_effect=lambda argv,**kw:self.events.append('command:'+' '.join(argv[1:]))).start()
        patch.object(cutover,'stopped',side_effect=lambda unit,*a:self.events.append('stopped:'+unit)).start()
        current={'run_id':PUBLIC_RUN,'container_id':PUBLIC_CID,'ready_at':165}
        patch.object(cutover,'candidate',return_value=current).start()
        patch.object(cutover,'service',return_value={'ActiveState':'active','SubState':'running'}).start()
        def selection():
            return release(),None,(self.state['new_release_sha256'],None,None,None,[])
        patch.object(cutover.host,'selection',side_effect=selection).start()
        patch.object(cutover.host,'authentication_ready',return_value=True).start()
        patch.object(cutover.time,'time',return_value=100).start()
        patch.object(cutover,'rollback_actions').start()
        patch.object(cutover,'contain').start()

    def test_stop_old_fresh_start_hold_then_public_and_no_enable(self):
        self.harness()
        cutover.switch(CASE,PLAN_SHA,'operator-reviewed-1')
        order=['closing_public_route','sessions:b','sessions:c','command:stop legacy-portal.service',
            'command:stop guacamole-portal.service','release_rebind_intent',
            'command:start guacamole-portal.service','selecting_public_candidate','rate-install',
            'awaiting_actual_public_acceptance']
        indices=[self.events.index(item) for item in order]
        self.assertEqual(indices,sorted(indices))
        self.assertFalse(any('enable' in e or 'disable' in e for e in self.events))
        admission=json.loads(self.writes[str(CASE/'admission.json')])
        self.assertIs(admission['public_rdp_admitted'],True)
        self.assertEqual(admission['plan_sha256'],PLAN_SHA)
        cutover.rollback_actions.assert_not_called()

    def test_transient_old_200_waits_for_actual_503_before_session_census(self):
        self.harness()
        statuses=iter([200,503,200])
        def status(base, **kwargs):
            value=next(statuses)
            self.events.append('status:'+str(value))
            self.assertLessEqual(kwargs['timeout'],1)
            return value
        cutover.public_status.side_effect=status
        with patch.object(cutover.time,'sleep'):
            cutover.switch(CASE,PLAN_SHA,'review-wait-1')
        self.assertLess(self.events.index('status:503'),self.events.index('sessions:b'))
        self.assertEqual(cutover.public_status.call_count,3)

    def test_status_timeout_records_fixed_diagnostic_before_rollback_no_stop(self):
        self.harness();now=[0.0]
        cutover.public_status.side_effect=None;cutover.public_status.return_value=200
        with patch.object(cutover.time,'monotonic',side_effect=lambda:now[0]), \
                patch.object(cutover.time,'sleep',side_effect=lambda seconds:now.__setitem__(0,now[0]+seconds)):
            with self.assertRaisesRegex(cutover.Refused,'rollback confirmed'):
                cutover.switch(CASE,PLAN_SHA,'review-timeout-1')
        failure=json.loads(self.writes[str(CASE/'switch.failure.json')])
        self.assertEqual(failure['failure_phase'],'closing_public_route')
        self.assertEqual(failure['failure_reason'],'Expected public HTTP status not confirmed within five seconds')
        self.assertEqual(failure['expected_public_status'],503)
        self.assertEqual(failure['last_public_status'],200)
        self.assertEqual(now[0],5)
        cutover.no_sessions.assert_not_called();cutover.run.assert_not_called()
        cutover.rollback_actions.assert_called_once()

    def test_rollback_error_preserves_original_failure_without_external_text(self):
        self.harness()
        def fail(argv,**kwargs):
            if argv[1]=='start':cutover.require(False,'Host command returned failure')
        cutover.run.side_effect=fail
        def rollback(*args):
            self.assertIn(str(CASE/'switch.failure.json'),self.writes)
            raise RuntimeError('PRIVATE TOKEN SUBPROCESS TEXT')
        cutover.rollback_actions.side_effect=rollback
        with self.assertRaisesRegex(cutover.Refused,'rollback unconfirmed'):
            cutover.switch(CASE,PLAN_SHA,'review-rollback-error-1')
        failure=json.loads(self.writes[str(CASE/'switch.failure.json')])
        secondary=json.loads(self.writes[str(CASE/'switch.rollback-failure.json')])
        self.assertEqual(failure['failure_phase'],'fresh_candidate_start')
        self.assertEqual(failure['failure_reason'],'Host command returned failure')
        self.assertEqual(secondary['failure_reason'],failure['failure_reason'])
        self.assertEqual(secondary['rollback_error_type'],'RuntimeError')
        self.assertNotIn('PRIVATE',str(self.writes))

    def test_unmarked_refusal_message_cannot_enter_failure_receipt(self):
        self.harness();cutover.reload_nginx.side_effect=cutover.Refused('PRIVATE EXTERNAL VALUE')
        with self.assertRaises(cutover.Refused):
            cutover.switch(CASE,PLAN_SHA,'review-unmarked-1')
        failure=json.loads(self.writes[str(CASE/'switch.failure.json')])
        self.assertEqual(failure['failure_reason'],'Unclassified refusal')
        self.assertNotIn('PRIVATE',str(self.writes))

    def test_private_failure_or_changed_live_state_refuses_before_mutations(self):
        self.harness();cutover.snapshot.return_value={}
        with self.assertRaisesRegex(cutover.Refused,'Live cutover bindings changed'):
            cutover.switch(CASE,PLAN_SHA,'operator-reviewed-1')
        self.assertEqual(self.events,[])
        self.assertEqual(self.writes,{})

    def test_known_start_failure_rolls_back_without_public_new(self):
        self.harness()
        def run(argv,**kw):
            self.events.append('command:'+' '.join(argv[1:]))
            if argv[1]=='start':raise cutover.Refused('Known start failure')
        cutover.run.side_effect=run
        with self.assertRaisesRegex(cutover.Refused,'rollback confirmed'):
            cutover.switch(CASE,PLAN_SHA,'operator-reviewed-1')
        cutover.rollback_actions.assert_called_once()
        self.assertNotIn('selecting_public_candidate',self.events)

    def test_short_replay_hold_refused_and_rolled_back(self):
        self.harness();cutover.candidate.return_value={'run_id':PUBLIC_RUN,'container_id':PUBLIC_CID,'ready_at':164.9}
        with self.assertRaisesRegex(cutover.Refused,'rollback confirmed'):
            cutover.switch(CASE,PLAN_SHA,'operator-reviewed-1')
        cutover.rollback_actions.assert_called_once()
        self.assertNotIn('selecting_public_candidate',self.events)

    def test_timeout_is_uncertain_contained_never_automatic_rollback(self):
        import subprocess
        self.harness()
        def run(argv,**kw):
            if argv[1]=='start':raise subprocess.TimeoutExpired('systemctl',140,output=b'secret')
        cutover.run.side_effect=run
        with self.assertRaises(subprocess.TimeoutExpired):
            cutover.switch(CASE,PLAN_SHA,'operator-reviewed-1')
        cutover.contain.assert_called_once()
        cutover.rollback_actions.assert_not_called()
        self.assertNotIn('selecting_public_candidate',self.events)

    def test_existing_intent_never_replays(self):
        self.harness();cutover.os.path.lexists.side_effect=lambda p:p==CASE/'switch.intent.json'
        with self.assertRaisesRegex(cutover.Refused,'no replay'):cutover.switch(CASE,PLAN_SHA,'review-1')
        cutover.snapshot.assert_not_called()
        cutover.run.assert_not_called()


class AcceptanceTests(Inert):
    def harness(self):
        self.events=[];self.current_plan=plan()
        self.state={'phase':'awaiting_actual_public_acceptance','candidate_run_id':PUBLIC_RUN,
                    'candidate_cid':PUBLIC_CID,'new_release_sha256':'f'*64}
        self.review={'path':'/var/lib/acceptance/public-review.json','sha256':'c'*64}
        self.proof={'schema':1,'scope':'actual public RDP acceptance','plan_sha256':PLAN_SHA,
                    'public_base':config()['public_base'],'browser':{'path':'/var/lib/acceptance/public.json','sha256':'d'*64},
                    'operator_reference':'review-public-browser-1'}
        patch.object(cutover,'load_case',return_value=(config(),self.current_plan)).start()
        patch.object(cutover.os.path,'lexists',return_value=False).start()
        patch.object(cutover,'read_artifact',side_effect=lambda item:self.proof if item==self.review else browser(public=True)).start()
        def read_json(path):
            if path.name=='progress.json':return self.state
            if path.name=='admission.json':return {'aliases':['desktop-a','desktop-b']}
            if path.name=='switch.result.json':return {'at':900}
            raise AssertionError('Unexpected JSON input')
        patch.object(cutover.host,'read_json',side_effect=read_json).start()
        patch.object(cutover,'candidate',side_effect=lambda:self.events.append('health') or {'run_id':PUBLIC_RUN,'container_id':PUBLIC_CID}).start()
        patch.object(cutover.host,'selection',return_value=(release(),None,('f'*64,[1,2]))).start()
        raw={config()['snippet_path']:b'new-route',config()['rate_limit_path']:b'rate'}
        self.current_plan['files']['new-snippet.conf']=cutover.host.sha(b'new-route')
        self.current_plan['files']['new-rate.conf']=cutover.host.sha(b'rate')
        patch.object(cutover.network,'protected_read',side_effect=lambda p:raw[str(p)]).start()
        self.enabled=False;self.old_disabled=False
        def service(unit):
            enabled=self.old_disabled is False if unit=='legacy-portal.service' else self.enabled
            return {'ActiveState':'active','SubState':'running','UnitFileState':'enabled' if enabled else 'disabled'}
        patch.object(cutover,'service',side_effect=service).start()
        patch.object(cutover,'public_status',return_value=200).start()
        patch.object(cutover,'json_new').start()
        patch.object(cutover,'progress').start()
        def run(argv,**kwargs):
            self.events.append(argv[1])
            if argv[1]=='enable':self.enabled=True
            if argv[1]=='disable':self.old_disabled=True
        patch.object(cutover,'run',side_effect=run).start()
        patch.object(cutover,'rollback_actions').start()
        patch.object(cutover,'contain').start()

    def test_enable_after_actual_public_health_disable_old_after_enable(self):
        self.harness();cutover.accept(CASE,PLAN_SHA,self.review)
        self.assertLess(self.events.index('health'),self.events.index('enable'))
        self.assertLess(self.events.index('enable'),self.events.index('disable'))
        self.assertEqual(self.events.count('health'),2)
        cutover.rollback_actions.assert_not_called()

    def test_private_receipt_cannot_count_as_public_acceptance(self):
        self.harness();self.proof['browser']=config()['private_windows']
        with self.assertRaisesRegex(cutover.Refused,'Independent public browser'):
            cutover.accept(CASE,PLAN_SHA,self.review)
        cutover.run.assert_not_called()

    def test_pending_failed_public_result_cannot_enable_or_disable(self):
        self.harness()
        cutover.read_artifact.side_effect=lambda item:self.proof if item==self.review else {**browser(public=True),'passed':False}
        with self.assertRaises(cutover.Refused):cutover.accept(CASE,PLAN_SHA,self.review)
        cutover.run.assert_not_called()

    def test_loopback_result_cannot_be_wrapped_as_public_acceptance(self):
        self.harness()
        cutover.read_artifact.side_effect=lambda item:self.proof if item==self.review else browser()
        with self.assertRaisesRegex(cutover.Refused,'browser origin'):cutover.accept(CASE,PLAN_SHA,self.review)
        cutover.run.assert_not_called()

    def test_enable_failure_rolls_back_with_old_enable_retained(self):
        self.harness();cutover.run.side_effect=cutover.Refused('enable failed')
        with self.assertRaisesRegex(cutover.Refused,'rollback confirmed'):
            cutover.accept(CASE,PLAN_SHA,self.review)
        cutover.rollback_actions.assert_called_once()
        self.assertFalse(self.old_disabled)


class RollbackTests(Inert):
    def harness(self):
        self.events=[];self.now=100
        self.state={'schema':1,'new_changed':True,'plan_sha256':PLAN_SHA}
        self.current_plan=plan()
        patch.object(cutover,'load_case',return_value=(config(),self.current_plan)).start()
        patch.object(cutover,'replace',side_effect=lambda p,raw,*a:self.events.append('close-route' if raw==cutover.CLOSED else 'replace')).start()
        patch.object(cutover,'reload_nginx',side_effect=lambda:self.events.append('nginx-test-reload')).start()
        patch.object(cutover,'public_status',side_effect=lambda base,**kw:self.events.append('public-status') or 503).start()
        patch.object(cutover,'service',return_value={'ActiveState':'active','SubState':'running','MainPID':'1'}).start()
        patch.object(cutover.host,'private_json',return_value={'container_id':PUBLIC_CID,'run_id':PUBLIC_RUN,'image_id':IMAGE}).start()
        patch.object(cutover.host,'owned',return_value={'State':{'Running':True}}).start()
        patch.object(cutover,'no_sessions',side_effect=lambda cid:self.events.append('session-census')).start()
        patch.object(cutover,'run',side_effect=lambda argv,**kw:self.events.append('command:'+argv[1])).start()
        patch.object(cutover,'progress',side_effect=lambda *a:self.events.append('progress')).start()
        patch.object(cutover,'json_new').start()
        patch.object(cutover.host,'unpublish',side_effect=AssertionError('Must preserve live readiness')).start()

    def test_active_desktop_after_route_close_refuses_stop(self):
        self.harness()
        def sessions(cid):
            self.events.append('session-census')
            raise cutover.Refused('Active desktop remains')
        cutover.no_sessions.side_effect=sessions
        with self.assertRaisesRegex(cutover.Refused,'Active desktop'):
            cutover.rollback_actions(CASE,config(),self.current_plan,self.state)
        self.assertEqual(self.events,['close-route','nginx-test-reload','public-status','session-census'])
        cutover.run.assert_not_called()
        cutover.host.unpublish.assert_not_called()

    def test_uncertainty_containment_closes_only_nginx_preserving_sessions(self):
        self.harness();cutover.contain(CASE,self.state)
        self.assertEqual(self.events,['close-route','nginx-test-reload','public-status','progress'])
        cutover.run.assert_not_called()
        cutover.host.unpublish.assert_not_called()
        cutover.no_sessions.assert_not_called()
        self.assertNotIn('containment_unconfirmed',self.state)

    def test_foreign_nginx_cannot_be_overwritten_by_containment(self):
        self.harness();cutover.replace.side_effect=cutover.Refused('Foreign route')
        cutover.contain(CASE,self.state)
        self.assertIs(self.state['containment_unconfirmed'],True)
        cutover.reload_nginx.assert_not_called()
        cutover.run.assert_not_called()
        cutover.host.unpublish.assert_not_called()

    def test_rollback_fresh_legacy_start_waits_full_65_seconds_and_native_gate(self):
        self.harness()
        cutover.service.side_effect=lambda unit:({'ActiveState':'inactive','SubState':'dead','MainPID':'0'}
            if self.now<165 else {'ActiveState':'active','SubState':'running','MainPID':'1'})
        cutover.public_status.side_effect=[503,200]
        patch.object(cutover,'stopped').start()
        patch.object(cutover.host,'directory',return_value=(1,3)).start()
        patch.object(cutover,'restore_file').start()
        patch.object(cutover.os.path,'lexists',side_effect=lambda p:str(p)==config()['legacy_ready_path']).start()
        patch.object(cutover,'legacy',return_value={}).start()
        patch.object(cutover.time,'time',side_effect=lambda:self.now).start()
        patch.object(cutover.time,'monotonic',side_effect=lambda:self.now).start()
        patch.object(cutover.time,'sleep',side_effect=lambda seconds:setattr(self,'now',self.now+seconds)).start()
        patch.object(cutover.host,'authentication_ready',return_value=True).start()
        cutover.rollback_actions(CASE,config(),self.current_plan,self.state)
        self.assertEqual(self.now,165)
        cutover.host.authentication_ready.assert_called_once_with(10079,[{'name':'username','type':'USERNAME'}])


if __name__=='__main__':unittest.main()
