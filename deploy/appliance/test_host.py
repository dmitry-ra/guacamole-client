"""Host-inert launcher tests: all engine, service and network actions are mocked."""
import json
import io
import os
from pathlib import Path
import signal
import stat
import subprocess
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest
import urllib.error
from unittest.mock import patch

import host
import catalog
import network

CID = 'c' * 64
RUN = 'a' * 32
IMAGE = 'sha256:' + 'b' * 64


def release():
    return dict(schema=1, image_id=IMAGE, config_sha256='d'*64, network_sha256='e'*64,
                acceptance_evidence_path='/var/lib/portal-acceptance/accepted.json',
                acceptance_evidence_sha256='f'*64, backend_loopback_port=10080,
                podman_network='portal-test', apparmor_profile='portal-test',
                apparmor_profile_path='/etc/apparmor.d/portal-test', apparmor_profile_sha256='1'*64)


def config():
    return network.parse_config(dict(schema_version=1, bridge='portalb0',
        subnet_ipv4='192.0.2.0/29', source_ipv4='192.0.2.2', gateway_ipv4='192.0.2.1',
        forward_interface='uplink0', snat_ipv4='198.51.100.1', host_backend_port=8080,
        local_endpoints=[]))


def record():
    return dict(schema=1, run_id=RUN, image_id=IMAGE, phase='starting', container_id=CID)


def inspected(running=True):
    return dict(Id=CID, Image=IMAGE, Name=host.NAME,
                Config={'Labels': {host.LABEL: '1', host.LABEL+'.run': RUN}},
                State={'Running': running})


def result(value=b'', code=0):
    return SimpleNamespace(stdout=value, stderr=b'', returncode=code)


class InertTests(unittest.TestCase):
    def setUp(self):
        self.engine = patch.object(host, 'engine', side_effect=AssertionError('Unexpected engine call')).start()
        self.command = patch.object(host, 'command', side_effect=AssertionError('Unexpected host call')).start()
        self.addCleanup(patch.stopall)
        self.addCleanup(setattr, host, 'DEADLINE', None)
        self.addCleanup(setattr, host, 'STOP', False)


class ConfigurationTests(InertTests):
    def test_mixed_ssh_requires_exact_gateway_local_tuple_no_public_ssh_egress(self):
        from dataclasses import replace
        from test_catalog import mixed_configuration
        value=mixed_configuration();ssh=value['targets']['terminal-c']
        ssh['hostname']='192.0.2.1';ssh['host_key']=ssh['host_key'].replace('192.0.2.30','192.0.2.1')
        registry=catalog.parse(value)
        with self.assertRaises(ValueError):network.policy(config(),registry)
        cfg=replace(config(),local_endpoints=(('192.0.2.1',10222),))
        derived=network.policy(cfg,registry)
        self.assertEqual(derived['endpoints'],[['192.0.2.1',10222],['192.0.2.10',3389],['192.0.2.20',3389]])
        self.assertEqual(derived['forwarded'],[['192.0.2.10',3389],['192.0.2.20',3389]])
        with self.assertRaises(ValueError):network.policy(replace(cfg,local_endpoints=(('192.0.2.1',22),)),registry)

    def test_protocol_specific_secret_bounds_use_metadata_only(self):
        info=SimpleNamespace(st_mode=stat.S_IFREG|0o600,st_uid=0,st_nlink=1,st_size=16384)
        with patch.object(Path,'lstat',return_value=info),patch.object(Path,'read_bytes',side_effect=AssertionError('No secret reads')):
            host.validate_secret_metadata(Path('/external'),{'terminal-key':16384})
            with self.assertRaises(RuntimeError):host.validate_secret_metadata(Path('/external'),{'rdp-password':512})
            for field,value in [('st_size',16385),('st_size',0),('st_uid',1000),('st_nlink',2),
                                ('st_mode',stat.S_IFLNK|0o600),('st_mode',stat.S_IFREG|0o644)]:
                changed=SimpleNamespace(**vars(info));setattr(changed,field,value)
                with self.subTest(field=field),patch.object(Path,'lstat',return_value=changed),self.assertRaises(RuntimeError):
                    host.validate_secret_metadata(Path('/external'),{'terminal-key':16384})

    def test_release_strict_identity_and_external_paths(self):
        self.assertEqual(host.parse_release(release()), release())
        cases = [('schema', True), ('image_id', 'latest'), ('config_sha256', 'A'*64),
                 ('network_sha256', None), ('backend_loopback_port', True),
                 ('podman_network', 'host'), ('apparmor_profile', 'unconfined'),
                 ('apparmor_profile_path', '/tmp/profile'),
                 ('acceptance_evidence_path', '../accepted.json')]
        for key, value in cases:
            with self.subTest(key=key), self.assertRaises((ValueError, TypeError)):
                host.parse_release({**release(), key: value})
        with self.assertRaises(ValueError): host.parse_release({**release(), 'targets': []})
        with self.assertRaises(ValueError): host.parse_release({k:v for k,v in release().items() if k != 'acceptance_evidence_sha256'})

    def test_argv_resources_external_network_and_mounts(self):
        args = host.container_args(release(), config(), RUN)
        for expected in ('--memory=2g', '--memory-swap=2g', '--cpus=2', '--pids-limit=384',
                         '--cap-drop=all', '--read-only', '--security-opt=no-new-privileges',
                         '--security-opt=apparmor=portal-test', '--network=portal-test',
                         '--ip=192.0.2.2', '--publish=127.0.0.1:10080:8080', '--pull=never',
                         '--label=guacamole.portal.run='+RUN):
            self.assertIn(expected, args)
        caps = [arg for arg in args if arg.startswith('--cap-add=')]
        self.assertEqual(set(caps), {'--cap-add='+cap for cap in
            ('SETUID', 'SETGID', 'CHOWN', 'DAC_OVERRIDE', 'FOWNER', 'KILL')})
        self.assertEqual(args[-2:], [IMAGE, 'serve'])
        self.assertIn('--volume=/etc/guacamole-portal:/config:ro', args)
        self.assertIn('--volume=/var/lib/guacamole-portal/secrets:/secrets:ro', args)
        self.assertFalse(any('privileged' in arg or 'unconfined' in arg for arg in args))
        changed = host.container_args({**release(), 'backend_loopback_port': 10081}, config(), RUN)
        self.assertIn('--publish=127.0.0.1:10081:8080', changed)

    def test_file_transfer_mount_is_separate_from_database_and_opt_in(self):
        expected = '--volume=/var/lib/guacamole-portal/transfers:/transfers:rw'
        self.assertNotIn(expected, host.container_args(release(), config(), RUN))
        self.assertIn(expected, host.container_args(release(), config(), RUN, enable_transfer=True))

    def test_engine_rotation_path_is_outside_every_container_writable_mount(self):
        args = host.container_args(release(), config(), RUN)
        prefix = '--log-opt=path='
        engine_log = Path(next(arg[len(prefix):] for arg in args if arg.startswith(prefix)))
        self.assertEqual(engine_log.parent, host.STATE/('engine-logs-'+RUN))
        writable = []
        for arg in args:
            if arg.startswith('--volume='):
                source, target, mode = arg[len('--volume='):].split(':')
                if mode == 'rw':
                    writable.append(Path(source))
        self.assertGreaterEqual(len(writable), 2)
        for source in writable:
            self.assertNotEqual(engine_log, source)
            self.assertNotIn(source, engine_log.parents)
            self.assertNotEqual(engine_log.parent, source)
        self.assertIn('--volume='+str(host.STATE/('logs-'+RUN))+':/run/web-rdp/diagnostics:rw', args)

    def test_non_image_internal_port_rejected_before_container_creation(self):
        cfg = config()
        for port in (8081, True):
            changed = SimpleNamespace(**{**vars(cfg), 'host_backend_port': port})
            with self.assertRaisesRegex(ValueError, 'internal HTTP port 8080'):
                host.container_args(release(), changed, RUN)
        self.command.assert_not_called()

    def test_directory_rejects_writable_ancestry_and_symlinks(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(RuntimeError): host.directory(Path(tmp))
        with self.assertRaises(ValueError): host.directory(Path('relative'))
        with self.assertRaises(ValueError): host.directory(Path('/etc/../etc'))

    def test_pinned_evidence_hash_checked_before_data_or_credentials(self):
        config_raw = (Path(__file__).parent/'examples/config.json').read_bytes()
        cfg = dict(schema_version=1, bridge='portalb0', subnet_ipv4='198.51.100.0/29',
            source_ipv4='198.51.100.2', gateway_ipv4='198.51.100.1', forward_interface='uplink0',
            snat_ipv4='203.0.113.1', host_backend_port=8080, local_endpoints=[])
        network_raw = json.dumps(cfg).encode()
        chosen = {**release(), 'config_sha256': host.sha(config_raw), 'network_sha256': host.sha(network_raw)}
        raw = json.dumps(chosen).encode()
        def protected(path):
            if path == host.RELEASE: return raw
            if path == host.CONFIG: return config_raw
            if path == host.NETWORK: return network_raw
            return b'changed'
        with patch.object(host.network, 'protected_read', side_effect=protected) as read, self.assertRaisesRegex(RuntimeError, 'Reviewed release input'):
            host.selection()
        self.assertEqual(read.call_args.args[0], Path(chosen['acceptance_evidence_path']))
        self.engine.assert_not_called()

    def test_network_cli_uses_fixed_paths_and_actions(self):
        self.command.side_effect = None
        host.network_command('check')
        self.assertEqual(self.command.call_args.args[0], ['/usr/bin/python3', '-B',
            host.ROOT/'network.py', 'check', '--config', host.NETWORK, '--catalog', host.CONFIG])

    def test_bootstrap_cli_uses_fixed_boot_action_and_bound(self):
        self.command.side_effect = None
        host.network_bootstrap()
        self.command.assert_called_once_with(['/usr/bin/python3', '-B',
            host.ROOT/'network_service.py', 'boot'], timeout=90)

    def test_directory_final_and_parent_symlinks_rejected(self):
        original = os.fstat
        def root_metadata(fd):
            info = original(fd)
            return SimpleNamespace(st_uid=0, st_gid=0, st_mode=info.st_mode & ~0o022,
                                   st_dev=info.st_dev, st_ino=info.st_ino)
        with tempfile.TemporaryDirectory() as tmp, patch.object(host.os, 'fstat', side_effect=root_metadata):
            root = Path(tmp); (root/'real').mkdir()
            (root/'link').symlink_to(root/'real', target_is_directory=True)
            for path in (root/'link', root/'link/child'):
                with self.assertRaises(OSError): host.directory(path)

    def test_public_directory_creation_survives_private_umask(self):
        original = os.fstat
        def root_metadata(fd):
            info = original(fd)
            return SimpleNamespace(st_uid=0, st_gid=0, st_mode=info.st_mode & ~0o022,
                                   st_dev=info.st_dev, st_ino=info.st_ino)
        with tempfile.TemporaryDirectory() as tmp, patch.object(host.os, 'fstat', side_effect=root_metadata):
            public = Path(tmp)/'public'
            old_umask = os.umask(0o077)
            try: host.directory(public, mode=0o755, create=True)
            finally: os.umask(old_umask)
            self.assertEqual(stat.S_IMODE(public.stat().st_mode), 0o755)

    def test_bridge_rejects_foreign_settings_before_member_query(self):
        cfg = config()
        bridge = dict(name='portal-test', driver='bridge', network_interface=cfg.bridge,
                      labels={host.LABEL:'1'}, subnets=[{'subnet':cfg.subnet_ipv4, 'gateway':cfg.gateway_ipv4}],
                      ipv6_enabled=False, internal=False, dns_enabled=False)
        for key, value in [('network_interface', 'foreign0'), ('dns_enabled', True),
                           ('labels', {}), ('subnets', [])]:
            self.engine.side_effect = None
            self.engine.return_value = result(json.dumps([{**bridge, key:value}]).encode())
            with patch.object(Path, 'read_text', return_value='portal-test (enforce)\n'), self.assertRaises(RuntimeError):
                host.guards(release(), cfg)
        self.assertTrue(all(call.args[:2] == ('network', 'inspect') for call in self.engine.call_args_list))


class OwnershipTests(InertTests):
    def test_foreign_labels_image_name_and_cid_rejected(self):
        variants = []
        for key, value in [('Id', 'd'*64), ('Image', 'sha256:'+'d'*64), ('Name', 'foreign')]:
            item = inspected(); item[key] = value; variants.append(item)
        item = inspected(); item['Config']['Labels'][host.LABEL+'.run'] = 'd'*32; variants.append(item)
        item = inspected(); item['Config']['Labels'] = {}; variants.append(item)
        for item in variants:
            self.engine.side_effect = None; self.engine.return_value = result(json.dumps([item]).encode())
            with self.assertRaises(RuntimeError): host.owned(record(), CID)
        self.assertTrue(all(call.args[0] == 'inspect' for call in self.engine.call_args_list))

    def test_unknown_inspection_does_not_mean_absent(self):
        self.engine.side_effect = [result(code=125), result(code=125)]
        with self.assertRaises(RuntimeError): host.owned(record(), CID)
        self.engine.side_effect = [result(code=125), result(code=1)]
        self.assertIsNone(host.owned(record(), CID))

    def test_bare_full_inspected_image_is_same_immutable_image(self):
        item = inspected(); item['Image'] = IMAGE.removeprefix('sha256:')
        self.engine.side_effect = None; self.engine.return_value = result(json.dumps([item]).encode())
        self.assertEqual(host.owned(record(), CID)['Id'], CID)

    def test_uncertain_creation_fresh_query_pins_exact_cid(self):
        pending = {k:v for k,v in record().items() if k != 'container_id'}
        self.engine.side_effect = [result((CID+'\n').encode()), result(json.dumps([inspected()]).encode())]
        with patch.object(host, 'write') as write:
            self.assertEqual(host.reconcile(pending), CID)
            self.assertEqual(pending['container_id'], CID)
            write.assert_called_once()
        self.assertFalse(any(call.args[0] == 'run' for call in self.engine.call_args_list))

    def test_uncertain_creation_absent_or_ambiguous_never_runs(self):
        pending = {k:v for k,v in record().items() if k != 'container_id'}
        self.engine.side_effect = None; self.engine.return_value = result()
        self.assertIsNone(host.reconcile(pending))
        self.engine.return_value = result((CID+'\n'+'d'*64+'\n').encode())
        with self.assertRaises(RuntimeError): host.reconcile(pending)
        self.assertTrue(all(call.args[0] == 'ps' for call in self.engine.call_args_list))

    def test_cutoff_foreign_inspection_never_stops_container(self):
        self.engine.side_effect = None; self.engine.return_value = result()
        with patch.object(host, 'unpublish'), patch.object(host, 'write'), \
             patch.object(host, 'reconcile', return_value=CID), \
             patch.object(host, 'owned', side_effect=RuntimeError('foreign')):
            with self.assertRaises(RuntimeError): host.cutoff(record())
        self.engine.assert_not_called()

    def test_shutdown_timeout_rechecks_owner_before_pinned_kill(self):
        self.engine.side_effect = [subprocess.TimeoutExpired('podman', 14), result(), result()]
        with patch.object(host, 'unpublish'), patch.object(host, 'write') as write, \
             patch.object(host, 'reconcile', return_value=CID), \
             patch.object(host, 'owned', side_effect=[inspected(), inspected(), inspected(False), None]):
            host.cutoff(record())
            self.assertEqual(write.call_args.args[1]['phase'], 'stopped')
        self.assertEqual([call.args for call in self.engine.call_args_list],
                         [('stop', '--time=10', CID), ('kill', '--signal=KILL', CID), ('rm', CID)])

    def test_marker_failure_still_stops_own_container(self):
        self.engine.side_effect = None
        with patch.object(host, 'unpublish', side_effect=RuntimeError('foreign marker')), \
             patch.object(host, 'write'), patch.object(host, 'reconcile', return_value=None):
            with self.assertRaises(RuntimeError): host.cutoff(record())

    def test_uncertain_creation_absence_retains_unresolved_never_records_stopped(self):
        pending = {k:v for k,v in record().items() if k != 'container_id'}
        pending['creation_uncertain'] = True
        with patch.object(host, 'unpublish'), patch.object(host, 'write') as write, \
             patch.object(host, 'reconcile', return_value=None):
            with self.assertRaisesRegex(RuntimeError, 'Uncertain creation'): host.cutoff(pending)
        self.assertEqual(pending['phase'], 'unresolved_creation')
        self.assertTrue(all(call.args[0] == host.STATE/'current.json' for call in write.call_args_list))
        self.engine.assert_not_called()


class MarkerTests(InertTests):
    def setUp(self):
        super().setUp()
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        patch.object(host, 'PUBLIC', Path(self.temp.name)).start()
        patch.object(host, 'directory').start()
        patch.object(host.network, 'protected_read', side_effect=lambda p: Path(p).read_bytes()).start()

    def test_marker_is_private_and_owned_cleanup_only(self):
        host.publish(RUN)
        marker = host.PUBLIC/'ready'
        self.assertEqual(stat.S_IMODE(marker.stat().st_mode), 0o600)
        info = marker.lstat()
        root_info = SimpleNamespace(st_uid=0, st_nlink=info.st_nlink, st_mode=info.st_mode)
        with patch.object(Path, 'lstat', return_value=root_info):
            with self.assertRaises(RuntimeError): host.unpublish('d'*32)
            self.assertTrue(marker.exists())
            host.unpublish(RUN)
        self.assertFalse(marker.exists())

    def test_symlink_marker_never_followed_or_deleted(self):
        target = host.PUBLIC/'target'; target.write_bytes(host.marker(RUN))
        (host.PUBLIC/'ready').symlink_to(target)
        with self.assertRaises(RuntimeError): host.unpublish(RUN)
        self.assertTrue((host.PUBLIC/'ready').is_symlink())
        with self.assertRaises(FileExistsError): host.publish(RUN)


class LifecycleTests(InertTests):
    def harness(self, health, gate=True):
        patch.object(host.catalog, 'load', return_value=SimpleNamespace(targets=[])).start()
        self.now = 0
        self.published = []
        def sleep(seconds): self.now += seconds
        self.engine.side_effect = lambda *args, **kw: (
            result(json.dumps([{'Id': IMAGE, 'Architecture': 'amd64'}]).encode())
            if args[:2] == ('image', 'inspect') else result(code=1))
        self.command.side_effect = None; self.command.return_value = result(CID.encode())
        self.binding = ('binding', None, None, None, [{'name':'username', 'type':'USERNAME'}])
        patch.object(host, 'selection', return_value=(release(), config(), self.binding)).start()
        patch.object(host, 'guards', return_value=[CID]).start()
        patch.object(host, 'network_command').start()
        patch.object(host, 'network_bootstrap').start()
        patch.object(host, 'directory').start()
        patch.object(host, 'owned', return_value=inspected()).start()
        patch.object(host, 'health', side_effect=health).start()
        patch.object(host, 'authentication_ready', return_value=gate).start()
        patch.object(host, 'write').start()
        patch.object(host, 'notify_ready').start()
        patch.object(host, 'publish', side_effect=lambda run: self.published.append(self.now)).start()
        patch.object(host, 'ready_owned', return_value=True).start()
        patch.object(host, 'cutoff').start()
        patch.object(host.time, 'monotonic', side_effect=lambda: self.now).start()
        patch.object(host.time, 'sleep', side_effect=sleep).start()
        patch.object(host.socket, 'socket').start()
        patch.object(host.secrets, 'token_hex', return_value=RUN).start()
        patch.object(host.os.path, 'lexists', return_value=False).start()
        patch.object(Path, 'exists', return_value=False).start()

    def test_healthy_gate_waits_65_seconds_and_health_loss_cuts_off(self):
        self.harness(lambda cid: self.now < 66)
        with self.assertRaises(RuntimeError): host.run()
        self.assertEqual(self.published, [65])
        host.network_bootstrap.assert_called_once_with()
        host.cutoff.assert_called_once()
        self.assertEqual(host.cutoff.call_args.args[0]['container_id'], CID)

    def test_unhealthy_startup_bounded_no_ready(self):
        self.harness(lambda cid: False)
        with self.assertRaises(RuntimeError): host.run()
        self.assertEqual(self.now, 120)
        self.assertEqual(self.published, [])
        host.cutoff.assert_called_once()

    def test_authentication_hold_cannot_be_bypassed_by_health(self):
        self.harness(lambda cid: True, gate=False)
        with self.assertRaises(RuntimeError): host.run()
        self.assertEqual(self.published, [])
        self.assertEqual(self.now, 120)

    def test_uncertain_run_creation_is_not_replayed(self):
        self.harness(lambda cid: True)
        self.command.side_effect = subprocess.TimeoutExpired('podman', 15)
        with self.assertRaises(subprocess.TimeoutExpired): host.run()
        self.command.assert_called_once()
        host.cutoff.assert_called_once()
        self.assertNotIn('container_id', host.cutoff.call_args.args[0])

    def test_lost_ready_marker_stops_own_container(self):
        self.harness(lambda cid: True)
        host.ready_owned.return_value = False
        with self.assertRaisesRegex(RuntimeError, 'Readiness marker lost'): host.run()
        self.assertEqual(self.published, [65])
        host.cutoff.assert_called_once()

    def test_release_change_after_ready_closes_container(self):
        self.harness(lambda cid: True)
        chosen = (release(), config(), self.binding)
        host.selection.side_effect = lambda: chosen if self.now < 66 else (release(), config(), ('changed',))
        with self.assertRaises(RuntimeError): host.run()
        self.assertEqual(self.published, [65])
        host.cutoff.assert_called_once()

    def test_restart_cutoff_precedes_bootstrap_and_bridge_guard(self):
        self.harness(lambda cid: True)
        events = []
        bridge = {'exists': True}
        old_record = {**record(), 'run_id':'d'*32}
        patch.object(Path, 'exists', return_value=True).start()
        patch.object(host, 'private_json', return_value=old_record).start()
        def cutoff(value):
            events.append('cutoff-old' if value is old_record else 'cutoff-current')
            bridge['exists'] = False
        def bootstrap():
            self.assertEqual(events, ['cutoff-old'])
            self.assertFalse(bridge['exists'])
            bridge['exists'] = True; events.append('bootstrap')
        def guards(*args, **kwargs):
            self.assertTrue(kwargs.get('empty'))
            self.assertTrue(bridge['exists']); events.append('guard-empty')
            return []
        def create(*args, **kwargs):
            self.assertEqual(events[:3], ['cutoff-old', 'bootstrap', 'guard-empty'])
            events.append('create'); host.STOP = True
            return result(CID.encode())
        host.cutoff.side_effect = cutoff
        host.network_bootstrap.side_effect = bootstrap
        host.guards.side_effect = guards
        self.command.side_effect = create
        host.run()
        self.assertEqual(events, ['cutoff-old', 'bootstrap', 'guard-empty', 'create', 'cutoff-current'])
        host.network_bootstrap.assert_called_once_with()

    def test_failed_bootstrap_after_cutoff_refuses_guards_and_container_create(self):
        self.harness(lambda cid: True)
        old_record = {**record(), 'run_id':'d'*32}
        patch.object(Path, 'exists', return_value=True).start()
        patch.object(host, 'private_json', return_value=old_record).start()
        def bootstrap():
            host.cutoff.assert_called_once_with(old_record)
            raise RuntimeError('Bootstrap prerequisites failed')
        host.network_bootstrap.side_effect = bootstrap
        with self.assertRaisesRegex(RuntimeError, 'Bootstrap prerequisites failed'): host.run()
        host.guards.assert_not_called()
        host.network_command.assert_not_called()
        self.command.assert_not_called()
        host.write.assert_not_called()

    def test_bootstrap_time_counts_in_total_startup_budget(self):
        self.harness(lambda cid: True)
        host.network_bootstrap.side_effect = lambda: setattr(self, 'now', 55)
        with self.assertRaisesRegex(RuntimeError, 'Startup deadline exceeded'): host.run()
        self.assertEqual(self.now, 120)
        self.assertEqual(self.published, [])
        host.cutoff.assert_called_once()

    def test_requested_stop_does_not_mask_cutoff_ownership_failure(self):
        def healthy_then_stop(cid):
            host.STOP = True
            return True
        self.harness(healthy_then_stop)
        host.cutoff.side_effect = RuntimeError('Foreign cleanup ownership')
        with self.assertRaisesRegex(RuntimeError,'Foreign cleanup ownership'):host.run()
        host.cutoff.assert_called_once()


class SignalLifecycleTests(unittest.TestCase):
    """Real signals target only a newly created owned Python process group.

    The helper executes the unchanged host.command, with a synthetic Python
    child replacing Podman. It reproduces the systemd signal boundary, not
    actual container shutdown. No service, engine or network command is run.
    """
    def stop_inflight(self, mode, child_exit=0):
        with tempfile.TemporaryDirectory(prefix='portal-stop-test-') as temporary:
            root=Path(temporary)
            child_source='''import os,pathlib,sys,time
root=pathlib.Path(sys.argv[1]);(root/'child').write_text(str(os.getpid()))
deadline=time.monotonic()+5
while not (root/'release').exists():
 if time.monotonic()>=deadline:sys.exit(8)
 time.sleep(.005)
sys.exit(int(sys.argv[2]))
'''
            helper_source='''import json,pathlib,signal,sys
sys.path.insert(0,sys.argv[1]);import host
root=pathlib.Path(sys.argv[2])
def stop(signum,frame):
 host.STOP=True;(root/'signaled').write_text('yes')
signal.signal(signal.SIGTERM,stop)
out={'outcome':'success'}
try:host.command([sys.executable,'-B','-c',sys.argv[3],str(root),sys.argv[4]],timeout=6)
except RuntimeError:out={'outcome':'failure','error_type':'RuntimeError'}
finally:
 out['stop_requested']=host.STOP;out['cleanup_reached']=True
 print(json.dumps(out),flush=True)
sys.exit(0 if out['outcome']=='success' else 1)
'''
            process=subprocess.Popen([sys.executable,'-B','-c',helper_source,str(Path(__file__).parent),
                str(root),child_source,str(child_exit)],start_new_session=True,
                stdout=subprocess.PIPE,stderr=subprocess.PIPE)
            child_pid=None
            try:
                deadline=time.monotonic()+3
                while not (root/'child').exists():
                    self.assertIsNone(process.poll(),'Synthetic supervisor exited before its child')
                    self.assertLess(time.monotonic(),deadline,'Synthetic child startup timed out')
                    time.sleep(.005)
                child_pid=int((root/'child').read_text())
                self.assertEqual(os.getpgid(child_pid),process.pid)
                if mode=='control-group':os.killpg(process.pid,signal.SIGTERM)
                elif mode=='mixed':os.kill(process.pid,signal.SIGTERM)
                else:self.fail('Unknown synthetic unit stop mode')
                deadline=time.monotonic()+3
                while not (root/'signaled').exists():
                    self.assertLess(time.monotonic(),deadline,'Supervisor stop signal not observed')
                    time.sleep(.005)
                (root/'release').write_text('yes')
                stdout,stderr=process.communicate(timeout=4)
                self.assertEqual(stderr,b'')
                with self.assertRaises(ProcessLookupError):os.kill(child_pid,0)
                return process.returncode,json.loads(stdout)
            finally:
                if process.poll() is None:
                    os.killpg(process.pid,signal.SIGKILL);process.communicate(timeout=3)
                if child_pid:
                    try:
                        if os.getpgid(child_pid)==process.pid:os.kill(child_pid,signal.SIGKILL)
                    except ProcessLookupError:pass

    def test_group_term_reproduces_command_failure_despite_stop_and_cleanup(self):
        code,value=self.stop_inflight('control-group')
        self.assertEqual(code,1)
        self.assertEqual(value,{'outcome':'failure','error_type':'RuntimeError',
                               'stop_requested':True,'cleanup_reached':True})

    def test_installed_unit_stop_mode_preserves_inflight_command(self):
        unit=(Path(__file__).parent/'guacamole-portal.service').read_text()
        mode=next(line.split('=',1)[1] for line in unit.splitlines() if line.startswith('KillMode='))
        self.assertEqual(mode,'mixed')
        code,value=self.stop_inflight(mode)
        self.assertEqual(code,0)
        self.assertEqual(value,{'outcome':'success','stop_requested':True,'cleanup_reached':True})

    def test_main_only_term_does_not_hide_genuine_child_failure(self):
        code,value=self.stop_inflight('mixed',child_exit=7)
        self.assertEqual(code,1)
        self.assertEqual(value['error_type'],'RuntimeError')
        self.assertIs(value['stop_requested'],True)
        self.assertIs(value['cleanup_reached'],True)


class HealthTests(InertTests):
    def test_native_component_status_requires_exact_true(self):
        cases = [dict(database_ready=True, web_ready=True, enrolled=True),
                 dict(database_ready=True, web_ready=True, enrolled=1),
                 dict(database_ready=True, web_ready=False, enrolled=True), {}]
        with patch.object(host, 'write') as write:
            self.engine.side_effect = None
            for value in cases:
                self.engine.return_value = result(json.dumps(value).encode())
                self.assertEqual(host.health(CID), value == cases[0] and type(value.get('enrolled')) is bool)
                self.assertEqual(set(write.call_args.args[1]['components']), set(host.COMPONENTS))

    def test_native_timeout_records_no_raw_output(self):
        self.engine.side_effect = subprocess.TimeoutExpired('podman', 4, output=b'secret')
        with patch.object(host, 'write') as write:
            self.assertFalse(host.health(CID))
            self.assertNotIn('secret', json.dumps(write.call_args.args[1]))
            self.assertEqual(write.call_args.args[1]['error_type'], 'TimeoutExpired')


class AuthenticationTests(InertTests):
    def registry(self, publish):
        value = json.loads((Path(__file__).parent/'examples/config.json').read_bytes())
        value['portal']['publish_target_labels'] = publish
        return catalog.parse(value)

    def probe(self, fields, expected, code=403):
        response = urllib.error.HTTPError('http://127.0.0.1/', code, 'fixture', {},
            io.BytesIO(json.dumps({'expected':fields}).encode()))
        opener = SimpleNamespace(open=lambda *a, **kw: (_ for _ in ()).throw(response))
        with patch.object(host.urllib.request, 'build_opener', return_value=opener):
            return host.authentication_ready(10080, expected)

    def test_username_only_matches_unpublished_catalog(self):
        expected = host.authentication_fields(self.registry(False))
        self.assertEqual(expected, [{'name':'username', 'type':'USERNAME'}])
        self.assertTrue(self.probe(expected, expected))
        published = host.authentication_fields(self.registry(True))
        self.assertFalse(self.probe(published, expected))

    def test_native_optional_target_form_matches_exact_published_aliases(self):
        expected = host.authentication_fields(self.registry(True))
        self.assertEqual(expected, [{'name':'username', 'type':'USERNAME'},
            {'name':'wrdp-target', 'type':'ENUM', 'options':['desktop-a', 'desktop-b']}])
        self.assertTrue(self.probe(expected, expected))
        self.assertFalse(self.probe(expected[:1], expected))

    def test_password_extra_field_wrong_type_and_changed_aliases_rejected(self):
        expected = host.authentication_fields(self.registry(True))
        wrong = [expected + [{'name':'password', 'type':'PASSWORD'}],
                 expected + [{'name':'unexpected', 'type':'TEXT'}],
                 [{'name':'username', 'type':'PASSWORD'}, expected[1]],
                 [expected[0], {'name':'wrdp-target', 'type':'ENUM', 'options':['foreign']}],
                 [expected[0], {'name':'wrdp-target', 'type':'ENUM', 'options':['desktop-b', 'desktop-a']}]]
        for fields in wrong:
            with self.subTest(fields=fields): self.assertFalse(self.probe(fields, expected))

    def test_anonymous_success_and_wrong_http_status_rejected(self):
        expected = host.authentication_fields(self.registry(True))
        self.assertFalse(self.probe(expected, expected, code=401))
        response = io.BytesIO(json.dumps({'expected':expected}).encode())
        opener = SimpleNamespace(open=lambda *a, **kw: response)
        with patch.object(host.urllib.request, 'build_opener', return_value=opener):
            self.assertFalse(host.authentication_ready(10080, expected))


if __name__ == '__main__': unittest.main()
