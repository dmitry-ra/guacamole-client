"""Inert controller boundaries; process, engine and HTTP operations are mocked."""
from copy import deepcopy
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import current_backup_window as window

REAL_BACKUP = window.backup
REAL_LOAD_CASE = window.load_case


def config():
    return {'schema': 1, 'snippet_path': '/etc/nginx/snippets/synthetic-portal.conf',
            'public_base': 'https://portal.example.invalid/desktop/app/', 'legacy_unit': 'legacy-portal.service'}


def record():
    return {'container_id': 'a'*64, 'run_id': 'b'*32, 'image_id': 'sha256:'+'c'*64,
            'release_sha256': 'd'*64, 'phase': 'ready', 'ready_at': 900}


def plan():
    return {'schema': 1, 'phase': 'staged', 'snapshot': {'record': record(), 'binding': {
        'release': {'backend_loopback_port': 10080}, 'authentication_fields': [{'name': 'username', 'type': 'USERNAME'}]}},
        'files': {'original-snippet.conf': window.host.sha(b'original-route')}, 'at': 900}


class PureTests(unittest.TestCase):
    def test_strict_configuration_cannot_select_other_mutation_targets(self):
        self.assertEqual(window.parse_config(config()), config())
        for field, value in [('schema', True), ('legacy_unit', window.pc.NEW_UNIT),
                             ('legacy_unit', 'bad;name.service'), ('snippet_path', '/etc/passwd'),
                             ('public_base', 'http://portal.example.invalid/desktop/app/'),
                             ('public_base', 'https://user:secret@portal.example.invalid/desktop/app/'),
                             ('public_base', 'https://portal.example.invalid/another/')]:
            with self.subTest(field=field), self.assertRaises((window.pc.Refused, ValueError)):
                window.parse_config({**config(), field: value})
        with self.assertRaises(ValueError):
            window.parse_config({**config(), 'source': '/arbitrary/data'})

    def test_staged_helpers_do_not_replace_operating_source_hash_bindings(self):
        observed = []
        changed = {}
        def read(path):
            observed.append(str(path))
            return changed.get(str(path), str(path).encode())
        with patch.object(window, 'OPERATING_ROOT', Path('/installed')), \
                patch.object(window.host, '__file__', '/installed/host.py'), \
                patch.object(window.catalog, '__file__', '/installed/catalog.py'), \
                patch.object(window.network, '__file__', '/installed/network.py'), \
                patch.object(window.pc, '__file__', '/staged/tools/public_cutover.py'), \
                patch.object(window.cold_copy, '__file__', '/staged/tools/cold_copy.py'), \
                patch.object(window.files, '__file__', '/staged/tools/prepare_instance.py'), \
                patch.object(window.network, 'protected_read', side_effect=read):
            units = {window.pc.NEW_UNIT: {'FragmentPath': '/units/current.service'}}
            original = window.source_hashes(units)
            changed['/installed/network_upgrade.py'] = b'changed policy binding code'
            current = window.source_hashes(units)
        for path in ('/installed/host.py', '/installed/tools/cold_copy.py', '/staged/tools/cold_copy.py',
                     '/installed/network_upgrade.py', '/units/current.service', '/etc/portal-rdp-transport/known_hosts'):
            self.assertIn(path, observed)
        self.assertNotIn('/etc/portal-rdp-transport/identity', observed)
        self.assertNotEqual(original, current)
        with patch.object(window, 'static_binding', return_value={'sources': current}):
            with self.assertRaisesRegex(window.pc.Refused, 'preserved host bindings changed'):
                window.unchanged(config(), {'snapshot': {'binding': {'sources': original}}})

    def test_nginx_scope_hash_ignores_only_owned_snippet_content(self):
        cfg = config()
        prefix = ('# configuration file /etc/nginx/nginx.conf:\nhttp {}\n\n'
                  '# configuration file '+cfg['snippet_path']+':\n').encode()
        suffix = b'\n# configuration file /etc/nginx/conf.d/other.conf:\nother;\n'
        def digest(snippet, other=suffix):
            result = subprocess.CompletedProcess([], 0, prefix+snippet+other, b'')
            with patch.object(window.pc, 'run', return_value=result), \
                    patch.object(window.network, 'protected_read', return_value=snippet):
                return window.nginx_scope(cfg)
        self.assertEqual(digest(b'original-route\n'), digest(window.pc.CLOSED))
        self.assertNotEqual(digest(b'original-route\n'), digest(b'original-route\n', suffix+b'changed'))


@unittest.skipUnless(os.geteuid() == 0, 'Synthetic protected private cases require root')
class WindowTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='portal-backup-window-', dir='/run')
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.case = self.root/'case'
        self.case.mkdir(mode=0o700)
        self.cfg, self.plan = config(), plan()
        self.clock = 1000
        self.current = record()
        self.status = 'active'
        self.route = b'original-route'
        self.loaded = 200
        self.events = []
        self.original_run = None
        def forbidden(*args, **kwargs):
            raise AssertionError('Unexpected actual host/engine/HTTP operation')
        for target, name in ((window.host, 'command'), (window.host, 'engine'),
                             (window.pc.urllib.request, 'build_opener')):
            self.patch(target, name, side_effect=forbidden)
        self.patch(window.signal, 'alarm', return_value=0)
        self.patch(window.time, 'time', side_effect=lambda: self.clock)
        self.patch(window.time, 'monotonic', side_effect=lambda: self.clock)
        self.patch(window.time, 'sleep', side_effect=lambda duration: setattr(self, 'clock', self.clock+duration))
        self.patch(window, 'load_case', return_value=(self.cfg, self.plan))
        self.patch(window, 'snapshot', side_effect=lambda cfg: deepcopy(self.plan['snapshot']))
        self.patch(window, 'unchanged')
        self.patch(window.pc, 'candidate', side_effect=lambda: deepcopy(self.current))
        self.patch(window.pc, 'no_sessions', side_effect=lambda cid: self.events.append(('sessions', cid)))
        self.patch(window.pc, 'service', side_effect=self.service)
        self.patch(window.pc, 'stopped', side_effect=self.stopped)
        self.patch(window.pc, 'run', side_effect=self.command)
        self.patch(window.pc, 'replace', side_effect=self.replace)
        self.patch(window.pc, 'restore_file', side_effect=self.restore_file)
        self.patch(window.pc, 'reload_nginx', side_effect=self.reload)
        self.patch(window.pc, 'wait_public_status', side_effect=self.wait)
        self.patch(window.pc, 'public_status', side_effect=lambda *args, **kwargs: self.loaded)
        protected_read = window.network.protected_read
        self.patch(window.network, 'protected_read', side_effect=lambda path:
                   self.route if Path(path) == Path(self.cfg['snippet_path']) else protected_read(path))
        self.patch(window.cold_copy, 'stopped_and_exclusive')
        self.patch(window.cold_copy, 'validate_cluster')
        self.patch(window.host, 'authentication_ready', return_value=True)
        self.patch(window, 'backup', side_effect=lambda case, record: self.events.append(('backup', record['container_id'])) or {'verified': True})
        self.review = self.root/'review.json'
        self.review.write_text(json.dumps({'schema': 1, 'scope': 'one current backup window',
            'plan_sha256': 'e'*64, 'operator_reference': 'operator:window-1',
            'allow_fixed_original_recovery': True, 'reviewed_at': 999, 'expires_at': 1299}))
        self.review.chmod(0o600)

    def patch(self, target, name, **kwargs):
        mock = patch.object(target, name, **kwargs)
        value = mock.start()
        self.addCleanup(mock.stop)
        return value

    def service(self, unit):
        self.assertEqual(unit, window.pc.NEW_UNIT)
        return {'LoadState': 'loaded', 'ActiveState': self.status,
                'SubState': 'running' if self.status == 'active' else 'dead',
                'MainPID': '50' if self.status == 'active' else '0'}

    def stopped(self, unit, ready):
        window.require(self.status in ('inactive', 'failed'), 'Service is not really stopped')

    def command(self, argv, timeout=10):
        self.events.append(tuple(argv))
        if argv == [window.pc.NGINX, '-t']:
            pass
        elif argv == [window.pc.SYSTEMCTL, 'reload', 'nginx.service']:
            self.reload()
        elif argv == [window.pc.SYSTEMCTL, 'stop', window.pc.NEW_UNIT]:
            self.status = 'inactive'
        elif argv == [window.pc.SYSTEMCTL, 'start', window.pc.NEW_UNIT]:
            self.status = 'active'
            self.clock += 70
            self.current = {**record(), 'container_id': '1'*64, 'run_id': '2'*32, 'ready_at': self.clock}
        else:
            raise AssertionError('Unexpected action target')
        return subprocess.CompletedProcess(argv, 0, b'', b'')

    def replace(self, path, raw, allowed):
        self.assertEqual(path, Path(self.cfg['snippet_path']))
        self.assertIn(window.host.sha(self.route), allowed)
        self.route = raw
        self.events.append(('route', raw == window.pc.CLOSED))

    def restore_file(self, case, name, path, allowed):
        self.assertEqual(name, 'original-snippet.conf')
        self.replace(path, b'original-route', allowed)

    def reload(self):
        self.events.append(('reload',))
        self.loaded = 503 if self.route == window.pc.CLOSED else 200

    def wait(self, base, expected, state=None):
        self.events.append(('status', expected))
        window.require(self.loaded == expected, 'Public status not confirmed')

    def run_window(self):
        return window.run(self.case, 'e'*64, self.review)

    def test_success_closes_checks_stops_once_backs_up_then_restores_unchanged(self):
        self.run_window()
        result = json.loads((self.case/'result.json').read_bytes())
        self.assertEqual(result['phase'], 'ready')
        self.assertTrue(result['original_restored'])
        self.assertEqual((self.route, self.loaded, self.status), (b'original-route', 200, 'active'))
        stop = (window.pc.SYSTEMCTL, 'stop', window.pc.NEW_UNIT)
        start = (window.pc.SYSTEMCTL, 'start', window.pc.NEW_UNIT)
        self.assertEqual(self.events.count(stop), 1)
        self.assertEqual(self.events.count(start), 1)
        self.assertLess(self.events.index(('status', 503)), self.events.index(stop))
        self.assertLess(self.events.index(stop), self.events.index(('backup', record()['container_id'])))
        self.assertLess(self.events.index(('backup', record()['container_id'])), self.events.index(start))
        self.assertEqual(sum(event[0] == 'sessions' for event in self.events), 2)
        window.host.authentication_ready.assert_called_once()
        self.assertTrue(all(window.pc.TRANSPORT not in event and self.cfg['legacy_unit'] not in event for event in self.events))

    def test_postclose_sessions_refuse_stop_and_restore_original_route(self):
        failure = window.pc.Refused('synthetic active desktop')
        window.pc.no_sessions.side_effect = [None, failure]
        with self.assertRaises(window.pc.Refused) as raised:
            self.run_window()
        self.assertIs(raised.exception, failure)
        self.assertNotIn((window.pc.SYSTEMCTL, 'stop', window.pc.NEW_UNIT), self.events)
        self.assertEqual((self.loaded, self.status), (200, 'active'))

    def test_backup_failure_recovers_original_service_and_preserves_primary_error(self):
        failure = OSError('synthetic copy failure')
        window.backup.side_effect = failure
        with self.assertRaises(OSError) as raised:
            self.run_window()
        self.assertIs(raised.exception, failure)
        self.assertEqual((self.loaded, self.status), (200, 'active'))
        recovery = json.loads((self.case/'recovery.result.json').read_bytes())
        self.assertTrue(recovery['original_restored'])
        self.assertEqual(json.loads((self.case/'failure.json').read_bytes())['error_type'], 'OSError')

    def test_unknown_stop_result_is_reconciled_without_replaying_stop(self):
        failure = TimeoutError('synthetic uncertain stop')
        def command(argv, timeout=10):
            result = self.command(argv, timeout)
            if argv[1] == 'stop':
                raise failure
            return result
        window.pc.run.side_effect = command
        with self.assertRaises(TimeoutError) as raised:
            self.run_window()
        self.assertIs(raised.exception, failure)
        self.assertEqual(self.events.count((window.pc.SYSTEMCTL, 'stop', window.pc.NEW_UNIT)), 1)
        self.assertEqual(self.events.count((window.pc.SYSTEMCTL, 'start', window.pc.NEW_UNIT)), 1)
        self.assertEqual(self.loaded, 200)
        window.backup.assert_not_called()

    def test_unknown_start_cannot_replay_and_recovery_error_does_not_replace_original(self):
        failure = TimeoutError('synthetic uncertain start')
        def command(argv, timeout=10):
            if argv[0] == window.pc.NGINX or argv[1] == 'reload':
                return self.command(argv, timeout)
            self.events.append(tuple(argv))
            if argv[1] == 'stop':
                self.status = 'inactive'
            else:
                self.status = 'failed'
                raise failure
        window.pc.run.side_effect = command
        with self.assertRaises(TimeoutError) as raised:
            self.run_window()
        self.assertIs(raised.exception, failure)
        self.assertEqual(self.events.count((window.pc.SYSTEMCTL, 'start', window.pc.NEW_UNIT)), 1)
        self.assertEqual(self.loaded, 503)
        value = json.loads((self.case/'recovery.failure.json').read_bytes())
        self.assertEqual(value['primary_error_type'], 'TimeoutError')
        self.assertTrue(value['operator_reconciliation_required'])

    def test_failed_empty_challenge_is_never_retried_or_opened(self):
        window.host.authentication_ready.return_value = False
        with self.assertRaises(window.pc.Refused):
            self.run_window()
        window.host.authentication_ready.assert_called_once()
        self.assertEqual(self.loaded, 503)
        self.assertTrue((self.case/'recovery.failure.json').exists())

    def test_expiry_after_close_allows_only_fixed_original_recovery(self):
        def sessions(cid):
            self.events.append(('sessions', cid))
            if self.loaded == 503:
                self.clock = 1300
        window.pc.no_sessions.side_effect = sessions
        with self.assertRaises(window.pc.Refused):
            self.run_window()
        self.assertNotIn((window.pc.SYSTEMCTL, 'stop', window.pc.NEW_UNIT), self.events)
        window.backup.assert_not_called()
        self.assertEqual((self.loaded, self.status), (200, 'active'))

    def test_stale_deployment_expired_review_and_replay_refuse_before_actions(self):
        window.snapshot.return_value = {'changed': True}
        window.snapshot.side_effect = None
        with self.assertRaises(window.pc.Refused):
            self.run_window()
        self.assertFalse((self.case/'run.intent.json').exists())
        window.snapshot.return_value = deepcopy(self.plan['snapshot'])
        self.clock = 1300
        with self.assertRaises(window.pc.Refused):
            self.run_window()
        self.assertFalse((self.case/'run.intent.json').exists())
        self.clock = 1000
        self.run_window()
        previous = list(self.events)
        with self.assertRaises(window.pc.Refused):
            self.run_window()
        self.assertEqual(self.events, previous)

    def test_readiness_requires_fresh_cid_run_and_actual65second_hold(self):
        def command(argv, timeout=10):
            result = self.command(argv, timeout)
            if argv[1] == 'start':
                self.current['ready_at'] = 1001
            return result
        window.pc.run.side_effect = command
        with self.assertRaisesRegex(window.pc.Refused, '65second'):
            self.run_window()
        self.assertEqual(self.loaded, 503)

    def test_expiry_during_nginx_syntax_cannot_dispatch_closed_reload(self):
        def command(argv, timeout=10):
            result = self.command(argv, timeout)
            if argv[0] == window.pc.NGINX:
                self.clock = 1300
            return result
        window.pc.run.side_effect = command
        with self.assertRaises(window.pc.Refused):
            self.run_window()
        self.assertNotIn((window.pc.SYSTEMCTL, 'reload', 'nginx.service'), self.events)
        self.assertNotIn((window.pc.SYSTEMCTL, 'stop', window.pc.NEW_UNIT), self.events)
        window.backup.assert_not_called()
        self.assertEqual((self.route, self.loaded), (b'original-route', 200))

    def test_expiry_after_real_stop_cannot_begin_new_backup_but_can_restore(self):
        def command(argv, timeout=10):
            result = self.command(argv, timeout)
            if argv[1] == 'stop':
                self.clock = 1300
            return result
        window.pc.run.side_effect = command
        with self.assertRaises(window.pc.Refused):
            self.run_window()
        window.backup.assert_not_called()
        self.assertEqual(self.events.count((window.pc.SYSTEMCTL, 'start', window.pc.NEW_UNIT)), 1)
        self.assertEqual((self.status, self.loaded), ('active', 200))

    def test_known_closed_loaded_state_allows_fixed_original_recovery_reload(self):
        original_reload = self.reload
        first_restore = [True]
        failure = TimeoutError('synthetic original reload uncertainty')
        def reload():
            if self.route == b'original-route' and first_restore[0]:
                first_restore[0] = False
                raise failure
            original_reload()
        window.pc.reload_nginx.side_effect = reload
        with self.assertRaises(TimeoutError) as raised:
            self.run_window()
        self.assertIs(raised.exception, failure)
        self.assertEqual((self.route, self.loaded), (b'original-route', 200))
        self.assertTrue((self.case/'recovery.result.json').exists())
        window.host.authentication_ready.assert_called_once()

    def test_reconcile_reports_actual_owned_presence_without_mutations(self):
        with patch.object(window.host, 'private_json', return_value=self.current), \
                patch.object(window.host, 'owned', return_value=None):
            before = list(self.events)
            value = window.reconcile(self.case, 'e'*64)
        self.assertTrue(value['no_actions_performed'])
        self.assertFalse(value['owned_container_present'])
        self.assertEqual(value['current']['container_id'], self.current['container_id'])
        self.assertEqual(self.events, before)

    def test_stage_has_no_lifecycle_mutation_and_binds_original_files(self):
        external = self.root/'operator.json'
        external.write_text(json.dumps(self.cfg))
        external.chmod(0o600)
        staged = self.root/'new-stage'
        digest = window.stage(external, staged)
        cfg, staged_plan = REAL_LOAD_CASE(staged, digest)
        self.assertEqual(cfg, self.cfg)
        self.assertEqual(staged_plan['snapshot'], self.plan['snapshot'])
        self.assertEqual(self.events, [(window.pc.NGINX, '-t')])
        self.assertEqual(self.loaded, 200)
        (staged/'original-snippet.conf').write_bytes(b'changed')
        with self.assertRaisesRegex(window.pc.Refused, 'original bytes'):
            REAL_LOAD_CASE(staged, digest)
        with self.assertRaises(FileExistsError):
            window.stage(external, staged)

    def test_backup_dispatches_genuine_cli_with_actual_unit_and_original_full_cid(self):
        target = self.case/'cold-backup'
        target.mkdir(mode=0o700)
        expected = {'schema': 1, 'entries': {'prepared.json': {'sha256': '9'*64}}}
        raw = json.dumps(expected).encode()
        result = {'schema': 1, 'operation': 'backup', 'phase': 'ready',
                  'source': str(window.host.PERSIST/'data'), 'target': str(target/'data'),
                  'legacy_cid': self.current['container_id'], 'for_migration': False,
                  'legacy_receipt_archived': False, 'allowed_stopped_consumers': [],
                  'stopped_consumer_census': {}, 'manifest_sha256': window.host.sha(raw)}
        window.files.write_new(target/'manifest.json', raw)
        window.files.json_new(target/'result.json', result)
        window.pc.run.side_effect = None
        window.pc.run.return_value = subprocess.CompletedProcess([], 0, b'{"success":true}', b'')
        with patch.object(window.cold_copy, 'manifest', return_value=expected) as census:
            proof = REAL_BACKUP(self.case, self.current)
        argv = window.pc.run.call_args.args[0]
        self.assertEqual(argv[:4], ['/usr/bin/python3', '-B', str(Path(window.cold_copy.__file__).resolve()), 'backup'])
        self.assertEqual(argv[argv.index('--service')+1], window.pc.NEW_UNIT)
        self.assertEqual(argv[argv.index('--container')+1], window.host.NAME)
        self.assertEqual(argv[argv.index('--legacy-container-id')+1], self.current['container_id'])
        self.assertEqual(argv[argv.index('--source')+1], str(window.host.PERSIST/'data'))
        self.assertNotIn('--for-migration', argv)
        self.assertEqual(census.call_count, 2)
        self.assertEqual(proof['manifest_sha256'], window.host.sha(raw))
        # A bound result cannot conceal subsequent manifest or tree changes.
        (target/'manifest.json').write_bytes(raw+b' ')
        with self.assertRaisesRegex(window.pc.Refused, 'manifest binding'):
            REAL_BACKUP(self.case, self.current)
        (target/'manifest.json').write_bytes(raw)
        with patch.object(window.cold_copy, 'manifest', return_value={'changed': True}):
            with self.assertRaisesRegex(window.pc.Refused, 'full backup/source census'):
                REAL_BACKUP(self.case, self.current)
        result['target'] = '/foreign/target'
        (target/'result.json').write_text(json.dumps(result))
        with self.assertRaisesRegex(window.pc.Refused, 'Exact successful'):
            REAL_BACKUP(self.case, self.current)


if __name__ == '__main__':
    unittest.main()
