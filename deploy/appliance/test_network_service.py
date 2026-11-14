"""Host-inert bootstrap tests; every engine, IP and policy action is mocked."""
import json
from pathlib import Path
import stat
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import host
import network
import network_service as service
from test_host import config, release

ENGINE = service.engine
OLD = '11111111-1111-1111-1111-111111111111'
NEW = '22222222-2222-2222-2222-222222222222'
ID = 'a' * 64
NAME = 'portal-test'


def result(value):
    return SimpleNamespace(stdout=json.dumps(value).encode(), returncode=0)


def binding():
    return dict(schema=1, podman_network=NAME, config_sha256='b' * 64,
                network_sha256='c' * 64, policy_hash='d' * 64)


def receipt(boot=OLD):
    return dict(schema=1, phase='ready', binding=binding(), boot_id=boot, network_id=ID)


def inspected():
    cfg = config()
    return dict(id=ID, name=NAME, driver='bridge', network_interface=cfg.bridge,
                subnets=[dict(subnet=cfg.subnet_ipv4, gateway=cfg.gateway_ipv4)],
                labels={host.LABEL: '1', service.BIND_LABEL: network.digest(binding())},
                ipv6_enabled=False, internal=False, dns_enabled=False, options={})


class InertTests(unittest.TestCase):
    def setUp(self):
        self.command = patch.object(host, 'command', side_effect=AssertionError('Unexpected host command')).start()
        self.engine = patch.object(service, 'engine', side_effect=AssertionError('Unexpected Podman command')).start()
        self.ip = patch.object(service, 'ip', side_effect=AssertionError('Unexpected IP command')).start()
        patch.object(network, 'run', side_effect=AssertionError('Unexpected firewall command')).start()
        self.addCleanup(patch.stopall)


class InputTests(InertTests):
    def test_provisional_and_final_need_no_acceptance_file(self):
        cfgraw, netraw = b'catalog', b'network'
        values = dict(schema=1, podman_network=NAME, config_sha256=host.sha(cfgraw),
                      network_sha256=host.sha(netraw))
        for candidate in (values, {**release(), **values}):
            with patch.object(host, 'read_json', return_value=candidate), \
                 patch.object(network, 'protected_read', side_effect=[cfgraw, netraw]) as read, \
                 patch.object(service.json, 'loads', side_effect=[{}, {}]), \
                 patch.object(network, 'parse_config', return_value=config()), \
                 patch.object(service.catalog, 'parse', return_value=object()), \
                 patch.object(network, 'policy', return_value={'synthetic': True}):
                self.assertEqual(service.selection()[0], NAME)
                self.assertEqual([c.args[0] for c in read.call_args_list], [host.CONFIG, host.NETWORK])

    def test_unknown_provisional_keys_and_unsafe_names_rejected(self):
        for candidate in ({**{k:v for k,v in release().items() if k in service.RELEASE_KEYS}, 'extra': 1},
                          {**release(), 'podman_network': 'x; touch /tmp/bad'},
                          {**release(), 'schema': True}):
            with patch.object(host, 'read_json', return_value=candidate), self.assertRaises(ValueError):
                service.selection()

    def test_network_and_bridge_argv_are_literal_and_scoped(self):
        cfg = config()
        args = service.network_create_args(NAME, cfg, binding())
        self.assertEqual(args[:4], ['network', 'create', '--driver=bridge', '--disable-dns'])
        self.assertIn('--interface-name=' + cfg.bridge, args)
        self.assertIn('--label=guacamole.portal=1', args)
        self.assertEqual(args[-1], NAME)
        self.ip.side_effect = None
        self.command.side_effect = None
        service.bridge_create(cfg, binding())
        calls = [c.args for c in self.ip.call_args_list]
        self.assertEqual(calls[0], ('link', 'add', 'name', cfg.bridge, 'type', 'bridge'))
        self.assertEqual(calls[2], ('address', 'add', '192.0.2.1/29', 'dev', cfg.bridge))
        self.assertEqual(calls[-1], ('link', 'set', 'dev', cfg.bridge, 'up'))
        self.assertFalse(any('wrdp0' in c or 'sysctl' in c for c in calls))
        self.command.assert_called_once_with(['/usr/sbin/sysctl', '-w',
            'net.ipv4.conf.portalb0.route_localnet=1'], timeout=10)


class CollisionTests(InertTests):
    def test_existing_name_never_adopted_without_receipt(self):
        with patch.object(service, 'inventory', return_value=[inspected()]), self.assertRaises(RuntimeError):
            service.inspect_network(NAME, config(), binding(), None)

    def test_exact_owned_network_and_drift(self):
        self.assert_network(inspected(), ID)
        for changes in ({'id': 'f' * 64}, {'driver': 'macvlan'}, {'dns_enabled': True},
                        {'ipv6_enabled': True}, {'internal': True}, {'labels': {}},
                        {'options': {'isolate': 'true'}}, {'subnets': []}):
            with self.subTest(changes=changes), self.assertRaises(RuntimeError):
                self.assert_network({**inspected(), **changes}, ID)

    def assert_network(self, value, expected):
        with patch.object(service, 'inventory', return_value=[value]):
            self.assertEqual(service.inspect_network(NAME, config(), binding(), receipt()), expected)

    def test_foreign_interface_subnet_or_missing_definition_refused(self):
        for value in ({**inspected(), 'name': 'foreign'},
                      {**inspected(), 'name': 'foreign', 'network_interface': 'otherb0'}):
            with patch.object(service, 'inventory', return_value=[value]), self.assertRaises(RuntimeError):
                service.inspect_network(NAME, config(), binding(), None)
        with patch.object(service, 'inventory', return_value=[]), self.assertRaises(RuntimeError):
            service.inspect_network(NAME, config(), binding(), receipt())

    def test_preexisting_bridge_refused_even_with_matching_alias(self):
        self.ip.side_effect = None
        self.ip.return_value = result([dict(ifname=config().bridge, flags=['UP'],
             ifalias='guacamole.portal=' + network.digest(binding()),
             linkinfo={'info_kind': 'bridge'})])
        with self.assertRaises(RuntimeError):
            service.inspect_bridge(config(), binding(), None)

    def test_owned_bridge_requires_own_route_localnet_and_never_repairs_drift(self):
        cfg = config()
        link = dict(ifname=cfg.bridge, flags=['UP'], ifindex=12,
                    ifalias='guacamole.portal=' + network.digest(binding()),
                    linkinfo={'info_kind': 'bridge'})
        address = dict(addr_info=[dict(family='inet', local=cfg.gateway_ipv4, prefixlen=29)])
        for value in ('1\n', '0\n'):
            self.ip.side_effect = [result([link]), result([address])]
            seen = []
            def read(path):
                seen.append(str(path))
                return value
            with patch.object(Path, 'read_text', autospec=True, side_effect=read):
                if value == '1\n':
                    self.assertTrue(service.inspect_bridge(cfg, binding(), receipt()))
                else:
                    with self.assertRaises(RuntimeError):
                        service.inspect_bridge(cfg, binding(), receipt())
            self.assertEqual(seen, ['/proc/sys/net/ipv4/conf/portalb0/route_localnet'])
        self.command.assert_not_called()

    def test_stopped_container_or_foreign_bridge_peer_blocks_mutation(self):
        self.engine.side_effect = None
        self.engine.return_value = SimpleNamespace(stdout=b'a' * 64 + b'\n')
        with self.assertRaises(RuntimeError): service.empty(NAME, config())
        self.engine.return_value = SimpleNamespace(stdout=b'')
        self.ip.side_effect = None
        self.ip.return_value = result([{'ifname': config().bridge, 'ifindex': 8},
                                       {'ifname': 'foreign0', 'master': 8}])
        with self.assertRaises(RuntimeError): service.empty(NAME, config())


class BootTests(InertTests):
    def test_absence_only_allows_exact_prior_boot_ready(self):
        p = {'synthetic': True}
        firewall = dict(phase='ready', policy=p, policy_hash=network.digest(p), boot_id=OLD)
        with patch.object(network, 'all_owned_absent', return_value=True):
            service.validate_firewall_absence(p, receipt(), NEW, firewall)
            for prior, now, saved in ((receipt(), OLD, firewall), (receipt(), NEW, None),
                    (receipt(), NEW, {**firewall, 'phase': 'intent'}),
                    (receipt(), NEW, {**firewall, 'policy': {}}),
                    (receipt(), NEW, {**firewall, 'boot_id': NEW}), (None, NEW, firewall)):
                with self.subTest(prior=prior, saved=saved), self.assertRaises((RuntimeError, ValueError)):
                    service.validate_firewall_absence(p, prior, now, saved)
        with patch.object(network, 'all_owned_absent', return_value=False), self.assertRaises(RuntimeError):
            service.validate_firewall_absence(p, receipt(), NEW, firewall)

    def harness(self, previous=None, bridge=False):
        self.events = []
        patch.object(service, 'saved', return_value=previous).start()
        patch.object(network, 'boot_id', return_value=NEW).start()
        patch.object(service, 'inspect_network', return_value=ID if previous else None).start()
        patch.object(service, 'inspect_bridge', side_effect=([False, False, False, True, True]
                     if previous is None else [False, False, True, True])
                     if not bridge else [True, True, True]).start()
        patch.object(service, 'empty', side_effect=lambda *a: self.events.append('empty')).start()
        patch.object(service, 'firewall_prerequisite', side_effect=lambda *a: self.events.append('prerequisite')).start()
        patch.object(service, 'archive_ready', return_value={'filename': 'prior.json', 'sha256': 'e' * 64}).start()
        patch.object(host, 'write', side_effect=lambda path, value: self.events.append(value['phase'])).start()
        patch.object(service, 'bridge_create', side_effect=lambda *a: self.events.append('bridge')).start()
        patch.object(service, 'inventory', return_value=[inspected()]).start()
        self.engine.side_effect = lambda *a: self.events.append('network-create')
        patch.object(service, 'policy_command', side_effect=lambda action: self.events.append(action)).start()

    def test_prepare_mutation_graph(self):
        self.harness()
        service.reconcile('prepare', NAME, config(), {}, binding())
        for before, after in (('prerequisite', 'intent'), ('intent', 'bridge'),
                              ('network-create', 'bridge'), ('bridge', 'apply'),
                              ('apply', 'check'), ('check', 'ready')):
            self.assertLess(self.events.index(before), self.events.index(after))

    def test_ordinary_boot_never_creates_without_receipt_or_replays_partial(self):
        for prior in (None, {**receipt(), 'phase': 'intent'}, {**receipt(), 'phase': 'failed'},
                      {**receipt(), 'binding': {}}, {**receipt(), 'boot_id': ''}):
            with patch.object(service, 'saved', return_value=prior), \
                 patch.object(network, 'boot_id', return_value=NEW), self.assertRaises(RuntimeError):
                service.reconcile('boot', NAME, config(), {}, binding())

    def test_ready_existing_bridge_only_calls_policy_module(self):
        self.harness(receipt(), bridge=True)
        service.reconcile('boot', NAME, config(), {}, binding())
        self.assertNotIn('bridge', self.events)
        self.assertNotIn('network-create', self.events)
        self.assertEqual(self.events[-3:], ['check', 'empty', 'ready'])

    def test_changed_boot_recreates_bridge_without_network_create(self):
        self.harness(receipt(), bridge=False)
        service.reconcile('boot', NAME, config(), {}, binding())
        self.assertIn('prerequisite', self.events)
        self.assertIn('bridge', self.events)
        self.assertNotIn('network-create', self.events)

    def test_same_boot_missing_bridge_requires_exact_live_firewall(self):
        p = {'synthetic': True}
        firewall = dict(phase='ready', policy=p, policy_hash=network.digest(p),
                        boot_id=NEW, guard_hash='f' * 64)
        with patch.object(network, 'verify') as verify, \
             patch.object(network, 'all_owned_absent', side_effect=AssertionError('No absence fallback')):
            proof = service.validate_firewall_absence(p, receipt(NEW), NEW, firewall)
            verify.assert_called_once_with(p, 'f' * 64)
            self.assertEqual(proof, dict(mode='same_boot_verified', boot_id=NEW,
                                        policy_hash=network.digest(p), guard_hash='f' * 64))
            for changed in ({'phase': 'intent'}, {'phase': 'failed'}, {'boot_id': OLD},
                            {'policy': {}}, {'policy_hash': '0' * 64}, {'guard_hash': None}):
                with self.subTest(changed=changed), self.assertRaises((RuntimeError, ValueError)):
                    service.validate_firewall_absence(p, receipt(NEW), NEW, {**firewall, **changed})
        with patch.object(network, 'verify', side_effect=RuntimeError('Guard/rule drift')), self.assertRaises(RuntimeError):
            service.validate_firewall_absence(p, receipt(NEW), NEW, firewall)

    def test_same_boot_recreation_receipt_binds_prior_bytes_and_rechecks_proof(self):
        self.harness(receipt(NEW), bridge=False)
        proof = dict(mode='same_boot_verified', boot_id=NEW, policy_hash=binding()['policy_hash'],
                     guard_hash='f' * 64, receipt_sha256='a' * 64)
        records = []
        with patch.object(service, 'firewall_prerequisite', return_value=proof) as prerequisite, \
             patch.object(host, 'write', side_effect=lambda path, value: records.append(dict(value))):
            service.reconcile('boot', NAME, config(), {}, binding())
        self.assertEqual(prerequisite.call_count, 2)
        self.assertEqual(records[0]['phase'], 'intent')
        self.assertEqual(records[0]['bridge_recreation'], proof)
        self.assertEqual(records[0]['previous_ready_archive']['sha256'], 'e' * 64)
        self.assertEqual(records[-1]['phase'], 'ready')
        self.assertNotIn('network-create', self.events)

    def test_proof_change_before_recreation_refuses_mutation(self):
        self.harness(receipt(NEW), bridge=False)
        proof = {'receipt_sha256': 'a' * 64}
        with patch.object(service, 'firewall_prerequisite', side_effect=[proof, {'receipt_sha256': 'b' * 64}]), \
             self.assertRaises(RuntimeError):
            service.reconcile('boot', NAME, config(), {}, binding())
        self.assertNotIn('bridge', self.events)
        self.assertEqual(self.events[-1], 'failed')

    def test_consumer_before_recreation_refuses_mutation(self):
        self.harness(receipt(NEW), bridge=False)
        with patch.object(service, 'empty', side_effect=[None, RuntimeError('Concurrent consumer')]), \
             self.assertRaises(RuntimeError):
            service.reconcile('boot', NAME, config(), {}, binding())
        self.assertNotIn('bridge', self.events)
        self.assertEqual(self.events[-1], 'failed')

    def test_firewall_proof_hashes_exact_ready_receipt_bytes(self):
        p = {'synthetic': True}
        firewall = dict(phase='ready', policy=p, policy_hash=network.digest(p),
                        boot_id=NEW, guard_hash='f' * 64)
        raw = json.dumps(firewall, indent=2).encode() + b'\n'
        with tempfile.TemporaryDirectory() as temporary:
            (Path(temporary) / 'lock').touch(mode=0o600)
            with patch.object(network, 'STATE', Path(temporary)), \
                 patch.object(network, 'secure_directory'), patch.object(network, 'saved_state', return_value=firewall), \
                 patch.object(network, 'protected_read', return_value=raw), patch.object(network, 'verify'), \
                 patch.object(service.os, 'fstat', return_value=SimpleNamespace(
                     st_mode=stat.S_IFREG | 0o600, st_uid=0, st_nlink=1)):
                proof = service.firewall_prerequisite(p, receipt(NEW), NEW)
                self.assertEqual(proof['receipt_sha256'], host.sha(raw))

    def test_failed_command_retains_failed_and_never_rolls_back(self):
        self.harness()
        with patch.object(service, 'bridge_create', side_effect=RuntimeError('synthetic')), self.assertRaises(RuntimeError):
            service.reconcile('prepare', NAME, config(), {}, binding())
        self.assertEqual(self.events[-1], 'failed')
        self.assertNotIn('apply', self.events)

    def test_network_create_nonzero_retains_bounded_private_stderr(self):
        self.command.side_effect = None
        self.command.return_value = SimpleNamespace(returncode=125, stdout=b'', stderr=b'x' * 9000)
        with patch.object(host, 'write') as write, self.assertRaises(RuntimeError):
            ENGINE('network', 'create', NAME)
        diagnostic = write.call_args.args[1]
        self.assertEqual(len(diagnostic['stderr']), 8192)
        self.assertTrue(diagnostic['stderr_truncated'])
        self.assertEqual(diagnostic['stderr_sha256'], host.sha(b'x' * 9000))
        self.assertFalse(self.command.call_args.kwargs['check'])


class RecoveryTests(InertTests):
    def failed(self):
        value = receipt(NEW)
        value.update(phase='failed', network_id=None, started_at=123.0, error_type='RuntimeError')
        return value

    def harness(self, previous=None):
        self.previous = previous or self.failed()
        self.raw = json.dumps(self.previous).encode()
        self.hash = host.sha(self.raw)
        patch.object(service, 'saved', return_value=self.previous).start()
        patch.object(network, 'boot_id', return_value=NEW).start()
        patch.object(network, 'protected_read', return_value=self.raw).start()
        self.net = patch.object(service, 'inspect_network', return_value=None).start()
        self.bridge = patch.object(service, 'inspect_bridge', return_value=True).start()
        self.empty = patch.object(service, 'empty').start()
        self.firewall = patch.object(service, 'firewall_prerequisite').start()
        self.archive = patch.object(service, 'archive_failed', return_value={'sha256': self.hash}).start()
        self.write = patch.object(host, 'write').start()
        self.install = patch.object(service, 'install').start()

    def test_explicit_reviewed_recovery_archives_intent_then_calls_bounded_install(self):
        self.harness()
        events = []
        self.archive.side_effect = lambda *a: events.append('archive') or {'sha256': self.hash}
        self.write.side_effect = lambda *a: events.append(a[1]['phase'])
        self.install.side_effect = lambda *a, **k: events.append('install')
        service.recover_failed_prepare(NAME, config(), {}, binding(), self.hash)
        self.assertEqual(events, ['archive', 'intent', 'install'])
        self.assertTrue(self.install.call_args.kwargs['remove_bridge'])

    def test_unknown_or_replayed_state_and_wrong_hash_refused(self):
        for changes in ({'phase': 'intent'}, {'network_id': ID}, {'boot_id': OLD},
                        {'error_type': 'TimeoutExpired'}, {'binding': {}},
                        {'recovered_from': {'sha256': '0' * 64}}):
            with patch.object(service, 'saved', return_value={**self.failed(), **changes}), \
                 patch.object(network, 'boot_id', return_value=NEW), self.assertRaises(RuntimeError):
                service.recover_failed_prepare(NAME, config(), {}, binding(), '0' * 64)
        self.harness()
        with self.assertRaises(RuntimeError):
            service.recover_failed_prepare(NAME, config(), {}, binding(), '0' * 64)
        self.install.assert_not_called()

    def test_missing_owned_bridge_or_any_live_state_refuses_before_archive(self):
        self.harness()
        self.bridge.return_value = False
        with self.assertRaises(RuntimeError):
            service.recover_failed_prepare(NAME, config(), {}, binding(), self.hash)
        self.archive.assert_not_called()
        self.bridge.return_value = True
        self.firewall.side_effect = RuntimeError('partial firewall')
        with self.assertRaises(RuntimeError):
            service.recover_failed_prepare(NAME, config(), {}, binding(), self.hash)
        self.archive.assert_not_called()

    def test_recovery_install_deletes_only_verified_bridge_then_creates_definition(self):
        events = []
        self.ip.side_effect = lambda *a: events.append(('ip', a))
        self.engine.side_effect = lambda *a: events.append(('engine', a))
        record = dict(schema=1, phase='intent', binding=binding(), boot_id=NEW,
                      network_id=None, recovered_from={'sha256': '0' * 64})
        with patch.object(service, 'inspect_network', return_value=None), \
             patch.object(service, 'inspect_bridge', side_effect=[True, False, False, False, True, True]), \
             patch.object(service, 'firewall_prerequisite'), patch.object(service, 'empty'), \
             patch.object(service, 'inventory', return_value=[inspected()]), \
             patch.object(service, 'bridge_create', side_effect=lambda *a: events.append(('bridge', ()))), \
             patch.object(service, 'policy_command', side_effect=lambda a: events.append((a, ()))), \
             patch.object(host, 'write'):
            service.install(record, NAME, config(), {}, binding(), None, True, remove_bridge=True)
        self.assertEqual(events[0], ('ip', ('link', 'delete', 'dev', config().bridge, 'type', 'bridge')))
        self.assertEqual([e[0] for e in events], ['ip', 'engine', 'bridge', 'apply', 'check'])
        self.assertEqual(record['phase'], 'ready')

    def test_failed_archive_preserves_exact_bytes_private_and_never_overwrites(self):
        previous = self.failed()
        raw = json.dumps(previous, indent=2).encode() + b'\n'
        expected = host.sha(raw)
        with tempfile.TemporaryDirectory() as temporary, \
             patch.object(service, 'STATE', Path(temporary)), \
             patch.object(network, 'protected_read', return_value=raw):
            archived = service.archive_failed(previous, expected)
            path = Path(temporary) / archived['filename']
            self.assertEqual(path.read_bytes(), raw)
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            with self.assertRaises(FileExistsError):
                service.archive_failed(previous, expected)
            with self.assertRaises(RuntimeError):
                service.archive_failed(previous, '0' * 64)

    def test_unit_orders_both_consumers_and_preserves_state(self):
        unit = Path(service.__file__).with_name('guacamole-portal-network.service').read_text()
        for text in ('Before=guacamole-portal.service portal-rdp-transport.service',
                     'After=network-online.target libvirtd.service apparmor.service',
                     'Type=oneshot', 'RemainAfterExit=yes', 'network_service.py boot'):
            self.assertIn(text, unit)
        self.assertNotIn('ExecStop=', unit)


if __name__ == '__main__':
    unittest.main()
