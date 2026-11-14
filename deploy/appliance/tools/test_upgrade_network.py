"""Inert additive firewall, protected proof and lifecycle regression tests."""
import copy
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time
import unittest
from unittest.mock import patch

import upgrade_network as upgrade
import network_upgrade as contract
import network
import network_service as bootstrap
from test_catalog import configuration, mixed_configuration
from test_network import configuration as network_configuration

BOOT = '11111111-1111-1111-1111-111111111111'
LATER_BOOT = '22222222-2222-2222-2222-222222222222'


def inputs():
    old = configuration()
    for target, host in zip(old['targets'].values(), ('198.51.100.7', '198.51.100.8')):
        target['hostname'] = host
    new = copy.deepcopy(old)
    new['schema_version'] = 2
    ssh = mixed_configuration()['targets']['terminal-c']
    ssh['hostname'] = '192.0.2.1'
    ssh['host_key'] = ssh['host_key'].replace('192.0.2.30', '192.0.2.1')
    new['targets']['terminal-c'] = ssh
    before = network_configuration()
    before['local_endpoints'] = []
    after = copy.deepcopy(before)
    after['local_endpoints'] = [{'hostname': '192.0.2.1', 'port': 10222}]
    return before, after, old, new


class PureTests(unittest.TestCase):
    def test_append_only_and_existing_record_preservation(self):
        p, q = contract.extension(*inputs())
        self.assertEqual(p['forwarded'], q['forwarded'])
        args = upgrade.insertion_commands(p, q)
        self.assertEqual(len(args), 2)
        self.assertEqual({arg[6] for arg in args}, {'GP_PORTAL_IN', 'INPUT'})
        self.assertTrue(all(arg[5] == '-I' for arg in args))
        self.assertNotIn('-F', str(args))
        for mutation in ('target', 'portal', 'source', 'delete', 'forward', 'rdp', 'old-field'):
            before, after, old, new = inputs()
            if mutation == 'target': new['targets']['desktop-a']['username'] = 'changed'
            if mutation == 'portal': new['portal']['default_target'] = 'desktop-b'
            if mutation == 'source': after['source_ipv4'] = '192.0.2.3'
            if mutation == 'delete': del new['targets']['desktop-a']
            if mutation == 'forward':
                after['local_endpoints'] = []
                new['targets']['terminal-c']['hostname'] = '192.0.2.30'
                new['targets']['terminal-c']['host_key'] = new['targets']['terminal-c']['host_key'].replace('192.0.2.1', '192.0.2.30')
            if mutation == 'rdp': new['targets']['extra'] = copy.deepcopy(old['targets']['desktop-a'])
            if mutation == 'old-field': new['targets']['desktop-a']['label'] = 'Previously absent'
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                contract.extension(before, after, old, new)

    def test_no_duplicate_json_or_incomplete_definition_proof(self):
        with self.assertRaises(ValueError): contract.load(b'{"schema":1,"schema":2}')
        selected = {'original': 'binding'}
        self.assertIs(contract.definition_binding(None, selected), selected)
        self.assertIs(contract.definition_binding({}, selected), selected)
        with self.assertRaises(ValueError):
            contract.definition_binding({'definition_binding': selected}, selected)
        for path in ('relative/proof.json', '/root/../proof.json'):
            with self.subTest(path=path), self.assertRaises(ValueError): contract.private_read(path)

    def test_network_binding_matches_host_dedicated_name_grammar(self):
        old_network, _, old_catalog, _ = inputs()
        raw_catalog, raw_network = json.dumps(old_catalog).encode(), json.dumps(old_network).encode()
        p, _ = contract.extension(*inputs())
        value = dict(schema=1,podman_network='p.'+'x'*94,config_sha256=contract.sha(raw_catalog),
            network_sha256=contract.sha(raw_network),policy_hash=network.digest(p))
        self.assertEqual(contract.binding(value,raw_catalog,raw_network,p),value)
        for name in ('host','none','bridge','unconfined','UPPER','p'*97):
            with self.subTest(name=name),self.assertRaises(ValueError):
                contract.binding({**value,'podman_network':name},raw_catalog,raw_network,p)

    def test_nft_replacement_is_one_scoped_transaction(self):
        _, q = contract.extension(*inputs())
        value = upgrade.guard_transaction(q)
        self.assertEqual(value.count('delete table'), 1)
        self.assertTrue(value.startswith('delete table inet guacamole_portal_guard\ntable inet guacamole_portal_guard {'))
        self.assertNotIn('flush ruleset', value)
        self.assertIn('ip daddr 192.0.2.1 tcp dport 10222 drop;', value)

    def test_listener_census_denies_ipv4_ipv6_and_wildcard(self):
        p, q = contract.extension(*inputs())
        for endpoint in ('192.0.2.1:10222', '0.0.0.0:10222', '[::]:10222', '*:10222'):
            with patch.object(upgrade.host, 'command', return_value=subprocess.CompletedProcess([], 0,
                    ('LISTEN 0 128 '+endpoint+' *:*\n').encode(), b'')):
                with self.subTest(endpoint=endpoint), self.assertRaisesRegex(ValueError, 'listener'):
                    upgrade.no_added_listeners(p, q)
        with patch.object(upgrade.host, 'command', return_value=subprocess.CompletedProcess([], 0,
                b'LISTEN 0 128 [::]:22 *:*\n', b'')):
            upgrade.no_added_listeners(p, q)

    def test_active_or_unknown_service_refused(self):
        for value in (b'LoadState=loaded\nActiveState=active\nMainPID=2\n',
                      b'LoadState=not-found\nActiveState=inactive\nMainPID=0\n'):
            with patch.object(upgrade.host, 'command', return_value=subprocess.CompletedProcess([], 0, value, b'')):
                with self.assertRaises(ValueError): upgrade.inactive(upgrade.UNIT)


@unittest.skipUnless(os.geteuid() == 0, 'Synthetic protected filesystem requires root')
class UpgradeTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(prefix='portal-network-upgrade-', dir='/run')
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.directory = self.root/'case'
        self.before, self.after, self.old, self.new = inputs()
        self.p, self.q = contract.extension(self.before, self.after, self.old, self.new)
        self.fw = self.root/'firewall'; self.fw.mkdir(mode=0o700)
        self.bs = self.root/'bootstrap'; self.bs.mkdir(mode=0o700)
        self.raws = {name: json.dumps(value).encode() for name, value in zip(upgrade.INPUTS, inputs())}
        for name, raw in self.raws.items(): self.write(name, raw)
        self.write('release.json', b'EXACT ORIGINAL RELEASE')
        self.original = dict(schema=1, phase='ready', binding=dict(schema=1, podman_network='portal-test',
            config_sha256=contract.sha(self.raws['old-catalog.json']),
            network_sha256=contract.sha(self.raws['old-network.json']), policy_hash=network.digest(self.p)),
            boot_id=BOOT, network_id='a'*64, started_at=1, finished_at=2)
        self.firewall = dict(phase='ready', policy=self.p, policy_hash=network.digest(self.p),
                            guard_hash='b'*64, boot_id=BOOT, started_at=1, finished_at=2)
        self.write('bootstrap/state.json', json.dumps(self.original).encode())
        self.write('firewall/state.json', json.dumps(self.firewall).encode())
        self.patch(network, 'STATE', self.fw)
        self.patch(bootstrap, 'RECEIPT', self.bs/'state.json')
        self.patch(upgrade.host, 'RELEASE', self.root/'release.json')
        self.patch(upgrade.host, 'CONFIG', self.root/'old-catalog.json')
        self.patch(upgrade.host, 'NETWORK', self.root/'old-network.json')
        self.patch(network, 'boot_id', return_value=BOOT)
        self.patch(upgrade, 'sources', return_value={'synthetic-only': 'f'*64})
        self.env = self.patch(upgrade, 'environment')
        self.patch(bootstrap, 'selection', return_value=('portal-test', network.parse_config(self.before), self.p, self.original['binding']))
        self.patch(network, 'verify_host')
        self.guard = 'b'*64
        self.patch(network, 'guard_hash', side_effect=lambda: self.guard)
        self.chain_map = {}
        for b, t, c, rules in self.p['rules']:
            self.chain_map[(b, t, c)] = [['-N', c]] + [['-A', c, *rule] for rule in rules]
        for key, rules in network.shared_groups(self.p).items():
            b, t, c = key
            self.chain_map[key] = [['-P', c, 'ACCEPT'], *copy.deepcopy(rules), ['-A', c, '-m', 'comment', '--comment', 'unrelated', '-j', 'ACCEPT']]
        self.patch(network, 'chain_lines', side_effect=lambda b, t, c: copy.deepcopy(self.chain_map[(b,t,c)]))
        self.commands = []
        self.inject = None
        self.patch(network, 'run', side_effect=self.dispatch)
        self.listener = b''
        self.patch(upgrade.host, 'command', side_effect=lambda *a, **k: subprocess.CompletedProcess([], 0, self.listener, b''))

    def patch(self, obj, name, *args, **kwargs):
        patcher = patch.object(obj, name, *args, **kwargs)
        value = patcher.start(); self.addCleanup(patcher.stop)
        return value

    def write(self, name, raw):
        path = self.root/name
        path.write_bytes(raw); path.chmod(0o600)
        return path

    def dispatch(self, args, **kwargs):
        self.commands.append(copy.deepcopy(args))
        if self.inject is not None: self.inject(args)
        if args[:2] == ['nft', '-f']:
            self.guard = 'c'*64 if 'tcp dport 10222' in kwargs['input'] else 'b'*64
        elif args[0] in ('iptables', 'ip6tables'):
            b, _, _, _, t, action, c, *spec = args
            rows = self.chain_map[(b,t,c)]
            if action == '-I':
                index = int(spec.pop(0))
                rows.insert(index, ['-A', c, *spec])
            elif action == '-D': rows.remove(['-A', c, *spec])
            else: raise AssertionError('Unexpected mutation')
        return subprocess.CompletedProcess(args, 0, '', '')

    def prepare(self):
        upgrade.prepare(self.directory, *(self.root/name for name in upgrade.INPUTS))
        self.digest = contract.sha((self.directory/'plan.json').read_bytes())
        self.review_path = self.write('review.json', json.dumps(self.review()).encode())

    def review(self):
        route = self.write('closed-route.conf', b'EXACT EXTERNALLY REVIEWED CLOSED ROUTE')
        census = self.write('sessions.json', b'{"sessions":0,"closed_before_census":true}')
        return dict(schema=1, operation='add-local-ssh', plan_sha256=self.digest, portal_closed=True,
            sessions_cleared=True, closed_route=dict(path=str(route), sha256=contract.sha(route.read_bytes())),
            session_census=dict(path=str(census), sha256=contract.sha(census.read_bytes())),
            reviewed_at=time.time()-1, expires_at=time.time()+120)

    def apply(self): upgrade.apply(self.directory, self.digest, self.review_path)
    def rollback(self): upgrade.rollback(self.directory, self.digest, self.review_path)

    def test_apply_and_explicit_rollback_preserve_every_shared_rule_and_original(self):
        baseline = copy.deepcopy(self.chain_map)
        self.prepare()
        self.assertEqual(self.chain_map, baseline)
        self.apply()
        network.check(self.q)
        current = bootstrap.saved()
        self.assertEqual(contract.definition_binding(current, current['binding']), self.original['binding'])
        self.assertEqual(current['network_id'], self.original['network_id'])
        self.assertEqual(self.guard, 'c'*64)
        self.rollback()
        self.assertEqual(self.chain_map, baseline)
        self.assertEqual(self.guard, 'b'*64)
        self.assertEqual(bootstrap.saved(), self.original)
        self.assertEqual(network.saved_state(), self.firewall)
        with self.assertRaises(ValueError): self.apply()
        with self.assertRaises(ValueError): self.rollback()
        self.assertTrue(all('-F' not in args and 'restart' not in args and 'reload' not in args for args in self.commands))

    def test_old_targets_archive_or_source_drift_refuses_before_intent(self):
        self.prepare()
        self.write('case/old-catalog.json', b'CHANGED')
        with self.assertRaisesRegex(ValueError, 'archive'): self.apply()
        self.assertFalse((self.directory/'apply-intent.json').exists())

    def test_changed_shared_rule_refuses_before_mutation(self):
        self.prepare()
        self.chain_map[('iptables','filter','INPUT')].append(['-A','INPUT','-j','DROP'])
        with self.assertRaisesRegex(ValueError, 'changed'): self.apply()
        self.assertFalse((self.directory/'apply-intent.json').exists())

    def test_review_expiry_each_boundary_and_no_replay(self):
        self.prepare()
        review = contract.load(self.review_path.read_bytes())
        for change in ({'portal_closed':False}, {'sessions_cleared':False}, {'plan_sha256':'0'*64},
                {'reviewed_at':time.time()+1}, {'expires_at':time.time()-1},
                {'expires_at':time.time()+600}, {'extra':True}, {'reviewed_at':float('nan')}):
            self.write('review.json', json.dumps({**review, **change}).encode())
            with self.subTest(change=change), self.assertRaises(ValueError): self.apply()
            self.assertFalse((self.directory/'apply-intent.json').exists())

    def test_expiry_after_guard_blocks_rule_insert_and_preserves_guard(self):
        self.prepare()
        # The parsed review is intentionally frozen; time itself must expire.
        now = time.time()
        value = self.review(); value['reviewed_at'] = now-1; value['expires_at'] = now+1
        self.write('review.json', json.dumps(value).encode())
        clock = [now]
        def run(args, **kwargs):
            result = self.dispatch(args, **kwargs)
            if args[:2] == ['nft','-f']: clock[0] = now+2
            return result
        with patch.object(upgrade.time, 'time', side_effect=lambda:clock[0]), patch.object(network,'run',side_effect=run):
            with self.assertRaisesRegex(ValueError, 'Fresh'): self.apply()
        self.assertEqual(self.guard, 'c'*64)
        self.assertFalse(any(args[0] == 'iptables' for args in self.commands))
        with self.assertRaises(ValueError): self.apply()

    def expire_after(self, trigger):
        self.prepare()
        now = time.time(); clock = [now]
        review = self.review(); review.update(reviewed_at=now-1, expires_at=now+1)
        self.write('review.json', json.dumps(review).encode())
        original_run, original_write, original_replace = self.dispatch, upgrade.files.json_new, upgrade.checked_replace
        inserted = [0]
        def run(args, **kwargs):
            result = original_run(args, **kwargs)
            if args[0] == 'iptables':
                inserted[0] += 1
                if trigger == 'first-insert' and inserted[0] == 1: clock[0] = now+2
                if trigger == 'last-insert' and inserted[0] == 2: clock[0] = now+2
            return result
        def write(path, value):
            result = original_write(path, value)
            if trigger == 'proof' and path.name == 'upgrade-proof.json': clock[0] = now+2
            return result
        def replace(path, raw, check, tag):
            result = original_replace(path, raw, check, tag)
            if trigger == 'intent' and contract.load(raw).get('phase') == 'intent': clock[0] = now+2
            return result
        with patch.object(upgrade.time,'time',side_effect=lambda:clock[0]), patch.object(network,'run',side_effect=run), \
                patch.object(upgrade.files,'json_new',side_effect=write), patch.object(upgrade,'checked_replace',side_effect=replace):
            with self.assertRaisesRegex(ValueError,'Fresh'): self.apply()
        self.assertEqual(network.saved_state()['phase'],'failed')
        with self.assertRaises(ValueError): self.apply()
        self.assertEqual(bootstrap.saved(),self.original)
        return inserted[0]

    def test_expiry_after_global_intent_prevents_guard_change(self):
        self.assertEqual(self.expire_after('intent'),0)
        self.assertEqual(self.guard,'b'*64)

    def test_expiry_after_preflight_before_durable_intent_preserves_live_receipt(self):
        self.prepare()
        real=upgrade.checkpoint; calls=[0]
        def checkpoint(*args):
            calls[0]+=1
            if calls[0]==2:raise ValueError('Fresh approval expired before intent')
            return real(*args)
        with patch.object(upgrade,'checkpoint',side_effect=checkpoint):
            with self.assertRaisesRegex(ValueError,'expired'):self.apply()
        self.assertFalse((self.directory/'apply-intent.json').exists())
        self.assertEqual(network.saved_state(),self.firewall)
        self.assertEqual(self.guard,'b'*64)
        with self.assertRaises(ValueError):self.apply()

    def test_expiry_between_insertions_prevents_next_rule(self):
        self.assertEqual(self.expire_after('first-insert'),1)
        self.assertEqual(self.guard,'c'*64)

    def test_expiry_after_final_rule_prevents_ready_publication(self):
        self.assertEqual(self.expire_after('last-insert'),2)
        self.assertFalse((self.directory/'upgrade-proof.json').exists())

    def test_expiry_after_proof_prevents_ready_publication(self):
        self.assertEqual(self.expire_after('proof'),2)
        self.assertTrue((self.directory/'upgrade-proof.json').exists())

    def test_expiry_while_receipt_temp_is_fsynced_prevents_rename(self):
        self.prepare()
        now = time.time(); clock = [now]
        review = self.review(); review.update(reviewed_at=now-1, expires_at=now+1)
        self.write('review.json',json.dumps(review).encode())
        original = upgrade.files.write_new
        def write(path, raw):
            value = original(path, raw)
            if path.name == 'state.json.upgrade-apply-intent': clock[0] = now+2
            return value
        with patch.object(upgrade.time,'time',side_effect=lambda:clock[0]), \
                patch.object(upgrade.files,'write_new',side_effect=write):
            with self.assertRaisesRegex(ValueError,'Fresh'): self.apply()
        self.assertEqual(self.guard,'b'*64)
        self.assertEqual(bootstrap.saved(),self.original)
        self.assertTrue((self.fw/'state.json.upgrade-apply-intent').exists())
        self.assertEqual(network.saved_state()['phase'],'failed')
        # Explicit rollback has a fresh approval and its own temp namespace;
        # the failed apply temp remains intact as provenance.
        self.review_path=self.write('review.json',json.dumps(self.review()).encode())
        self.rollback()
        self.assertEqual(network.saved_state(),self.firewall)
        self.assertTrue((self.fw/'state.json.upgrade-apply-intent').exists())

    def test_rollback_expiry_after_first_inverse_preserves_new_guard_and_refuses_retry(self):
        self.prepare(); self.apply()
        now = time.time(); clock = [now]
        review = self.review(); review.update(reviewed_at=now-1, expires_at=now+1)
        self.write('review.json',json.dumps(review).encode())
        def dispatch(args, **kwargs):
            value = self.dispatch(args, **kwargs)
            if args[0] == 'iptables': clock[0] = now+2
            return value
        with patch.object(upgrade.time,'time',side_effect=lambda:clock[0]), patch.object(network,'run',side_effect=dispatch):
            with self.assertRaisesRegex(ValueError,'Fresh'): self.rollback()
        self.assertEqual(self.guard,'c'*64)
        with self.assertRaises(ValueError): self.rollback()
        self.assertEqual(contract.load((self.directory/'rollback-result.json').read_bytes())['phase'],'failed')

    def test_listener_appearing_after_inverse_prevents_guard_drop(self):
        self.prepare(); self.apply()
        def dispatch(args, **kwargs):
            value = self.dispatch(args, **kwargs)
            if args[0] == 'iptables': self.listener=b'LISTEN 0 128 0.0.0.0:10222 *:*\n'
            return value
        with patch.object(network,'run',side_effect=dispatch):
            with self.assertRaisesRegex(ValueError,'listener'): self.rollback()
        self.assertEqual(self.guard,'c'*64)

    def test_missing_dispatch_intent_and_unknown_guard_refuse_rollback(self):
        self.prepare(); self.apply()
        self.guard='d'*64
        with self.assertRaisesRegex(ValueError,'Unknown independent'): self.rollback()
        self.guard='c'*64
        self.write('case/step-0-intent.json',b'{"argv":[]}')
        with self.assertRaisesRegex(ValueError,'dispatch intent'): self.rollback()

    def test_original_exception_survives_failed_failure_receipt(self):
        self.prepare()
        def inject(args):
            if args[:2] == ['nft','-f']: raise TimeoutError('Original uncertain guard dispatch')
        self.inject=inject
        with patch.object(network,'save',side_effect=RuntimeError('Secondary failed receipt')):
            with self.assertRaisesRegex(TimeoutError,'Original uncertain'): self.apply()
        with self.assertRaises(ValueError): self.apply()

    def test_known_partial_failure_rolls_back_exact_inverse(self):
        self.prepare(); baseline = copy.deepcopy(self.chain_map)
        count = [0]
        def failure(args):
            if args[0] == 'iptables':
                count[0] += 1
                if count[0] == 2: raise RuntimeError('Synthetic dispatch failure')
        self.inject = failure
        with self.assertRaisesRegex(RuntimeError, 'Synthetic'): self.apply()
        self.assertEqual(network.saved_state()['phase'], 'failed')
        with self.assertRaises(ValueError): self.apply()
        self.inject = None
        self.rollback()
        self.assertEqual(self.chain_map, baseline)

    def test_after_effect_uncertain_dispatch_is_reconciled_not_replayed(self):
        self.prepare(); baseline = copy.deepcopy(self.chain_map)
        real = self.dispatch
        def run(args, **kwargs):
            result = real(args, **kwargs)
            if args[0] == 'iptables': raise TimeoutError('Uncertain after insertion')
            return result
        with patch.object(network, 'run', side_effect=run), self.assertRaises(TimeoutError): self.apply()
        self.rollback()
        self.assertEqual(self.chain_map, baseline)

    def test_listener_blocks_rollback_before_any_policy_change(self):
        self.prepare(); self.apply()
        before = copy.deepcopy(self.chain_map)
        self.listener = b'LISTEN 0 128 [::]:10222 *:*\n'
        with self.assertRaisesRegex(ValueError, 'listener'): self.rollback()
        self.assertEqual(self.chain_map, before)
        self.assertEqual(self.guard, 'c'*64)
        self.assertFalse((self.directory/'rollback-intent.json').exists())

    def test_foreign_partial_rules_never_adopted_for_rollback(self):
        self.prepare(); self.apply()
        self.chain_map[('iptables','filter','INPUT')].append(['-A','INPUT','-j','DROP'])
        with self.assertRaisesRegex(ValueError, 'Unknown partial'): self.rollback()
        self.assertEqual(self.guard, 'c'*64)

    def test_proof_changed_missing_forged_foreign_binding_or_archive_refused(self):
        self.prepare(); self.apply()
        current = bootstrap.saved(); selected = current['binding']
        original_proof = (self.directory/'upgrade-proof.json').read_bytes()
        for changes in ({'new_binding':self.original['binding']}, {'network_id':'d'*64},
                        {'creation_boot_id':LATER_BOOT}, {'upgrade_boot_id':LATER_BOOT}, {'extra':'secret'}):
            proof = contract.load(original_proof); proof.update(changes)
            raw = json.dumps(proof).encode(); self.write('case/upgrade-proof.json', raw)
            changed = copy.deepcopy(current); changed['upgrade_proof']['sha256'] = contract.sha(raw)
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                contract.definition_binding(changed, selected)
        self.write('case/upgrade-proof.json', original_proof)
        changed = copy.deepcopy(current); changed['upgrade_proof']['sha256'] = '0'*64
        with self.assertRaises(ValueError): contract.definition_binding(changed, selected)
        changed = copy.deepcopy(current); del changed['upgrade_proof']
        with self.assertRaises(ValueError): contract.definition_binding(changed, selected)
        self.write('case/old-catalog.json', b'CHANGED ORIGINAL')
        with self.assertRaises(ValueError): contract.definition_binding(current, selected)

    def test_historical_creation_boot_and_review_survive_later_boot(self):
        self.prepare(); self.apply()
        current = bootstrap.saved(); current['boot_id'] = LATER_BOOT
        self.write('closed-route.conf',b'PUBLIC ROUTE REOPENED AFTER MAINTENANCE')
        self.write('sessions.json',b'NEW UNRELATED CENSUS')
        # Proof freshness is historical; boot does not re-authorize mutation.
        with patch.object(upgrade.time, 'time', return_value=time.time()+86400):
            self.assertEqual(contract.definition_binding(current, current['binding']), self.original['binding'])

    def test_boot_reconciliation_carries_proof_and_recreates_only_original_alias(self):
        self.prepare(); self.apply()
        current = bootstrap.saved(); selected = current['binding']
        cfg = network.parse_config(self.after)
        with patch.object(bootstrap,'inspect_network',return_value='a'*64), \
                patch.object(bootstrap,'inspect_bridge',return_value=False), patch.object(bootstrap,'empty'), \
                patch.object(bootstrap,'firewall_prerequisite',return_value={'mode':'cold_boot_absent'}), \
                patch.object(bootstrap,'archive_ready',return_value={'filename':'old.json','sha256':'e'*64}), \
                patch.object(network,'boot_id',return_value=LATER_BOOT), patch.object(bootstrap,'install') as install:
            bootstrap.reconcile('boot','portal-test',cfg,self.q,selected)
        receipt = install.call_args.args[0]
        self.assertEqual(receipt['definition_binding'],self.original['binding'])
        self.assertEqual(receipt['upgrade_proof'],current['upgrade_proof'])
        self.assertEqual(receipt['boot_id'],LATER_BOOT)
        self.assertEqual(contract.definition_binding(receipt,selected),self.original['binding'])
        with patch.object(bootstrap,'inspect_network'), patch.object(bootstrap,'inspect_bridge',side_effect=[False,True,True]), \
                patch.object(bootstrap,'empty'), patch.object(bootstrap,'firewall_prerequisite',return_value={'mode':'cold_boot_absent'}), \
                patch.object(bootstrap,'bridge_create') as create, patch.object(bootstrap,'policy_command'):
            receipt['bridge_recreation']={'mode':'cold_boot_absent'}
            bootstrap.install(receipt,'portal-test',cfg,self.q,selected,'a'*64,False,recreate_from=current)
        self.assertEqual(create.call_args.args,(cfg,self.original['binding']))

    def test_immutable_network_label_still_checked_against_original_definition(self):
        self.prepare(); self.apply()
        current = bootstrap.saved(); cfg = network.parse_config(self.after)
        row = dict(name='portal-test', id='a'*64, driver='bridge', network_interface=cfg.bridge,
            subnets=[{'subnet':cfg.subnet_ipv4,'gateway':cfg.gateway_ipv4}],
            labels={'guacamole.portal':'1',bootstrap.BIND_LABEL:network.digest(self.original['binding'])},
            ipv6_enabled=False,internal=False,dns_enabled=False,options={})
        with patch.object(bootstrap, 'inventory', return_value=[row]):
            self.assertEqual(bootstrap.inspect_network('portal-test',cfg,current['binding'],current),'a'*64)
            row['id'] = 'd'*64
            with self.assertRaises(RuntimeError): bootstrap.inspect_network('portal-test',cfg,current['binding'],current)

    def test_proof_archive_must_remain_private_single_link_and_non_symlink(self):
        self.prepare(); self.apply()
        current=bootstrap.saved(); selected=current['binding']
        path=self.directory/'old-network.json'
        path.chmod(0o644)
        with self.assertRaises(ValueError): contract.definition_binding(current,selected)
        path.chmod(0o600)
        os.link(path,self.directory/'extra-link')
        with self.assertRaises(ValueError): contract.definition_binding(current,selected)


if __name__ == '__main__': unittest.main()
