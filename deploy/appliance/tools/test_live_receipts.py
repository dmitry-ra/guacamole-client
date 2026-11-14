#!/usr/bin/env python3
"""Offline deployment-proof and observed-browser-base boundary tests."""
import contextlib
import copy
import importlib.util
import io
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import AsyncMock, patch

SPEC = importlib.util.spec_from_file_location('portal_test_live', Path(__file__).with_name('test_live.py'))
live = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(live)
IMAGE = 'a' * 64


def proof():
    return {'container_id': 'b' * 64, 'run_id': 'c' * 32, 'image_id': 'sha256:' + IMAGE,
            'config_sha256': 'd' * 64, 'network_sha256': 'e' * 64, 'release_sha256': 'f' * 64}


class ProofBoundaryTests(unittest.TestCase):
    def test_two_windows_and_optional_ssh_have_distinct_exact_catalog_ids(self):
        expected = live.expected_catalog_aliases(['desktop-a', 'desktop-b'], 'terminal-c')
        rows = [{'alias':name,'id':str(index)} for index,name in enumerate(expected,1)]
        self.assertEqual(live.catalog_mapping(rows,expected),
                         {'desktop-a':'1','desktop-b':'2','terminal-c':'3'})
        self.assertEqual(live.expected_catalog_aliases(['desktop-a','desktop-b']),
                         ['desktop-a','desktop-b'])
        for bad in (rows[:2], rows+[{'alias':'extra','id':'4'}],
                    [*rows[:2],{'alias':'terminal-c','id':'2'}],
                    [*rows[:2],{'alias':'terminal-c','id':3}]):
            with self.subTest(rows=bad),self.assertRaises(live.StaticFailure):
                live.catalog_mapping(bad,expected)
        for alias in ('desktop-a','../terminal',''):
            with self.assertRaises(live.StaticFailure):
                live.expected_catalog_aliases(['desktop-a','desktop-b'],alias)

    def test_identical_exact_proofs_pass(self):
        before = proof()
        live.require_same_proof(before, copy.deepcopy(before), IMAGE)

    def test_each_changed_admission_identity_is_rejected(self):
        for key in proof():
            with self.subTest(key=key):
                after = proof()
                after[key] = ('sha256:' if key == 'image_id' else '') + '1' * (32 if key == 'run_id' else 64)
                with self.assertRaises(live.StaticFailure):
                    live.require_same_proof(proof(), after, IMAGE)

    def test_extra_fields_and_noncanonical_identities_are_rejected(self):
        for key, value in [('token', 'must-never-be-present'), ('run_id', 'x' * 32),
                           ('image_id', IMAGE), ('container_id', 'b' * 63)]:
            with self.subTest(key=key):
                invalid = proof()
                invalid[key] = value
                with self.assertRaises(live.StaticFailure):
                    live.validate_proof(invalid, IMAGE)

    def test_root_helper_rejects_changed_run_inside_capture(self):
        self.run_root_helper(change='run_id', should_pass=False)

    def test_root_helper_rejects_changed_config_inside_capture(self):
        self.run_root_helper(change='config_sha256', should_pass=False)

    def test_root_helper_emits_only_agreed_nonsecret_proof(self):
        output = self.run_root_helper(change=None, should_pass=True)
        import json
        self.assertEqual(json.loads(output), proof())

    def run_root_helper(self, change, should_pass):
        initial = proof()
        release = {'image_id': initial['image_id'], 'config_sha256': initial['config_sha256'],
                   'network_sha256': initial['network_sha256']}
        record = {'container_id': initial['container_id'], 'run_id': initial['run_id'],
                  'phase': 'ready', 'image_id': initial['image_id'], 'release_sha256': initial['release_sha256']}
        calls = [0]
        def selection():
            calls[0] += 1
            result = dict(release)
            if calls[0] == 2 and change == 'config_sha256':
                result['config_sha256'] = '1' * 64
            return result, 'validated_network_config', (initial['release_sha256'],)
        def state(_):
            result = dict(record)
            if calls[0] == 2 and change == 'run_id':
                result['run_id'] = '1' * 32
            return result
        fake_host = SimpleNamespace(selection=selection, private_json=state, STATE=Path('/unused'),
            identifier=lambda value, length=64: value,
            owned=lambda rec, cid: {'State': {'Running': True}}, ready_owned=lambda run: True,
            guards=lambda rel, cfg: [initial['container_id']])
        output = io.StringIO()
        with patch.object(live.os, 'geteuid', return_value=0), patch.object(live.signal, 'alarm'), \
                patch.dict(sys.modules, {'host': fake_host}), patch.object(sys, 'path', list(sys.path)), \
                contextlib.redirect_stdout(output):
            if should_pass:
                live.root_deployment_proof(SimpleNamespace(expected_image=IMAGE))
            else:
                with self.assertRaises(live.StaticFailure):
                    live.root_deployment_proof(SimpleNamespace(expected_image=IMAGE))
                self.assertEqual(output.getvalue(), '')
        return output.getvalue()


class ProofOrchestrationTests(unittest.IsolatedAsyncioTestCase):
    async def test_failed_preproof_cannot_open_browser(self):
        browser = AsyncMock()
        with patch.object(live, 'remote_proof', AsyncMock(side_effect=live.StaticFailure('proof unavailable'))), \
                patch.object(live, 'browser', browser), patch.object(live, 'mark_phase'):
            with self.assertRaises(live.StaticFailure):
                await live.acceptance(SimpleNamespace(expected_image=IMAGE), {})
        browser.assert_not_awaited()

    async def test_changed_postproof_rejects_successful_browser(self):
        changed = proof()
        changed['run_id'] = '1' * 32
        with patch.object(live, 'remote_proof', AsyncMock(side_effect=[proof(), changed])), \
                patch.object(live, 'browser', AsyncMock()), patch.object(live, 'mark_phase'):
            with self.assertRaisesRegex(live.StaticFailure, 'Deployment changed'):
                await live.acceptance(SimpleNamespace(expected_image=IMAGE), {})

    async def test_postproof_does_not_mask_original_browser_failure(self):
        original = live.StaticFailure('original browser failure')
        receipt = {}
        with patch.object(live, 'remote_proof', AsyncMock(side_effect=[proof(), live.StaticFailure('postproof failed')])), \
                patch.object(live, 'browser', AsyncMock(side_effect=original)), patch.object(live, 'mark_phase'):
            with self.assertRaises(live.StaticFailure) as caught:
                await live.acceptance(SimpleNamespace(expected_image=IMAGE), receipt)
        self.assertIs(caught.exception, original)
        self.assertEqual(receipt['deployment_after_error_type'], 'StaticFailure')


class BrowserBoundaryTests(unittest.TestCase):
    def test_actual_public_and_private_bases(self):
        for base, observed in [
            ('https://portal.example.invalid/desktop/app/', {'scheme': 'https', 'host': 'portal.example.invalid', 'port': '', 'path': '/desktop/app/'}),
            ('http://127.0.0.1:10432/guacamole/', {'scheme': 'http', 'host': '127.0.0.1', 'port': '10432', 'path': '/guacamole/'}),
        ]:
            self.assertEqual(live.observed_base(observed, base), base)

    def test_unexpected_browser_scheme_host_port_path_rejected(self):
        base = 'https://portal.example.invalid/desktop/app/'
        observed = {'scheme': 'https', 'host': 'portal.example.invalid', 'port': '', 'path': '/desktop/app/'}
        for key, value in [('scheme', 'http'), ('host', 'other.example.invalid'),
                           ('port', '10432'), ('path', '/guacamole/')]:
            with self.subTest(key=key):
                changed = dict(observed)
                changed[key] = value
                with self.assertRaises(live.StaticFailure):
                    live.observed_base(changed, base)

    def test_private_run_cannot_be_labeled_public(self):
        with self.assertRaises(live.StaticFailure):
            live.observed_base({'scheme': 'http', 'host': '127.0.0.1', 'port': '10432', 'path': '/guacamole/'},
                               'https://portal.example.invalid/desktop/app/')

    def test_query_hash_or_token_fields_rejected(self):
        base = 'https://portal.example.invalid/desktop/app/'
        observed = {'scheme': 'https', 'host': 'portal.example.invalid', 'port': '', 'path': '/desktop/app/'}
        for key in ('hash', 'query', 'token'):
            with self.assertRaises(live.StaticFailure):
                live.observed_base({**observed, key: 'secret'}, base)

    def test_base_normalization_matches_browser_default_port(self):
        self.assertEqual(live.validate_base('https://PORTAL.example.invalid:443/desktop/app/'),
                         'https://portal.example.invalid/desktop/app/')


if __name__ == '__main__':
    unittest.main()
