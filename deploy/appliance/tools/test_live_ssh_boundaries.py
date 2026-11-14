"""Inert SSH driver catalog, privacy and owned-browser cleanup boundaries."""
import asyncio
import json
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest.mock import patch

import test_live as live
import test_live_ssh as driver


class Boundaries(unittest.TestCase):
    def test_three_exact_aliases_and_ssh_membership(self):
        self.assertEqual(driver.aliases3('desktop-a,desktop-b,terminal-c', 'terminal-c'),
                         ['desktop-a', 'desktop-b', 'terminal-c'])
        for value, selected in [('a,b', 'b'), ('a,b,b', 'b'), ('a,b,c', 'missing'),
                                ('a,b,../secret', 'a'), ('a,b,c,d', 'a')]:
            with self.assertRaises(live.StaticFailure): driver.aliases3(value, selected)

    def test_native_tree_requires_protocols_and_unique_ids(self):
        tree = [{'alias': 'a', 'id': '1', 'protocol': 'rdp'}, {'alias': 'b', 'id': '2', 'protocol': 'rdp'},
                {'alias': 'c', 'id': '3', 'protocol': 'ssh'}]
        self.assertEqual(driver.ssh_mapping(tree, ['a','b','c'], 'c'), {'a':'1','b':'2','c':'3'})
        for mutation in [dict(tree[2], protocol='rdp'), dict(tree[2], id='2'),
                         dict(tree[2], secret='SECRET_KEY'), dict(tree[2], alias='other')]:
            with self.assertRaises(live.StaticFailure): driver.ssh_mapping([*tree[:2], mutation], ['a','b','c'], 'c')

    def test_canvas_receipt_never_retains_extra_payload_fields(self):
        good = dict(state='CONNECTED', status=0, width=800, height=600, nonblack=1000)
        self.assertEqual(driver.canvas_receipt(good), good)
        for mutation in [dict(good, text='SECRET_TERMINAL'), dict(good, status=519),
                         dict(good, width=True), dict(good, nonblack=480001), dict(good, state='DISCONNECTED')]:
            with self.assertRaises(live.StaticFailure): driver.canvas_receipt(mutation)

    def test_shared_network_telemetry_discards_url_headers_and_payload(self):
        receipt = {}
        telemetry = live.NetworkTelemetry('https://example.invalid/desktop/app/', receipt)
        telemetry.feed('Network.requestWillBeSent', {'requestId': 'local', 'request': {
            'url': 'https://example.invalid/desktop/app/api/tokens?token=SECRET_TOKEN',
            'method': 'POST', 'headers': {'Secret': 'SECRET_HEADER'}, 'postData': 'SECRET_OTP'}})
        telemetry.feed('Network.responseReceived', {'requestId': 'local', 'response': {
            'status': 200, 'url': 'SECRET_URL', 'headers': {'Secret': 'SECRET_COOKIE'}}})
        self.assertNotIn('SECRET', json.dumps(receipt))

    def test_failed_browser_start_removes_only_fresh_profile(self):
        with tempfile.TemporaryDirectory() as directory:
            fresh = Path(directory)/'owned'; fresh.mkdir()
            unrelated = Path(directory)/'owner'; unrelated.mkdir(); (unrelated/'keep').write_text('owner')
            args = SimpleNamespace(chrome='/usr/bin/google-chrome', directory=Path(directory))
            receipt = {'http': [], 'started_at': 0, 'driver_sha256': 'a'*64}
            with patch.object(driver.tempfile, 'mkdtemp', return_value=str(fresh)), \
                 patch.dict(driver.sys.modules, {'aiohttp': SimpleNamespace()}), \
                 patch.object(driver.subprocess, 'Popen', side_effect=OSError('SECRET_DETAIL')), \
                 patch.object(driver, 'stop_chrome') as stop:
                with self.assertRaises(OSError): asyncio.run(driver.browser(args, receipt))
            self.assertFalse(fresh.exists()); self.assertTrue((unrelated/'keep').exists())
            stop.assert_not_called()
            self.assertNotIn('SECRET', json.dumps(receipt))

    def test_root_rejected_before_creating_case_or_authentication(self):
        values = ['test_live_ssh.py', '--ssh-alias','c','--expected-catalog-aliases','a,b,c',
            '--expected-image','a'*64,'--base','https://example.invalid/desktop/app/',
            '--ssh-host','admin-example','--directory','/unused/new-case','--username','operator']
        with patch.object(driver.sys, 'argv', values), patch.object(driver.os, 'geteuid', return_value=0), \
             patch.object(driver, 'acceptance') as accept, patch.object(driver.Path, 'mkdir') as mkdir:
            with self.assertRaises(live.StaticFailure): driver.main()
            mkdir.assert_not_called(); accept.assert_not_called()

    def test_after_proof_failure_preserves_original_browser_error_without_payload(self):
        original = live.StaticFailure('Native SSH connection failed')
        async def browser(*args): raise original
        async def proof(*args):
            proof.calls += 1
            if proof.calls == 1: return {'safe': True}
            raise ValueError('SECRET_RAW_HELPER_ERROR')
        proof.calls = 0
        with tempfile.TemporaryDirectory() as directory:
            args = SimpleNamespace(directory=Path(directory), expected_image='a'*64)
            receipt = {'driver_sha256': 'b'*64}
            with patch.object(driver, 'browser', side_effect=browser), \
                 patch.object(driver.live, 'remote_proof', side_effect=proof):
                with self.assertRaises(live.StaticFailure) as caught:
                    asyncio.run(driver.acceptance(args, receipt))
            self.assertIs(caught.exception, original)
            self.assertEqual(proof.calls, 2)
            self.assertEqual(receipt['deployment_after_error_type'], 'ValueError')
            self.assertNotIn('SECRET', json.dumps(receipt))


if __name__ == '__main__': unittest.main()
