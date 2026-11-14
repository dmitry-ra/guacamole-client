#!/usr/bin/env python3
"""Focused inert checks for public source-input acquisition."""
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location('fetch_source_inputs',
                                             Path(__file__).with_name('fetch_source_inputs.py'))
FETCH = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(FETCH)


def record(raw, url='https://example.invalid/public.tar.gz'):
    return {'sha256': hashlib.sha256(raw).hexdigest(), 'url': url}


class InputFetchTest(unittest.TestCase):

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.inputs = self.root / 'inputs'
        self.inputs.mkdir()
        self.cache = self.root / 'cache'
        self.cache.mkdir()
        self.attempt = self.root / 'attempt'
        self.attempt.mkdir()

    def test_reuse_hash_matching_input_without_network_or_rewrite(self):
        path = self.inputs / 'source.tar.gz'
        path.write_bytes(b'public')
        before = path.stat()
        with patch.object(FETCH, 'download', side_effect=AssertionError('network called')):
            self.assertEqual(FETCH.install_locked(path.name, record(b'public'),
                             self.inputs, None, self.attempt, {}), 'reused')
        self.assertEqual(path.stat().st_ino, before.st_ino)
        self.assertEqual(path.stat().st_mtime_ns, before.st_mtime_ns)

    def test_mismatch_preserves_original(self):
        path = self.inputs / 'source.tar.gz'
        path.write_bytes(b'old-public')
        with self.assertRaisesRegex(ValueError, 'retained unchanged'):
            FETCH.install_locked(path.name, record(b'new-public'), self.inputs,
                                 self.cache, self.attempt, {})
        self.assertEqual(path.read_bytes(), b'old-public')

    def test_cache_copy_and_wrong_download_rejection(self):
        name = 'postgresql-42.7.14.jar'
        path = self.cache / 'dependencies' / name
        path.parent.mkdir()
        path.write_bytes(b'driver')
        with patch.object(FETCH, 'download', side_effect=AssertionError('network called')):
            FETCH.install_locked(name, record(b'driver'), self.inputs,
                                 self.cache, self.attempt, {})
        self.assertEqual((self.inputs / name).read_bytes(), b'driver')
        with patch.object(FETCH, 'download', side_effect=lambda url, path: path.write_bytes(b'bad')):
            with self.assertRaisesRegex(ValueError, 'hash/size mismatch'):
                FETCH.install_locked('source.tar.gz', record(b'good'), self.inputs,
                                     None, self.attempt, {})
        self.assertFalse((self.inputs / 'source.tar.gz').exists())
        self.assertEqual((self.attempt / 'source.tar.gz.download').read_bytes(), b'bad')

    def test_linked_leaf_parent_and_unsafe_url_refused(self):
        outside = self.root / 'outside'
        outside.write_bytes(b'public')
        (self.inputs / 'linked').symlink_to(outside)
        with self.assertRaisesRegex(ValueError, 'Linked input'):
            FETCH.install_locked('linked', record(b'public'), self.inputs,
                                 None, self.attempt, {})
        linked = self.root / 'linked-cache'
        linked.symlink_to(self.cache, target_is_directory=True)
        with self.assertRaisesRegex(ValueError, 'Linked input'):
            FETCH.checked(linked / 'missing', record(b'public'))
        for url in ('http://example.invalid/a', 'https://user:pass@example.invalid/a',
                    'file:///etc/passwd'):
            with self.subTest(url=url), self.assertRaises(ValueError):
                FETCH.https_url(url)

    def test_server_receipt_exact_bytes_and_hash(self):
        archive_hash = 'a' * 64
        commit = 'b' * 40
        raw = ('{"commit":"' + commit + '","archive_sha256":"' + archive_hash + '"}\n').encode()
        lock = {'server': {'commit': commit},
                'sources': {'guacamole-server-source.tar.gz': {'sha256': archive_hash}}}
        FETCH.install_locked('server-source.json', record(raw), self.inputs,
                             None, self.attempt, lock)
        self.assertEqual((self.inputs / 'server-source.json').read_bytes(), raw)

    def test_failed_attempt_has_failure_receipt_and_no_completed_input(self):
        lock_path = self.root / 'lock.json'
        lock_path.write_text(json.dumps({'sources': {'source.tar.gz': record(b'good')}}))
        with patch.object(FETCH, 'download', side_effect=TimeoutError('bounded transfer failed')):
            with self.assertRaisesRegex(TimeoutError, 'bounded transfer'):
                FETCH.fetch(self.inputs, lock_path=lock_path)
        attempts = list(self.inputs.glob('fetch-attempt-*'))
        self.assertEqual(len(attempts), 1)
        receipt = json.loads((attempts[0] / 'receipt.json').read_text())
        self.assertEqual(receipt['status'], 'failed')
        self.assertEqual(receipt['tomcat_signature'], 'not_verified')
        self.assertFalse((self.inputs / 'source.tar.gz').exists())

    def test_download_byte_limit_and_https_redirect_boundary(self):
        response = io.BytesIO(b'too much data')
        response.geturl = lambda: 'https://example.invalid/public'
        with patch.object(FETCH.urllib.request, 'urlopen', return_value=response):
            with self.assertRaisesRegex(ValueError, 'size limit'):
                FETCH.download('https://example.invalid/public', self.attempt / 'large', maximum=3)
        response = io.BytesIO(b'public')
        response.geturl = lambda: 'http://example.invalid/public'
        with patch.object(FETCH.urllib.request, 'urlopen', return_value=response):
            with self.assertRaisesRegex(ValueError, 'HTTPS'):
                FETCH.download('https://example.invalid/public', self.attempt / 'redirect')


if __name__ == '__main__':
    unittest.main()
