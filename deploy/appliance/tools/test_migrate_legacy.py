"""Migration-controller boundary tests; engine and instance access are mocked."""

import contextlib
import copy
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import migrate_legacy as migration


class MigrationCleanupTests(unittest.TestCase):
    image = 'sha256:' + 'a' * 64
    cid = 'b' * 64
    run_id = 'c' * 32

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='migration-controller-test-')
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.case = self.root / 'case'
        self.calls = []
        self.receipts = {}
        self.output = io.StringIO()
        previous_umask = os.umask(0o077)
        self.addCleanup(os.umask, previous_umask)
        self.stack = contextlib.ExitStack()
        self.addCleanup(self.stack.close)
        for target, replacement in (
                (migration.os, 'geteuid'), (migration.host, 'directory'),
                (migration.cold_copy, 'stopped_and_exclusive'),
                (migration.cold_copy, 'validate_cluster')):
            self.stack.enter_context(patch.object(target, replacement, return_value=0))
        self.stack.enter_context(patch.object(migration.secrets, 'token_hex', return_value=self.run_id))
        self.stack.enter_context(patch.object(migration.host.network, 'protected_read',
                                              return_value=b'{"synthetic":true}'))
        self.stack.enter_context(patch.object(migration.host, 'write', side_effect=self.write_receipt))
        self.stack.enter_context(patch.object(sys, 'argv', ['migrate_legacy.py', '--image', self.image,
            '--data', str(self.root / 'synthetic-data'), '--directory', str(self.case),
            '--original-alias', 'desktop-a']))
        self.stack.enter_context(contextlib.redirect_stdout(self.output))

    def write_receipt(self, path, value):
        self.receipts[path.name] = copy.deepcopy(value)
        path.write_text(json.dumps(value))

    def engine(self, *, missing_cid=False, absence=1, foreign=None, running=False,
               migration_error=None, cleanup_error=None, migration_code=0):
        def execute(*argv, **kwargs):
            self.calls.append(argv)
            if argv[0] == 'run':
                if not missing_cid:
                    (self.case / 'cid').write_text(self.cid + '\n')
                if migration_error is not None:
                    raise migration_error
                output = json.dumps({'migrated': True, 'identity_unchanged': True,
                                     'enrolled': True, 'connections': {'desktop-a': 1}}).encode()
                return subprocess.CompletedProcess(argv, migration_code, output, b'')
            if cleanup_error is not None and argv[0] == cleanup_error[0]:
                raise cleanup_error[1]
            if argv[0] == 'inspect':
                value = {'Id': self.cid, 'Image': self.image,
                         'Config': {'Labels': {migration.LABEL: self.run_id}},
                         'State': {'Running': running}}
                if foreign == 'id':
                    value['Id'] = 'd' * 64
                elif foreign == 'image':
                    value['Image'] = 'sha256:' + 'd' * 64
                elif foreign == 'label':
                    value['Config']['Labels'][migration.LABEL] = 'foreign-run'
                return subprocess.CompletedProcess(argv, 0, json.dumps([value]).encode(), b'')
            if argv[0] == 'container':
                return subprocess.CompletedProcess(argv, absence, b'', b'')
            if argv[0] in {'stop', 'rm'}:
                return subprocess.CompletedProcess(argv, 0, b'', b'')
            self.fail('Unexpected engine call')
        return patch.object(migration.host, 'engine', side_effect=execute)

    def assert_failed_receipt(self, cleanup_phase):
        result = self.receipts['receipt.json']
        self.assertIs(result['passed'], False)
        self.assertEqual(result['phase'], 'failed')
        self.assertIs(result['cleanup_verified'], False)
        self.assertEqual(result['cleanup_phase'], cleanup_phase)
        self.assertEqual(json.loads((self.case / 'receipt.json').read_text()), result)
        self.assertEqual(self.output.getvalue(), '')
        return result

    def test_success_requires_verified_absence_and_publishes_terminal_receipt(self):
        with self.engine():
            migration.main()
        result = self.receipts['receipt.json']
        self.assertEqual(result['phase'], 'passed')
        self.assertIs(result['passed'], True)
        self.assertIs(result['cleanup_verified'], True)
        self.assertEqual(result['cleanup_phase'], 'verified')
        self.assertEqual(result['cleanup_exists_returncode'], 1)
        self.assertEqual(json.loads(self.output.getvalue()), result)
        self.assertEqual(self.calls[-2:], [('rm', self.cid), ('container', 'exists', self.cid)])

    def test_missing_cid_after_success_cannot_claim_cleanup_or_success(self):
        with self.engine(missing_cid=True), self.assertRaisesRegex(RuntimeError, 'ID unconfirmed'):
            migration.main()
        self.assert_failed_receipt('confirm_cid')
        self.assertEqual(len(self.calls), 1)

    def test_exists_zero_is_failure_after_successful_migration(self):
        with self.engine(absence=0), self.assertRaisesRegex(RuntimeError, 'absence unconfirmed'):
            migration.main()
        result = self.assert_failed_receipt('verify_absence')
        self.assertEqual(result['cleanup_exists_returncode'], 0)

    def test_exists_engine_error_is_failure_after_successful_migration(self):
        with self.engine(absence=125), self.assertRaisesRegex(RuntimeError, 'absence unconfirmed'):
            migration.main()
        result = self.assert_failed_receipt('verify_absence')
        self.assertEqual(result['cleanup_exists_returncode'], 125)

    def test_foreign_id_image_or_label_never_authorizes_cleanup(self):
        for foreign in ('id', 'image', 'label'):
            with self.subTest(foreign=foreign):
                # Each main invocation needs an independent new case.
                self.case = self.root / foreign
                sys.argv[sys.argv.index('--directory') + 1] = str(self.case)
                self.calls.clear()
                with self.engine(foreign=foreign), self.assertRaisesRegex(RuntimeError, 'Foreign'):
                    migration.main()
                self.assert_failed_receipt('verify_ownership')
                self.assertEqual([call[0] for call in self.calls], ['run', 'inspect'])

    def test_running_owned_container_is_stopped_then_removed(self):
        with self.engine(running=True):
            migration.main()
        self.assertIn(('stop', '--time=10', self.cid), self.calls)
        self.assertIs(self.receipts['receipt.json']['passed'], True)

    def test_cleanup_engine_failure_still_writes_terminal_receipt(self):
        for operation, phase in (('inspect', 'verify_ownership'), ('stop', 'stop'), ('rm', 'remove')):
            with self.subTest(operation=operation):
                self.case = self.root / operation
                sys.argv[sys.argv.index('--directory') + 1] = str(self.case)
                error = TimeoutError('synthetic cleanup timeout')
                with self.engine(running=True, cleanup_error=(operation, error)), \
                        self.assertRaises(TimeoutError) as caught:
                    migration.main()
                self.assertIs(caught.exception, error)
                self.assertEqual(self.assert_failed_receipt(phase)['cleanup_error_type'], 'TimeoutError')

    def test_original_failure_is_preserved_when_cleanup_succeeds(self):
        original = ValueError('synthetic migration failure')
        with self.engine(migration_error=original), self.assertRaises(ValueError) as caught:
            migration.main()
        self.assertIs(caught.exception, original)
        result = self.receipts['receipt.json']
        self.assertEqual(result['phase'], 'failed')
        self.assertIs(result['passed'], False)
        self.assertIs(result['cleanup_verified'], True)
        self.assertEqual(result['error_type'], 'ValueError')
        self.assertEqual(self.output.getvalue(), '')

    def test_original_failure_is_preserved_when_foreign_cleanup_is_refused(self):
        original = OSError('synthetic migration failure')
        with self.engine(migration_error=original, foreign='label'), self.assertRaises(OSError) as caught:
            migration.main()
        self.assertIs(caught.exception, original)
        result = self.assert_failed_receipt('verify_ownership')
        self.assertEqual(result['error_type'], 'OSError')
        self.assertEqual(result['cleanup_error_type'], 'RuntimeError')

    def test_original_failure_is_preserved_when_cleanup_engine_errors(self):
        original = ValueError('synthetic migration failure')
        with self.engine(migration_error=original, cleanup_error=('inspect', TimeoutError())), \
                self.assertRaises(ValueError) as caught:
            migration.main()
        self.assertIs(caught.exception, original)
        result = self.assert_failed_receipt('verify_ownership')
        self.assertEqual(result['error_type'], 'ValueError')
        self.assertEqual(result['cleanup_error_type'], 'TimeoutError')

    def test_nonzero_migration_response_remains_failed_after_verified_cleanup(self):
        with self.engine(migration_code=5), self.assertRaisesRegex(RuntimeError, 'Migration failed'):
            migration.main()
        result = self.receipts['receipt.json']
        self.assertIs(result['passed'], False)
        self.assertIs(result['cleanup_verified'], True)

    def test_receipt_write_error_does_not_mask_original_failure(self):
        original = ValueError('synthetic migration failure')
        write = self.write_receipt
        def fail_terminal(path, value):
            if path.name == 'receipt.json':
                raise OSError('synthetic full disk')
            write(path, value)
        with patch.object(migration.host, 'write', side_effect=fail_terminal), \
                self.engine(migration_error=original), self.assertRaises(ValueError) as caught:
            migration.main()
        self.assertIs(caught.exception, original)
        self.assertIn('Terminal receipt write failed: OSError', original.__notes__)
        self.assertIs(self.receipts['intent.json']['passed'], False)
        self.assertEqual(self.output.getvalue(), '')


if __name__ == '__main__':
    unittest.main()
