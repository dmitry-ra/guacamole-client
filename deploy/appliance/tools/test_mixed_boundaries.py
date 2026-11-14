"""Inert mixed fixture input, exact evidence and safe metadata boundaries."""
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

import test_mixed_image as fixture


class Boundaries(unittest.TestCase):
    def test_schema2_preserves_both_original_rdp_entries(self):
        old = json.loads((fixture.HERE.parent/'examples/config.json').read_bytes())
        new = json.loads(fixture.catalog_bytes('PUBLIC_SYNTHETIC_PIN'))
        self.assertIs(old['portal']['publish_target_labels'], False)
        self.assertEqual(dict(old['portal'], publish_target_labels=True), new['portal'])
        self.assertEqual(new['schema_version'], 2)
        for alias in ('desktop-a', 'desktop-b'):
            self.assertEqual(old['targets'][alias], new['targets'][alias])
        target = new['targets']['terminal-c']
        self.assertEqual(target['hostname'], '127.0.0.1')
        self.assertNotIn('password', target)
        self.assertNotIn('private-key', target)

    def test_exact_utf8_received_hash_not_canvas_is_required(self):
        item = {'sentinel': {'pid': 1, 'start': 2}, 'process': {'pid': 3, 'start': 4,
            'counter': 5, 'rows': 20, 'cols': 80, 'input_sha256': fixture.EXPECTED_INPUT}}
        self.assertEqual(fixture.safe_metadata(item), item)
        for mutation in [{'input_sha256': hashlib.sha256(b'wrong').hexdigest()},
                         {'rows': 'SECRET'}, {'cols': True}, {'secret': 'PRIVATE_KEY'}]:
            bad = dict(item, process=dict(item['process'], **mutation))
            with self.assertRaises(ValueError): fixture.safe_metadata(bad)

    def test_refusal_evidence_binds_image_hash_and_complete_cleanup(self):
        good = {'image': 'sha256:'+'a'*64, 'passed': True, 'cleanup_verified': True,
                'checks': {'wrong_pin': {'outcome': 'guacd_error', 'status': 512},
                           'wrong_appkey': {'status': 769}, 'none_denied': True, 'command_denied': True}}
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/'result.json'
            path.write_text(json.dumps(good))
            sha = hashlib.sha256(path.read_bytes()).hexdigest()
            self.assertEqual(fixture.refusal_proof(path, good['image'], sha), sha)
            for image, checksum in [('sha256:'+'b'*64, sha), (good['image'], '0'*64)]:
                with self.assertRaises(ValueError): fixture.refusal_proof(path, image, checksum)
            bad = dict(good, cleanup_verified=False)
            path.write_text(json.dumps(bad))
            with self.assertRaises(ValueError):
                fixture.refusal_proof(path, good['image'], hashlib.sha256(path.read_bytes()).hexdigest())

    def test_arbitrary_metadata_never_projected(self):
        with self.assertRaises(ValueError): fixture.safe_metadata({'secret': 'PRIVATE_KEY'})

    def test_root_browser_identity_refused(self):
        for uid in [0, -1, True, '1000']:
            with self.assertRaises(ValueError): fixture.browser_identity(uid)


if __name__ == '__main__': unittest.main()
