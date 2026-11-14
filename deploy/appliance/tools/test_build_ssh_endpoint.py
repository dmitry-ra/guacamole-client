"""Read-only endpoint input selection and drift refusal; no engine operations."""
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import build_ssh_endpoint as builder


class EndpointInputsTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.tools = self.root/'tools'; self.tools.mkdir()
        self.recipe = (builder.HERE/'ssh-endpoint.Containerfile').read_bytes()
        self.lock = json.loads((builder.HERE.parent/'source-inputs-lock.json').read_text())
        self.ca = self.root/'bootstrap-ca-certificates.crt'
        self.ca.write_bytes(b'SYNTHETIC PUBLIC CA INPUT')
        self.lock['sources']['bootstrap-ca-certificates.crt']['sha256'] = hashlib.sha256(self.ca.read_bytes()).hexdigest()
        (self.root/'source-inputs-lock.json').write_text(json.dumps(self.lock))
        (self.tools/'ssh-endpoint.Containerfile').write_bytes(self.recipe)
        self.patch = patch.object(builder, 'HERE', self.tools)
        self.patch.start(); self.addCleanup(self.patch.stop)

    def test_current_lock_alone_accepts_exact_recipe_and_ca_bytes(self):
        self.assertFalse((self.root/'images-lock.json').exists())
        with patch.object(builder.subprocess, 'run', side_effect=AssertionError('No engine call permitted')):
            self.assertEqual(builder.inputs(self.ca), (self.recipe, self.ca.read_bytes()))
        (self.root/'images-lock.json').write_text('{"obsolete":true}')
        self.assertEqual(builder.inputs(self.ca), (self.recipe, self.ca.read_bytes()))

    def test_changed_ca_is_rejected_without_build(self):
        self.ca.write_bytes(b'CHANGED PUBLIC CA INPUT')
        with self.assertRaisesRegex(ValueError, 'CA checksum mismatch'):
            builder.inputs(self.ca)

    def test_base_drift_is_rejected(self):
        changed = self.recipe.replace(self.lock['base_image'].encode(), b'ubuntu:latest')
        self.assertNotEqual(changed, self.recipe)
        (self.tools/'ssh-endpoint.Containerfile').write_bytes(changed)
        with self.assertRaisesRegex(ValueError, 'base/snapshot drift'):
            builder.inputs(self.ca)

    def test_snapshot_drift_is_rejected(self):
        changed = self.recipe.replace(self.lock['apt_snapshot'].encode(), b'20000101T000000Z')
        self.assertNotEqual(changed, self.recipe)
        (self.tools/'ssh-endpoint.Containerfile').write_bytes(changed)
        with self.assertRaisesRegex(ValueError, 'base/snapshot drift'):
            builder.inputs(self.ca)


if __name__ == '__main__':
    unittest.main()
