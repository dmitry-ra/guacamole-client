"""Inert source-build input, archive boundary and packaging regression checks."""
import hashlib
import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest.mock import patch
import zipfile

import build_extension as tool


class InputsTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)

    def client(self):
        (self.root / 'artifacts').mkdir()
        data = io.BytesIO()
        with zipfile.ZipFile(data, 'w') as archive:
            archive.writestr('WEB-INF/lib/guacamole-ext-test.jar', b'synthetic')
        war = data.getvalue()
        (self.root / 'artifacts/guacamole.war').write_bytes(war)
        self.receipt = {'schema': 1, 'status': 'success', 'guacamole_version': '1.6.1',
                        'source': {'head': 'a' * 40},
                        'tests': [{'tests': '1', 'errors': '0', 'failures': '0'}],
                        'artifacts': {'guacamole.war': {
                            'size': len(war), 'sha256': hashlib.sha256(war).hexdigest()}}}
        self.save()
        return war

    def save(self):
        (self.root / 'provenance.json').write_text(json.dumps(self.receipt))

    def test_current_source_version_and_war_binding(self):
        war = self.client()
        actual, version, identity = tool.client_input(self.root)
        self.assertEqual(actual, war)
        self.assertEqual(version, '1.6.1')
        self.assertEqual(identity['head'], 'a' * 40)
        (self.root / 'artifacts/guacamole.war').write_bytes(war + b'drift')
        with self.assertRaisesRegex(ValueError, 'differs'):
            tool.client_input(self.root)

    def test_failed_or_untested_build_is_not_an_input(self):
        self.client()
        for key, value in [('status', 'failure'), ('tests', []),
                           ('tests', [{'tests': '1', 'errors': '1', 'failures': '0'}]),
                           ('guacamole_version', '../1.6.1')]:
            original = self.receipt[key]
            self.receipt[key] = value
            self.save()
            with self.assertRaises(ValueError):
                tool.client_input(self.root)
            self.receipt[key] = original

    def test_flat_war_library_boundary(self):
        self.assertEqual(tool.war_libraries(self.client()),
                         {'guacamole-ext-test.jar': b'synthetic'})
        data = io.BytesIO()
        with zipfile.ZipFile(data, 'w') as archive:
            archive.writestr('WEB-INF/lib/../../escape.jar', b'bad')
        with self.assertRaisesRegex(ValueError, 'Unsafe'):
            tool.war_libraries(data.getvalue())

    def test_servlet_api_is_bound_to_locked_archive(self):
        path = self.root / 'apache-tomcat-9.0.123.tar.gz'
        with tarfile.open(path, 'w:gz') as archive:
            member = tarfile.TarInfo('apache-tomcat-9.0.123/lib/servlet-api.jar')
            member.size = len(b'synthetic-api')
            archive.addfile(member, io.BytesIO(b'synthetic-api'))
        lock = self.root / 'lock.json'
        lock.write_text(json.dumps({'sources': {path.name: {'sha256': tool.digest(path)}}}))
        self.assertEqual(tool.servlet_input(path, lock)[0], b'synthetic-api')
        path.write_bytes(path.read_bytes() + b'drift')
        with self.assertRaisesRegex(ValueError, 'differs'):
            tool.servlet_input(path, lock)

    def test_dynamic_version_and_resource_packaging(self):
        classes = self.root / 'classes'; classes.mkdir()
        (classes / 'PortalAuthenticationProvider.class').write_bytes(b'auth')
        (classes / 'PortalGateFilter.class').write_bytes(b'gate')
        web = self.root / 'web'; (web / 'translations').mkdir(parents=True)
        for name in ('target-selection.js', 'target-selection.css', 'translations/en.json'):
            (web / name).write_text('synthetic')
        with patch.object(tool, 'HERE', self.root):
            tool.write_jar(self.root / 'portal-auth.jar', classes, '1.6.1', True)
            tool.write_jar(self.root / 'portal-gate.jar', classes, '1.6.1', False)
        with zipfile.ZipFile(self.root / 'portal-auth.jar') as jar:
            self.assertEqual(json.loads(jar.read('guac-manifest.json'))['guacamoleVersion'], '1.6.1')
            self.assertIn('target-selection.css', jar.namelist())
            self.assertNotIn('PortalGateFilter.class', jar.namelist())
        with zipfile.ZipFile(self.root / 'portal-gate.jar') as jar:
            self.assertEqual(jar.namelist(), ['PortalGateFilter.class'])


if __name__ == '__main__':
    unittest.main()
