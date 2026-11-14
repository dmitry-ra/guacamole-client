#!/usr/bin/env python3
"""Source-artifact binding checks without Maven, containers or network."""
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location('build_source_image',
                                             Path(__file__).with_name('build_image.py'))
BUILD = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(BUILD)
SCHEMA = 'extensions/guacamole-auth-jdbc/modules/guacamole-auth-jdbc-postgresql/schema/'


class SourceFreezeTest(unittest.TestCase):

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.checkout = self.root / 'checkout'
        self.checkout.mkdir()
        native = {'pom.xml': b'<project xmlns="http://maven.apache.org/POM/4.0.0"><properties><revision>1.6.1</revision></properties></project>',
                  SCHEMA + '001-create-schema.sql': b'CREATE TABLE synthetic(id INTEGER);',
                  SCHEMA + 'upgrade/upgrade-pre-1.6.1.sql': b'ALTER TABLE synthetic ADD value INTEGER;'}
        files = {}
        for name, raw in native.items():
            path = self.checkout / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(raw)
            files[name] = {'sha256': BUILD.digest(path), 'mode': 0o644}
        self.build = self.root / 'build'
        self.build.mkdir()
        artifacts = {'guacamole.war': b'fake WAR',
                     'extensions/guacamole-auth-jdbc-postgresql.jar': b'fake JDBC',
                     'extensions/guacamole-auth-totp.jar': b'fake TOTP',
                     'extensions/guacamole-auth-ban.jar': b'fake ban'}
        artifacts.update({'postgresql/schema/' + name[len(SCHEMA):]: raw
                          for name, raw in native.items() if name.startswith(SCHEMA)})
        records = {}
        for name, raw in artifacts.items():
            path = self.build / 'artifacts' / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(raw)
            records[name] = {'sha256': BUILD.digest(path), 'size': len(raw)}
        self.receipt = {'schema': 1, 'status': 'success', 'guacamole_version': '1.6.1',
                        'source': {'head': 'a' * 40, 'files': files,
                                   'tree_sha256': hashlib.sha256(json.dumps(files, sort_keys=True,
                                        separators=(',', ':')).encode('ascii')).hexdigest()},
                        'toolchain': {'java_version': 'openjdk version "25.0.5" 2026-10-20'},
                        'artifacts': records}
        self.receipt_path = self.build / 'provenance.json'
        self.save()
        self.addCleanup(patch.stopall)
        patch.object(BUILD, 'HERE', self.checkout / 'deploy/appliance').start()
        patch.object(BUILD, 'run', side_effect=lambda command, **kwargs: subprocess.CompletedProcess(
            command, 0, stdout=('a' * 40 + '\n') if 'rev-parse' in command else
            b'\0'.join(name.encode() for name in files) + b'\0')).start()

    def save(self):
        self.receipt_path.write_text(json.dumps(self.receipt))

    def freeze(self):
        return BUILD.freeze_client(self.build, self.root / 'frozen')

    def test_complete_native_namespace_and_schema_freezes(self):
        self.freeze()
        self.assertEqual((self.root / 'frozen/client-source-build.json').read_bytes(),
                         self.receipt_path.read_bytes())
        self.assertTrue((self.root / 'frozen/postgresql/schema/upgrade/upgrade-pre-1.6.1.sql').is_file())

    def test_missing_sql_rejected(self):
        del self.receipt['artifacts']['postgresql/schema/upgrade/upgrade-pre-1.6.1.sql']
        self.save()
        with self.assertRaisesRegex(RuntimeError, 'namespace differs'):
            self.freeze()

    def test_changed_sql_cannot_be_blessed_by_artifact_receipt(self):
        name = 'postgresql/schema/001-create-schema.sql'
        path = self.build / 'artifacts' / name
        path.write_bytes(b'different SQL')
        self.receipt['artifacts'][name] = {'size': path.stat().st_size, 'sha256': BUILD.digest(path)}
        self.save()
        with self.assertRaisesRegex(RuntimeError, 'SQL differs from native source'):
            self.freeze()

    def test_additional_sql_outside_native_schema_rejected(self):
        self.receipt['artifacts']['postgresql/schema/extra.sql'] = {
            'size': 1, 'sha256': 'a' * 64}
        self.save()
        with self.assertRaisesRegex(RuntimeError, 'namespace differs'):
            self.freeze()

    def test_linked_war_rejected(self):
        path = self.build / 'artifacts/guacamole.war'
        retained = self.root / 'retained.war'
        path.rename(retained)
        path.symlink_to(retained)
        with self.assertRaisesRegex(RuntimeError, 'Regular input'):
            self.freeze()

    def test_version_mismatch_rejected(self):
        self.receipt['guacamole_version'] = '1.6.0'
        self.save()
        with self.assertRaisesRegex(RuntimeError, 'Maven revision'):
            self.freeze()

    def test_original_validated_receipt_bytes_retained_if_input_changes(self):
        original_bytes = self.receipt_path.read_bytes()
        loads = json.loads
        def parse_then_change(raw):
            parsed = loads(raw)
            self.receipt_path.write_bytes(b'changed after parse')
            return parsed
        with patch.object(BUILD.json, 'loads', side_effect=parse_then_change):
            self.freeze()
        self.assertEqual((self.root / 'frozen/client-source-build.json').read_bytes(), original_bytes)

    def test_native_file_changes_rejected(self):
        (self.checkout / 'pom.xml').write_bytes(b'changed native source')
        with self.assertRaisesRegex(RuntimeError, 'native source changed'):
            self.freeze()


    def test_native_manifest_digest_corruption_rejected(self):
        self.receipt['source']['tree_sha256'] = '0' * 64
        self.save()
        with self.assertRaisesRegex(RuntimeError, 'manifest digest differs'):
            self.freeze()

    def test_added_native_source_namespace_rejected(self):
        path = self.checkout / 'new-native.java'
        path.write_bytes(b'class NewNative {}')
        names = list(self.receipt['source']['files']) + ['new-native.java']
        with patch.object(BUILD, 'run', return_value=subprocess.CompletedProcess(
                [], 0, stdout=b'\0'.join(name.encode() for name in names) + b'\0')):
            with self.assertRaisesRegex(RuntimeError, 'native source namespace changed'):
                self.freeze()

    def test_linked_artifact_parent_rejected(self):
        artifacts = self.build / 'artifacts'
        retained = self.root / 'retained-artifacts'
        artifacts.rename(retained)
        artifacts.symlink_to(retained, target_is_directory=True)
        with self.assertRaisesRegex(RuntimeError, 'Artifact symlink parent refused'):
            self.freeze()

    def test_traversal_artifact_namespace_rejected(self):
        self.receipt['artifacts']['../escape.sql'] = {'size': 1, 'sha256': 'a' * 64}
        self.save()
        with self.assertRaisesRegex(RuntimeError, 'namespace differs'):
            self.freeze()
        self.assertFalse((self.root / 'escape.sql').exists())


class CurrentCheckoutFreezeTest(unittest.TestCase):

    def test_actual_native_manifest_with_synthetic_application_artifacts(self):
        """Read the selected checkout only; no compilation or checkout mutation."""
        checkout = BUILD.HERE.parents[1]
        selected = BUILD.run(['git', '-C', checkout, 'ls-files', '-z', '--cached',
                              '--others', '--exclude-standard'], capture_output=True).stdout
        names = sorted({name.decode('utf-8') for name in selected.split(b'\0') if name
                        and name != b'AGENTS.md' and not name.startswith(b'deploy/')
                        and (checkout / name.decode('utf-8')).is_file()})
        files = {name: {'sha256': BUILD.digest(checkout / name),
                        'mode': 0o755 if (checkout / name).stat().st_mode & 0o111 else 0o644}
                 for name in names}
        self.assertGreater(len(files), 1000)
        self.assertIn('pom.xml', files)
        head = BUILD.run(['git', '-C', checkout, 'rev-parse', 'HEAD'],
                         capture_output=True, text=True).stdout.strip()
        revision = BUILD.ET.parse(checkout / 'pom.xml').findtext(
            '{http://maven.apache.org/POM/4.0.0}properties/'
            '{http://maven.apache.org/POM/4.0.0}revision')
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            build = root / 'build'
            build.mkdir()
            artifacts = {'guacamole.war': b'synthetic WAR',
                         'extensions/guacamole-auth-jdbc-postgresql.jar': b'synthetic JDBC',
                         'extensions/guacamole-auth-totp.jar': b'synthetic TOTP',
                         'extensions/guacamole-auth-ban.jar': b'synthetic ban'}
            artifacts.update({'postgresql/schema/' + name[len(SCHEMA):]:
                              (checkout / name).read_bytes() for name in names
                              if name.startswith(SCHEMA) and name.endswith('.sql')})
            records = {}
            for name, raw in artifacts.items():
                path = build / 'artifacts' / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(raw)
                records[name] = {'sha256': BUILD.digest(path), 'size': len(raw)}
            tree = hashlib.sha256(json.dumps(files, sort_keys=True,
                                             separators=(',', ':')).encode('ascii')).hexdigest()
            receipt = {'schema': 1, 'status': 'success', 'guacamole_version': revision,
                       'source': {'head': head, 'files': files, 'tree_sha256': tree},
                       'toolchain': {'java_version': 'openjdk version "25.0.5"'},
                       'artifacts': records}
            (build / 'provenance.json').write_text(json.dumps(receipt))
            frozen = BUILD.freeze_client(build, root / 'frozen')
            self.assertEqual(head, frozen['source']['head'])
            self.assertEqual(len(names), len(frozen['source']['files']))
            self.assertEqual(tree, frozen['source']['tree_sha256'])
            self.assertEqual(records, frozen['artifacts'])


if __name__ == '__main__':
    unittest.main()
