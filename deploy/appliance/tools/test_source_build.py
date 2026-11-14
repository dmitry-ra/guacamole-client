#!/usr/bin/env python3
"""Local synthetic boundaries for selected-source build and provenance."""
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import source_build


class SourceBuildTests(unittest.TestCase):

    def test_dirty_source_bytes_are_frozen_and_identified(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            checkout = root / 'checkout'
            checkout.mkdir()
            (checkout / 'tracked.java').write_text('changed source')
            (checkout / 'new.java').write_text('new source')
            outputs = ['a' * 40 + '\n', b' M tracked.java\0?? new.java\0',
                       b'tracked.java\0new.java\0deleted.java\0']
            with patch.object(source_build, 'run', side_effect=outputs):
                receipt = source_build.freeze(checkout, root / 'frozen')
            self.assertEqual({'tracked.java', 'new.java'}, set(receipt['files']))
            self.assertEqual('changed source', (root / 'frozen/tracked.java').read_text())
            before = receipt['tree_sha256']
            (checkout / 'tracked.java').write_text('different source')
            with patch.object(source_build, 'run', side_effect=outputs):
                changed = source_build.freeze(checkout, root / 'second')
            self.assertNotEqual(before, changed['tree_sha256'])
            self.assertEqual('changed source', (root / 'frozen/tracked.java').read_text())

    def test_appliance_is_separate_from_native_maven_license_scope(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / 'source'
            (source / 'deploy/appliance').mkdir(parents=True)
            (source / 'pom.xml').write_text('native')
            (source / 'deploy/appliance/own.py').write_text('downstream')
            (source / 'AGENTS.md').write_text('instructions')
            files = {name: {'sha256': source_build.digest(source / name), 'mode': 0o644}
                     for name in ('pom.xml', 'deploy/appliance/own.py', 'AGENTS.md')}
            identity = source_build.split_native_source(source, root / 'downstream', {'files': files})
            self.assertEqual({'pom.xml'}, set(identity['files']))
            self.assertEqual({'deploy/appliance/own.py', 'AGENTS.md'}, set(identity['downstream_files']))
            self.assertFalse((source / 'deploy').exists())
            self.assertEqual('downstream', (root / 'downstream/deploy/appliance/own.py').read_text())
            self.assertNotEqual(identity['tree_sha256'], identity['selected_tree_sha256'])

    def test_source_symlink_and_escape_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            checkout = root / 'checkout'
            checkout.mkdir()
            (root / 'outside').write_text('outside')
            (checkout / 'linked').symlink_to(root / 'outside')
            for name in (b'linked\0', b'../outside\0'):
                destination = root / ('freeze-' + str(len(name)))
                with patch.object(source_build, 'run', side_effect=['a' * 40, b'', name]):
                    with self.assertRaises(ValueError):
                        source_build.freeze(checkout, destination)

    def test_collect_canonical_artifacts_and_complete_schema(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / 'source'
            source.mkdir()
            (source / 'pom.xml').write_text(
                '<project xmlns="http://maven.apache.org/POM/4.0.0">'
                '<properties><revision>1.6.1</revision></properties></project>')
            war = source / 'guacamole/target/guacamole-1.6.1.war'
            war.parent.mkdir(parents=True)
            war.write_bytes(b'synthetic WAR')
            for module in source_build.MODULES[1:]:
                jar = source / module / 'target' / (Path(module).name + '-1.6.1.jar')
                jar.parent.mkdir(parents=True)
                jar.write_bytes(module.encode('ascii'))
            schema = source / source_build.MODULES[1] / 'schema'
            (schema / 'upgrade').mkdir(parents=True)
            (schema / '001-create.sql').write_text('CREATE TABLE synthetic;')
            (schema / 'upgrade/upgrade-pre-1.6.0.sql').write_text('ALTER TABLE synthetic;')
            records = source_build.collect(source, root / 'artifacts')
            self.assertEqual(6, len(records))
            for name, record in records.items():
                self.assertEqual(source_build.digest(root / 'artifacts' / name), record['sha256'])
            self.assertIn('postgresql/schema/upgrade/upgrade-pre-1.6.0.sql', records)

    def test_unverified_cached_maven_is_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            cache = Path(directory)
            (cache / 'apache-maven-3.9.12-bin.tar.gz').write_bytes(b'wrong archive')
            with self.assertRaisesRegex(RuntimeError, 'checksum mismatch'):
                source_build.maven(cache)

    def test_build_deadline_stops_owned_process(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with self.assertRaises(subprocess.TimeoutExpired):
                source_build.bounded_build([sys.executable, '-c', 'import time; time.sleep(30)'],
                                           root, os.environ, root / 'log', 0.1)
            self.assertTrue((root / 'log').is_file())


if __name__ == '__main__':
    unittest.main()
