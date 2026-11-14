"""Native fixture uncertain-dispatch cleanup boundaries; no engine calls."""
import json
from pathlib import Path
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import test_current_image as fixture
import catalog
import current_migration


class CleanupTests(unittest.TestCase):
    def execute(self, mismatch=False, unavailable=False):
        image='a'*64;cid='b'*64;token='c'*32
        name='portal-current-pg-'+token
        original=subprocess.TimeoutExpired(['podman','run'],180)
        calls=[]
        def engine(*args,**kwargs):
            calls.append(args)
            if args[0]=='run':raise original
            if args[:2]==('container','exists'):
                if unavailable:return SimpleNamespace(returncode=125)
                removed=any(call==('rm',cid) for call in calls)
                return SimpleNamespace(returncode=1 if removed else 0)
            if args[0]=='inspect':
                value={'Id':cid,'Image':image,'Name':name,
                    'Config':{'Labels':{fixture.LABEL:'wrong' if mismatch else token}},
                    'State':{'Running':True}}
                return SimpleNamespace(stdout=json.dumps([value]).encode())
            return SimpleNamespace(returncode=0)
        with tempfile.TemporaryDirectory() as path:
            directory=Path(path)
            with patch.object(fixture,'engine',side_effect=engine),patch.object(fixture.secrets,'token_hex',return_value=token):
                with self.assertRaises(subprocess.TimeoutExpired) as caught:
                    fixture.run_owned(image,directory,directory,directory,directory,'pass','prepare')
            self.assertIs(caught.exception,original)
        return calls,original,cid,name

    def test_timeout_before_cid_creation_reconciles_owned_name_and_removes_exact_id(self):
        calls,error,cid,name=self.execute()
        self.assertIn(('inspect',name),calls)
        self.assertIn(('stop','--time=10',cid),calls)
        self.assertIn(('rm',cid),calls)
        self.assertFalse(getattr(error,'__notes__',[]))

    def test_wrong_ownership_cannot_remove_and_preserves_original_dispatch_failure(self):
        calls,error,_,_=self.execute(mismatch=True)
        self.assertFalse(any(call[0] in ('stop','rm') for call in calls))
        self.assertIn('Owned fixture cleanup failed: AssertionError',error.__notes__)

    def test_engine_error_is_not_absence_and_preserves_original_failure(self):
        calls,error,_,_=self.execute(unavailable=True)
        self.assertFalse(any(call[0] in ('stop','rm') for call in calls))
        self.assertIn('Owned fixture cleanup failed: AssertionError',error.__notes__)


class ConfigurationTests(unittest.TestCase):
    def test_privacy_native_gate_keeps_existing_mixed_catalog_and_only_hides_labels(self):
        examples = Path(fixture.__file__).resolve().parents[1]/'examples'
        old_raw,new_raw = fixture.fixture_configuration('hide-labels',examples)
        old,new = json.loads(old_raw),json.loads(new_raw)
        public = json.loads((examples/'config-ssh.json').read_bytes())
        expected = json.loads((examples/'config-ssh.json').read_bytes())
        expected['portal']['publish_target_labels'] = True
        self.assertEqual(old,expected)
        self.assertEqual(json.loads((examples/'config-ssh.json').read_bytes()),public)
        self.assertTrue(old['portal']['publish_target_labels'])
        self.assertFalse(new['portal']['publish_target_labels'])
        new['portal']['publish_target_labels'] = True
        self.assertEqual(old,new)
        previous,registry = catalog.parse(old),catalog.parse(json.loads(new_raw))
        mapping = {t.alias:i for i,t in enumerate(previous.targets,1)}
        self.assertEqual(current_migration.plan(previous,registry,mapping),(mapping,[]))

    def test_append_inputs_unchanged_and_unknown_mode_rejected(self):
        examples = Path(fixture.__file__).resolve().parents[1]/'examples'
        old,new = fixture.fixture_configuration('append-ssh',examples)
        self.assertEqual(old,(examples/'config.json').read_bytes())
        self.assertEqual(new,(examples/'config-ssh.json').read_bytes())
        with self.assertRaises(ValueError):fixture.fixture_configuration('reenable-labels',examples)

    def test_native_payloads_compile_without_execution(self):
        compile(fixture.PREPARE,'prepare','exec')
        compile(fixture.MIGRATE,'migrate','exec')


if __name__=='__main__':unittest.main()
