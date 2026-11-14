"""CURRENT catalog migration validation; PostgreSQL/process operations mocked."""
import base64
import copy
import json
import os
from pathlib import Path
import struct
import tempfile
import unittest
from unittest.mock import patch
from types import SimpleNamespace

import catalog
import current_migration as migration
import runtime


def configurations():
    old=json.loads((Path(__file__).parent/'examples/config.json').read_bytes())
    # Exercise the explicit historical chooser fixture, not public defaults.
    old['portal']['publish_target_labels']=True
    new=copy.deepcopy(old);new['schema_version']=2
    key=struct.pack('>I',11)+b'ssh-ed25519'+struct.pack('>I',32)+bytes(range(32))
    new['targets']['terminal-c']={'protocol':'ssh','hostname':'192.0.2.30','port':10222,
        'username':'terminal-user','host_key':'[192.0.2.30]:10222 ssh-ed25519 '+base64.b64encode(key).decode(),
        'private_key_file':'terminal-c-key','command':'/usr/local/libexec/portal-tmux'}
    return old,new


def state(registry,mapping):
    result={name:0 for name in runtime.EMPTY_TABLES}
    result.update(entities=[[7,registry.username,'USER']],users=[[9,7,False,False]],
        connections=[[mapping[t.alias],t.alias,t.protocol,1,1,None,None,None,None,False,None] for t in registry.targets],
        parameters=[[i,k,v] for i,params in registry.parameters(mapping).items() for k,v in params.items()],
        permissions=[[7,i,'READ'] for i in mapping.values()],user_permissions=[[7,9,'READ']])
    return result


class PlanningTests(unittest.TestCase):
    def setUp(self):
        old,new=configurations();self.old=catalog.parse(old);self.new=catalog.parse(new)
        self.mapping={'desktop-a':7,'desktop-b':42}

    def test_only_append_ssh_above_maximum_preserving_rdp_exactly(self):
        mapping,added=migration.plan(self.old,self.new,self.mapping)
        self.assertEqual(mapping,{'desktop-a':7,'desktop-b':42,'terminal-c':43})
        self.assertEqual(added,['terminal-c'])
        for alias,ident in self.mapping.items():
            self.assertEqual(self.old.target(alias).parameters(),self.new.parameters(mapping)[ident])
        self.assertEqual(self.mapping,{'desktop-a':7,'desktop-b':42})

    def test_changed_old_settings_parameters_secret_reference_or_removal_rejected(self):
        old,new=configurations()
        variants=[]
        for field,value in [('username','other'),('default_target','desktop-b'),('publish_target_labels',False),
                            ('trusted_proxy_ipv4','192.0.2.1')]:
            obj=copy.deepcopy(new);obj['portal'][field]=value;variants.append(obj)
        for field,value in [('username','other-desktop-user'),('hostname','192.0.2.11'),
                            ('password_file','changed-password'),('label','changed-label')]:
            obj=copy.deepcopy(new);obj['targets']['desktop-a'][field]=value;variants.append(obj)
        obj=copy.deepcopy(new);del obj['targets']['desktop-b'];variants.append(obj)
        for obj in variants:
            with self.subTest(obj=obj),self.assertRaises((RuntimeError,ValueError)):
                migration.plan(self.old,catalog.parse(obj),self.mapping)

    def test_hide_labels_preserves_mapping_and_complete_census_without_sql_mutations(self):
        old, _ = configurations()
        hidden = copy.deepcopy(old)
        hidden['portal']['publish_target_labels'] = False
        registry = catalog.parse(hidden)
        mapping, added = migration.plan(self.old, registry, self.mapping)
        self.assertEqual(mapping, self.mapping)
        self.assertIsNot(mapping, self.mapping)
        self.assertEqual(added, [])
        before = state(self.old, self.mapping)
        after = migration.expected_snapshot(before, registry, mapping, added)
        self.assertEqual(after, migration.normalize(before))
        with patch.object(runtime, 'target_sql', side_effect=AssertionError('No target SQL permitted')):
            sql = migration.transaction(runtime, registry, mapping, added, before, after)
        for forbidden in ('INSERT ', 'UPDATE ', 'DELETE ', 'setval(', 'CREATE ROLE'):
            self.assertNotIn(forbidden, sql)
        self.assertIn('IN ACCESS EXCLUSIVE MODE', sql)
        self.assertIn('Prior complete census changed', sql)
        self.assertIn('Identity or TOTP changed', sql)

    def test_hide_labels_rejects_every_other_portal_or_target_change(self):
        old, mixed = configurations()
        for original in (old, mixed):
            mapping = {t.alias:i for i,t in enumerate(catalog.parse(original).targets,1)}
            hidden = copy.deepcopy(original)
            hidden['portal']['publish_target_labels'] = False
            changes = []
            for field, value in (('username','other'), ('default_target','desktop-b'),
                                 ('trusted_proxy_ipv4','192.0.2.1')):
                changed = copy.deepcopy(hidden)
                changed['portal'][field] = value
                changes.append(changed)
            for field, value in (('username','other'), ('hostname','192.0.2.11'),
                                 ('password_file','other-password'), ('label','Other')):
                changed = copy.deepcopy(hidden)
                changed['targets']['desktop-a'][field] = value
                changes.append(changed)
            for changed in changes:
                with self.subTest(changed=changed), self.assertRaises((RuntimeError,ValueError)):
                    migration.plan(catalog.parse(original),catalog.parse(changed),mapping)

    def test_hidden_labels_cannot_be_reenabled_or_combined_with_append(self):
        old, new = configurations()
        hidden = copy.deepcopy(old)
        hidden['portal']['publish_target_labels'] = False
        with self.assertRaises(RuntimeError):
            migration.plan(catalog.parse(hidden), self.old, self.mapping)
        with self.assertRaises(RuntimeError):
            migration.plan(catalog.parse(hidden), catalog.parse(hidden), self.mapping)
        new['portal']['publish_target_labels'] = False
        with self.assertRaises(RuntimeError):
            migration.plan(self.old, catalog.parse(new), self.mapping)

    def test_noop_rdp_addition_and_overflow_rejected(self):
        with self.assertRaises(RuntimeError):migration.plan(self.old,self.old,self.mapping)
        old,new=configurations();new['targets']['third-rdp']={**new['targets']['desktop-a'],'password_file':'third-password'}
        with self.assertRaises(RuntimeError):migration.plan(self.old,catalog.parse(new),self.mapping)
        with self.assertRaises(RuntimeError):migration.plan(self.old,self.new,{'desktop-a':1,'desktop-b':2147483647})
        for bad in ({'desktop-a':True,'desktop-b':42},{'desktop-a':7,'desktop-b':7}):
            with self.assertRaises((RuntimeError,ValueError)):migration.plan(self.old,self.new,bad)

    def test_complete_post_snapshot_and_transaction_do_not_rewrite_old_rdp(self):
        mapping,added=migration.plan(self.old,self.new,self.mapping)
        before=state(self.old,self.mapping);frozen=copy.deepcopy(before)
        after=migration.expected_snapshot(before,self.new,mapping,added)
        self.assertTrue(runtime.validate_snapshot(self.new,mapping,after))
        self.assertEqual(before,frozen)
        sql=migration.transaction(runtime,self.new,mapping,added,before,after)
        self.assertTrue(sql.startswith('BEGIN;'))
        self.assertTrue(sql.endswith('COMMIT;'))
        self.assertIn('IN ACCESS EXCLUSIVE MODE',sql)
        self.assertIn('CREATE TEMP TABLE portal_current_identity_guard ON COMMIT DROP',sql)
        self.assertIn("VALUES(43,'terminal-c','ssh',1,1)",sql)
        self.assertIn('${PORTAL_TARGET_TERMINAL_C_PRIVATE_KEY}',sql)
        for forbidden in ('UPDATE ','DELETE ','CREATE ROLE','CREATE TABLE guacamole_',"VALUES(7,","VALUES(42,"):
            self.assertNotIn(forbidden,sql)
        self.assertIn('Prior complete census changed',sql)
        self.assertIn('Appended complete census changed',sql)
        self.assertIn('Identity or TOTP changed',sql)


class MigrationTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.data=Path(self.temp.name)/'data';self.data.mkdir(mode=0o700)
        old,new=configurations();self.old_raw=json.dumps(old).encode();self.old=catalog.parse(old);self.new=catalog.parse(new)
        self.old_digest=migration.digest(self.old_raw);self.new_digest=migration.digest(json.dumps(new).encode())
        self.old_mapping={'desktop-a':7,'desktop-b':42};self.mapping,added=migration.plan(self.old,self.new,self.old_mapping)
        self.old_prepared=json.dumps(runtime.receipt(self.old_mapping,self.old_digest)).encode()
        self.before=state(self.old,self.old_mapping);self.after=state(self.new,self.mapping)
        self.identity={'users':[{'password_hash':'synthetic-hash','password_salt':'synthetic-salt'}],
                       'entities':[{'entity_id':7,'name':'operator'}],
                       'attributes':[{'attribute_name':'guac-totp-key-secret','attribute_value':'SYNTHETIC_PRIVATE_VALUE'}]}
        self.events=[];self.queries=[];self.committed=False
        patch.object(runtime,'DATA',self.data).start()
        patch.object(runtime,'RUN',Path(self.temp.name)/'run').start()
        patch.object(runtime,'protected_read',return_value=self.old_raw).start()
        patch.object(migration.os,'statvfs',return_value=SimpleNamespace(f_flag=os.ST_RDONLY)).start()
        patch.object(migration,'stopped_data').start()
        patch.object(migration,'prepared_bytes',return_value=self.old_prepared).start()
        patch.object(runtime,'check_cluster',side_effect=[self.old_mapping,self.mapping]).start()
        patch.object(runtime.life,'start_pg',side_effect=lambda:self.events.append('start-pg')).start()
        patch.object(runtime.life,'pg_sql',side_effect=self.execute).start()
        patch.object(runtime,'enrolled',return_value=True).start()
        patch.object(runtime,'database_health',return_value=True).start()
        patch.object(runtime,'save_receipt',side_effect=lambda *a:self.events.append('save-receipt')).start()
        self.addCleanup(patch.stopall)

    def execute(self,query,app=False):
        self.queries.append(query)
        if query==runtime.snapshot_query():
            self.events.append('post-census' if self.committed else 'old-census')
            return json.dumps(self.after if self.committed else self.before)
        if query==migration.IDENTITY_QUERY:
            self.events.append('post-identity' if self.committed else 'old-identity')
            return json.dumps(self.identity)
        self.assertTrue(query.startswith('BEGIN;'))
        self.assertNotIn('SYNTHETIC_PRIVATE_VALUE',query)
        self.events.append('transaction');self.committed=True;return ''

    def migrate(self):return migration.migrate(self.new,self.new_digest,Path('/config/previous.json'))

    def test_success_preserves_exact_old_receipt_and_identity_and_finalizes_last(self):
        result=self.migrate()
        self.assertTrue(result['migrated']);self.assertTrue(result['identity_unchanged'])
        self.assertEqual(result['connections'],self.mapping)
        self.assertEqual((self.data/migration.JOURNAL/'previous-prepared.json').read_bytes(),self.old_prepared)
        self.assertEqual((self.data/migration.JOURNAL/'previous-config.json').read_bytes(),self.old_raw)
        self.assertEqual(self.events,['start-pg','old-census','old-identity','transaction','post-census','post-identity','save-receipt'])
        runtime.save_receipt.assert_called_once_with(self.mapping,self.new_digest)
        self.assertEqual(json.loads((self.data/migration.JOURNAL/'result.json').read_bytes())['phase'],'ready')

    def test_old_census_drift_fails_before_transaction_and_burns_target(self):
        self.before['permissions'].append([7,7,'ADMINISTER'])
        with self.assertRaises(RuntimeError):self.migrate()
        self.assertFalse(self.committed);runtime.save_receipt.assert_not_called()
        outcome=json.loads((self.data/migration.JOURNAL/'result.json').read_bytes())
        self.assertEqual(outcome['phase'],'failed')
        runtime.check_cluster.side_effect=[self.old_mapping,self.mapping]
        with self.assertRaises(FileExistsError):self.migrate()

    def test_post_census_or_identity_drift_never_replaces_prepared_receipt(self):
        self.after['parameters'][0][2]='changed'
        with self.assertRaises(RuntimeError):self.migrate()
        self.assertTrue(self.committed);runtime.save_receipt.assert_not_called()
        self.assertEqual((self.data/migration.JOURNAL/'previous-prepared.json').read_bytes(),self.old_prepared)

    def test_totp_or_account_drift_never_replaces_prepared_receipt(self):
        original=self.execute
        def execute(query,app=False):
            if self.committed and query==migration.IDENTITY_QUERY:return json.dumps({'changed':True})
            return original(query,app)
        runtime.life.pg_sql.side_effect=execute
        with self.assertRaisesRegex(RuntimeError,'Account or TOTP'):self.migrate()
        runtime.save_receipt.assert_not_called()

    def test_pending_totp_fails_before_sql(self):
        runtime.enrolled.return_value=False
        with self.assertRaisesRegex(RuntimeError,'Confirmed current TOTP'):self.migrate()
        self.assertFalse(self.committed);runtime.save_receipt.assert_not_called()

    def test_legacy_receipt_boolean_schema_or_old_config_mismatch_refused(self):
        for value in ({'schema':1,'profile':'legacy'},
                      {**runtime.receipt(self.old_mapping,self.old_digest),'schema':True},
                      runtime.receipt(self.old_mapping,'a'*64)):
            migration.prepared_bytes.return_value=json.dumps(value).encode()
            with self.subTest(value=value),self.assertRaises(RuntimeError):self.migrate()
        runtime.life.start_pg.assert_not_called()

    def test_terminal_storage_failure_preserves_original_sql_error(self):
        error=RuntimeError('Synthetic SQL primary failure')
        runtime.life.pg_sql.side_effect=error
        original=migration.json_new
        def write(path,value):
            if path.name=='result.json':raise OSError('Synthetic terminal storage failure')
            return original(path,value)
        with patch.object(migration,'json_new',side_effect=write):
            with self.assertRaises(RuntimeError) as caught:self.migrate()
        self.assertIs(caught.exception,error)
        self.assertTrue(any('terminal write failed' in n for n in error.__notes__))

    def test_previous_config_must_be_absolute_protected_and_read_only(self):
        for value in ('relative.json','/config/../previous.json'):
            with self.assertRaises(RuntimeError):migration.migrate(self.new,self.new_digest,value)
        migration.os.statvfs.return_value=SimpleNamespace(f_flag=0)
        with self.assertRaisesRegex(RuntimeError,'Read-only previous'):self.migrate()
        runtime.life.start_pg.assert_not_called()


class PrivacyMigrationTests(MigrationTests):
    """Run every full migration identity/drift boundary without any added target."""
    def setUp(self):
        super().setUp()
        hidden = json.loads(self.old_raw)
        hidden['portal']['publish_target_labels'] = False
        self.new = catalog.parse(hidden)
        self.new_digest = migration.digest(json.dumps(hidden).encode())
        self.mapping, added = migration.plan(self.old, self.new, self.old_mapping)
        self.assertEqual(added, [])
        self.after = copy.deepcopy(self.before)
        runtime.check_cluster.side_effect = [self.old_mapping, self.mapping]

    def test_success_has_no_connection_or_sequence_mutation(self):
        with patch.object(runtime, 'target_sql', side_effect=AssertionError('No target SQL permitted')):
            result = self.migrate()
        self.assertEqual(result['connections'], self.old_mapping)
        self.assertEqual(self.after, self.before)
        self.assertEqual(self.identity['attributes'][0]['attribute_value'], 'SYNTHETIC_PRIVATE_VALUE')


if __name__=='__main__':unittest.main()
