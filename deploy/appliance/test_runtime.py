import copy
import base64
import struct
import json
import os
import re
import xml.etree.ElementTree as ET
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import catalog
import runtime


def registry():
    return catalog.load(Path(__file__).parent/'examples/config.json')


def snapshot(reg, mapping):
    state = {table: 0 for table in runtime.EMPTY_TABLES}
    state.update(entities=[[7, reg.username, 'USER']], users=[[9, 7, False, False]],
                 connections=[[mapping[t.alias], t.alias, t.protocol, 1, 1, None, None, None, None, False, None] for t in reg.targets],
                 parameters=[[ident, k, v] for ident, params in reg.parameters(mapping).items() for k, v in params.items()],
                 permissions=[[7, ident, 'READ'] for ident in mapping.values()],
                 user_permissions=[[7, 9, 'READ']])
    return state


def format_only_key(cipher=b'none'):
    # Synthetic structural fixture, deliberately not a usable SSH identity.
    field=lambda raw:struct.pack('>I',len(raw))+raw
    public=bytes(range(32))
    pub=field(b'ssh-ed25519')+field(public)
    private=struct.pack('>II',7,7)+field(b'ssh-ed25519')+field(public)+field(bytes(32)+public)+field(b'synthetic')
    padding=8-len(private)%8
    private+=bytes(range(1,padding+1))
    data=b'openssh-key-v1\0'+field(cipher)+field(b'none')+field(b'')+struct.pack('>I',1)+field(pub)+field(private)
    return b'-----BEGIN OPENSSH PRIVATE KEY-----\n'+base64.b64encode(data)+b'\n-----END OPENSSH PRIVATE KEY-----\n'


class RuntimeTests(unittest.TestCase):
    def setUp(self):
        self.reg = registry()
        self.mapping = {t.alias: i for i, t in enumerate(self.reg.targets, 4)}

    def test_mixed_sql_and_snapshot_retain_existing_ids_and_rdp_params(self):
        from test_catalog import mixed_configuration
        reg=catalog.parse(mixed_configuration());mapping={'desktop-a':17,'desktop-b':92,'terminal-c':93}
        state=snapshot(reg,mapping)
        self.assertTrue(runtime.validate_snapshot(reg,mapping,state))
        query=runtime.target_sql(reg,mapping)
        self.assertIn("VALUES(93,'terminal-c','ssh',1,1)",query)
        self.assertIn('PORTAL_TARGET_TERMINAL_C_PRIVATE_KEY',query)
        self.assertNotIn('BEGIN OPENSSH',query)
        for row in state['connections']:
            if row[0]==93:row[2]='rdp'
        with self.assertRaises(RuntimeError):runtime.validate_snapshot(reg,mapping,state)

    def test_bounded_multiline_key_reader_rejects_encryption_and_corruption(self):
        key=format_only_key()
        with patch.object(runtime,'protected_read',return_value=key) as read:
            self.assertEqual(runtime.ssh_private_key('terminal-key'),key.decode())
            read.assert_called_once_with(runtime.SECRETS/'terminal-key',private=True,limit=16384)
        for value in (b'',key.replace(b'OPENSSH',b'RSA'),format_only_key(b'aes256-ctr'),
                      key.replace(b'\n',b'\r\n'),key.replace(b'\n',b'\0',1),b'a'*16385):
            with self.subTest(),patch.object(runtime,'protected_read',return_value=value),self.assertRaises(RuntimeError):
                runtime.ssh_private_key('terminal-key')
        with patch.object(runtime,'protected_read',return_value=key),self.assertRaises(RuntimeError):
            runtime.target_secret('terminal-key')
        for name in ('../key','/key','a/b'):
            with self.assertRaises(RuntimeError):runtime.ssh_private_key(name)

    def test_typed_credential_dispatch_does_not_use_password_reader_for_ssh(self):
        from test_catalog import mixed_configuration
        reg=catalog.parse(mixed_configuration())
        with patch.object(runtime,'target_secret',return_value='password') as password,patch.object(runtime,'ssh_private_key',return_value='key') as key:
            self.assertEqual(runtime.target_credential(reg.target('terminal-c')),'key')
            password.assert_not_called();key.assert_called_once_with('terminal-c-key')
            self.assertEqual(runtime.target_credential(reg.target('desktop-a')),'password')
            password.assert_called_once_with('target-a-password')

    def test_provision_sql_has_explicit_mapping_without_default_admin(self):
        query = runtime.prepare_sql(self.reg, self.mapping, 'db-secret', 'portal-secret', '-- synthetic schema')
        self.assertNotIn('guacadmin', query)
        self.assertNotIn('002-create-admin-user.sql', query)
        self.assertNotIn('portal-secret', query)
        self.assertIn('BEGIN;', query)
        for t in self.reg.targets:
            self.assertIn(t.password_token, query)
            self.assertIn("VALUES("+str(self.mapping[t.alias])+","+runtime.sql(t.alias), query)

    def test_exact_census_and_mutations(self):
        state = snapshot(self.reg, self.mapping)
        self.assertTrue(runtime.validate_snapshot(self.reg, self.mapping, state))
        for key, replacement in [('permissions', [[7, 4, 'ADMINISTER']]),
                                 ('user_permissions', []), ('users', [[9, 7, True, False]]),
                                 ('entities', [[7, 'intruder', 'USER']]),
                                 ('parameters', state['parameters'][:-1]),
                                 ('connections', state['connections'][:-1])]:
            changed = copy.deepcopy(state)
            changed[key] = replacement
            with self.subTest(key=key), self.assertRaises(RuntimeError):
                runtime.validate_snapshot(self.reg, self.mapping, changed)
        for table in runtime.EMPTY_TABLES:
            changed = copy.deepcopy(state)
            changed[table] = 1
            with self.subTest(table=table), self.assertRaises(RuntimeError):
                runtime.validate_snapshot(self.reg, self.mapping, changed)

    def test_lease_production_and_fixture_bounds(self):
        with patch.dict(os.environ, {'WEB_RDP_PRODUCTION': '1'}, clear=True):
            self.assertEqual(runtime.lease(), (float('inf'), float('inf')))
        for values in ({}, {'WEB_RDP_DURATION_SECONDS': 'nan', 'WEB_RDP_DEADLINE_EPOCH': '100'},
                       {'WEB_RDP_PRODUCTION': '1', 'WEB_RDP_DURATION_SECONDS': '3'}):
            with patch.dict(os.environ, values, clear=True), self.assertRaises((KeyError, RuntimeError)):
                runtime.lease()

    def test_secret_validation_and_staging_no_overwrite(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/'secret'
            runtime.write_private(path, 'a'*24, os.geteuid())
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            with self.assertRaises(FileExistsError):
                runtime.write_private(path, 'overwrite', os.geteuid())
        with patch.object(runtime, 'protected_read', return_value=b'a'*24) as read:
            with patch.object(runtime, 'SECRETS', Path('/external')):
                self.assertEqual(runtime.secret('target-one'), 'a'*24)
                read.assert_called_once_with(Path('/external/target-one'), private=True, limit=4096)
        for name in ('../escape', '/escape', 'a/b'):
            with self.assertRaises(RuntimeError):
                runtime.secret(name)

    def test_java_stages_connection_specific_secrets_and_properties(self):
        def copy_conf(source, dest):
            dest.mkdir()
        with tempfile.TemporaryDirectory() as directory:
            run = Path(directory)
            (run/'java').mkdir()
            values = {t.password_file: 'password-for-' + t.alias for t in self.reg.targets}
            values['db-password'] = 'database-password'
            with patch.object(runtime, 'RUN', run), patch.object(runtime.life, 'runtime_dirs'), patch.object(runtime.life, 'mkdir', side_effect=lambda path, uid: path.mkdir()), patch.object(runtime, 'secret', side_effect=values.__getitem__), patch.object(runtime, 'target_secret', side_effect=values.__getitem__), patch.object(runtime.shutil, 'copytree', side_effect=copy_conf), patch.object(runtime.os, 'chown'), patch.object(runtime.os, 'fchown') as chown:
                runtime.configure_java(self.reg, self.mapping)
                self.assertTrue(all(call.args[1:] == (2001, 2001) for call in chown.call_args_list))
            for target in self.reg.targets:
                path = run/'java'/('target-' + target.alias + '-password')
                self.assertEqual(path.read_text(), values[target.password_file])
                self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            props = (run/'guacamole/guacamole.properties').read_text()
            self.assertIn('extension-priority: portal, postgresql, totp, ban', props)
            self.assertIn('totp-mode: sha1', props)
            for target in self.reg.targets:
                self.assertIn('portal-target-' + target.alias + '-id: ' + str(self.mapping[target.alias]), props)
                self.assertNotIn(values[target.password_file], props)

    def test_mixed_java_stages_key_separately_without_property_material(self):
        from test_catalog import mixed_configuration
        reg=catalog.parse(mixed_configuration());mapping={'desktop-a':17,'desktop-b':92,'terminal-c':93}
        key=format_only_key().decode()
        with tempfile.TemporaryDirectory() as directory:
            run=Path(directory);(run/'java').mkdir()
            with patch.object(runtime,'RUN',run),patch.object(runtime.life,'runtime_dirs'), \
                    patch.object(runtime.life,'mkdir',side_effect=lambda p,uid:p.mkdir()), \
                    patch.object(runtime,'target_secret',return_value='synthetic-password') as passwords, \
                    patch.object(runtime,'ssh_private_key',return_value=key) as keys, \
                    patch.object(runtime,'secret',return_value='synthetic-database-password'), \
                    patch.object(runtime.shutil,'copytree',side_effect=lambda src,dst:dst.mkdir()), \
                    patch.object(runtime.os,'chown'),patch.object(runtime.os,'fchown'):
                runtime.configure_java(reg,mapping)
            self.assertEqual(keys.call_args.args,('terminal-c-key',))
            self.assertEqual(passwords.call_count,2)
            self.assertEqual((run/'java/target-terminal-c-private-key').read_text(),key)
            self.assertFalse((run/'java/target-terminal-c-password').exists())
            props=(run/'guacamole/guacamole.properties').read_text()
            self.assertIn('portal-target-terminal-c-protocol: ssh',props)
            self.assertIn('portal-target-desktop-a-protocol: rdp',props)
            self.assertNotIn('BEGIN OPENSSH',props)
            self.assertEqual((run/'java/target-terminal-c-private-key').stat().st_mode&0o777,0o600)

    def test_direct_tomcat_has_no_forwarded_header_valve(self):
        root = ET.fromstring(runtime.tomcat_server_xml())
        self.assertEqual(root.findall('.//Valve'), [])

    def test_tomcat_trusts_only_exact_configured_proxy(self):
        root = ET.fromstring(runtime.tomcat_server_xml('192.0.2.44'))
        valves = root.findall('.//Valve')
        self.assertEqual(len(valves), 1)
        valve = valves[0]
        self.assertEqual(valve.attrib, {
            'className': 'org.apache.catalina.valves.RemoteIpValve',
            'internalProxies': r'192\.0\.2\.44',
            'remoteIpHeader': 'X-Forwarded-For',
            'protocolHeader': 'X-Forwarded-Proto',
        })
        expression = valve.attrib['internalProxies']
        self.assertIsNotNone(re.fullmatch(expression, '192.0.2.44'))
        for peer in ('192X0X2X44', '192.0.2.45', '127.0.0.1', '10.0.0.1', '192.0.2.440'):
            self.assertIsNone(re.fullmatch(expression, peer))

    def test_target_secret_allows_short_password_and_enforces_exact_bytes(self):
        for raw in (b'a', 'short'.encode(), ('\u00e9'*256).encode()):
            with patch.object(runtime, 'protected_read', return_value=raw):
                self.assertEqual(runtime.target_secret('target-a').encode(), raw)
        for raw in (b'', b'abc\n', b'abc\r', b'abc\x00', b'a'*513, ('\u00e9'*257).encode(), b'\xff'):
            with patch.object(runtime, 'protected_read', return_value=raw), self.assertRaises((RuntimeError, UnicodeDecodeError)):
                runtime.target_secret('target-a')

    def test_properties_escape_password_metacharacters(self):
        self.assertEqual(runtime.property_value(' a:b\\c'), '\\u0020a\\u003ab\\u005cc')

    def test_migration_preserves_identity_and_totp(self):
        first = self.reg.targets[0]
        single = catalog.Catalog(self.reg.username, first.alias, False, (first,))
        state = snapshot(single, {first.alias: 1})
        state['connections'][0][1] = 'Legacy descriptive name'
        for row in state['parameters']:
            if row[1] == 'password':
                row[2] = '${HOMELAB_WINDOWS_PASSWORD}'
        with tempfile.TemporaryDirectory() as directory, patch.object(runtime, 'DATA', Path(directory)), patch.object(runtime, 'RUN', Path(directory)), patch.object(runtime.life, 'PROCESSES', {}), patch.object(runtime.life, 'start_pg'), patch.object(runtime.life, 'pg_sql', side_effect=[json.dumps(state), '']) as execute, patch.object(runtime, 'enrolled', return_value=True), patch.object(runtime, 'database_health'), patch.object(runtime, 'save_receipt') as save:
            runtime.migrate(self.reg, 'digest', first.alias)
            query = execute.call_args_list[1].args[0]
            for forbidden in ('CREATE ROLE', 'CREATE TABLE', 'guacamole_user_attribute', 'guacamole_user SET', 'DELETE'):
                self.assertNotIn(forbidden, query)
            self.assertEqual(save.call_args.args[0][first.alias], 1)

    def test_unenrolled_migration_fails_before_write(self):
        first = self.reg.targets[0]
        single = catalog.Catalog(self.reg.username, first.alias, False, (first,))
        state = snapshot(single, {first.alias: 1})
        for row in state['parameters']:
            if row[1] == 'password': row[2] = '${HOMELAB_WINDOWS_PASSWORD}'
        with tempfile.TemporaryDirectory() as directory, patch.object(runtime, 'DATA', Path(directory)), patch.object(runtime, 'RUN', Path(directory)), patch.object(runtime.life, 'PROCESSES', {}), patch.object(runtime.life, 'start_pg'), patch.object(runtime.life, 'pg_sql', return_value=json.dumps(state)) as execute, patch.object(runtime, 'enrolled', return_value=False):
            with self.assertRaises(RuntimeError): runtime.migrate(self.reg, 'digest', first.alias)
            self.assertEqual(execute.call_count, 1)

    def test_health_does_not_check_target_network(self):
        response = unittest.mock.MagicMock()
        response.__enter__.return_value.status = 200
        with patch.object(runtime, 'check_cluster', return_value=self.mapping), patch.object(runtime, 'database_health', return_value=True), patch.object(runtime, 'enrolled', return_value=True), patch.object(runtime.urllib.request, 'urlopen', return_value=response) as request:
            self.assertEqual(runtime.health(self.reg, 'digest'), dict(database_ready=True, web_ready=True, enrolled=True))
            self.assertEqual(request.call_count, 1)
            self.assertIn('127.0.0.1:8080', request.call_args.args[0])

    def test_totp_key_strictness(self):
        self.assertTrue(runtime.valid_totp_key('A'*32))
        for key in (None, '', 'a'*32, 'A'*16, 'A'*31+'*', 'A'*32+'=', 'A'*40, 'A'*31):
            self.assertFalse(runtime.valid_totp_key(key))


if __name__ == '__main__':
    unittest.main()
