"""Catalog validation and endpoint-specific credential isolation."""

import json
import base64
import struct
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).parent))
import catalog


def configuration():
    target = {"protocol": "rdp", "hostname": "192.0.2.10", "port": 3389,
              "username": "desktop-user", "certificate_fingerprint": "sha256:" + ":".join(["ab"] * 32),
              "password_file": "target-a-password"}
    other = {**target, "hostname": "192.0.2.20", "password_file": "target-b-password"}
    return {"schema_version": 1, "portal": {"username": "operator", "default_target": "desktop-a"},
            "targets": {"desktop-a": target, "desktop-b": other}}


def mixed_configuration():
    value = configuration()
    value['schema_version'] = 2
    public = struct.pack('>I', 11)+b'ssh-ed25519'+struct.pack('>I', 32)+bytes(range(32))
    value['targets']['terminal-c'] = {'protocol':'ssh','hostname':'192.0.2.30','port':10222,
        'username':'terminal-user','host_key':'[192.0.2.30]:10222 ssh-ed25519 '+base64.b64encode(public).decode(),
        'private_key_file':'terminal-c-key','command':'/usr/local/libexec/portal-tmux'}
    return value


class CatalogTests(unittest.TestCase):
    def test_file_transfer_is_opt_in_and_target_scoped(self):
        value = configuration()
        before = catalog.parse(value)
        value['targets']['desktop-a']['enable_drive'] = True
        after = catalog.parse(value)
        params = after.target('desktop-a').parameters()
        self.assertEqual(params['enable-drive'], 'true')
        self.assertEqual(params['drive-path'], '/transfers/desktop-a')
        self.assertEqual(params['drive-name'], 'Files')
        self.assertEqual(params['create-drive-path'], 'true')
        self.assertEqual(after.target('desktop-b').parameters(), before.target('desktop-b').parameters())
        for key in ('hostname', 'port', 'username', 'domain', 'security', 'cert-fingerprints', 'password'):
            self.assertEqual(params[key], before.target('desktop-a').parameters()[key])
        for invalid in ('true', 1, None):
            value['targets']['desktop-a']['enable_drive'] = invalid
            with self.assertRaises(ValueError):
                catalog.parse(value)

    def test_clipboard_budget_is_explicit_bounded_and_does_not_change_old_defaults(self):
        value = configuration()
        self.assertNotIn('clipboard-buffer-size', catalog.parse(value).target('desktop-a').parameters())
        value['targets']['desktop-a']['clipboard_buffer_size'] = 33554432
        self.assertEqual(catalog.parse(value).target('desktop-a').parameters()['clipboard-buffer-size'], '33554432')
        for invalid in (True, '33554432', 262143, 52428801, None):
            value['targets']['desktop-a']['clipboard_buffer_size'] = invalid
            with self.assertRaises(ValueError):catalog.parse(value)

    def test_mixed_schema_preserves_rdp_and_exposes_typed_ssh(self):
        old = catalog.parse(configuration())
        new = catalog.parse(mixed_configuration())
        self.assertEqual(new.username, old.username)
        self.assertNotEqual(new.username, new.target('terminal-c').username)
        for target in old.targets:
            self.assertEqual(new.target(target.alias).parameters(),target.parameters())
            self.assertEqual(new.target(target.alias).secret_file,target.password_file)
        ssh = new.target('terminal-c')
        self.assertEqual(ssh.protocol,'ssh')
        self.assertEqual(ssh.secret_parameter,'private-key')
        self.assertEqual(ssh.secret_token,'PORTAL_TARGET_TERMINAL_C_PRIVATE_KEY')
        self.assertEqual(ssh.secret_limit,16384)
        self.assertEqual(ssh.parameters()['private-key'],'${PORTAL_TARGET_TERMINAL_C_PRIVATE_KEY}')
        self.assertEqual(ssh.parameters()['enable-sftp'],'false')
        self.assertNotIn('password',ssh.parameters())
        self.assertFalse(any('recording' in key for key in ssh.parameters()))
        with self.assertRaises(ValueError):_ = ssh.password_file
        with self.assertRaises(ValueError):_ = ssh.password_token
        self.assertEqual(new.parameters({'desktop-a':17,'desktop-b':92,'terminal-c':93})[17],old.target('desktop-a').parameters())

    def test_exact_ecdsa_host_pin_matches_native_libssh2_preference(self):
        field=lambda raw:struct.pack('>I',len(raw))+raw
        blob=field(b'ecdsa-sha2-nistp256')+field(b'nistp256')+field(b'\4'+bytes(64))
        obj=mixed_configuration()
        pin='[192.0.2.30]:10222 ecdsa-sha2-nistp256 '+base64.b64encode(blob).decode()
        obj['targets']['terminal-c']['host_key']=pin
        self.assertEqual(catalog.parse(obj).target('terminal-c').host_key,pin)
        for invalid in (blob[:-1],blob.replace(b'nistp256',b'nistp384'),blob+b'extra'):
            obj['targets']['terminal-c']['host_key']='[192.0.2.30]:10222 ecdsa-sha2-nistp256 '+base64.b64encode(invalid).decode()
            with self.assertRaises(ValueError):catalog.parse(obj)

    def test_ssh_pins_commands_and_secret_fields_fail_closed(self):
        valid = mixed_configuration()
        key=valid['targets']['terminal-c']['host_key']
        for field,value in [('host_key',key.replace('10222','22')),('host_key',key.replace('192.0.2.30','192.0.2.31')),
            ('host_key',key+' comment'),('host_key',key.replace('ssh-ed25519','ssh-rsa')),
            ('host_key','SHA256:not-an-entry'),('command','/bin/sh -c command'),('command','../launcher'),
            ('command','/usr/../bin/sh'),('command','/bin/sh;command'),('private_key_file','../key'),
            ('private_key_file','target-a-password')]:
            obj=mixed_configuration();obj['targets']['terminal-c'][field]=value
            with self.subTest(field=field,value=value),self.assertRaises(ValueError):catalog.parse(obj)
        for field in ('password_file','password','passphrase','domain','security','recording-path','enable-sftp'):
            obj=mixed_configuration();obj['targets']['terminal-c'][field]='forbidden'
            with self.subTest(field=field),self.assertRaises(ValueError):catalog.parse(obj)
        obj=mixed_configuration();obj['schema_version']=1
        with self.assertRaises(ValueError):catalog.parse(obj)

    def test_proxy_is_an_exact_optional_ipv4_not_a_pattern(self):
        self.assertIsNone(catalog.parse(configuration()).trusted_proxy_ipv4)
        obj = configuration(); obj['portal']['trusted_proxy_ipv4'] = '10.55.0.1'
        self.assertEqual(catalog.parse(obj).trusted_proxy_ipv4, '10.55.0.1')
        for invalid in ('0.0.0.0', '224.0.0.1', '.*', '10.55.0.1|127.0.0.1',
                        '10.55.0.1\n', 'example.invalid', '::1', True):
            with self.subTest(invalid=invalid), self.assertRaises((ValueError, TypeError)):
                obj['portal']['trusted_proxy_ipv4'] = invalid
                catalog.parse(obj)

    def test_separate_targets_preserve_parameters_and_secret_references(self):
        parsed = catalog.parse(configuration())
        self.assertEqual(parsed.target("desktop-a").password_file, "target-a-password")
        self.assertEqual(parsed.target("desktop-b").password_file, "target-b-password")
        parameters = parsed.parameters({"desktop-a": 17, "desktop-b": 92})
        self.assertEqual(parameters[17]["hostname"], "192.0.2.10")
        self.assertEqual(parameters[92]["hostname"], "192.0.2.20")
        self.assertNotEqual(parameters[17]["password"], parameters[92]["password"])
        self.assertEqual(parameters[17]["enable-font-smoothing"], "true")
        self.assertNotIn("target-a-password", str(parameters))
        self.assertFalse(parsed.publish_target_labels)

    def test_explicit_mapping_is_not_assumed_to_use_id_one(self):
        parsed = catalog.parse(configuration())
        for mapping in ({"desktop-a": 1}, {"desktop-a": 1, "desktop-b": 1},
                        {"desktop-a": True, "desktop-b": 2},
                        {"desktop-a": 0, "desktop-b": 2}):
            with self.subTest(mapping=mapping), self.assertRaises(ValueError):
                parsed.parameters(mapping)

    def test_unknown_defaults_and_browser_host_inputs_fail(self):
        obj = configuration(); obj["portal"]["default_target"] = "missing"
        with self.assertRaises(ValueError):
            catalog.parse(obj)
        parsed = catalog.parse(configuration())
        for selected in ("missing", "192.0.2.10", "../desktop-a", "desktop_a", ["desktop-a"]):
            with self.subTest(selected=selected), self.assertRaises(ValueError):
                parsed.target(selected)

    def test_invalid_target_values_fail_closed(self):
        changes = [("hostname", "0.0.0.0"), ("hostname", "224.0.0.1"),
                   ("hostname", "arbitrary.example"), ("hostname", "::1"),
                   ("port", True), ("port", 0), ("port", 65536), ("port", "3389"),
                   ("protocol", "ssh"), ("security", "any"),
                   ("certificate_fingerprint", "ignore"),
                   ("password_file", "../secret"), ("password_file", "/secrets/private"),
                   ("password_file", "a\nb"), ("username", "a\nb"), ("username", "")]
        for key, value in changes:
            obj = configuration(); obj["targets"]["desktop-a"][key] = value
            with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                catalog.parse(obj)

    def test_unknown_fields_and_wrong_types_are_rejected(self):
        for change in (lambda x: x.update({"password": "do-not-store"}),
                       lambda x: x.update({"schema_version": True}),
                       lambda x: x["portal"].update({"publish_target_labels": "true"}),
                       lambda x: x["targets"]["desktop-a"].update({"ignore-cert": True}),
                       lambda x: x.update({"targets": {}})):
            obj = configuration(); change(obj)
            with self.assertRaises(ValueError):
                catalog.parse(obj)

    def test_duplicate_json_keys_are_rejected(self):
        with self.assertRaises(ValueError):
            catalog.unique_object([("a", 1), ("a", 2)])

    def test_file_loader_rejects_links_duplicates_and_unsafe_permissions(self):
        with tempfile.TemporaryDirectory() as work:
            path = Path(work) / "config.json"
            path.write_text(json.dumps(configuration()))
            path.chmod(0o600)
            self.assertEqual(len(catalog.load(path).targets), 2)
            link = Path(work) / "link.json"; link.symlink_to(path)
            with self.assertRaises(OSError):
                catalog.load(link)
            path.chmod(0o666)
            with self.assertRaises(ValueError):
                catalog.load(path)
            path.chmod(0o600); path.write_text('{"schema_version":1,"schema_version":2}')
            with self.assertRaises(ValueError):
                catalog.load(path)

    def test_endpoint_set_is_specific_and_deduplicated(self):
        parsed = catalog.parse(configuration())
        self.assertEqual(parsed.endpoints(), [("192.0.2.10", 3389), ("192.0.2.20", 3389)])


if __name__ == "__main__":
    unittest.main()
