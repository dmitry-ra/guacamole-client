"""Inert transport upgrade tests; all process/account inspection is mocked."""
import base64
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import upgrade_transport_server as upgrade


def configs():
    key = 'ssh-ed25519 ' + base64.b64encode(b'\0\0\0\x0bssh-ed25519\0\0\0\x20' + bytes(32)).decode()
    old = dict(schema=1, client_address='192.0.2.10', server_address='192.0.2.20',
               server_port=22, listen_address='10.55.0.1', listen_port=10473,
               target_address='192.168.50.10', target_port=3389, public_key=key, host_key=key)
    names = ('listen_address', 'listen_port', 'target_address', 'target_port')
    new = {key: value for key, value in old.items() if key not in names}
    new.update(schema=2, forwards=[{key: old[key] for key in names},
               dict(listen_address='10.55.0.1', listen_port=10475,
                    target_address='192.168.50.1', target_port=22)])
    return old, new


class ExtensionTests(unittest.TestCase):
    def test_only_additive_same_identity_same_bridge_allowed(self):
        old, new = configs()
        upgrade.extension(old, new)
        cases = [{**new, 'server_port': 2222}, {**new, 'client_address': '192.0.2.11'},
                 {**new, 'forwards': new['forwards'][1:]},
                 {**new, 'forwards': [{**item, 'listen_address': '10.56.0.1'} for item in new['forwards']]}]
        for changed in cases:
            with self.subTest(changed=changed), self.assertRaises(ValueError):
                upgrade.extension(old, changed)

    def test_duplicate_json_never_accepted(self):
        with self.assertRaises(ValueError):
            upgrade.load(b'{"schema":1,"schema":2}')


@unittest.skipUnless(os.geteuid() == 0, 'Synthetic ownership tests require root')
class UpgradeTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='portal-transport-upgrade-', dir='/run')
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name)
        self.root = self.base/'transport'
        self.root.mkdir(mode=0o700)
        self.unit = self.base/'transport.service'
        self.sshd = self.base/'sshd_config'
        self.key = self.base/'host.pub'
        for name, value in [('ROOT', self.root), ('UNIT', self.unit), ('SSHD', self.sshd), ('HOST_KEY', self.key)]:
            mock = patch.object(upgrade, name, value)
            mock.start()
            self.addCleanup(mock.stop)
        self.old, self.new = configs()
        self.write('old-config.json', json.dumps(self.old).encode())
        self.write('new-config.json', json.dumps(self.new).encode())
        self.commands = []
        self.active = False
        def run(*args):
            self.commands.append(tuple(map(str, args)))
            if args[0] == '/usr/sbin/ip':
                output = json.dumps([{'addr_info': [{'local': self.old['client_address']}, {'local': self.old['server_address']}]}])
            elif args[0] == '/usr/bin/systemctl':
                output = 'LoadState=loaded\nActiveState='+('active' if self.active else 'inactive')+'\nMainPID='+('99' if self.active else '0')+'\n'
            else:
                output = ''
            return subprocess.CompletedProcess(args, 0, output, '')
        mock = patch.object(upgrade.server, 'run', side_effect=run)
        mock.start()
        self.addCleanup(mock.stop)
        mock = patch.object(upgrade.pwd, 'getpwnam', return_value=SimpleNamespace(
            pw_uid=998, pw_gid=998, pw_shell='/usr/sbin/nologin', pw_dir='/nonexistent'))
        mock.start()
        self.addCleanup(mock.stop)

    def write(self, name, raw, mode=0o600):
        path = self.base/name
        path.write_bytes(raw)
        path.chmod(mode)
        return path

    def installed(self, role):
        rendered = upgrade.renderer.render(self.old)
        if role == 'server':
            self.root.chmod(0o755)
            self.write('transport/sshd.conf', rendered['sshd.conf'].encode(), 0o644)
            self.write('transport/authorized_keys', rendered['authorized_keys'].encode(), 0o644)
            self.write('sshd_config', ('Port 22\nInclude '+str(self.root/'sshd.conf')+'\n').encode(), 0o644)
            self.write('host.pub', self.old['host_key'].encode(), 0o644)
        else:
            self.write('transport/client.conf', rendered['client.conf'].encode())
            self.write('transport/known_hosts', rendered['known_hosts'].encode())
            self.write('transport/identity', b'PRIVATE KEY MUST NEVER BE READ')
            self.write('transport/identity.pub', self.old['public_key'].encode(), 0o644)
            self.write('transport.service', upgrade.client_unit(self.old).encode(), 0o644)

    def prepare(self, role='client'):
        case = self.base/'case'
        upgrade.prepare(role, case, self.base/'old-config.json', self.base/'new-config.json',
                        'administrator' if role == 'server' else None)
        return case, upgrade.sha((case/'plan.json').read_bytes())

    def review(self, role, digest):
        return self.write('review.json', json.dumps({'schema': 1, 'role': role, 'plan_sha256': digest,
            'deployment_reference': 'operator:exact-deployment-review', 'portal_closed': True,
            'sessions_cleared': True, 'reviewed_at': time.time()-1, 'expires_at': time.time()+120}).encode())

    def test_client_preparation_does_not_install_and_apply_preserves_key_unit_knownhost(self):
        self.installed('client')
        before = {path: path.read_bytes() for path in (self.root/'client.conf', self.unit, self.root/'known_hosts', self.root/'identity')}
        case, digest = self.prepare()
        self.assertEqual((self.root/'client.conf').read_bytes(), before[self.root/'client.conf'])
        upgrade.apply('client', case, digest, self.review('client', digest))
        self.assertEqual((self.root/'client.conf').read_bytes(), upgrade.renderer.render(self.new)['client.conf'].encode())
        for path in (self.unit, self.root/'known_hosts', self.root/'identity'):
            self.assertEqual(path.read_bytes(), before[path])
        self.assertEqual((case/'backup-0').read_bytes(), before[self.root/'client.conf'])
        self.assertFalse(json.loads((case/'result.json').read_bytes())['activated'])
        with self.assertRaises(ValueError):
            upgrade.apply('client', case, digest, self.review('client', digest))
        self.assertTrue(all('restart' not in cmd and 'reload' not in cmd and 'start' not in cmd and 'stop' not in cmd for cmd in self.commands))

    def test_original_drift_and_review_hash_refuse_before_intent(self):
        self.installed('client')
        case, digest = self.prepare()
        review = self.review('client', digest)
        with self.assertRaises(ValueError):
            upgrade.apply('client', case, '0'*64, review)
        self.write('transport/known_hosts', b'changed')
        with self.assertRaisesRegex(ValueError, 'original config'):
            upgrade.apply('client', case, digest, review)
        self.assertFalse((case/'apply-intent.json').exists())

    def test_active_transport_refuses_even_with_maintenance_attestation(self):
        self.installed('client')
        case, digest = self.prepare()
        self.active = True
        with self.assertRaisesRegex(ValueError, 'externally stopped'):
            upgrade.apply('client', case, digest, self.review('client', digest))
        self.assertFalse((case/'apply-intent.json').exists())

    def test_missing_clearance_expired_wrong_role_or_plan_review_refused(self):
        self.installed('client')
        case, digest = self.prepare()
        for changes in ({'portal_closed': False}, {'sessions_cleared': False}, {'role': 'server'},
                        {'plan_sha256': '0'*64}, {'reviewed_at': 0, 'expires_at': 120},
                        {'expires_at': time.time()+600}, {'extra': 1}):
            review = self.review('client', digest)
            value = json.loads(review.read_bytes())
            value.update(changes)
            self.write('review.json', json.dumps(value).encode())
            with self.subTest(changes=changes), self.assertRaisesRegex(ValueError, 'closed-portal'):
                upgrade.apply('client', case, digest, review)
        self.assertFalse((case/'apply-intent.json').exists())

    def test_candidate_tampering_and_prepare_replay_refused(self):
        self.installed('client')
        case, digest = self.prepare()
        with self.assertRaises(FileExistsError):
            self.prepare()
        self.write('case/candidate-0', b'Host *\nProxyCommand malicious\n')
        with self.assertRaisesRegex(ValueError, 'Candidate or backup'):
            upgrade.apply('client', case, digest, self.review('client', digest))
        self.assertFalse((case/'apply-intent.json').exists())

    def test_server_preserves_global_ssh_key_account_and_requires_policy_validation(self):
        self.installed('server')
        original = self.sshd.read_bytes()
        with patch.object(upgrade, 'validate_server', return_value='a'*64) as policy:
            case, digest = self.prepare('server')
            upgrade.apply('server', case, digest, self.review('server', digest))
        self.assertEqual(policy.call_count, 3)
        self.assertEqual(self.sshd.read_bytes(), original)
        self.assertEqual((case/'global-sshd-backup').read_bytes(), original)
        self.assertEqual((self.root/'authorized_keys').read_bytes(), upgrade.renderer.render(self.new)['authorized_keys'].encode())
        self.assertEqual((self.root/'authorized_keys').stat().st_mode & 0o777, 0o644)

    def test_server_effective_policy_refuses_shell_agent_remote_unix_or_extra_endpoint(self):
        self.installed('server')
        policy = {'maxsessions': '0', 'allowtcpforwarding': 'local',
            'allowstreamlocalforwarding': 'no', 'permitlisten': 'none',
            'passwordauthentication': 'no', 'kbdinteractiveauthentication': 'no',
            'pubkeyauthentication': 'yes', 'authenticationmethods': 'publickey',
            'authorizedkeyscommand': 'none', 'trustedusercakeys': 'none',
            'disableforwarding': 'no', 'permittty': 'no', 'x11forwarding': 'no',
            'allowagentforwarding': 'no', 'permittunnel': 'no',
            'authorizedkeysfile': str(self.root/'authorized_keys'),
            'permitopen': '192.168.50.10:3389 192.168.50.1:22'}
        current = dict(policy)
        def effective(path, user, address):
            return '\n'.join(key+' '+value for key, value in current.items()) if user == upgrade.USER else 'administrative policy'
        with patch.object(upgrade.server, 'effective', side_effect=effective):
            upgrade.validate_server(self.base/'candidate', self.new, 'administrator')
            for field, value in [('maxsessions', '1'), ('allowtcpforwarding', 'yes'),
                ('allowstreamlocalforwarding', 'yes'), ('permitlisten', 'any'),
                ('permittty', 'yes'), ('allowagentforwarding', 'yes'),
                ('permitopen', policy['permitopen']+' 192.168.50.1:80'), ('passwordauthentication', 'yes')]:
                current = {**policy, field: value}
                with self.subTest(field=field), self.assertRaisesRegex(ValueError, 'restricted tunnel'):
                    upgrade.validate_server(self.base/'candidate', self.new, 'administrator')
            current = {**policy, 'allowusers': 'other'}
            with self.assertRaisesRegex(ValueError, 'access lists'):
                upgrade.validate_server(self.base/'candidate', self.new, 'administrator')

    def test_failed_partial_apply_has_terminal_receipt_and_cannot_replay(self):
        self.installed('client')
        case, digest = self.prepare()
        review = self.review('client', digest)
        with patch.object(upgrade.os, 'replace', side_effect=OSError('synthetic failure')):
            with self.assertRaises(OSError):
                upgrade.apply('client', case, digest, review)
        self.assertEqual(json.loads((case/'result.json').read_bytes())['phase'], 'failed')
        with self.assertRaisesRegex(ValueError, 'never replayed'):
            upgrade.apply('client', case, digest, review)

    def expiring_review(self, role, digest):
        review = self.review(role, digest)
        value = json.loads(review.read_bytes())
        value.update(reviewed_at=99, expires_at=100.1)
        return self.write('review.json', json.dumps(value).encode())

    def test_expiry_during_client_validation_refuses_before_intent_or_host_mutation(self):
        self.installed('client')
        case, digest = self.prepare()
        review = self.expiring_review('client', digest)
        original = (self.root/'client.conf').read_bytes()
        clock = [100]
        original_run = upgrade.server.run
        def run(*args):
            result = original_run(*args)
            if args[0] == '/usr/bin/ssh':
                clock[0] = 101
            return result
        with patch.object(upgrade.time, 'time', side_effect=lambda: clock[0]), \
                patch.object(upgrade.server, 'run', side_effect=run), \
                patch.object(upgrade.os, 'replace') as replace:
            with self.assertRaisesRegex(ValueError, 'Fresh external'):
                upgrade.apply('client', case, digest, review)
            replace.assert_not_called()
        self.assertFalse((case/'apply-intent.json').exists())
        self.assertEqual((self.root/'client.conf').read_bytes(), original)

    def test_expiry_after_temporary_metadata_refuses_replacement_and_records_failure(self):
        self.installed('client')
        case, digest = self.prepare()
        review = self.expiring_review('client', digest)
        original = (self.root/'client.conf').read_bytes()
        clock = [100]
        original_chmod = upgrade.os.chmod
        def chmod(path, mode):
            original_chmod(path, mode)
            clock[0] = 101
        with patch.object(upgrade.time, 'time', side_effect=lambda: clock[0]), \
                patch.object(upgrade.os, 'chmod', side_effect=chmod), \
                patch.object(upgrade.os, 'replace') as replace:
            with self.assertRaisesRegex(ValueError, 'Fresh external'):
                upgrade.apply('client', case, digest, review)
            replace.assert_not_called()
        self.assertEqual((self.root/'client.conf').read_bytes(), original)
        self.assertEqual(json.loads((case/'result.json').read_bytes())['phase'], 'failed')
        self.assertTrue((self.root/'client.conf.portal-upgrade-next').exists())
        with self.assertRaisesRegex(ValueError, 'never replayed'):
            upgrade.apply('client', case, digest, review)

    def test_expiry_between_server_files_retains_partial_failure_without_second_replacement(self):
        self.installed('server')
        original_key = (self.root/'authorized_keys').read_bytes()
        with patch.object(upgrade, 'validate_server', return_value='a'*64):
            case, digest = self.prepare('server')
            review = self.expiring_review('server', digest)
            clock = [100]
            original_replace = upgrade.os.replace
            replacements = []
            def replace(source, target):
                original_replace(source, target)
                replacements.append(target)
                clock[0] = 101
            with patch.object(upgrade.time, 'time', side_effect=lambda: clock[0]), \
                    patch.object(upgrade.os, 'replace', side_effect=replace):
                with self.assertRaisesRegex(ValueError, 'Fresh external'):
                    upgrade.apply('server', case, digest, review)
        self.assertEqual(replacements, [self.root/'sshd.conf'])
        self.assertEqual((self.root/'sshd.conf').read_bytes(), upgrade.renderer.render(self.new)['sshd.conf'].encode())
        self.assertEqual((self.root/'authorized_keys').read_bytes(), original_key)
        self.assertEqual(json.loads((case/'result.json').read_bytes())['phase'], 'failed')
        with self.assertRaisesRegex(ValueError, 'never replayed'):
            upgrade.apply('server', case, digest, review)

    def test_expiry_during_final_server_validation_cannot_publish_installed(self):
        self.installed('server')
        clock = [100]
        def validate(path, config, admin):
            if path == self.sshd:
                clock[0] = 101
            return 'a'*64
        with patch.object(upgrade, 'validate_server', side_effect=validate):
            case, digest = self.prepare('server')
            review = self.expiring_review('server', digest)
            with patch.object(upgrade.time, 'time', side_effect=lambda: clock[0]):
                with self.assertRaisesRegex(ValueError, 'Fresh external'):
                    upgrade.apply('server', case, digest, review)
        for name in ('sshd.conf', 'authorized_keys'):
            self.assertEqual((self.root/name).read_bytes(), upgrade.renderer.render(self.new)[name].encode())
        self.assertEqual(json.loads((case/'result.json').read_bytes())['phase'], 'failed')
        with self.assertRaisesRegex(ValueError, 'never replayed'):
            upgrade.apply('server', case, digest, review)


if __name__ == '__main__':
    unittest.main()
