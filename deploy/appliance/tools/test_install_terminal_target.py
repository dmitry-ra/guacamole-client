"""Inert terminal installer tests using only synthetic root-owned /run files."""
import base64
import copy
import json
import os
from pathlib import Path
import stat
import struct
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import install_terminal_target as install
import terminal_launcher


def public():
    return 'ssh-ed25519 '+base64.b64encode(struct.pack('>I',11)+b'ssh-ed25519'+struct.pack('>I',32)+bytes(range(32))).decode()


class PureTests(unittest.TestCase):
    def config(self):
        return dict(schema=1,username='terminal',from_addresses=['192.0.2.5'],public_key_path='/protected/application.pub',session='portal')

    def test_exact_key_options_fixed_command_and_renderer_reuse(self):
        value=self.config();state={'home':'/home/terminal','username':'terminal'}
        result=install.rendered(value,state,public(),b'OLD EXISTING KEY WITHOUT NEWLINE')
        line=result['authorized_keys-new'].decode().splitlines()[-1]
        self.assertTrue(line.startswith('from="192.0.2.5",restrict,pty,command="/usr/local/libexec/portal-tmux" ssh-ed25519 '))
        self.assertNotIn('permitopen',line)
        self.assertNotIn('no-pty',line)
        self.assertTrue(result['authorized_keys-new'].startswith(b'OLD EXISTING KEY WITHOUT NEWLINE\n'))
        self.assertEqual(result['launcher'],terminal_launcher.render(launcher=str(install.LAUNCHER),
            socket=str(install.DATA_ROOT/'tmux/socket'),config=str(install.CONFIG_ROOT/'tmux.conf'),
            home='/home/terminal',username='terminal',session='portal').encode())

    def test_public_only_exact_blob_no_options_or_multiline(self):
        self.assertEqual(install.public_key((public()+' generated application key\n').encode()),public())
        for value in ('-----BEGIN OPENSSH PRIVATE KEY-----\n', 'restrict '+public(),public()+'\n'+public(),
                public().replace('ssh-ed25519','ssh-rsa'), 'ssh-ed25519 !!!!',public()+'\r\n'):
            with self.subTest(value=value),self.assertRaises(ValueError):install.public_key(value.encode())
        with self.assertRaises(ValueError):install.public_key(b'ssh-ed25519 '+base64.b64encode(bytes(51)))

    def test_literal_sources_and_account_fields_only(self):
        self.assertEqual(install.configuration(json.dumps(self.config()).encode()),self.config())
        for change in ({'from_addresses':['192.0.2.0/24']},{'from_addresses':['*']},{'from_addresses':['example.invalid']},
            {'from_addresses':['192.0.2.5','192.0.2.5']},{'from_addresses':['127.0.0.1']},
            {'username':'x;id'},{'session':'portal;id'},{'public_key_path':'../key'}, {'extra':'unknown'}):
            with self.subTest(change=change),self.assertRaises((ValueError,TypeError)):
                install.configuration(json.dumps({**self.config(),**change}).encode())


@unittest.skipUnless(os.geteuid()==0,'Synthetic ownership fixtures require root')
class InstallTests(unittest.TestCase):
    def setUp(self):
        temp=tempfile.TemporaryDirectory(prefix='portal-terminal-install-',dir='/run')
        self.addCleanup(temp.cleanup);self.root=Path(temp.name)
        self.home=self.root/'home';self.home.mkdir(mode=0o755);os.chown(self.home,12345,12346)
        self.ssh=self.home/'.ssh';self.ssh.mkdir(mode=0o700);os.chown(self.ssh,12345,12346)
        self.auth=self.ssh/'authorized_keys';self.auth.write_bytes(b'# Existing administrative access\nssh-ed25519 OLD_PUBLIC_KEY existing-admin')
        os.chown(self.auth,12345,12346);self.auth.chmod(0o600)
        self.original=self.auth.read_bytes()
        self.pub=self.root/'application.pub';self.pub.write_text(public()+' application\n');self.pub.chmod(0o600)
        self.libexec=self.root/'libexec';self.libexec.mkdir(mode=0o755)
        for name,path in (('LAUNCHER',self.libexec/'portal-tmux'),('CONFIG_ROOT',self.root/'config'),('DATA_ROOT',self.root/'state')):
            self.patch(install,name,path)
        self.pwd=SimpleNamespace(pw_name='terminal',pw_uid=12345,pw_gid=12346,pw_dir=str(self.home),pw_shell='/bin/bash')
        self.patch(install.pwd,'getpwnam',side_effect=lambda _:self.pwd)
        self.patch(install,'sources',return_value={'inert-synthetic-source':'a'*64})
        self.config=dict(schema=1,username='terminal',from_addresses=['192.0.2.5'],public_key_path=str(self.pub),session='portal')
        self.config_path=self.root/'config.json';self.config_path.write_text(json.dumps(self.config));self.config_path.chmod(0o600)
        self.directory=self.root/'case'

    def patch(self,obj,name,*args,**kwargs):
        patcher=patch.object(obj,name,*args,**kwargs);value=patcher.start();self.addCleanup(patcher.stop);return value

    def prepare(self):
        install.prepare(self.directory,self.config_path)
        self.digest=install.sha((self.directory/'plan.json').read_bytes())
    def apply(self):install.apply(self.directory,self.digest)

    def test_install_preserves_old_keys_and_owner_mode_authorizes_last(self):
        self.prepare();self.assertEqual(self.auth.read_bytes(),self.original)
        self.assertEqual((self.directory/'authorized_keys-backup').read_bytes(),self.original)
        self.assertFalse(install.LAUNCHER.exists())
        old=install.append_last
        def append(*args):
            self.assertTrue(install.LAUNCHER.exists())
            self.assertTrue((install.CONFIG_ROOT/'tmux.conf').exists())
            self.assertTrue((install.DATA_ROOT/'tmux').exists())
            self.assertEqual(self.auth.read_bytes(),self.original)
            return old(*args)
        with patch.object(install,'append_last',side_effect=append):self.apply()
        self.assertTrue(self.auth.read_bytes().startswith(self.original+b'\n'))
        self.assertEqual(self.auth.stat().st_uid,12345)
        self.assertEqual(stat.S_IMODE(self.auth.stat().st_mode),0o600)
        socket_dir=install.DATA_ROOT/'tmux'
        self.assertEqual((socket_dir.stat().st_uid,socket_dir.stat().st_gid,stat.S_IMODE(socket_dir.stat().st_mode)),(12345,12346,0o700))
        self.assertEqual(install.DATA_ROOT.stat().st_uid,0)
        self.assertEqual(install.LAUNCHER.stat().st_uid,0)
        self.assertEqual(stat.S_IMODE(install.LAUNCHER.stat().st_mode),0o755)
        self.assertFalse((socket_dir/'socket').exists())
        self.assertFalse(json.loads((self.directory/'result.json').read_bytes())['authenticated'])
        with self.assertRaises(ValueError):self.apply()

    def test_current_file_drift_refuses_before_intent(self):
        self.prepare();self.auth.write_bytes(self.original+b'\nANOTHER ADMIN KEY\n')
        with self.assertRaisesRegex(ValueError,'state changed'):self.apply()
        self.assertFalse((self.directory/'apply-intent.json').exists())

    def test_existing_root_owned_public_mode_authorization_is_preserved(self):
        os.chown(self.auth,0,0);self.auth.chmod(0o644)
        self.prepare();self.apply()
        self.assertEqual((self.auth.stat().st_uid,self.auth.stat().st_gid,stat.S_IMODE(self.auth.stat().st_mode)),(0,0,0o644))
        self.assertTrue(self.auth.read_bytes().startswith(self.original+b'\n'))

    def test_symlink_product_path_refused_without_following(self):
        foreign=self.root/'foreign-config';foreign.mkdir(mode=0o755)
        install.CONFIG_ROOT.symlink_to(foreign)
        with self.assertRaisesRegex(ValueError,'absent'):self.prepare()
        self.assertEqual(list(foreign.iterdir()),[])

    def test_foreign_uid_authorization_refused(self):
        os.chown(self.auth,12347,12346)
        with self.assertRaisesRegex(ValueError,'metadata'):self.prepare()
        self.assertEqual(self.auth.read_bytes(),self.original)

    def test_uid_shell_and_foreign_key_drift_refuse(self):
        self.prepare();self.pwd.pw_uid=0
        with self.assertRaises(ValueError):self.apply()
        self.pwd.pw_uid=12345;self.pwd.pw_shell='/bin/sh'
        with self.assertRaises(ValueError):self.apply()
        self.pwd.pw_shell='/bin/bash';self.pub.write_text(public()+' CHANGED COMMENT\n')
        with self.assertRaisesRegex(ValueError,'state changed'):self.apply()
        self.assertFalse((self.directory/'apply-intent.json').exists())

    def test_source_and_staged_artifact_drift_refuse_before_intent(self):
        self.prepare()
        with patch.object(install,'sources',return_value={'changed':'b'*64}),self.assertRaises(ValueError):self.apply()
        (self.directory/'launcher').write_bytes(b'MODIFIED')
        with self.assertRaisesRegex(ValueError,'artifact changed'):self.apply()

    def test_existing_product_or_foreign_socket_parent_refused(self):
        install.DATA_ROOT.mkdir(mode=0o700)
        with self.assertRaisesRegex(ValueError,'absent'):self.prepare()
        self.assertEqual(self.auth.read_bytes(),self.original)

    def test_symlink_authorized_keys_never_followed(self):
        foreign=self.root/'foreign';foreign.write_bytes(b'UNTOUCHED')
        self.auth.unlink();self.auth.symlink_to(foreign)
        with self.assertRaises(OSError):self.prepare()
        self.assertEqual(foreign.read_bytes(),b'UNTOUCHED')

    def test_symlink_ssh_parent_and_hardlink_keys_refused(self):
        os.link(self.auth,self.root/'extra-auth-link')
        with self.assertRaises(ValueError):self.prepare()
        (self.root/'extra-auth-link').unlink()
        target=self.home/'.ssh-original';self.ssh.rename(target);self.ssh.symlink_to(target)
        with self.assertRaises(ValueError):self.prepare()

    def test_preexisting_same_application_key_refused(self):
        self.auth.write_bytes(self.original+b'\n'+public().encode()+b'\n')
        with self.assertRaisesRegex(ValueError,'already occurs'):self.prepare()

    def test_partial_product_failure_never_authorizes_and_never_replays(self):
        self.prepare();original=install.create_file
        def create(path,*args):
            if path.name=='tmux.conf':raise RuntimeError('Synthetic config failure')
            return original(path,*args)
        with patch.object(install,'create_file',side_effect=create),self.assertRaisesRegex(RuntimeError,'Synthetic'):self.apply()
        self.assertEqual(self.auth.read_bytes(),self.original)
        self.assertTrue(install.LAUNCHER.exists())
        self.assertEqual(json.loads((self.directory/'result.json').read_bytes())['phase'],'failed')
        with self.assertRaises(ValueError):self.apply()

    def test_key_drift_after_product_creation_is_preserved(self):
        self.prepare();original=install.append_last
        def append(*args):
            self.auth.write_bytes(self.original+b'\nNEW CONCURRENT ADMIN KEY\n')
            return original(*args)
        with patch.object(install,'append_last',side_effect=append),self.assertRaisesRegex(ValueError,'changed'):self.apply()
        self.assertTrue(self.auth.read_bytes().endswith(b'NEW CONCURRENT ADMIN KEY\n'))
        self.assertNotIn(public().encode(),self.auth.read_bytes())

    def test_failure_after_authorization_retains_intent_no_replay(self):
        self.prepare();original=install.files.json_new
        def write(path,value):
            if path.name=='result.json':raise OSError('Synthetic receipt disk failure')
            return original(path,value)
        with patch.object(install.files,'json_new',side_effect=write),self.assertRaisesRegex(OSError,'Synthetic'):self.apply()
        self.assertIn(public().encode(),self.auth.read_bytes())
        self.assertTrue((self.directory/'apply-intent.json').exists())
        with self.assertRaises(ValueError):self.apply()

    def test_optional_creation_of_absent_root_libexec_parent(self):
        self.libexec.rmdir();self.prepare();self.apply()
        self.assertEqual(self.libexec.stat().st_uid,0)
        self.assertEqual(stat.S_IMODE(self.libexec.stat().st_mode),0o755)

    def test_native_multicall_executable_larger_than_eight_mib_is_bound_and_hashed(self):
        binary=self.root/'synthetic-coreutils'
        with binary.open('wb') as stream:stream.truncate(12*1024*1024)
        binary.chmod(0o755)
        self.assertEqual(install.native_hash(binary),install.sha(binary.read_bytes()))
        with binary.open('wb') as stream:stream.truncate(32*1024*1024+1)
        with self.assertRaises(ValueError):install.native_hash(binary)


if __name__=='__main__':unittest.main()
