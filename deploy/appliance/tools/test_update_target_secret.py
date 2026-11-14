#!/usr/bin/env python3
"""Inert stale-config, identity, stdin and stopped-service boundaries."""
import copy
import hashlib
import io
import json
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch
import update_target_secret as update


class Boundaries(unittest.TestCase):
    def fixture(self):
        config=json.loads((Path(__file__).resolve().parents[1]/'examples/config.json').read_bytes())
        raw=json.dumps(config).encode()
        alias=next(iter(config['targets']))
        args=SimpleNamespace(alias=alias,expected_username=config['targets'][alias]['username'],
                             expected_config_sha256=hashlib.sha256(raw).hexdigest())
        return config,raw,args

    def test_config_digest_and_expected_username_required(self):
        config,raw,args=self.fixture()
        with patch.object(update.network,'protected_read',return_value=raw), \
                patch.object(Path,'lstat',return_value=SimpleNamespace(st_mode=0o100644,st_nlink=1)):
            self.assertEqual(update.target(args),update.SECRETS/config['targets'][args.alias]['password_file'])
            args.expected_username='OtherUser'
            with self.assertRaises(ValueError):update.target(args)
            args.expected_config_sha256='0'*64
            with self.assertRaises(ValueError):update.target(args)

    def test_shared_target_secret_refused(self):
        config,raw,args=self.fixture()
        targets=list(config['targets'].values())
        targets[1]['password_file']=targets[0]['password_file']
        raw=json.dumps(config).encode();args.expected_config_sha256=hashlib.sha256(raw).hexdigest()
        with patch.object(update.network,'protected_read',return_value=raw), \
                patch.object(Path,'lstat',return_value=SimpleNamespace(st_mode=0o100644,st_nlink=1)):
            with self.assertRaises(ValueError):update.target(args)

    def test_access_time_does_not_change_identity_but_real_changes_do(self):
        fields=dict(st_uid=0,st_gid=0,st_mode=0o100600,st_nlink=1,st_dev=1,st_ino=2,
                    st_size=12,st_mtime_ns=100,st_ctime_ns=100,st_atime_ns=100)
        before=SimpleNamespace(**fields);after=copy.copy(before);after.st_atime_ns=200
        self.assertEqual(update.stable(before),update.stable(after))
        for field in ('st_uid','st_gid','st_mode','st_nlink','st_dev','st_ino','st_size','st_mtime_ns','st_ctime_ns'):
            changed=copy.copy(before);setattr(changed,field,getattr(changed,field)+1)
            self.assertNotEqual(update.stable(before),update.stable(changed))

    def test_running_service_prevents_any_stdin_or_case_read(self):
        args=SimpleNamespace(directory=Path('/private/synthetic-new-case'),expected_config_sha256='a'*64)
        incoming=Mock()
        meta=SimpleNamespace(st_mode=0o100600,st_uid=0,st_nlink=1)
        with patch.object(update.os,'geteuid',return_value=0),patch.object(update.files,'protected_directory'), \
                patch.object(update.os,'open',return_value=99),patch.object(update.os,'fstat',return_value=meta), \
                patch.object(update.os,'close'),patch.object(update.fcntl,'flock'), \
                patch.object(update,'inactive',side_effect=ValueError('active')), \
                patch.object(update.files,'new_directory') as create:
            with self.assertRaises(ValueError):update.update(args,incoming,{'success':False})
        incoming.read.assert_not_called();create.assert_not_called()

    def test_single_bounded_line_normalization(self):
        self.assertEqual(update.files.windows_password(b'SyntheticOnly\n'),b'SyntheticOnly')
        for raw in (b'',b'a\nb',b'a\r\n',b'a\0b',b'a'*513):
            with self.assertRaises(ValueError):update.files.windows_password(raw)


if __name__=='__main__':unittest.main()
