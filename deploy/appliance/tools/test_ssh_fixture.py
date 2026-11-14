#!/usr/bin/env python3
"""Inert fixture privacy, wire, identity and cleanup ownership boundaries."""
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from types import SimpleNamespace

import probe_login
import ssh_fixture
import test_ssh
import build_ssh_endpoint


class Socket:
    def __init__(self, messages):
        self.data = b''.join(probe_login.encode(m) for m in messages)
        self.sent = []
    def __enter__(self): return self
    def __exit__(self, *args): pass
    def settimeout(self, value): pass
    def recv(self, size):
        value, self.data = self.data[:size], self.data[size:]
        return value
    def sendall(self, data): self.sent.append(data)


def params():
    return {'hostname': '127.0.0.1', 'port': '2222', 'username': 'fixture',
            'command': '/run/fixture/launcher', 'host-key': 'SECRET_PIN', 'private-key': 'SECRET_KEY'}


class Boundaries(unittest.TestCase):
    def test_error_text_and_keys_not_retained(self):
        sock = Socket([['args', *params()], ['error', 'SECRET_ERROR_TEXT', '519']])
        with patch('ssh_fixture.socket.create_connection', return_value=sock):
            result = ssh_fixture.native(params())
        self.assertEqual(result['status'], 519)
        self.assertNotIn('SECRET', json.dumps(result))
        self.assertEqual(result, test_ssh.native_result(result))
        self.assertEqual(sum(b'.connect,' in v for v in sock.sent), 1)

    def test_unexpected_endpoint_refused_before_socket(self):
        for key, value in [('hostname', '192.0.2.1'), ('port', '22'),
                           ('username', 'owner'), ('command', '/bin/bash')]:
            with self.subTest(key=key), patch('ssh_fixture.socket.create_connection') as connect:
                with self.assertRaises(ValueError): ssh_fixture.native(dict(params(), **{key: value}))
                connect.assert_not_called()

    def test_password_or_oversized_key_refused(self):
        for value in [dict(params(), password='SECRET'), dict(params(), **{'private-key': 'x'*16385})]:
            with patch('ssh_fixture.socket.create_connection') as connect:
                with self.assertRaises(ValueError): ssh_fixture.native(value)
                connect.assert_not_called()

    def test_malformed_error_code_never_returned(self):
        sock = Socket([['args', *params()], ['error', 'SECRET', 'TOKEN']])
        with patch('ssh_fixture.socket.create_connection', return_value=sock):
            with self.assertRaises(probe_login.ProtocolError): ssh_fixture.native(params())

    def test_receipt_rejects_arbitrary_output_fields(self):
        safe = dict(status=519, display_instructions=0, syncs=0, injected=False, outcome='guacd_error')
        for value in [dict(safe, error='SECRET'), dict(safe, status=True), dict(safe, status=65536),
                      dict(safe, outcome='SECRET')]:
            with self.assertRaises(ValueError): test_ssh.native_result(value)

    def test_process_identity_not_just_pid(self):
        a = {'sentinel': {'pid': 1, 'start': 1}, 'process': {'pid': 20, 'start': 30, 'counter': 4}}
        b = {'sentinel': {'pid': 1, 'start': 1}, 'process': {'pid': 20, 'start': 30, 'counter': 8}}
        self.assertTrue(test_ssh.persisted(a, b))
        for changed in [dict(b['process'], start=31), dict(b['process'], counter=4), dict(b['process'], pid=21)]:
            self.assertFalse(test_ssh.persisted(a, dict(b, process=changed)))
        self.assertFalse(test_ssh.persisted(a, dict(b, sentinel={'pid': 2, 'start': 2})))
        with self.assertRaises(ValueError): test_ssh.metadata_result(dict(b, secret='SECRET'))

    def test_cleanup_requires_all_owned_bindings(self):
        expected = dict(cid='a'*64, image='sha256:'+'b'*64, token='t', name='fixture')
        info = {'Id': expected['cid'], 'Image': expected['image'], 'Name': '/fixture',
                'Config': {'Labels': {test_ssh.LABEL: 't'}}}
        self.assertTrue(test_ssh.owned(info, **expected))
        self.assertTrue(test_ssh.owned(dict(info, Image='b'*64), **expected))
        for key in expected:
            wrong = dict(expected, **{key: 'wrong'})
            self.assertFalse(test_ssh.owned(info, **wrong))

    def test_mutable_image_tags_not_accepted(self):
        self.assertEqual(test_ssh.exact_image('a'*64), 'sha256:'+'a'*64)
        for value in ['latest', 'localhost/image:latest', 'sha256:'+'a'*63, 'A'*64]:
            with self.assertRaises(ValueError): test_ssh.exact_image(value)

    def test_builder_rejects_unverified_ca_before_build(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/'ca'
            path.write_bytes(b'UNVERIFIED')
            with self.assertRaises(ValueError): build_ssh_endpoint.inputs(path)

    def test_empty_or_extra_process_metadata_not_accepted(self):
        for value in [{}, {'sentinel': {'pid': 1, 'start': 'SECRET'}},
                      {'sentinel': {'pid': 1, 'start': 2, 'error': 'SECRET'}}]:
            with self.assertRaises(ValueError): test_ssh.metadata_result(value)

    def test_uncertain_start_cleanup_uses_owned_id_and_bounded_stop_grace(self):
        item = {'name': 'fresh', 'cid': None, 'image': 'sha256:'+'a'*64}
        cid = 'b'*64
        calls = []
        def engine(*args, **kwargs):
            calls.append((args, kwargs))
            if args[0] == 'inspect':
                return SimpleNamespace(stdout=json.dumps([{'Id': cid, 'Image': 'a'*64,
                    'Name': 'fresh', 'Config': {'Labels': {test_ssh.LABEL: 'token'}}}]).encode())
            removed = any(c[0][0] == 'rm' for c in calls)
            return SimpleNamespace(returncode=1 if removed else 0)
        with patch.object(test_ssh, 'engine', side_effect=engine): test_ssh.cleanup_owned(item, 'token')
        self.assertIn((('rm', '-f', '--time=2', cid), {'timeout': 15}), calls)
        self.assertEqual(calls[-1][0], ('container', 'exists', 'fresh'))

    def test_engine_error_is_not_cleanup_absence(self):
        with patch.object(test_ssh, 'engine', return_value=SimpleNamespace(returncode=125)) as engine:
            with self.assertRaises(RuntimeError):
                test_ssh.cleanup_owned({'name': 'fresh', 'cid': None, 'image': 'sha256:'+'a'*64}, 'token')
        self.assertEqual(engine.call_count, 1)


if __name__ == '__main__': unittest.main()
