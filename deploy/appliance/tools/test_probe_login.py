#!/usr/bin/env python3
"""Inert protocol, parameter-preservation and durable no-replay boundaries."""
import contextlib
import io
import json
from pathlib import Path
from types import SimpleNamespace
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import catalog
import probe_login as probe
import run_login_probe as runner

ARGS = ['VERSION_1_5_0','hostname','port','username','domain','password','security','cert-fingerprints']


def report():
    return dict(schema=1, uid=0, domain_empty=True, single_connection=True, full_browser_acceptance=False,
                stage='validate', outcome='probe_failure', status=None, instructions=0,
                display_instructions=0, display_payload_characters=0)


class Socket:
    def __init__(self, data, chunk=16384):
        self.data, self.chunk, self.sent = data, chunk, []
    def recv(self, size):
        block, self.data = self.data[:min(size,self.chunk)], self.data[min(size,self.chunk):]
        return block
    def sendall(self, value): self.sent.append(value)
    def settimeout(self, value): pass


class ProtocolTests(unittest.TestCase):
    def test_error_message_is_never_returned(self):
        sock = Socket(probe.encode(['args',*ARGS])+probe.encode(['error','PRIVATE PASSWORD AND DESKTOP TEXT','519']))
        value = report()
        probe.exchange(sock, {'username':'synthetic','password':'SECRET'}, time.monotonic()+2, value)
        self.assertEqual(value['status'],519)
        self.assertEqual(value['outcome'],'guacd_error')
        self.assertNotIn('PRIVATE',json.dumps(value))
        self.assertEqual(sum(b'.connect,' in msg for msg in sock.sent),1)

    def test_display_blob_and_sync_acknowledged_without_export(self):
        sock = Socket(b''.join(probe.encode(msg) for msg in [
            ['args',*ARGS],['img','0','0','image/png','0','0','0'],['blob','0','PRIVATE_BITMAP'],['sync','123']]))
        value = report()
        probe.exchange(sock, {}, time.monotonic()+2, value)
        self.assertEqual(value['outcome'],'display_activity')
        self.assertEqual(value['display_instructions'],1)
        self.assertEqual(value['display_payload_characters'],14)
        self.assertIn(probe.encode(['ack','0','OK','0']),sock.sent)
        self.assertIn(probe.encode(['sync','123']),sock.sent)
        self.assertNotIn('PRIVATE',json.dumps(value))
        self.assertFalse(value['full_browser_acceptance'])

    def test_default_geometry_and_return_behavior_remain_unchanged(self):
        sock = Socket(b''.join(probe.encode(msg) for msg in [
            ['args',*ARGS],['rect','0','0','0','10','10'],['sync','123']]))
        returned = probe.exchange(sock, {}, time.monotonic()+2, report())
        self.assertIsNone(returned)
        self.assertIn(probe.encode(['size','1024','768','96']), sock.sent)
        for instruction in [['audio'],['video'],['image','image/png','image/jpeg'],['timezone','Etc/UTC']]:
            self.assertIn(probe.encode(instruction),sock.sent)

    def test_explicit_geometry_returns_same_buffered_protocol(self):
        sock = Socket(b''.join(probe.encode(msg) for msg in [
            ['args',*ARGS],['rect','0','0','0','10','10'],['sync','123'],['sync','456']]))
        protocol = probe.exchange(sock, {}, time.monotonic()+2, report(),
                                  geometry=(1100,800,96), return_protocol=True)
        self.assertIs(protocol.sock, sock)
        self.assertIn(probe.encode(['size','1100','800','96']), sock.sent)
        self.assertEqual(protocol.read(), ['sync','456'])

    def test_explicit_media_order_and_timezone_are_preserved(self):
        sock = Socket(b''.join(probe.encode(msg) for msg in [
            ['args',*ARGS],['rect','0','0','0','10','10'],['sync','123']]))
        media={'audio':['audio/L8','audio/L16'],'video':[],
               'image':['image/webp','image/jpeg','image/png'],'timezone':'Etc/UTC'}
        probe.exchange(sock,{},time.monotonic()+2,report(),media=media)
        self.assertIn(probe.encode(['audio','audio/L8','audio/L16']),sock.sent)
        self.assertIn(probe.encode(['video']),sock.sent)
        self.assertIn(probe.encode(['image','image/webp','image/jpeg','image/png']),sock.sent)
        self.assertIn(probe.encode(['timezone','Etc/UTC']),sock.sent)

    def test_invalid_optional_media_fails_before_wire_writes(self):
        sock=Socket(b'')
        with self.assertRaises(ValueError):
            probe.exchange(sock,{},time.monotonic()+2,report(),media={'token':'private'})
        self.assertEqual(sock.sent,[])

    def test_invalid_geometry_is_rejected_before_protocol_writes(self):
        for geometry in ((0,800,96), (1100,800,True), (1100,800), 'private value'):
            sock = Socket(b'')
            with self.subTest(geometry=geometry), self.assertRaises(ValueError):
                probe.exchange(sock, {}, time.monotonic()+2, report(), geometry=geometry)
            self.assertEqual(sock.sent, [])

    def test_oversized_length_and_nonnumeric_error_rejected(self):
        for data in [b'9999999.x;',b'x.bad;',b'1.x!',probe.encode(['args',*ARGS])+probe.encode(['error','PRIVATE','NaN'])]:
            with self.subTest():
                with self.assertRaises(probe.ProtocolError):
                    probe.exchange(Socket(data),{},time.monotonic()+2,report())

    def test_expired_deadline_stops_before_write(self):
        sock = Socket(b'')
        with self.assertRaises(TimeoutError):
            probe.exchange(sock,{},time.monotonic()-1,report())
        self.assertEqual(sock.sent,[])

    def test_eof_and_instruction_limit_are_bounded(self):
        with self.assertRaises(EOFError):
            probe.Protocol(Socket(b'5.ab'),time.monotonic()+2).read()
        sock=Socket(probe.encode(['args',*ARGS])+probe.encode(['sync','123']))
        with patch.object(probe,'MAX_INSTRUCTIONS',1), self.assertRaises(probe.ProtocolError):
            probe.exchange(sock,{},time.monotonic()+2,report())

    def test_unicode_lengths_and_split_utf8(self):
        self.assertEqual(probe.encode(['password','a\u00e9']),b'8.password,2.a\xc3\xa9;')
        self.assertEqual(probe.Protocol(Socket(probe.encode(['x','a\u00e9']),chunk=1),time.monotonic()+2).read(),['x','a\u00e9'])

    def test_only_domain_and_password_are_substituted(self):
        target=catalog.Target('desktop-a','Synthetic','192.0.2.9',3389,'SyntheticUser','LOCALHOST',
            'nla','sha256:'+':'.join(['00']*32),'desktop-a-password')
        original=target.parameters()
        result=probe.parameters(target,'SyntheticUser',lambda ref:'SECRET')
        self.assertEqual({k:v for k,v in result.items() if k not in {'domain','password'}},
                         {k:v for k,v in original.items() if k not in {'domain','password'}})
        self.assertEqual(result['domain'],'')
        self.assertEqual(result['password'],'SECRET')
        self.assertEqual(target.domain,'LOCALHOST')
        with self.assertRaises(ValueError): probe.parameters(target,'OtherUser',lambda ref:'SECRET')


class IntentTests(unittest.TestCase):
    def args(self, directory):
        return SimpleNamespace(ssh_host='synthetic-admin',container='a'*64,expected_image='b'*64,
            alias='desktop-a',expected_username='SyntheticUser',authorization='owner:synthetic',directory=directory)

    def test_intent_durable_before_dispatch_and_case_refuses_replay(self):
        with tempfile.TemporaryDirectory() as parent:
            directory=Path(parent)/'case'
            dispatched=[]
            def dispatch(command,**kwargs):
                intent=json.loads((directory/'intent.json').read_text())
                self.assertEqual(intent['container_id'],'a'*64)
                self.assertTrue(intent['domain_empty'])
                self.assertEqual(len(intent['source_sha256']),64)
                self.assertIn('-oStrictHostKeyChecking=yes',command)
                self.assertIn('-oControlMaster=no',command)
                dispatched.append(command)
                value=report();value.update(stage='observe',outcome='guacd_error',status=519,instructions=1)
                return SimpleNamespace(returncode=1,stdout=json.dumps(value).encode())
            with patch.object(runner.subprocess,'run',side_effect=dispatch), contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(runner.run(self.args(directory)),1)
                with self.assertRaises(FileExistsError): runner.run(self.args(directory))
            self.assertEqual(len(dispatched),1)
            self.assertEqual((directory/'intent.json').stat().st_mode&0o777,0o600)

    def test_raw_output_and_unexpected_fields_never_written(self):
        with tempfile.TemporaryDirectory() as parent:
            directory=Path(parent)/'case'
            value=report();value['raw_error']='PRIVATE SECRET'
            with patch.object(runner.subprocess,'run',return_value=SimpleNamespace(returncode=1,stdout=json.dumps(value).encode())), contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(runner.run(self.args(directory)),1)
            self.assertNotIn('PRIVATE', (directory/'result.json').read_text())
            self.assertEqual({p.name for p in directory.iterdir()},{'intent.json','result.json'})


if __name__=='__main__': unittest.main()
