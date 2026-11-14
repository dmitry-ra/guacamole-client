"""Synthetic RDP telemetry remains useful on failure without retaining content."""
import unittest
import json
import subprocess
import sys
import tempfile
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch
import test_rdp


class MarkerTelemetryTest(unittest.TestCase):
    def pixels(self):
        return {'state': 'CONNECTED', 'status': 0, 'width': 0, 'height': 0,
                'green': 0, 'navy': 0, 'nonblack': 0,
                'unexpected_private_content': 'must not be retained'}

    def test_empty_pending_display_is_recorded_without_content(self):
        row = test_rdp.marker_observation('desktop-a', 'green', self.pixels(), 100)
        self.assertEqual(row, {'alias': 'desktop-a', 'expected_marker': 'green',
                              'polls': 100, 'state': 'CONNECTED', 'status': 0,
                              'width': 0, 'height': 0, 'green': 0, 'navy': 0, 'nonblack': 0})

    def test_invalid_alias_or_values_are_not_echoed(self):
        with self.assertRaisesRegex(ValueError, 'Unknown synthetic marker alias'):
            test_rdp.marker_observation('arbitrary private alias', 'green', self.pixels(), 1)
        for key, value in [('state', 'arbitrary private state'), ('status', True),
                           ('width', -1), ('nonblack', 'private content')]:
            pixels = self.pixels(); pixels[key] = value
            with self.assertRaises(ValueError) as error:
                test_rdp.marker_observation('desktop-a', 'green', pixels, 1)
            self.assertNotIn('private', str(error.exception))


class DiagnosticModeTest(unittest.TestCase):
    def test_diagnostic_completion_never_becomes_normal_acceptance(self):
        receipt = {'passed': True}
        test_rdp.finish_receipt(receipt, True)
        self.assertEqual(receipt, {'passed': False, 'diagnostic_complete': True})
        test_rdp.finish_receipt(receipt, False)
        self.assertEqual(receipt, {'passed': True, 'diagnostic_complete': False})


    def test_diagnostic_never_emits_full_connected_stage_even_with_both_markers(self):
        states = {'desktop-a': {'state': 'CONNECTED', 'status': 0, 'green': 6000, 'nonblack': 12000},
                  'desktop-b': {'state': 'CONNECTED', 'status': 0, 'navy': 6000, 'nonblack': 12000}}
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            test_rdp.connected_stage(directory, states, True)
            self.assertFalse((directory/'both-connected.json').exists())
            test_rdp.connected_stage(directory, states, False)
            self.assertTrue((directory/'both-connected.json').is_file())
            states['desktop-b']['state'] = 'TUNNEL_ERROR'
            with self.assertRaisesRegex(AssertionError, 'Incomplete synthetic connected stage'):
                test_rdp.connected_stage(directory, states, False)


class DiagnosticPropagationTest(unittest.IsolatedAsyncioTestCase):
    async def test_diagnostic_flag_reaches_browser_without_network(self):
        class Response:
            status = 403
            async def __aenter__(self): return self
            async def __aexit__(self, *args): pass
        class Session:
            async def __aenter__(self): return self
            async def __aexit__(self, *args): pass
            def post(self, *args, **kwargs): return Response()
        fake = SimpleNamespace(ClientSession=Session,
                               ClientTimeout=lambda **kwargs: None,
                               ClientError=RuntimeError)
        with patch.dict(sys.modules, {'aiohttp': fake}), patch.object(test_rdp, 'browser', new_callable=AsyncMock) as browser:
            await test_rdp.acceptance('http://synthetic.invalid/', None, [], True)
            browser.assert_awaited_once_with('http://synthetic.invalid/', None, [], True, 'alpha-beta')


class TargetOrderTest(unittest.TestCase):
    def test_default_acceptance_order_and_diagnostic_reverse_preserve_identity(self):
        expected = [('desktop-a', '1', 'green'), ('desktop-b', '2', 'navy')]
        self.assertEqual(test_rdp.target_sequence(), expected)
        self.assertEqual(test_rdp.target_sequence('beta-alpha', True), list(reversed(expected)))

    def test_alternate_order_cannot_be_full_acceptance(self):
        with self.assertRaisesRegex(ValueError, 'requires diagnostic mode'):
            test_rdp.target_sequence('beta-alpha', False)
        with self.assertRaisesRegex(ValueError, 'Invalid synthetic target order'):
            test_rdp.target_sequence('unknown', True)


class SafePhaseTest(unittest.TestCase):
    def test_private_suffixes_and_unrecognized_messages_never_survive(self):
        private = 'password=must-not-survive endpoint=private.invalid username=hidden'
        raw = ('2026-11-14T16:00:00.123Z GuacamoleUpstreamTimeoutException ' + private + '\n'
               '2026-11-14T16:00:01Z ERRCONNECT_TLS_CONNECT_FAILED ' + private + '\n' + private)
        summary = test_rdp.safe_phase_summary(raw)
        self.assertEqual(summary['counts']['java_upstream_timeout'], 1)
        self.assertEqual(summary['counts']['freerdp_TLS_error'], 1)
        self.assertEqual(len(summary['events']), 2)
        self.assertEqual(summary['events'][0]['timestamp'], '2026-11-14T16:00:00.123Z')
        self.assertNotIn('must-not-survive', str(summary))
        self.assertNotIn('private.invalid', str(summary))
        self.assertNotIn('username', str(summary))

    def test_resource_errors_are_counted_without_private_messages(self):
        raw = ('pthread_create failed: Resource temporarily unavailable secret-password\n'
               'java.lang.OutOfMemoryError: unable to create native thread username-hidden')
        summary = test_rdp.safe_phase_summary(raw)
        self.assertEqual(summary['counts']['thread_creation_error'], 1)
        self.assertEqual(summary['counts']['resource_exhaustion'], 2)
        self.assertEqual(summary['counts']['java_out_of_memory'], 1)
        self.assertNotIn('secret-password', str(summary))
        self.assertNotIn('username-hidden', str(summary))

    def test_summary_is_bounded(self):
        summary = test_rdp.safe_phase_summary('x' * 300000 + '\nSocketTimeoutException')
        self.assertTrue(summary['truncated'])
        self.assertLessEqual(summary['characters_considered'], 256 * 1024)
        self.assertEqual(summary['counts']['java_socket_timeout'], 1)


class NativeModeGuardTest(unittest.IsolatedAsyncioTestCase):
    async def test_native_consumers_cannot_enter_full_acceptance(self):
        with patch.object(test_rdp, 'podman', side_effect=AssertionError('engine touched')):
            with self.assertRaisesRegex(ValueError, 'requires diagnostic mode'):
                await test_rdp.fixture('a'*64, None, None, None, None,
                                       markers_only=False, native_concurrent=True)


class PublicClientInfoTest(unittest.TestCase):
    def info(self):
        return {'audio':['audio/L8','audio/L16'],'video':[],
                'image':['image/webp','image/png','image/jpeg'],
                'timezone':'Etc/UTC','width':1100,'height':800,'dpi':96}

    def test_exact_public_lists_preserve_browser_order(self):
        value=self.info()
        self.assertEqual(test_rdp.validated_client_info(value),value)

    def test_private_unknown_fields_values_and_bad_geometry_are_refused(self):
        for key,value in [('token','private-token'),('audio',['audio/PRIVATE_SECRET']),
                          ('image',['image/png','image/png']),('width',True),
                          ('timezone','private secret')]:
            info=self.info();info[key]=value
            with self.subTest(key=key),self.assertRaises(ValueError) as error:
                test_rdp.validated_client_info(info)
            self.assertNotIn('private',str(error.exception).lower())
            self.assertNotIn('SECRET',str(error.exception))


class JavaDiagnosticTest(unittest.IsolatedAsyncioTestCase):
    async def test_java_cannot_enter_acceptance_or_share_native_mode(self):
        with patch.object(test_rdp,'podman',side_effect=AssertionError('engine touched')):
            for markers,native in ((False,False),(True,True)):
                with self.assertRaisesRegex(ValueError,'exclusive diagnostic'):
                    await test_rdp.fixture('a'*64,None,None,None,None,
                        markers_only=markers,native_concurrent=native,java_concurrent=True)

    def test_properties_escape_control_characters_without_new_keys(self):
        value=test_rdp.java_properties({'key':' leading\\slash\nsecond\tpart'})
        self.assertEqual(value,'key=\\ leading\\\\slash\\nsecond\\tpart\n')
        self.assertEqual(len(value.splitlines()),1)

    def test_nonzero_numeric_java_failure_is_retained_but_content_refused(self):
        self.assertEqual(test_rdp.numeric_java_report({'result':2,'status':512}),
                         {'result':2,'status':512})
        with self.assertRaises(ValueError) as error:
            test_rdp.numeric_java_report({'result':1,'message':'PRIVATE_PASSWORD'})
        self.assertNotIn('PRIVATE',str(error.exception))


class RawWebDiagnosticTest(unittest.IsolatedAsyncioTestCase):
    def values(self):
        return {'client_state':3,'client_error':0,'tunnel_error':0,'tunnel_state':1,
                'ws_state':1,'http_state':2,'instructions':100,'sync':5,'blob':10,
                'required':0,'argv':0,'width':1100,'height':800,
                'green':0,'navy':120000,'nonblack':140000,'canvas_error':0,'managed_clients':0}

    async def test_raw_web_cannot_enter_full_or_other_diagnostic_modes(self):
        with patch.object(test_rdp,'podman',side_effect=AssertionError('engine touched')):
            for markers,native,java in ((False,False,False),(True,True,False),(True,False,True)):
                with self.assertRaisesRegex(ValueError,'exclusive diagnostic'):
                    await test_rdp.fixture('a'*64,None,None,None,None,markers_only=markers,
                        native_concurrent=native,java_concurrent=java,raw_web=True)

    def test_actual_alias_color_and_connected_state_are_required(self):
        row=test_rdp.raw_web_observation('desktop-b','navy',self.values(),1)
        self.assertTrue(test_rdp.raw_web_ready(row))
        values=self.values();values['navy']=0;values['green']=120000
        self.assertFalse(test_rdp.raw_web_ready(test_rdp.raw_web_observation('desktop-b','navy',values,1)))
        values=self.values();values['tunnel_error']=514
        self.assertFalse(test_rdp.raw_web_ready(test_rdp.raw_web_observation('desktop-b','navy',values,1)))
        values=self.values();values.update(ws_state=2,http_state=2,tunnel_state=2)
        self.assertFalse(test_rdp.raw_web_ready(test_rdp.raw_web_observation('desktop-b','navy',values,1)))

    def test_raw_callbacks_forward_native_handlers_and_keep_token_private(self):
        profile=PublicClientInfoTest().info()
        bootstrap=test_rdp.RAW_WEB_BOOTSTRAP.replace('__PROFILE__',json.dumps(profile))
        program="""global.window={};global.document={documentElement:{}};
global.angular={element:()=>({injector:()=>({get:()=>({getManagedClients:()=>({})})})})};
let shared=0,context=true;const calls={client_state:0,client_error:0,tunnel_state:0,tunnel_error:0,instruction:0};
global.fetch=async(url,options)=>({status:options.method==='POST'?200:204,json:async()=>({authToken:'FAKE_PRIVATE_TOKEN'})});
class Tunnel {constructor(){this.state=2;}};
class Chain {constructor(first,second){this.first=first;this.second=second;}};
class Client {constructor(tunnel){this.tunnel=tunnel;const self=this;
this.onstatechange=function(){calls.client_state++;context&&=this===self;};
this.onerror=function(){calls.client_error++;context&&=this===self;};
tunnel.onstatechange=function(){calls.tunnel_state++;context&&=this===tunnel;};
tunnel.onerror=function(){calls.tunnel_error++;context&&=this===tunnel;};
tunnel.oninstruction=function(){calls.instruction++;context&&=this===tunnel;};}
connect(data){if(new URLSearchParams(data).get('token')==='FAKE_PRIVATE_TOKEN')shared++;this.tunnel.first.state=1;this.onstatechange(3);this.onerror({code:0});this.tunnel.onstatechange(1);this.tunnel.onerror({code:0});this.tunnel.oninstruction('sync',['1']);}
getDisplay(){return {flatten:()=>({width:0,height:0})};}disconnect(){this.onstatechange(5);}}
global.Guacamole={WebSocketTunnel:Tunnel,HTTPTunnel:Tunnel,ChainedTunnel:Chain,Client};
(async()=>{const initialized="""+bootstrap+""";const auth=await window.__homelabRawRdp.login('000000');window.__homelabRawRdp.start('desktop-b','2');window.__homelabRawRdp.start('desktop-a','1');const rows=[initialized,auth,window.__homelabRawRdp.observe('desktop-b'),window.__homelabRawRdp.observe('desktop-a'),await window.__homelabRawRdp.close()];if(JSON.stringify(rows).includes('FAKE_PRIVATE_TOKEN'))throw new Error('Privacy failure');console.log(JSON.stringify({shared,context,calls}));})().catch(()=>{process.exitCode=1;});"""
        result=subprocess.run(['node','-e',program],check=True,capture_output=True,text=True,timeout=10)
        value=json.loads(result.stdout)
        self.assertEqual(value['shared'],2)
        self.assertTrue(value['context'])
        self.assertEqual(value['calls'],{'client_state':4,'client_error':2,
            'tunnel_state':2,'tunnel_error':2,'instruction':2})

    def test_raw_telemetry_refuses_private_extra_fields(self):
        values=self.values();values['token']='PRIVATE_TOKEN'
        with self.assertRaises(ValueError) as error:
            test_rdp.raw_web_observation('desktop-b','navy',values,1)
        self.assertNotIn('PRIVATE',str(error.exception))


class HandshakeAuditTest(unittest.IsolatedAsyncioTestCase):
    def flow(self):
        return {'flow': 1, 'alias': 'desktop-b', 'phases': {'syn': 1.0, 'connect': 2.0},
            'equality': {'password': True}, 'unknown_parameter_count': 0,
            'comparison_observed': True, 'status': None, 'ready': False, 'complete': False,
            'password_placeholder': False}

    def test_observations_cannot_export_values_or_unknown_names(self):
        value = self.flow()
        self.assertEqual(test_rdp.safe_handshake_record(value), value)
        for field, item in [('extra', 'PRIVATE'), ('alias', 'PRIVATE'),
                            ('phases', {'PRIVATE': 1}), ('equality', {'password': 'PRIVATE'}),
                            ('status', 65536), ('flow', True), ('phases', {'syn': float('nan')})]:
            bad = self.flow(); bad[field] = item
            with self.assertRaises(ValueError) as error:
                test_rdp.safe_handshake_record(bad)
            self.assertNotIn('PRIVATE', str(error.exception))

    async def test_audit_rejects_non_raw_modes_before_lifecycle(self):
        for options in ({}, {'markers_only': True}, {'raw_web': True},
                        {'raw_web': True, 'markers_only': True, 'native_concurrent': True}):
            with self.assertRaisesRegex(ValueError, 'exclusive raw web diagnostic'):
                await test_rdp.fixture('a'*64, None, None, None, None,
                                       audit_handshake=True, **options)

    async def test_safe_reader_records_ready_flow_finish_without_external_process(self):
        with tempfile.TemporaryDirectory() as temporary:
            audit = test_rdp.HandshakeAudit(Path(temporary))
            audit.ready = test_rdp.asyncio.get_running_loop().create_future()
            reader = test_rdp.asyncio.StreamReader()
            audit.process = SimpleNamespace(stdout=reader)
            rows = [{'capture_ready': True, 'epoch': 1.0}, self.flow(),
                    {'finished': True, 'epoch': 3.0, 'flows': 1}]
            for row in rows:
                reader.feed_data((json.dumps(row)+'\n').encode())
            reader.feed_eof()
            await audit.read()
            self.assertTrue(audit.ready.result())
            self.assertEqual(audit.records, rows)
            self.assertEqual(json.loads((Path(temporary)/'handshake-audit.json').read_text())['records'], rows)

    async def test_stop_closes_stdin_before_waiting_for_collector(self):
        calls = []
        class Process:
            returncode = 0
            stdin = SimpleNamespace(close=lambda: calls.append('eof'))
            async def wait(self): calls.append('wait')
        audit = test_rdp.HandshakeAudit(None)
        audit.process = Process()
        audit.started = test_rdp.time.monotonic()
        audit.task = test_rdp.asyncio.get_running_loop().create_future()
        audit.task.set_result(None)
        await audit.stop()
        self.assertEqual(calls, ['eof', 'wait'])


class HttpRelayTelemetryTest(unittest.TestCase):
    def test_queued_slots_and_backend_eof_are_distinct_from_release(self):
        with tempfile.TemporaryDirectory() as temporary:
            telemetry = test_rdp.HttpRelayTelemetry(Path(temporary))
            rows = [telemetry.accepted() for _ in range(10)]
            for row in rows[:8]:
                telemetry.acquired(row)
                telemetry.child_started(row)
                telemetry.backend_connected(row)
            self.assertEqual((telemetry.active, telemetry.queued, telemetry.children), (8, 2, 8))
            telemetry.data(rows[0], 'client', 100)
            telemetry.data(rows[0], 'backend', 200)
            telemetry.eof(rows[0], 'backend')
            telemetry.pipe_finished(rows[0], 'backend')
            telemetry.pipe_finished(rows[0], 'client')
            self.assertNotIn('client_eof_epoch', rows[0])
            self.assertEqual((telemetry.active, telemetry.queued), (8, 2))
            self.assertNotIn('released_epoch', rows[0])
            telemetry.released(rows[0])
            self.assertEqual((telemetry.active, telemetry.children), (7, 8))
            telemetry.acquired(rows[8])
            telemetry.closed(rows[0])
            self.assertEqual((telemetry.active, telemetry.queued, telemetry.children), (8, 1, 7))
            telemetry.released(rows[9]); telemetry.closed(rows[9])
            self.assertEqual(telemetry.queued, 0)
            result = json.loads((Path(temporary)/'http-relay.json').read_bytes())
            self.assertEqual(result['limit'], 8)
            self.assertEqual(result['highwater'], {'active': 8, 'queued': 10, 'children': 8})
            self.assertEqual(rows[0]['client_bytes'], 100)
            self.assertEqual(rows[0]['backend_bytes'], 200)
            self.assertLessEqual(rows[0]['released_epoch'], rows[0]['closed_epoch'])
            self.assertLessEqual(rows[0]['released_epoch'], rows[0]['child_exited_epoch'])
            self.assertTrue(all(row['queue_wait_ms'] >= 0 for row in rows[:9]))

    def test_transport_counter_refuses_arbitrary_content(self):
        with tempfile.TemporaryDirectory() as temporary:
            telemetry = test_rdp.HttpRelayTelemetry(Path(temporary))
            row = telemetry.accepted()
            with self.assertRaises(AssertionError):
                telemetry.data(row, 'PRIVATE', 1)
            with self.assertRaises(AssertionError):
                telemetry.data(row, 'client', 'PRIVATE')
            self.assertNotIn('PRIVATE', (Path(temporary)/'http-relay.json').read_text())


class HttpRelayTeardownTest(unittest.IsolatedAsyncioTestCase):
    class Writer:
        def __init__(self): self.data = bytearray(); self.eof = False
        def write(self, data): self.data.extend(data)
        async def drain(self): pass
        def write_eof(self): self.eof = True

    async def test_seven_backend_eof_connections_release_slots_for_ninth(self):
        with tempfile.TemporaryDirectory() as temporary:
            telemetry = test_rdp.HttpRelayTelemetry(Path(temporary))
            semaphore = test_rdp.asyncio.Semaphore(8)
            admitted = test_rdp.asyncio.Event()
            tasks = []
            async def connection(index):
                row = telemetry.accepted()
                try:
                    async with semaphore:
                        telemetry.acquired(row)
                        if index == 8: admitted.set()
                        client = test_rdp.asyncio.StreamReader()
                        backend = test_rdp.asyncio.StreamReader()
                        if index < 7: backend.feed_eof()
                        await test_rdp.http_relay_streams(client, self.Writer(),
                            backend, self.Writer(), telemetry, row)
                finally:
                    telemetry.released(row); telemetry.closed(row)
            try:
                tasks = [test_rdp.asyncio.create_task(connection(index)) for index in range(8)]
                await test_rdp.asyncio.sleep(0)
                tasks.append(test_rdp.asyncio.create_task(connection(8)))
                await test_rdp.asyncio.wait_for(admitted.wait(), 0.2)
                self.assertEqual(telemetry.highwater['active'], 8)
                self.assertLessEqual(telemetry.active, 2)
            finally:
                for task in tasks: task.cancel()
                await test_rdp.asyncio.gather(*tasks, return_exceptions=True)

    async def test_client_half_close_preserves_pending_backend_response(self):
        with tempfile.TemporaryDirectory() as temporary:
            telemetry = test_rdp.HttpRelayTelemetry(Path(temporary))
            row = telemetry.accepted(); telemetry.acquired(row)
            client = test_rdp.asyncio.StreamReader(); client.feed_eof()
            backend = test_rdp.asyncio.StreamReader()
            browser_writer = self.Writer(); backend_writer = self.Writer()
            task = test_rdp.asyncio.create_task(test_rdp.http_relay_streams(
                client, browser_writer, backend, backend_writer, telemetry, row))
            try:
                for _ in range(5): await test_rdp.asyncio.sleep(0)
                self.assertTrue(backend_writer.eof)
                self.assertFalse(task.done())
                backend.feed_data(b'SYNTHETIC RESPONSE'); backend.feed_eof()
                await test_rdp.asyncio.wait_for(task, 0.2)
                self.assertEqual(browser_writer.data, b'SYNTHETIC RESPONSE')
                self.assertTrue(browser_writer.eof)
            finally:
                if not task.done(): task.cancel()
                await test_rdp.asyncio.gather(task, return_exceptions=True)


if __name__ == '__main__':
    unittest.main()
