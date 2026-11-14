#!/usr/bin/env python3
"""Offline privacy and current-client boundaries for passive CDP metadata."""
import importlib.util
import asyncio
import json
from pathlib import Path
import unittest
from unittest.mock import AsyncMock, patch

SPEC=importlib.util.spec_from_file_location('live_telemetry_subject',Path(__file__).with_name('test_live.py'))
live=importlib.util.module_from_spec(SPEC);SPEC.loader.exec_module(live)
BASE='https://portal.example.invalid/desktop/app/'
SECRET='PRIVATE_SENTINEL_MUST_NOT_ESCAPE'


class TelemetryTests(unittest.TestCase):
    def test_websocket_lifecycle_retains_only_fixed_metadata(self):
        receipt={}; t=live.NetworkTelemetry(BASE,receipt)
        common={'requestId':SECRET,'timestamp':12.5,'headers':{'Cookie':SECRET}}
        t.feed('Network.webSocketCreated',{**common,'url':'wss://portal.example.invalid/desktop/app/websocket-tunnel?token='+SECRET+'#'+SECRET})
        t.feed('Network.webSocketWillSendHandshakeRequest',{**common,'request':{'headers':{'Authorization':SECRET}}})
        t.feed('Network.webSocketHandshakeResponseReceived',{**common,'response':{'status':101,'headers':{'Set-Cookie':SECRET}}})
        t.feed('Network.webSocketClosed',common)
        events=receipt['network_events']
        self.assertEqual([e['event'] for e in events],['websocket_created','websocket_handshake_sent','websocket_handshake_response','websocket_closed'])
        self.assertEqual({e['ordinal'] for e in events},{1})
        self.assertEqual({e['category'] for e in events},{'websocket_tunnel'})
        self.assertNotIn(SECRET,json.dumps(receipt));self.assertNotIn('wss://',json.dumps(receipt))

    def test_arbitrary_error_text_and_method_never_retained(self):
        receipt={};t=live.NetworkTelemetry(BASE,receipt)
        t.feed('Network.requestWillBeSent',{'requestId':SECRET,'request':{'url':BASE+'api/tokens?token='+SECRET,'method':SECRET,'postData':SECRET}})
        t.feed('Network.loadingFailed',{'requestId':SECRET,'errorText':'net::ERR_TIMED_OUT '+SECRET,'blockedReason':SECRET})
        self.assertEqual(receipt['network_events'][-1]['error_code'],'UNKNOWN')
        self.assertEqual(receipt['network_events'][0]['method'],'OTHER')
        self.assertNotIn(SECRET,json.dumps(receipt))
        self.assertEqual(live.network_error('net::ERR_TIMED_OUT'),'net::ERR_TIMED_OUT')
        self.assertEqual(live.network_error('net::ERR_'+SECRET),'UNKNOWN')

    def test_response_timing_is_finite_numeric_allowlist_only(self):
        receipt={};t=live.NetworkTelemetry(BASE,receipt)
        t.feed('Network.requestWillBeSent',{'requestId':'1','type':'Document','request':{'url':BASE,'method':'GET'}})
        t.feed('Network.responseReceived',{'requestId':'1','response':{'status':200,'url':SECRET,
            'protocol':SECRET,'connectionReused':True,'fromDiskCache':False,
            'timing':{'requestTime':1.25,'proxyStart':-1,'dnsStart':SECRET,'sslStart':True,
                'proxyEnd':float('inf'),'receiveHeadersEnd':25000.0,SECRET:SECRET},'headers':{SECRET:SECRET}}})
        event=receipt['network_events'][-1]
        self.assertEqual(event['timing'],{'requestTime':1.25,'proxyStart':-1,'receiveHeadersEnd':25000.0})
        self.assertIs(event['connection_reused'],True)
        self.assertIs(event['from_disk_cache'],False)
        self.assertEqual(event['protocol'],'OTHER')
        self.assertNotIn(SECRET,json.dumps(receipt))
        t.feed('Network.responseReceived',{'requestId':'1','response':{'status':200,'protocol':'http/1.1'}})
        self.assertEqual(receipt['network_events'][-1]['protocol'],'http1.1')

    def test_frames_and_unrelated_payloads_are_ignored(self):
        receipt={};t=live.NetworkTelemetry(BASE,receipt)
        for kind in ('Network.webSocketFrameReceived','Network.webSocketFrameSent','Other.private'):
            t.feed(kind,{'requestId':SECRET,'response':{'payloadData':SECRET},'url':SECRET,'errorText':SECRET})
        self.assertEqual(receipt['network_events'],[])

    def test_unexpected_origins_credentials_and_bad_ports_are_categories_only(self):
        for url,category in [('wss://'+SECRET+'/desktop/app/websocket-tunnel','other_origin'),
            ('wss://user:'+SECRET+'@portal.example.invalid/desktop/app/websocket-tunnel','invalid'),
            ('wss://portal.example.invalid:'+SECRET+'/desktop/app/websocket-tunnel','invalid'),
            (BASE+SECRET,'other_path')]:
            receipt={};t=live.NetworkTelemetry(BASE,receipt)
            t.feed('Network.webSocketCreated',{'requestId':'1','url':url})
            self.assertEqual(receipt['network_events'][0]['category'],category)
            self.assertNotIn(SECRET,json.dumps(receipt))

    def test_events_and_identifiers_are_bounded(self):
        receipt={};t=live.NetworkTelemetry(BASE,receipt)
        t.feed('Network.webSocketCreated',{'requestId':'1','url':BASE+'websocket-tunnel'})
        for _ in range(300):t.feed('Network.webSocketClosed',{'requestId':'1'})
        self.assertEqual(len(receipt['network_events']),256)
        self.assertGreater(receipt['network_events_dropped'],0)
        for i in range(300):t.feed('Network.webSocketCreated',{'requestId':str(i),'url':BASE+'websocket-tunnel'})
        self.assertLessEqual(len(t.slots),128)

    def test_only_selected_current_route_error_is_reported(self):
        snapshot={'route_client_index':1,'clients':[{'present':True,'state':'TUNNEL_ERROR','status':519},
            {'present':True,'state':'CONNECTED','status':0}]}
        self.assertIsNone(live.selected_client_error(snapshot,1))
        self.assertIsNone(live.selected_client_error(snapshot,0))
        snapshot['clients'][1].update(state='TUNNEL_ERROR',status=514,raw_error=SECRET)
        self.assertEqual(live.selected_client_error(snapshot,1),{'client_index':1,'state':'TUNNEL_ERROR','status':514})
        self.assertNotIn(SECRET,json.dumps(live.selected_client_error(snapshot,1)))
        self.assertIsNone(live.selected_client_error(snapshot,None))

    def test_optional_fail_fast_preserves_first_observation(self):
        receipt={}
        snapshot={'route_client_index':0,'clients':[{'present':True,'state':'TUNNEL_ERROR','status':514}]}
        live.fail_on_selected_error(False,receipt,snapshot,0)
        self.assertNotIn('first_observed_native_error',receipt)
        with self.assertRaisesRegex(live.StaticFailure,'Selected native client'):
            live.fail_on_selected_error(True,receipt,snapshot,0)
        first=dict(receipt['first_observed_native_error'])
        snapshot['clients'][0]['status']=519
        with self.assertRaises(live.StaticFailure):live.fail_on_selected_error(True,receipt,snapshot,0)
        self.assertEqual(receipt['first_observed_native_error'],first)

    def test_outer_chained_tunnel_state_is_explicitly_nonauthoritative(self):
        expression=live.client_diagnostic_expression(['desktop-a','desktop-b'],{'desktop-a':'1','desktop-b':'2'})
        self.assertIn('outer_tunnel_state_non_authoritative',expression)
        self.assertNotIn('tunnel_state:',expression)


class SubmitReadinessTests(unittest.IsolatedAsyncioTestCase):
    async def test_readiness_polls_then_clicks_once(self):
        calls=[];states=iter([False,False,True])
        async def js(expression):
            calls.append(expression)
            if expression==live.SUBMIT_READY:return next(states)
            self.assertEqual(expression,live.SUBMIT_CLICK)
            self.assertEqual(calls[-2],'phase-click')
            return True
        with patch.object(live.asyncio,'sleep',AsyncMock()):
            await live.submit_once(js,lambda:calls.append('phase-click'))
        self.assertEqual(calls.count(live.SUBMIT_READY),3)
        self.assertEqual(calls.count(live.SUBMIT_CLICK),1)

    async def test_readiness_timeout_never_clicks(self):
        calls=[];now=[0.0]
        async def js(expression):calls.append(expression);return False
        async def sleep(seconds):now[0]+=seconds
        with patch.object(live.time,'monotonic',side_effect=lambda:now[0]),patch.object(live.asyncio,'sleep',sleep):
            with self.assertRaisesRegex(live.StaticFailure,'not ready within ten seconds'):
                await live.submit_once(js,lambda:calls.append('phase-click'))
        self.assertNotIn(live.SUBMIT_CLICK,calls);self.assertNotIn('phase-click',calls)

    async def test_changed_control_does_not_retry_click(self):
        calls=[]
        async def js(expression):calls.append(expression);return expression==live.SUBMIT_READY
        with self.assertRaisesRegex(live.StaticFailure,'Missing submit control'):
            await live.submit_once(js,lambda:None)
        self.assertEqual(calls,[live.SUBMIT_READY,live.SUBMIT_CLICK])


if __name__=='__main__':unittest.main()
