#!/usr/bin/env python3
"""Finite operator-invoked acceptance of an already installed private portal."""
import argparse
import asyncio
import base64
import hashlib
import json
import math
import os
from pathlib import Path
import re
import shlex
import shutil
import signal
import subprocess
import sys
import tempfile
import time
from urllib.parse import urlsplit

INSTALLED = '/opt/guacamole-portal/tools/test_live.py'
OTP_SOURCE = r'''
import base64, hashlib, hmac, json, re, signal, struct, sys, time
signal.alarm(12)
sys.path.insert(0, '/opt/homelab-web-rdp')
import runtime
import lifecycle as life
registry, _ = runtime.configuration()
if registry.username != sys.argv[1]:
    raise RuntimeError('Identity mismatch')
attrs = json.loads(life.pg_sql("SELECT coalesce(json_object_agg(attribute_name,attribute_value),'{}') FROM guacamole_user_attribute a JOIN guacamole_user u USING(user_id) JOIN guacamole_entity e USING(entity_id) WHERE e.name=" + runtime.sql(registry.username) + ";", app=True))
key = attrs.get('guac-totp-key-secret', '')
if (attrs.get('guac-totp-key-confirmed') != 'true' or attrs.get('guac-totp-disabled') == 'true' or not re.fullmatch('[A-Z2-7]{32}', key)):
    raise RuntimeError('Confirmed identity required')
digest = hmac.new(base64.b32decode(key), struct.pack('>Q', int(time.time()) // 30), hashlib.sha1).digest()
offset = digest[-1] & 15
print(str((struct.unpack('>I', digest[offset:offset+4])[0] & 0x7fffffff) % 1000000).zfill(6))
'''


class StaticFailure(RuntimeError):
    """A reviewed fixed diagnostic, never an external exception message."""


def require(condition, message):
    if not condition:
        raise StaticFailure(message)


def mark_phase(args, receipt, phase):
    receipt['phase'] = phase
    receipt.setdefault('phases', []).append({'phase': phase, 'at': time.time()})
    # Only fixed phase names, timestamps and the driver identity reach progress.
    # An evidence write error must never mask a pre-existing browser failure.
    try:
        (args.directory / 'progress.json').write_text(json.dumps({
            'driver_sha256': receipt['driver_sha256'], 'phase': phase,
            'phases': receipt['phases']}) + '\n')
    except OSError:
        receipt['progress_write_error'] = True


HTTP_TIMING_FIELDS = ('requestTime', 'proxyStart', 'proxyEnd', 'dnsStart', 'dnsEnd',
    'connectStart', 'connectEnd', 'sslStart', 'sslEnd', 'sendStart', 'sendEnd',
    'receiveHeadersStart', 'receiveHeadersEnd')

NET_ERRORS = {'net::ERR_ABORTED', 'net::ERR_FAILED', 'net::ERR_TIMED_OUT',
    'net::ERR_CONNECTION_RESET', 'net::ERR_CONNECTION_CLOSED', 'net::ERR_CONNECTION_REFUSED',
    'net::ERR_NAME_NOT_RESOLVED', 'net::ERR_TUNNEL_CONNECTION_FAILED', 'net::ERR_SSL_PROTOCOL_ERROR',
    'net::ERR_CERT_AUTHORITY_INVALID', 'net::ERR_HTTP_RESPONSE_CODE_FAILURE',
    'net::ERR_NETWORK_CHANGED', 'net::ERR_INTERNET_DISCONNECTED', 'net::ERR_BLOCKED_BY_CLIENT',
    'net::ERR_WS_PROTOCOL_ERROR'}


def endpoint_category(value, base):
    try:
        u, b = urlsplit(value), urlsplit(base)
        if u.username or u.password:
            return 'invalid'
        scheme = {'ws': 'http', 'wss': 'https'}.get(u.scheme, u.scheme)
        if (scheme, u.hostname, u.port or (443 if scheme == 'https' else 80)) != (
                b.scheme, b.hostname, b.port or (443 if b.scheme == 'https' else 80)):
            return 'other_origin'
        return {b.path: 'application', b.path+'api/tokens': 'login', b.path+'api/session': 'session',
                b.path+'websocket-tunnel': 'websocket_tunnel', b.path+'tunnel': 'HTTP_tunnel'}.get(u.path, 'other_path')
    except (ValueError, TypeError, AttributeError):
        return 'invalid'


def network_error(value):
    if isinstance(value, str) and value in NET_ERRORS:
        return value
    if value == 'WebSocket is closed before the connection is established.':
        return 'CLOSED_BEFORE_ESTABLISHED'
    return 'UNKNOWN'


class NetworkTelemetry:
    """Bounded passive CDP metadata; raw identifiers/URLs remain memory-only."""
    def __init__(self, base, receipt):
        self.base, self.receipt, self.slots = base, receipt, {}
        self.events = receipt.setdefault('network_events', [])

    def slot(self, identifier, category):
        if not isinstance(identifier, str):
            return None
        if identifier not in self.slots:
            if len(self.slots) >= 128:
                return None
            self.slots[identifier] = {'ordinal': len(self.slots)+1, 'category': category}
        return self.slots[identifier]

    def feed(self, kind, p):
        if not isinstance(p, dict):
            return
        identifier = p.get('requestId')
        slot = self.slots.get(identifier) if isinstance(identifier, str) else None
        label, extra = None, {}
        if kind == 'Network.webSocketCreated':
            slot = self.slot(identifier, endpoint_category(p.get('url'), self.base))
            label = 'websocket_created'
        elif kind == 'Network.requestWillBeSent':
            request = p.get('request', {})
            category = endpoint_category(request.get('url'), self.base)
            if category in ('login', 'session', 'HTTP_tunnel') or (category == 'application' and p.get('type') == 'Document'):
                slot = self.slot(identifier, category)
                method = request.get('method')
                extra['method'] = method if method in ('GET', 'POST', 'DELETE', 'HEAD', 'OPTIONS') else 'OTHER'
                label = 'http_request'
        elif kind in ('Network.webSocketWillSendHandshakeRequest', 'Network.webSocketHandshakeResponseReceived',
                      'Network.webSocketClosed', 'Network.webSocketFrameError', 'Network.loadingFailed', 'Network.responseReceived'):
            label = {'Network.webSocketWillSendHandshakeRequest': 'websocket_handshake_sent',
                'Network.webSocketHandshakeResponseReceived': 'websocket_handshake_response',
                'Network.webSocketClosed': 'websocket_closed', 'Network.webSocketFrameError': 'websocket_error',
                'Network.loadingFailed': 'http_failed', 'Network.responseReceived': 'http_response'}[kind]
            if kind in ('Network.webSocketFrameError', 'Network.loadingFailed'):
                extra['error_code'] = network_error(p.get('errorMessage') if kind.endswith('FrameError') else p.get('errorText'))
                if kind == 'Network.loadingFailed':
                    extra['canceled'] = p.get('canceled') is True
            if kind in ('Network.webSocketHandshakeResponseReceived', 'Network.responseReceived'):
                status = p.get('response', {}).get('status')
                extra['status'] = int(status) if type(status) in (int, float) and math.isfinite(status) and 100 <= status <= 599 else None
            if kind == 'Network.responseReceived':
                response = p.get('response', {})
                timing = response.get('timing', {})
                extra['timing'] = {key: timing[key] for key in HTTP_TIMING_FIELDS
                    if isinstance(timing, dict) and type(timing.get(key)) in (int, float) and math.isfinite(timing[key])}
                extra['connection_reused'] = response.get('connectionReused') is True
                extra['from_disk_cache'] = response.get('fromDiskCache') is True
                protocol = response.get('protocol')
                extra['protocol'] = {'h2':'h2','http/1.1':'http1.1','http1.1':'http1.1','h3':'h3'}.get(protocol, 'OTHER') if isinstance(protocol, str) else 'OTHER'
        if label is None or slot is None:
            return
        event = {**slot, 'event': label, 'at': time.time(), **extra}
        timestamp = p.get('timestamp')
        if type(timestamp) in (int, float) and math.isfinite(timestamp) and 0 <= timestamp < 1e12:
            event['cdp_timestamp'] = timestamp
        if len(self.events) < 256:
            self.events.append(event)
        else:
            self.receipt['network_events_dropped'] = self.receipt.get('network_events_dropped', 0)+1


def selected_client_error(snapshot, index):
    if not isinstance(snapshot, dict) or snapshot.get('route_client_index') != index:
        return None
    clients = snapshot.get('clients')
    if not isinstance(clients, list) or type(index) is not int or not 0 <= index < len(clients):
        return None
    client = clients[index]
    if not isinstance(client, dict) or client.get('present') is not True or client.get('state') not in ('CLIENT_ERROR', 'TUNNEL_ERROR'):
        return None
    status = client.get('status')
    return {'client_index': index, 'state': client['state'],
            'status': status if type(status) is int and 0 <= status <= 65535 else None}


def fail_on_selected_error(enabled, receipt, snapshot, index):
    error = selected_client_error(snapshot, index)
    if enabled and error is not None:
        receipt.setdefault('first_observed_native_error', {**error, 'at': time.time()})
        raise StaticFailure('Selected native client reported a tunnel or client error')


SUBMIT_CONTROL = '[...document.querySelectorAll("button[type=submit],input[type=submit]")].find(e=>e.getClientRects().length&&!e.disabled)'
SUBMIT_READY = '!!(' + SUBMIT_CONTROL + ')'
SUBMIT_CLICK = '(()=>{const e=' + SUBMIT_CONTROL + ';if(!e)return false;e.click();return true})()'


async def submit_once(js, before_click):
    """Wait for native form readiness, then issue exactly one click attempt."""
    deadline = time.monotonic() + 10
    while True:
        remaining = deadline - time.monotonic()
        require(remaining > 0, 'Visible enabled submit control not ready within ten seconds')
        try:
            ready = await asyncio.wait_for(js(SUBMIT_READY), remaining)
        except asyncio.TimeoutError:
            raise StaticFailure('Visible enabled submit control not ready within ten seconds') from None
        if ready is True:
            require(time.monotonic() <= deadline, 'Visible enabled submit control not ready within ten seconds')
            break
        remaining = deadline - time.monotonic()
        require(remaining > 0, 'Visible enabled submit control not ready within ten seconds')
        await asyncio.sleep(min(.2, remaining))
    before_click()
    # No click retry if the native control changes state after readiness.
    require(await js(SUBMIT_CLICK), 'Missing submit control')


def image_id(value):
    value = value.removeprefix('sha256:')
    require(re.fullmatch('[0-9a-f]{64}', value), 'Exact image SHA256 required')
    return value


def validate_base(value):
    u = urlsplit(value)
    require(not u.username and not u.password and not u.query and not u.fragment,
            'Bare application base URL required')
    if u.scheme == 'https':
        require(bool(u.hostname) and u.path == '/desktop/app/', 'HTTPS application base required')
    else:
        require(u.scheme == 'http' and u.hostname in ('127.0.0.1', '::1', 'localhost')
                and u.port is not None and 10000 <= u.port <= 10999
                and u.path in ('/guacamole', '/guacamole/'), 'Private loopback lab base required')
    hostname = (u.hostname or '').lower()
    if ':' in hostname:
        hostname = '[' + hostname + ']'
    port = u.port
    authority = hostname + (':' + str(port) if port is not None and port != (443 if u.scheme == 'https' else 80) else '')
    return u.scheme + '://' + authority + u.path.rstrip('/') + '/'


def validate_aliases(value):
    aliases = value.split(',')
    require(len(aliases) == 2 and len(set(aliases)) == 2
            and all(re.fullmatch('[a-z][a-z0-9-]{0,31}', a) for a in aliases),
            'Exactly two distinct catalog aliases required')
    return aliases


def expected_catalog_aliases(aliases, ssh_alias=None):
    if ssh_alias is None:
        return list(aliases)
    require(isinstance(ssh_alias, str) and re.fullmatch('[a-z][a-z0-9-]{0,31}', ssh_alias)
            and ssh_alias not in aliases, 'Distinct SSH catalog alias required')
    return [*aliases, ssh_alias]


def catalog_mapping(tree, expected):
    require(isinstance(tree, list) and len(tree) == len(expected)
            and all(isinstance(row, dict) and set(row) == {'alias', 'id'} for row in tree)
            and {row['alias'] for row in tree} == set(expected)
            and all(isinstance(row['id'], str) and re.fullmatch('[0-9]+', row['id']) for row in tree)
            and len({row['id'] for row in tree}) == len(expected), 'Authenticated JDBC tree mismatch')
    return {row['alias']: row['id'] for row in tree}


def inspected_container(value, expected):
    require(isinstance(value, list) and len(value) == 1, 'One production container required')
    v = value[0]
    require(re.fullmatch('[0-9a-f]{64}', v.get('Id', ''))
            and v.get('Name', '').lstrip('/') == 'guacamole-portal'
            and v.get('Config', {}).get('Labels', {}).get('guacamole.portal') == '1'
            and v.get('Image', '').removeprefix('sha256:') == expected
            and v.get('State', {}).get('Running') is True, 'Production container binding mismatch')
    return v['Id']


def root_otp(args):
    require(os.geteuid() == 0, 'Root-only helper')
    def inspect(cid):
        p = subprocess.run(['podman', 'inspect', '--type=container', cid],
                           capture_output=True, timeout=8, check=True)
        require(len(p.stdout) < 262144, 'Inspect exceeds bound')
        return inspected_container(json.loads(p.stdout), args.expected_image)
    cid = inspect('guacamole-portal')
    if args.wait_fresh_code:
        time.sleep(30 - time.time() % 30 + .5)
    require(inspect(cid) == cid, 'Production container changed')
    p = subprocess.run(['podman', 'exec', '-i', cid, 'python3', '-B', '-', args.username],
                       input=OTP_SOURCE.encode(), capture_output=True, timeout=15)
    require(p.returncode == 0 and re.fullmatch(rb'[0-9]{6}\n', p.stdout), 'OTP helper failed')
    require(inspect(cid) == cid, 'Production container changed')
    # Protocol output only, consumed by the calling driver in memory. Never log.
    sys.stdout.buffer.write(p.stdout)


PROOF_KEYS = {'container_id', 'run_id', 'image_id', 'config_sha256',
              'network_sha256', 'release_sha256'}


def validate_proof(value, expected_image):
    require(isinstance(value, dict) and set(value) == PROOF_KEYS, 'Deployment proof fields invalid')
    require(value.get('image_id') == 'sha256:' + expected_image, 'Deployment proof image mismatch')
    for key in PROOF_KEYS - {'image_id'}:
        length = 32 if key == 'run_id' else 64
        require(isinstance(value[key], str) and re.fullmatch('[0-9a-f]{%d}' % length, value[key]),
                'Deployment proof immutable identity invalid')
    return value


def require_same_proof(before, after, expected_image):
    validate_proof(before, expected_image)
    validate_proof(after, expected_image)
    require(before == after, 'Deployment changed during browser acceptance')


def root_deployment_proof(args):
    require(os.geteuid() == 0, 'Root-only helper')
    signal.alarm(35)
    sys.path.insert(0, '/opt/guacamole-portal')
    import host
    def capture():
        release, cfg, binding = host.selection()
        record = host.private_json(host.STATE / 'current.json')
        cid = host.identifier(record.get('container_id'))
        run = host.identifier(record.get('run_id'), 32)
        require(record.get('phase') == 'ready' and record.get('image_id') == release['image_id']
                and record.get('release_sha256') == binding[0], 'Ready deployment admission mismatch')
        container = host.owned(record, cid)
        require(container is not None and container.get('State', {}).get('Running') is True,
                'Production deployment not running')
        require(host.ready_owned(run), 'Production readiness marker missing')
        require(host.guards(release, cfg) == [cid], 'Production network membership mismatch')
        proof = {'container_id': cid, 'run_id': run, 'image_id': release['image_id'],
                 'config_sha256': release['config_sha256'], 'network_sha256': release['network_sha256'],
                 'release_sha256': binding[0]}
        return validate_proof(proof, args.expected_image), (release, cfg, binding, record)
    before, first_binding = capture()
    after, last_binding = capture()
    require_same_proof(before, after, args.expected_image)
    require(first_binding == last_binding, 'Deployment proof inputs changed during inspection')
    print(json.dumps(before, sort_keys=True))


async def remote_proof(args):
    command = ['sudo', '-n', 'python3', '-B', INSTALLED, '--deployment-proof',
               '--expected-image', args.expected_image]
    process = await asyncio.create_subprocess_exec('ssh', '-oBatchMode=yes',
        '-oStrictHostKeyChecking=yes', '-oConnectTimeout=10', '-oControlMaster=no',
        '-oControlPath=none', '-oControlPersist=no', args.ssh_host, shlex.join(command),
        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL)
    try:
        stdout, _ = await asyncio.wait_for(process.communicate(), 45)
    except BaseException:
        try:
            process.kill()
        except ProcessLookupError:
            pass
        await process.wait()
        raise
    require(process.returncode == 0 and len(stdout) <= 4096, 'Remote deployment proof failed')
    return validate_proof(json.loads(stdout), args.expected_image)


def observed_base(observed, expected):
    """Compare only browser scheme/host/port/path; never return hash/query."""
    require(isinstance(observed, dict) and set(observed) == {'scheme', 'host', 'port', 'path'},
            'Browser base fields invalid')
    u = urlsplit(expected)
    expected_port = str(u.port) if u.port is not None else ''
    # Browser location.port omits the scheme's default port.
    if expected_port == ('443' if u.scheme == 'https' else '80'):
        expected_port = ''
    expected_host = u.hostname or ''
    if ':' in expected_host:
        expected_host = '[' + expected_host + ']'
    require(observed == {'scheme': u.scheme, 'host': expected_host.lower(),
                         'port': expected_port, 'path': u.path}, 'Browser origin or application path mismatch')
    return u.scheme + '://' + expected_host.lower() + (':' + expected_port if expected_port else '') + u.path


async def acceptance(args, receipt):
    mark_phase(args, receipt, 'deployment_before')
    receipt['deployment_before'] = await remote_proof(args)
    try:
        await browser(args, receipt)
    finally:
        prior_failure = sys.exc_info()[0] is not None
        try:
            mark_phase(args, receipt, 'deployment_after')
            receipt['deployment_after'] = await remote_proof(args)
            require_same_proof(receipt['deployment_before'], receipt['deployment_after'], args.expected_image)
        except BaseException as error:
            receipt['deployment_after_error_type'] = type(error).__name__
            if isinstance(error, StaticFailure):
                receipt['deployment_after_failure_reason'] = str(error)
            if not prior_failure:
                raise


async def remote_otp(args, receipt):
    command = ['sudo', '-n', 'python3', '-B', INSTALLED, '--otp',
               '--expected-image', args.expected_image, '--username', args.username]
    if args.wait_fresh_code:
        command.append('--wait-fresh-code')
    process = await asyncio.create_subprocess_exec('ssh', '-oBatchMode=yes',
        '-oStrictHostKeyChecking=yes', '-oConnectTimeout=10',
        '-oControlMaster=no', '-oControlPath=none', '-oControlPersist=no', args.ssh_host,
        shlex.join(command), stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL)
    try:
        stdout, _ = await asyncio.wait_for(process.communicate(), 65)
    except BaseException:
        try:
            process.kill()
        except ProcessLookupError:
            pass
        await process.wait()
        raise
    receipt['otp_ssh_returncode'] = process.returncode
    require(process.returncode == 0, 'Remote OTP SSH/helper exit failure')
    require(re.fullmatch(rb'[0-9]{6}\n', stdout), 'Remote OTP protocol invalid')
    return stdout.decode().strip()


def client_diagnostic_expression(aliases, mapping):
    """Return only fixed categories/numbers for the two expected JDBC clients."""
    expected = [{'id': mapping[a], 'encoded': base64.urlsafe_b64encode(
        (mapping[a] + '\0c\0postgresql').encode()).decode().rstrip('=')} for a in aliases]
    return r'''(()=>{
        const expected=EXPECTED, aliases=ALIASES;
        const read=(fn,fallback=null)=>{try{return fn()}catch(_){return fallback}};
        const bounded=(n,max)=>Number.isInteger(n)&&n>=0&&n<=max?n:null;
        const number=(fn,max)=>bounded(read(fn),max);
        const hash=read(()=>location.hash.split('?')[0],'');
        const routeIndex=expected.findIndex(e=>hash==='#/client/'+e.encoded);
        const routeKind=routeIndex>=0?'expected_client':hash.startsWith('#/client/')?'other_client':hash==='#/'||hash===''?'home':'other';
        const injector=read(()=>window.angular&&angular.element(document.documentElement).injector());
        const clients=read(()=>injector.get('guacClientManager').getManagedClients(),{});
        const selection=read(()=>injector.get('portalTargetSelection').get(),{});
        const states=['IDLE','CONNECTING','WAITING','CONNECTED','DISCONNECTED','CLIENT_ERROR','TUNNEL_ERROR'];
        return {route_kind:routeKind,route_client_index:routeIndex,injector_present:!!injector,
            selection_present:read(()=>selection.present)===true,
            selection_client_index:aliases.indexOf(read(()=>selection.alias)),
            same_native_token:read(()=>!!window.portalAcceptanceToken&&window.portalAcceptanceToken===injector.get('authenticationService').getCurrentToken(),false)===true,
            clients:expected.map(e=>{const c=read(()=>clients[e.encoded]);if(!c)return {id:e.id,present:false};
                const state=read(()=>c.clientState,{});
                const native=read(()=>state.connectionState);
                const display=read(()=>c.client.getDisplay());
                return {id:e.id,present:true,state:states.includes(native)?native:'OTHER',
                    status:number(()=>state.statusCode,65535),tunnel_unstable:read(()=>state.tunnelUnstable)===true,
                    outer_tunnel_state_non_authoritative:number(()=>c.tunnel.state,10),
                    width:number(()=>display.getWidth(),32768),height:number(()=>display.getHeight(),32768),
                    required_parameters_present:read(()=>c.requiredParameters!==null&&c.requiredParameters!==undefined,false)===true};})};
    })()'''.replace('EXPECTED', json.dumps(expected)).replace('ALIASES', json.dumps(aliases))



def stop_chrome(chrome):
    errors = []
    for sig in (signal.SIGTERM, signal.SIGKILL):
        try:
            os.killpg(chrome.pid, sig)
        except ProcessLookupError:
            pass
        except OSError:
            errors.append('process_group_signal')
        try:
            chrome.wait(timeout=5)
        except subprocess.TimeoutExpired:
            if sig == signal.SIGKILL:
                errors.append('process_wait')
    return errors


async def browser(args, receipt):
    import aiohttp
    profile = tempfile.mkdtemp(prefix='portal-live-chrome-')
    chrome = None
    try:
        mark_phase(args, receipt, 'owned_chrome_start')
        chrome = subprocess.Popen([args.chrome, '--headless', '--disable-gpu',
            '--no-first-run', '--disable-background-networking', '--disable-extensions',
            '--disable-dev-shm-usage', '--disable-component-update', '--disable-sync',
            '--no-default-browser-check', '--remote-debugging-address=127.0.0.1',
            '--remote-debugging-port=0', '--user-data-dir=' + profile, 'about:blank'],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
        portfile = Path(profile) / 'DevToolsActivePort'
        for _ in range(100):
            if portfile.exists():
                break
            require(chrome.poll() is None, 'Owned Chrome exited')
            await asyncio.sleep(.1)
        port = int(portfile.read_text().splitlines()[0])
        async with aiohttp.ClientSession() as session:
            async with session.put(f'http://127.0.0.1:{port}/json/new?about:blank') as response:
                target = await response.json()
            async with session.ws_connect(target['webSocketDebuggerUrl'], max_msg_size=1024*1024) as ws:
                seq = 0
                requests = {}
                statuses = receipt['http']
                telemetry = NetworkTelemetry(args.base, receipt)
                async def rpc(method, params=None):
                    nonlocal seq
                    seq += 1
                    await ws.send_json({'id': seq, 'method': method, 'params': params or {}})
                    while True:
                        item = await ws.receive_json(timeout=45)
                        kind, p = item.get('method'), item.get('params', {})
                        telemetry.feed(kind, p)
                        if kind == 'Network.requestWillBeSent':
                            req = p.get('request', {})
                            path = urlsplit(req.get('url', '')).path
                            if path == urlsplit(args.base).path + 'api/tokens':
                                requests[p['requestId']] = ('login', req.get('method'))
                            elif path == urlsplit(args.base).path + 'api/session' and req.get('method') == 'DELETE':
                                requests[p['requestId']] = ('logout', 'DELETE')
                            elif path == urlsplit(args.base).path + 'tunnel':
                                requests[p['requestId']] = ('HTTP_tunnel', req.get('method'))
                        elif kind == 'Network.responseReceived' and p.get('requestId') in requests:
                            category, verb = requests.pop(p['requestId'])
                            statuses.append({'category': category, 'method': verb,
                                             'status': int(p['response']['status']),
                                             'phase': receipt.get('phase')})
                        elif kind == 'Network.webSocketHandshakeResponseReceived':
                            statuses.append({'category': 'websocket_handshake',
                                'status': int(p['response']['status']), 'phase': receipt.get('phase')})
                        if item.get('id') == seq:
                            require('error' not in item, 'CDP failed')
                            return item.get('result', {})
                async def js(expression, promise=False):
                    v = await rpc('Runtime.evaluate', {'expression': expression,
                        'returnByValue': True, 'awaitPromise': promise})
                    require('exceptionDetails' not in v, 'Browser expression failed')
                    return v.get('result', {}).get('value')
                async def observe_clients(selected=None):
                    if mapping is None:
                        return
                    try:
                        snapshot = await js(client_diagnostic_expression(args.aliases, mapping))
                        observations = receipt.setdefault('client_observations', [])
                        if not observations or observations[-1]['snapshot'] != snapshot:
                            observations.append({'phase': receipt.get('phase'), 'at': time.time(), 'snapshot': snapshot})
                            del observations[:-64]
                    except Exception:
                        receipt['client_observation_unavailable'] = True
                        return
                    fail_on_selected_error(args.fail_on_tunnel_error, receipt, snapshot, selected)
                async def until(expression, seconds=35, observe=False, selected=None):
                    deadline = time.monotonic() + seconds
                    while time.monotonic() < deadline:
                        if observe:
                            await observe_clients(selected)
                        value = await js(expression)
                        if value:
                            return value
                        await asyncio.sleep(.4)
                    raise StaticFailure('Browser stage timed out')
                async def fill(selector, value):
                    require(await js('(()=>{let e=document.querySelector(' + json.dumps(selector)
                        + ');if(!e)return false;e.value=' + json.dumps(value)
                        + ';e.dispatchEvent(new Event("input",{bubbles:true}));e.dispatchEvent(new Event("change",{bubbles:true}));return true})()'), 'Missing login field')
                async def submit(stage):
                    # Waiting reads DOM only. It never sends another auth request.
                    mark_phase(args, receipt, stage + '_ready')
                    await submit_once(js, lambda: mark_phase(args, receipt, stage))
                injector = 'angular.element(document.documentElement).injector()'
                auth = injector + '.get("authenticationService")'
                logged_out = False
                mapping = None
                try:
                    await rpc('Page.enable')
                    await rpc('Runtime.enable')
                    await rpc('Network.enable', {'maxTotalBufferSize': 0, 'maxResourceBufferSize': 0})
                    await rpc('Emulation.setDeviceMetricsOverride', {'width': 1100, 'height': 800,
                        'deviceScaleFactor': 1, 'mobile': False})
                    mark_phase(args, receipt, 'login_DOM_wait')
                    await rpc('Page.navigate', {'url': args.base + '#/?wrdp-target=' + args.aliases[0]})
                    await until('!!document.querySelector("input[name=username]")')
                    receipt['observed_base'] = observed_base(await js('({scheme:location.protocol.slice(0,-1),host:location.hostname,port:location.port,path:location.pathname})'), args.base)
                    require(await js('!document.querySelector("input[type=password]")'), 'Unexpected password form')
                    mark_phase(args, receipt, 'username_fill_and_selector')
                    await fill('input[name=username]', args.username)
                    selector = await js('(()=>{let e=document.querySelector("select[name=wrdp-target]");return e?[...e.options].map(o=>o.textContent).filter(Boolean):null})()')
                    if selector is not None:
                        require(set(selector) == set(args.catalog_aliases), 'Login selector differs from expected aliases')
                        require(await js('(()=>{let e=document.querySelector("select[name=wrdp-target]");let o=[...e.options].find(o=>o.textContent===' + json.dumps(args.aliases[0]) + ');if(!o)return false;e.value=o.value;e.dispatchEvent(new Event("change",{bubbles:true}));return true})()'), 'Alias option absent')
                    receipt['login_selector_present'] = selector is not None
                    await submit('username_submit')
                    mark_phase(args, receipt, 'TOTP_DOM_wait')
                    await until('!!document.querySelector("input[name=guac-totp]")')
                    mark_phase(args, receipt, 'remote_OTP_wait')
                    otp = await remote_otp(args, receipt)
                    mark_phase(args, receipt, 'TOTP_fill')
                    await fill('input[name=guac-totp]', otp)
                    otp = None
                    await submit('TOTP_submit')
                    mark_phase(args, receipt, 'native_authentication_wait')
                    await until('location.hash.startsWith("#/client/")')
                    require(await js(auth + '.getCurrentUsername()===' + json.dumps(args.username)), 'Authenticated identity mismatch')
                    # Token never crosses CDP or enters an artifact. It stays in
                    # native service storage and this in-browser comparison only.
                    await js('window.portalAcceptanceToken=' + auth + '.getCurrentToken();true')
                    mark_phase(args, receipt, 'authenticated_JDBC_tree')
                    tree = await js('Promise.resolve(' + injector + '.get("connectionGroupService").getConnectionGroupTree("postgresql","ROOT")).then(t=>{let a=[];function walk(g){for(let c of g.childConnections||[])a.push({alias:c.name,id:c.identifier});for(let c of g.childConnectionGroups||[])walk(c)}walk(t);return a})', True)
                    mapping = catalog_mapping(tree, args.catalog_aliases)
                    receipt['jdbc_clients'] = [{'alias': a, 'client_id': mapping[a]} for a in args.aliases]
                    if args.ssh_alias is not None:
                        receipt['catalog_clients'] = [{'alias': a, 'client_id': mapping[a]} for a in args.catalog_aliases]
                        receipt['SSH_acceptance'] = 'not performed by this Windows driver'
                    async def canvas(alias, refreshing=False):
                        prefix = 'reload' if refreshing else ('first_alias', 'second_alias')[args.aliases.index(alias)]
                        mark_phase(args, receipt, prefix + '_route_wait')
                        selected = args.aliases.index(alias)
                        encoded = base64.urlsafe_b64encode((mapping[alias] + '\0c\0postgresql').encode()).decode().rstrip('=')
                        await until('location.hash.split("?")[0]===' + json.dumps('#/client/' + encoded), observe=True, selected=selected)
                        getter = injector + '.get("guacClientManager").getManagedClients()[' + json.dumps(encoded) + ']'
                        mark_phase(args, receipt, prefix + '_native_connection_wait')
                        await until('(()=>{let c=' + getter + ';return c&&c.clientState.connectionState==="CONNECTED"&&c.clientState.statusCode===0})()', observe=True, selected=selected)
                        mark_phase(args, receipt, prefix + '_pixels_wait')
                        return await until('(()=>{let c=' + getter + ';let v=c.client.getDisplay().flatten();if(!v.width||!v.height)return false;let d=v.getContext("2d").getImageData(0,0,v.width,v.height).data,n=0;for(let i=0;i<d.length;i+=4)if(d[i]+d[i+1]+d[i+2]>30)n++;return n>10000?{state:c.clientState.connectionState,status:c.clientState.statusCode,width:v.width,height:v.height,nonblack:n}:false})()', observe=True, selected=selected)
                    receipt['desktops'] = []
                    for index, alias in enumerate(args.aliases):
                        mark_phase(args, receipt, ('first_alias_navigate', 'second_alias_navigate')[index])
                        await rpc('Page.navigate', {'url': args.base + '#/?wrdp-target=' + alias})
                        mark_phase(args, receipt, ('first_alias_connected_wait', 'second_alias_connected_wait')[index])
                        pixels = await canvas(alias)
                        if args.desktop_hold_seconds:
                            mark_phase(args, receipt, ('first_alias_stability_hold', 'second_alias_stability_hold')[index])
                            deadline = time.monotonic() + args.desktop_hold_seconds
                            while time.monotonic() < deadline:
                                await asyncio.sleep(min(1, max(0, deadline-time.monotonic())))
                                await observe_clients(index)
                                require(await js('(()=>{let c=' + injector + '.get("guacClientManager").getManagedClients()['
                                    + json.dumps(base64.urlsafe_b64encode((mapping[alias]+'\0c\0postgresql').encode()).decode().rstrip('='))
                                    + '];return c&&c.clientState.connectionState==="CONNECTED"&&c.clientState.statusCode===0})()'),
                                    'Native desktop connection lost during stability hold')
                            pixels = await canvas(alias)
                        require(await js('window.portalAcceptanceToken===' + auth + '.getCurrentToken()'), 'Alias navigation changed native token')
                        require(pixels['state'] == 'CONNECTED' and pixels['status'] == 0, 'Canvas lost native connection')
                        receipt['desktops'].append({'alias': alias, 'client_id': mapping[alias], **pixels})
                        mark_phase(args, receipt, ('first_alias_connected', 'second_alias_connected')[index])
                    mark_phase(args, receipt, 'reload_start')
                    await rpc('Page.reload')
                    await until('document.readyState==="complete"&&performance.getEntriesByType("navigation")[0].type==="reload"&&!!(window.angular&&angular.element(document.documentElement).injector())')
                    mark_phase(args, receipt, 'reload_connected_wait')
                    receipt['refresh'] = await canvas(args.aliases[-1], refreshing=True)
                    require(receipt['refresh']['state'] == 'CONNECTED' and receipt['refresh']['status'] == 0, 'Refresh lost connection')
                    require(await js(auth + '.getCurrentUsername()===' + json.dumps(args.username)), 'Refresh identity mismatch')
                    receipt['checks'] += ['native_username_TOTP', 'authenticated_JDBC_tree',
                        'both_aliases_same_native_token_CONNECTED_status0_nonblack', 'native_authenticated_refresh']
                finally:
                    # Cleanup is attempted even after a failing canvas. Preserve
                    # original failure and record cleanup failure independently.
                    active_failure = sys.exc_info()[0] is not None
                    if active_failure:
                        receipt['failure_phase'] = receipt.get('phase')
                        if receipt.get('first_observed_native_error') and receipt.get('client_observations'):
                            # Reuse the already sanitized error observation and
                            # begin logout without another diagnostic round trip.
                            receipt['failure_client_diagnostics'] = receipt['client_observations'][-1]['snapshot']
                        elif mapping is not None:
                            try:
                                receipt['failure_client_diagnostics'] = await asyncio.wait_for(
                                    js(client_diagnostic_expression(args.aliases, mapping)), 4)
                            except BaseException:
                                receipt['failure_diagnostics_unavailable'] = True
                    mark_phase(args, receipt, 'own_logout_start')
                    async def revoke_owned():
                        if await js('!!(window.angular&&angular.element(document.documentElement).injector()&&' + auth + '.getCurrentToken())'):
                            await js('Promise.resolve(' + auth + '.logout()).then(()=>true)', True)
                            await js('window.portalAcceptanceToken=null;true')
                            require(any(r['category'] == 'logout' and r['status'] == 204 for r in statuses), 'Own logout HTTP204 absent')
                            return True
                        return False
                    try:
                        logged_out = await asyncio.wait_for(revoke_owned(), 10)
                    except BaseException as cleanup_error:
                        receipt['logout_cleanup_error'] = True
                        if isinstance(cleanup_error, StaticFailure):
                            receipt['logout_cleanup_reason'] = str(cleanup_error)
                        if not active_failure:
                            raise
                    receipt['own_logout_204'] = logged_out
                    mark_phase(args, receipt, 'own_logout_finished')
                require(logged_out, 'Own authenticated token logout unconfirmed')
                final_base = observed_base(await js('({scheme:location.protocol.slice(0,-1),host:location.hostname,port:location.port,path:location.pathname})'), args.base)
                require(final_base == receipt['observed_base'], 'Browser base changed during acceptance')
                require(not any(r['status'] == 429 for r in statuses), 'Authentication rate limit reached')
    finally:
        if sys.exc_info()[0] is not None:
            receipt.setdefault('failure_phase', receipt.get('phase'))
        mark_phase(args, receipt, 'owned_chrome_cleanup')
        try:
            errors = stop_chrome(chrome) if chrome else []
        except Exception:
            errors = ['process_cleanup_exception']
        receipt['owned_chrome_group_cleanup'] = not errors
        try:
            shutil.rmtree(profile)
            receipt['owned_profile_removed'] = True
        except OSError:
            receipt['owned_profile_removed'] = False
        if not sys.exc_info()[0]:
            require(not errors and receipt['owned_profile_removed'], 'Owned browser cleanup failed')


def main():
    p = argparse.ArgumentParser(description=__doc__)
    modes = p.add_mutually_exclusive_group()
    modes.add_argument('--otp', action='store_true', help='root-only ephemeral protocol output; never invoke in a logging terminal')
    modes.add_argument('--deployment-proof', action='store_true', help='root-only nonsecret deployment JSON; no authentication')
    p.add_argument('--expected-image', required=True)
    p.add_argument('--username')
    p.add_argument('--wait-fresh-code', action='store_true')
    p.add_argument('--desktop-hold-seconds', type=int, default=0,
                   help='hold each connected target 0..30 seconds for independent guest/session checks')
    p.add_argument('--fail-on-tunnel-error', action='store_true',
                   help='diagnostic: stop at first observed selected native client/tunnel error')
    p.add_argument('--base')
    p.add_argument('--ssh-host')
    p.add_argument('--directory', type=Path)
    p.add_argument('--aliases')
    p.add_argument('--ssh-alias', help='additional expected catalog entry; this driver still tests only the two Windows targets')
    p.add_argument('--chrome', default='/usr/bin/google-chrome')
    args = p.parse_args()
    require(0 <= args.desktop_hold_seconds <= 30, 'Desktop stability hold must be zero through thirty seconds')
    args.expected_image = image_id(args.expected_image)
    if args.deployment_proof:
        root_deployment_proof(args)
        return
    require(isinstance(args.username, str) and re.fullmatch('[A-Za-z0-9][A-Za-z0-9_.@-]{0,63}', args.username), 'Literal username required')
    if args.otp:
        root_otp(args)
        return
    require(args.base and args.ssh_host and args.directory and args.aliases, 'All browser bindings required')
    require(re.fullmatch('[A-Za-z0-9][A-Za-z0-9_.-]{0,127}', args.ssh_host), 'Administrative SSH alias required')
    require(os.geteuid() != 0, 'Run disposable sandboxed Chrome as an ordinary user')
    args.base = validate_base(args.base)
    args.aliases = validate_aliases(args.aliases)
    args.catalog_aliases = expected_catalog_aliases(args.aliases, args.ssh_alias)
    os.umask(0o077)
    args.directory.mkdir(mode=0o700, parents=False)
    receipt = {'schema': 1, 'passed': False, 'expected_image': args.expected_image,
               'checks': [], 'http': [], 'started_at': time.time(),
               'desktop_hold_seconds': args.desktop_hold_seconds,
               'fail_on_tunnel_error': args.fail_on_tunnel_error,
               'driver_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest()}
    (args.directory / 'intent.json').write_text(json.dumps({'schema': 1, 'started_at': receipt['started_at'],
        'expected_image': args.expected_image, 'driver_sha256': receipt['driver_sha256']}) + '\n')
    try:
        asyncio.run(asyncio.wait_for(acceptance(args, receipt), timeout=220))
        receipt['passed'] = True
        mark_phase(args, receipt, 'complete')
    except BaseException as error:
        receipt['error_type'] = type(error).__name__
        receipt.setdefault('failure_phase', receipt.get('phase'))
        if isinstance(error, StaticFailure):
            receipt['failure_reason'] = str(error)
        raise
    finally:
        receipt['finished_at'] = time.time()
        (args.directory / 'result.json').write_text(json.dumps(receipt, indent=2) + '\n')


if __name__ == '__main__':
    try:
        main()
    except SystemExit:
        raise
    except BaseException as error:
        # Never expose subprocess output, CDP payloads, configuration or secrets.
        print('Live acceptance failed: ' + type(error).__name__, file=sys.stderr)
        raise SystemExit(1)
