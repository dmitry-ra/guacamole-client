#!/usr/bin/env python3
"""Operator-invoked SSH-only browser acceptance; never sends terminal input."""
import argparse
import asyncio
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import time
from urllib.parse import urlsplit

import test_live as live
from test_live import (StaticFailure, require, mark_phase, NetworkTelemetry,
    client_diagnostic_expression, fail_on_selected_error, submit_once, observed_base,
    remote_otp, stop_chrome)


def aliases3(value, ssh_alias):
    items = value.split(',')
    require(len(items) == 3 and len(set(items)) == 3
        and all(re.fullmatch('[a-z][a-z0-9-]{0,31}', a) for a in items),
        'Exactly three distinct catalog aliases required')
    require(isinstance(ssh_alias, str) and ssh_alias in items, 'Selected SSH alias absent from catalog')
    return items


def ssh_mapping(tree, expected, ssh_alias):
    require(isinstance(tree, list) and len(tree) == 3
        and all(isinstance(row, dict) and set(row) == {'alias', 'id', 'protocol'} for row in tree),
        'Authenticated mixed JDBC schema mismatch')
    require(all(row['protocol'] == ('ssh' if row['alias'] == ssh_alias else 'rdp') for row in tree),
        'Authenticated mixed JDBC protocol mismatch')
    return live.catalog_mapping([{'alias': r['alias'], 'id': r['id']} for r in tree], expected)


def canvas_receipt(value):
    require(isinstance(value, dict) and set(value) == {'state', 'status', 'width', 'height', 'nonblack'},
        'SSH canvas receipt fields invalid')
    require(value['state'] == 'CONNECTED' and type(value['status']) is int and value['status'] == 0,
        'SSH canvas lost native connection')
    require(all(type(value[k]) is int and 0 < value[k] <= 16384 for k in ('width', 'height'))
        and type(value['nonblack']) is int and 100 < value['nonblack'] <= value['width']*value['height'],
        'SSH canvas dimensions or pixel count invalid')
    return dict(value)


async def acceptance(args, receipt):
    mark_phase(args, receipt, 'deployment_before')
    receipt['deployment_before'] = await live.remote_proof(args)
    try:
        await browser(args, receipt)
    finally:
        failed = sys.exc_info()[0] is not None
        try:
            mark_phase(args, receipt, 'deployment_after')
            receipt['deployment_after'] = await live.remote_proof(args)
            live.require_same_proof(receipt['deployment_before'], receipt['deployment_after'], args.expected_image)
        except BaseException as error:
            receipt['deployment_after_error_type'] = type(error).__name__
            if isinstance(error, StaticFailure): receipt['deployment_after_failure_reason'] = str(error)
            if not failed: raise


async def browser(args, receipt):
    import aiohttp
    profile = tempfile.mkdtemp(prefix='portal-live-ssh-chrome-')
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
                    tree = await js('Promise.resolve(' + injector + '.get("connectionGroupService").getConnectionGroupTree("postgresql","ROOT")).then(t=>{let a=[];function walk(g){for(let c of g.childConnections||[])a.push({alias:c.name,id:c.identifier,protocol:c.protocol});for(let c of g.childConnectionGroups||[])walk(c)}walk(t);return a})', True)
                    mapping = ssh_mapping(tree, args.catalog_aliases, args.ssh_alias)
                    receipt['jdbc_clients'] = [{'alias': a, 'client_id': mapping[a]} for a in args.aliases]
                    receipt['catalog_clients'] = [{'alias': a, 'client_id': mapping[a], 'protocol': 'ssh' if a == args.ssh_alias else 'rdp'} for a in args.catalog_aliases]
                    async def canvas(alias, refreshing=False):
                        prefix = 'reload' if refreshing else 'ssh'
                        mark_phase(args, receipt, prefix + '_route_wait')
                        selected = args.aliases.index(alias)
                        encoded = base64.urlsafe_b64encode((mapping[alias] + '\0c\0postgresql').encode()).decode().rstrip('=')
                        await until('location.hash.split("?")[0]===' + json.dumps('#/client/' + encoded), observe=True, selected=selected)
                        getter = injector + '.get("guacClientManager").getManagedClients()[' + json.dumps(encoded) + ']'
                        mark_phase(args, receipt, prefix + '_native_connection_wait')
                        await until('(()=>{let c=' + getter + ';return c&&c.clientState.connectionState==="CONNECTED"&&c.clientState.statusCode===0})()', observe=True, selected=selected)
                        mark_phase(args, receipt, prefix + '_pixels_wait')
                        return canvas_receipt(await until('(()=>{let c=' + getter + ';let v=c.client.getDisplay().flatten();if(!v.width||!v.height)return false;let d=v.getContext("2d").getImageData(0,0,v.width,v.height).data,n=0;for(let i=0;i<d.length;i+=4)if(d[i]+d[i+1]+d[i+2]>30)n++;return n>100?{state:c.clientState.connectionState,status:c.clientState.statusCode,width:v.width,height:v.height,nonblack:n}:false})()', observe=True, selected=selected))
                    async def hold(stage):
                        if not args.hold_seconds:
                            return
                        mark_phase(args, receipt, stage + '_hold')
                        deadline = time.monotonic() + args.hold_seconds
                        while time.monotonic() < deadline:
                            await asyncio.sleep(min(.5, max(0, deadline-time.monotonic())))
                            await observe_clients(0)
                            require(await js('(()=>{let c=' + injector + '.get("guacClientManager").getManagedClients()['
                                + json.dumps(base64.urlsafe_b64encode((mapping[args.ssh_alias]+'\0c\0postgresql').encode()).decode().rstrip('='))
                                + '];return c&&c.clientState.connectionState==="CONNECTED"&&c.clientState.statusCode===0})()'),
                                'SSH connection lost during passive hold')
                    receipt['terminal'] = {'alias': args.ssh_alias, 'client_id': mapping[args.ssh_alias], **(await canvas(args.ssh_alias))}
                    await hold('first_terminal')
                    mark_phase(args, receipt, 'reload_start')
                    await rpc('Page.reload')
                    await until('document.readyState==="complete"&&performance.getEntriesByType("navigation")[0].type==="reload"&&!!(window.angular&&angular.element(document.documentElement).injector())')
                    receipt['refresh'] = await canvas(args.ssh_alias, refreshing=True)
                    require(await js(auth + '.getCurrentUsername()===' + json.dumps(args.username)), 'Refresh identity mismatch')
                    await js('window.portalAcceptanceToken=' + auth + '.getCurrentToken();true')
                    await hold('refreshed_terminal')
                    encoded = base64.urlsafe_b64encode((mapping[args.ssh_alias]+'\0c\0postgresql').encode()).decode().rstrip('=')
                    mark_phase(args, receipt, 'owned_SSH_disconnect')
                    require(await js(injector + '.get("guacClientManager").removeManagedClient(' + json.dumps(encoded) + ')'), 'Owned SSH client absent at disconnect')
                    await rpc('Page.navigate', {'url': args.base + '#/'})
                    await until('location.hash==="#/"&&!!document.querySelector(".home")')
                    require(await js('window.portalAcceptanceToken===' + auth + '.getCurrentToken()'), 'Disconnect changed native token')
                    mark_phase(args, receipt, 'owned_SSH_reconnect')
                    await rpc('Page.navigate', {'url': args.base + '#/?wrdp-target=' + args.ssh_alias})
                    receipt['reconnect'] = await canvas(args.ssh_alias)
                    require(await js('window.portalAcceptanceToken===' + auth + '.getCurrentToken()'), 'Reconnect changed native token')
                    await hold('reconnected_terminal')
                    receipt['checks'] += ['native_username_TOTP', 'exact_three_entry_JDBC_tree_with_protocols',
                        'selected_SSH_CONNECTED_status0_nonblack', 'native_authenticated_refresh',
                        'owned_SSH_disconnect_reconnect_same_client_id_and_native_identity', 'no_terminal_input_sent']
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
    p.add_argument('--ssh-alias', required=True)
    p.add_argument('--expected-catalog-aliases', required=True)
    p.add_argument('--expected-image', required=True)
    p.add_argument('--base', required=True)
    p.add_argument('--ssh-host', required=True)
    p.add_argument('--directory', required=True, type=Path)
    p.add_argument('--username', required=True)
    p.add_argument('--hold-seconds', type=int, default=0,
        help='passive 0..20 second hold after each terminal connection for independent trusted PID checks')
    args = p.parse_args()
    require(os.geteuid() != 0, 'Run disposable sandboxed Chrome as an ordinary user')
    require(0 <= args.hold_seconds <= 20, 'Passive hold must be zero through twenty seconds')
    require(re.fullmatch('[A-Za-z0-9][A-Za-z0-9_.-]{0,127}', args.ssh_host), 'Administrative SSH alias required')
    require(re.fullmatch('[A-Za-z0-9][A-Za-z0-9_.@-]{0,63}', args.username), 'Literal username required')
    args.expected_image = live.image_id(args.expected_image)
    args.base = live.validate_base(args.base)
    args.catalog_aliases = aliases3(args.expected_catalog_aliases, args.ssh_alias)
    args.aliases = [args.ssh_alias]
    args.chrome = '/usr/bin/google-chrome'
    args.wait_fresh_code = True
    args.fail_on_tunnel_error = True
    require(args.directory.is_absolute() and not args.directory.exists() and not args.directory.is_symlink(),
        'New absolute private evidence directory required')
    os.umask(0o077)
    args.directory.mkdir(mode=0o700)
    receipt = {'schema': 1, 'passed': False, 'scope': 'actual SSH browser only; no terminal input or host pane PID proof',
        'expected_image': args.expected_image, 'ssh_alias': args.ssh_alias,
        'expected_catalog_aliases': args.catalog_aliases, 'checks': [], 'http': [],
        'started_at': time.time(), 'hold_seconds': args.hold_seconds,
        'driver_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        'shared_helper_sha256': hashlib.sha256(Path(live.__file__).read_bytes()).hexdigest(),
        'terminal_input_sent': False}
    (args.directory/'intent.json').write_text(json.dumps(receipt, sort_keys=True)+'\n')
    with (args.directory/'intent.json').open('rb') as stream: os.fsync(stream.fileno())
    try:
        asyncio.run(asyncio.wait_for(acceptance(args, receipt), timeout=260))
        receipt['passed'] = True
        mark_phase(args, receipt, 'complete')
    except BaseException as error:
        receipt['error_type'] = type(error).__name__
        receipt.setdefault('failure_phase', receipt.get('phase'))
        if isinstance(error, StaticFailure): receipt['failure_reason'] = str(error)
        raise
    finally:
        receipt['finished_at'] = time.time()
        (args.directory/'result.json').write_text(json.dumps(receipt, indent=2)+'\n')


if __name__ == '__main__':
    try: main()
    except SystemExit: raise
    except BaseException as error:
        print('SSH browser acceptance failed: '+type(error).__name__, file=sys.stderr)
        raise SystemExit(1)
