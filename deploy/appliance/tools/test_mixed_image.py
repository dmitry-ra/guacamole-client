#!/usr/bin/env python3
"""Complete-image synthetic native TOTP/JDBC/SSH browser fixture, no owner data."""
import argparse
import asyncio
import base64
import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import secrets
import signal
import subprocess
import sys
import tempfile
import time

HERE = Path(__file__).resolve().parent
ROOT = '/opt/homelab-web-rdp'
UNICODE = 'synthetic \u0442\u0435\u0441\u0442 \u03bb \u754c'
EXPECTED_INPUT = hashlib.sha256(UNICODE.encode()).hexdigest()
LABEL = 'guacamole.ssh-fixture'

CONTROL = '''import fcntl,hashlib,json,os,struct,sys,termios,time
from pathlib import Path
p=Path('/run/fixture/home/mixed-state.json')
pid=os.getpid();start=int(Path('/proc/self/stat').read_text().split(') ')[1].split()[19])
print('synthetic \\u0442\\u0435\\u0441\\u0442 \\u03bb \\u754c',flush=True)
data=sys.stdin.readline().rstrip('\\n')
digest=hashlib.sha256(data.encode('utf-8')).hexdigest()
for counter in range(600):
 rows,cols,_,_=struct.unpack('HHHH',fcntl.ioctl(0,termios.TIOCGWINSZ,bytes(8)))
 value=dict(pid=pid,start=start,counter=counter,rows=rows,cols=cols,input_sha256=digest)
 temp=p.with_suffix('.next');temp.write_text(json.dumps(value));temp.replace(p)
 print('synthetic counter',counter,flush=True);time.sleep(.2)
'''


def inside():
    if (Path(__file__) != Path('/mixed-fixture.py') or os.geteuid() != 0
            or not Path('/run/.containerenv').is_file()
            or re.fullmatch('[a-f0-9]{32}', os.environ.get('PORTAL_SSH_FIXTURE', '')) is None):
        raise ValueError('Owned disposable container required')
    signal.alarm(440)
    raw = sys.stdin.buffer.readline(18000)
    value = json.loads(raw)
    if set(value) != {'private_key'} or not isinstance(value['private_key'], str) or len(value['private_key']) > 16384:
        raise ValueError('Invalid synthetic key')
    sys.path.insert(0, ROOT)
    import runtime
    import lifecycle as life
    os.umask(0o077)
    os.chown('/data', 2000, 2000); os.chmod('/data', 0o700)
    for name in ('db-password', 'portal-password', 'desktop-a-password', 'desktop-b-password'):
        runtime.write_private(Path('/secrets')/name, secrets.token_urlsafe(32))
    runtime.write_private(Path('/secrets/terminal-c-key'), value['private_key'])
    value.clear()
    subprocess.run(['python3', '-B', ROOT+'/runtime.py', 'prepare'], check=True, timeout=90,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        life.start_pg()
        life.pg_sql("INSERT INTO guacamole_user_attribute SELECT user_id,'guac-totp-key-secret','AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' FROM guacamole_user; INSERT INTO guacamole_user_attribute SELECT user_id,'guac-totp-key-confirmed','true' FROM guacamole_user;")
    finally:
        life.shutdown()
    os.execv('/usr/bin/python3', ['python3', '-B', ROOT+'/runtime.py', 'serve'])


def catalog_bytes(host_key):
    original = json.loads((HERE.parent/'examples/config.json').read_text())
    result = json.loads(json.dumps(original))
    # This synthetic fixture intentionally exercises the optional chooser.
    result['portal']['publish_target_labels'] = True
    result['schema_version'] = 2
    result['targets']['terminal-c'] = dict(protocol='ssh', hostname='127.0.0.1', port=2222,
        username='fixture', host_key=host_key, private_key_file='terminal-c-key', command='/run/fixture/launcher')
    return json.dumps(result, sort_keys=True).encode()


class InputMismatch(ValueError):
    def __init__(self, received):
        self.received = received
        super().__init__('Fixed synthetic BMP UTF-8 bytes differ')


def safe_metadata(value):
    if not isinstance(value, dict) or set(value) != {'sentinel', 'process'}:
        raise ValueError('Invalid metadata fields')
    sentinel, process = value['sentinel'], value['process']
    if (not isinstance(sentinel, dict) or set(sentinel) != {'pid', 'start'}
            or not isinstance(process, dict)
            or set(process) != {'pid', 'start', 'counter', 'rows', 'cols', 'input_sha256'}):
        raise ValueError('Invalid metadata schema')
    if (any(type(v) is not int or not 0 < v < 2**63 for v in sentinel.values())
            or any(type(process[k]) is not int or not 0 <= process[k] < 2**63
                   for k in ('pid', 'start', 'counter', 'rows', 'cols'))
            or not isinstance(process['input_sha256'], str)
            or re.fullmatch('[a-f0-9]{64}', process['input_sha256']) is None):
        raise ValueError('Synthetic input or numeric metadata mismatch')
    if process['input_sha256'] != EXPECTED_INPUT:
        raise InputMismatch(process['input_sha256'])
    return {'sentinel': dict(sentinel), 'process': dict(process)}


def refusal_proof(path, image, expected_sha):
    raw = path.read_bytes()
    if hashlib.sha256(raw).hexdigest() != expected_sha:
        raise ValueError('Native evidence checksum mismatch')
    value = json.loads(raw)
    checks = value.get('checks', {})
    if (value.get('image') != image or value.get('passed') is not True
            or value.get('cleanup_verified') is not True
            or checks.get('wrong_pin', {}).get('outcome') != 'guacd_error'
            or checks.get('wrong_pin', {}).get('status') != 512
            or checks.get('wrong_appkey', {}).get('status') != 769
            or checks.get('none_denied') is not True or checks.get('command_denied') is not True):
        raise ValueError('Native refusal evidence mismatch')
    return expected_sha


def browser_identity(uid):
    if type(uid) is not int or uid <= 0:
        raise ValueError('Explicit nonroot browser UID required')
    account = pwd.getpwuid(uid)
    return uid, account.pw_gid


async def browser(base, receipt, metadata, browser_uid):
    import aiohttp
    import test_image
    with tempfile.TemporaryDirectory(prefix='portal-mixed-chrome-') as profile:
        uid, gid = browser_identity(browser_uid)
        os.chown(profile, uid, gid)
        environment = dict(os.environ, HOME=profile, XDG_CACHE_HOME=profile+'/cache',
                           XDG_CONFIG_HOME=profile+'/config', XDG_RUNTIME_DIR=profile)
        chrome = subprocess.Popen(['/usr/bin/google-chrome', '--headless',
            '--disable-gpu', '--no-first-run', '--disable-background-networking', '--disable-extensions',
            '--disable-dev-shm-usage', '--disable-component-update', '--disable-sync',
            '--no-default-browser-check', '--remote-debugging-address=127.0.0.1',
            '--remote-debugging-port=0', '--user-data-dir='+profile, 'about:blank'],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True,
            user=uid, group=gid, extra_groups=(), env=environment)
        logged_in = False
        js = None
        try:
            portfile = Path(profile)/'DevToolsActivePort'
            for _ in range(100):
                if portfile.exists(): break
                if chrome.poll() is not None: raise RuntimeError('Owned Chrome exited')
                await asyncio.sleep(.1)
            port = int(portfile.read_text().splitlines()[0])
            async with aiohttp.ClientSession() as session:
                async with session.put(f'http://127.0.0.1:{port}/json/new?about:blank') as response:
                    target = await response.json()
                async with session.ws_connect(target['webSocketDebuggerUrl']) as ws:
                    sequence, logout_ids = 0, set()
                    async def rpc(method, params=None):
                        nonlocal sequence
                        sequence += 1
                        await ws.send_json({'id': sequence, 'method': method, 'params': params or {}})
                        while True:
                            item = await ws.receive_json(timeout=35)
                            data = item.get('params', {})
                            if item.get('method') == 'Network.requestWillBeSent':
                                request = data.get('request', {})
                                if (request.get('method') == 'DELETE' and
                                        request.get('url', '').split('?', 1)[0].rstrip('/').endswith('/api/session')):
                                    logout_ids.add(data.get('requestId'))
                            if (item.get('method') == 'Network.responseReceived'
                                    and data.get('requestId') in logout_ids
                                    and data.get('response', {}).get('status') == 204):
                                receipt['own_logout_204'] = True
                            if item.get('id') == sequence:
                                if 'error' in item: raise RuntimeError('CDP command failed')
                                return item.get('result', {})
                    async def evaluate(expression, await_promise=False):
                        result = await rpc('Runtime.evaluate', {'expression': expression,
                            'returnByValue': True, 'awaitPromise': await_promise})
                        if 'exceptionDetails' in result: raise RuntimeError('Browser expression failed')
                        return result.get('result', {}).get('value')
                    js = evaluate
                    async def until(expression, seconds=30):
                        end = time.monotonic()+seconds
                        while time.monotonic() < end:
                            value = await js(expression)
                            if value: return value
                            await asyncio.sleep(.25)
                        raise RuntimeError('Browser stage timed out')
                    async def fill(selector, value):
                        if not await js('(()=>{let e=document.querySelector('+json.dumps(selector)+');if(!e)return false;e.value='+json.dumps(value)+';e.dispatchEvent(new Event("input",{bubbles:true}));e.dispatchEvent(new Event("change",{bubbles:true}));return true})()'):
                            raise RuntimeError('Native form field absent')
                    async def submit():
                        await until('[...document.querySelectorAll("button[type=submit],input[type=submit]")].some(e=>e.getClientRects().length&&!e.disabled)', 10)
                        if not await js('(()=>{let e=[...document.querySelectorAll("button[type=submit],input[type=submit]")].find(e=>e.getClientRects().length&&!e.disabled);if(!e)return false;e.click();return true})()'):
                            raise RuntimeError('Native submit unavailable')
                    injector = 'angular.element(document.documentElement).injector()'
                    manager = injector+'.get("guacClientManager")'
                    encoded = lambda ident: base64.urlsafe_b64encode((ident+'\0c\0postgresql').encode()).decode().rstrip('=')
                    terminal = encoded('3')
                    client = manager+'.getManagedClients()['+json.dumps(terminal)+']'
                    async def canvas():
                        await until('(()=>{let c='+client+';return c&&c.clientState.connectionState==="CONNECTED"&&c.clientState.statusCode===0})()')
                        return await until('(()=>{let c='+client+';let v=c.client.getDisplay().flatten();if(!v.width||!v.height)return false;let d=v.getContext("2d").getImageData(0,0,v.width,v.height).data,n=0;for(let i=0;i<d.length;i+=4)if(d[i]+d[i+1]+d[i+2]>30)n++;return n>1000?{width:v.width,height:v.height,nonblack:n}:false})()')
                    async def send(text):
                        keys = [0xff0d if c == '\r' else ord(c) if ord(c) <= 255 else 0x01000000|ord(c) for c in text]
                        if not await js('(()=>{let c='+client+';if(!c||c.clientState.connectionState!=="CONNECTED")return false;for(let k of '+json.dumps(keys)+'){c.client.sendKeyEvent(1,k);c.client.sendKeyEvent(0,k)}return true})()'):
                            raise RuntimeError('Synthetic input unavailable')
                    try:
                        await rpc('Page.enable'); await rpc('Runtime.enable'); await rpc('Network.enable')
                        await rpc('Emulation.setDeviceMetricsOverride', {'width': 1280, 'height': 900, 'deviceScaleFactor': 1, 'mobile': False})
                        receipt['phase'] = 'native_login'
                        await rpc('Page.navigate', {'url': base+'#/?wrdp-target=desktop-a'})
                        await until('!!document.querySelector("input[name=username]")')
                        options = await js('[...document.querySelectorAll("select[name=wrdp-target] option")].map(e=>e.textContent).filter(x=>x).sort()')
                        if options != ['desktop-a', 'desktop-b', 'terminal-c']: raise RuntimeError('Mixed native selector mismatch')
                        await fill('input[name=username]', 'operator')
                        await js('(()=>{let e=document.querySelector("select[name=wrdp-target]");e.value=[...e.options].find(o=>o.textContent==="terminal-c").value;e.dispatchEvent(new Event("change",{bubbles:true}))})()')
                        await submit()
                        await until('!!document.querySelector("input[name=guac-totp]")')
                        await fill('input[name=guac-totp]', test_image.code()); await submit()
                        await until('location.hash.split("?")[0]==='+json.dumps('#/client/'+terminal))
                        logged_in = True
                        receipt['phase'] = 'jdbc_tree'
                        tree = await js('(()=>{let t='+injector+'.get("authenticationService").getCurrentToken();return fetch("api/session/data/postgresql/connectionGroups/ROOT/tree?token="+encodeURIComponent(t)).then(r=>{if(r.status!==200)throw Error();return r.json()}).then(v=>v.childConnections.map(c=>[c.identifier,c.name]).sort())})()', True)
                        if tree != [['1', 'desktop-a'], ['2', 'desktop-b'], ['3', 'terminal-c']]: raise RuntimeError('Mixed JDBC tree mismatch')
                        receipt['tree'] = tree
                        receipt['phase'] = 'ssh_first'
                        receipt['first_canvas'] = await canvas()
                        await send('exec python3 /run/fixture/control.py\r')
                        await asyncio.sleep(.6)
                        await send(UNICODE+'\r')
                        before = None
                        for _ in range(30):
                            before = await metadata()
                            if before: break
                            await asyncio.sleep(.2)
                        if not before: raise RuntimeError('Unicode byte proof absent')
                        receipt['terminal_before_resize'] = before
                        receipt['phase'] = 'resize'
                        await rpc('Emulation.setDeviceMetricsOverride', {'width': 960, 'height': 640, 'deviceScaleFactor': 1, 'mobile': False})
                        after_resize = None
                        for _ in range(40):
                            after_resize = await metadata()
                            if (after_resize['process']['rows'], after_resize['process']['cols']) != (before['process']['rows'], before['process']['cols']): break
                            await asyncio.sleep(.2)
                        if (after_resize['process']['rows'], after_resize['process']['cols']) == (before['process']['rows'], before['process']['cols']):
                            raise RuntimeError('SSH PTY geometry unchanged')
                        receipt['terminal_after_resize'] = after_resize
                        receipt['resized_canvas'] = await canvas()
                        receipt['phase'] = 'alias_routes'
                        for alias, ident in [('desktop-a', '1'), ('desktop-b', '2')]:
                            await rpc('Page.navigate', {'url': base+'#/?wrdp-target='+alias})
                            await until('location.hash.split("?")[0]==='+json.dumps('#/client/'+encoded(ident)))
                            await js(manager+'.removeManagedClient('+json.dumps(encoded(ident))+')')
                        receipt['rdp_alias_routes_only'] = ['desktop-a', 'desktop-b']
                        receipt['phase'] = 'disconnect'
                        if not await js(manager+'.removeManagedClient('+json.dumps(terminal)+')'):
                            raise RuntimeError('Owned SSH disconnect missing')
                        await rpc('Page.navigate', {'url': base+'#/'})
                        await until('location.hash==="#/" && !!document.querySelector(".home")')
                        disconnected = await metadata()
                        await asyncio.sleep(1)
                        receipt['phase'] = 'reconnect'
                        await rpc('Page.navigate', {'url': base+'#/?wrdp-target=terminal-c'})
                        receipt['reconnect_canvas'] = await canvas()
                        after = await metadata()
                        import test_ssh
                        if not test_ssh.persisted(disconnected, after): raise RuntimeError('SSH pane identity/counter changed')
                        if before['sentinel'] != after['sentinel']: raise RuntimeError('Default sentinel changed')
                        receipt['terminal_disconnected'], receipt['terminal_reconnected'] = disconnected, after
                        receipt['unicode_input_sha256'] = EXPECTED_INPUT
                        receipt['unicode_input_mechanism'] = 'native Guacamole BMP keyboard events'
                        receipt['unicode_scope'] = 'exact received Cyrillic/lambda/CJK BMP UTF-8 bytes; fixed output emitted, glyph correctness not asserted'
                        receipt['phase'] = 'logout'
                        await js('Promise.resolve('+injector+'.get("authenticationService").logout()).then(()=>true)', True)
                        logged_in = False
                        if not receipt.get('own_logout_204'): raise RuntimeError('Own logout HTTP204 absent')
                    finally:
                        if logged_in:
                            try:
                                await js('Promise.resolve(angular.element(document.documentElement).injector().get("authenticationService").logout()).then(()=>true)', True)
                                logged_in = False
                            except Exception: receipt['logout_cleanup_failed'] = True
        finally:
            try: os.killpg(chrome.pid, signal.SIGTERM)
            except ProcessLookupError: pass
            try: chrome.wait(timeout=5)
            except subprocess.TimeoutExpired:
                os.killpg(chrome.pid, signal.SIGKILL); chrome.wait(timeout=5)
            try: os.killpg(chrome.pid, signal.SIGKILL)
            except ProcessLookupError: pass
            await asyncio.sleep(.3)


async def fixture(args):
    import aiohttp
    import terminal_launcher
    import test_ssh
    import test_image
    image, endpoint_image = test_ssh.exact_image(args.image), test_ssh.exact_image(args.endpoint_image)
    if os.geteuid() != 0 or not args.directory.is_absolute() or args.directory.exists():
        raise ValueError('Root and new absolute case required')
    native_sha = refusal_proof(args.native_receipt, image, args.native_receipt_sha256)
    os.umask(0o077); args.directory.mkdir(mode=0o700)
    token = secrets.token_hex(16)
    receipt = dict(schema=1, image=image, endpoint_image=endpoint_image, run_id=token,
        native_refusal_sha256=native_sha, passed=False, cleanup_verified=False, phase='start',
        scope='complete packaged mixed TOTP/JDBC/SSH browser; RDP alias routing only')
    sources = [Path(__file__), HERE/'test_ssh.py', HERE/'ssh_fixture.py', HERE/'terminal_launcher.py', HERE/'test_image.py']
    receipt['sources'] = {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in sources}
    (args.directory/'intent.json').write_text(json.dumps(receipt, sort_keys=True)+'\n')
    containers, tasks, children = [], set(), set()
    server, runtime_process = None, None
    try:
        for selected in (image, endpoint_image):
            info = json.loads(test_ssh.engine('image', 'inspect', selected).stdout)[0]
            if test_ssh.exact_image(info['Id']) != selected: raise RuntimeError('Image identity mismatch')
        endpoint_info = json.loads(test_ssh.engine('image', 'inspect', endpoint_image).stdout)[0]
        if (endpoint_info.get('Labels', {}).get('guacamole.ssh-fixture.source-sha256') !=
                hashlib.sha256((HERE/'ssh-endpoint.Containerfile').read_bytes()).hexdigest()):
            raise RuntimeError('Endpoint source binding mismatch')
        def start(role, selected, network, extra):
            item = dict(name='portal-mixed-'+token+'-'+role, image=selected, cid=None)
            containers.append(item)
            cid = test_ssh.engine('run', '-d', '--pull=never', '--name', item['name'], '--label', LABEL+'='+token,
                '--env', 'PORTAL_SSH_FIXTURE='+token, '--network', network, '--cpus=2', '--memory=1400m',
                '--pids-limit=256', '--tmpfs', '/tmp:rw,nosuid,nodev,mode=1777,size=64m',
                '--entrypoint=sleep', *extra, selected, '470').stdout.decode().strip()
            if re.fullmatch('[a-f0-9]{64}', cid) is None: raise RuntimeError('Invalid container ID')
            item['cid'] = cid
            if not test_ssh.owned(json.loads(test_ssh.engine('inspect', cid).stdout)[0],
                    cid=cid, image=selected, token=token, name=item['name']): raise RuntimeError('Ownership mismatch')
            return cid
        endpoint = start('endpoint', endpoint_image, 'none', ['--tmpfs', '/run:rw,nosuid,nodev,size=32m'])
        launcher = terminal_launcher.render(launcher='/run/fixture/launcher', socket='/run/fixture/home/portal.sock',
            config='/run/fixture/tmux.conf', home='/run/fixture/home', username='fixture')
        test_ssh.inner(endpoint, {'mode': 'initialize', 'launcher': launcher})
        test_ssh.engine('exec', '-i', endpoint, 'python3', '-c',
            'from pathlib import Path;import sys;p=Path("/run/fixture/control.py");p.write_text(sys.stdin.read());p.chmod(0o644)',
            data=CONTROL.encode())
        keys = test_ssh.inner(endpoint, {'mode': 'export'})
        config = args.directory/'config.json'; config.write_bytes(catalog_bytes(keys['host-key'])); config.chmod(0o644)
        receipt['config_sha256'] = hashlib.sha256(config.read_bytes()).hexdigest()
        candidate = start('app', image, 'container:'+endpoint, ['--read-only',
            '--tmpfs', '/data:rw,nosuid,nodev,size=256m', '--tmpfs', '/run/web-rdp:rw,nosuid,nodev,size=128m',
            '--tmpfs', '/secrets:rw,nosuid,nodev,size=1m',
            '--volume', str(config)+':/config/config.json:ro',
            '--volume', str(Path(__file__).resolve())+':/mixed-fixture.py:ro',
            '--env', 'WEB_RDP_DURATION_SECONDS=440', '--env', 'WEB_RDP_DEADLINE_EPOCH='+str(time.time()+440)])
        receipt['containers'] = {'candidate': candidate, 'endpoint': endpoint}
        runtime_process = subprocess.Popen(['podman', 'exec', '-i', candidate, 'python3', '-B', '/mixed-fixture.py', '--inside'],
            stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
        runtime_process.stdin.write(json.dumps({'private_key': keys['private-key']}).encode()+b'\n')
        runtime_process.stdin.close(); keys.clear()
        initial = json.loads(test_ssh.engine('inspect', candidate).stdout)[0]; pid = initial['State']['Pid']
        def inode(): return os.stat('/proc/'+str(pid)+'/ns/net').st_ino
        netns = inode()
        if netns == os.stat('/proc/self/ns/net').st_ino: raise RuntimeError('Host namespace refused')
        semaphore = asyncio.Semaphore(8)
        relay = 'import socket,threading,sys; s=socket.create_connection(("127.0.0.1",8080),3)\ndef up():\n try:\n  while True:\n   b=sys.stdin.buffer.read1(65536)\n   if not b:break\n   s.sendall(b)\n except OSError:pass\n try:s.shutdown(socket.SHUT_WR)\n except OSError:pass\nthreading.Thread(target=up,daemon=True).start()\ntry:\n while True:\n  b=s.recv(65536)\n  if not b:break\n  sys.stdout.buffer.write(b);sys.stdout.buffer.flush()\nexcept OSError:pass'
        async def connection(reader, writer):
            task = asyncio.current_task(); tasks.add(task); child = None
            try:
                async with semaphore:
                    state = json.loads((await asyncio.to_thread(test_ssh.engine, 'inspect', candidate)).stdout)[0]
                    if (not test_ssh.owned(state, cid=candidate, image=image, token=token, name=containers[-1]['name'])
                            or state['State']['Pid'] != pid or inode() != netns): raise RuntimeError('Namespace binding changed')
                    child = await asyncio.create_subprocess_exec('nsenter', '-t', str(pid), '-n', '/usr/bin/python3', '-u', '-c', relay,
                        stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL)
                    children.add(child)
                    async def pipe(source, dest):
                        try:
                            while data := await source.read(65536): dest.write(data); await dest.drain()
                        finally:
                            try: dest.write_eof()
                            except (OSError, AttributeError): pass
                    await asyncio.wait_for(asyncio.gather(pipe(reader, child.stdin), pipe(child.stdout, writer)), 180)
            except (Exception, asyncio.CancelledError): pass
            finally:
                if child:
                    if child.returncode is None: child.terminate()
                    await child.wait(); children.discard(child)
                writer.close(); tasks.discard(task)
        for port in range(10840,10860):
            try: server = await asyncio.start_server(connection, '127.0.0.1', port); break
            except OSError: continue
        if server is None: raise RuntimeError('No lab port available')
        base = 'http://127.0.0.1:'+str(port)+'/guacamole/'
        receipt['phase'] = 'startup'
        async with aiohttp.ClientSession() as session:
            end = time.monotonic()+150
            while time.monotonic() < end:
                if runtime_process.poll() is not None: raise RuntimeError('Packaged runtime exited')
                try:
                    async with session.post(base+'api/tokens', data={}, timeout=aiohttp.ClientTimeout(total=5)) as response:
                        if response.status == 403:
                            value = await response.json()
                            fields = value['expected']
                            if fields[1]['options'] != ['desktop-a', 'desktop-b', 'terminal-c']: raise RuntimeError('Mixed native bootstrap mismatch')
                            break
                except (aiohttp.ClientError, asyncio.TimeoutError): pass
                await asyncio.sleep(.5)
            else: raise RuntimeError('Packaged startup timed out')
        async def metadata():
            sentinel = (await asyncio.to_thread(test_ssh.inner, endpoint, {'mode': 'metadata'}))['sentinel']
            raw = await asyncio.to_thread(test_ssh.engine, 'exec', endpoint, 'python3', '-c',
                'from pathlib import Path;import json;p=Path("/run/fixture/home/mixed-state.json");print(p.read_text() if p.exists() else "null")')
            state = json.loads(raw.stdout)
            if state is None: return None
            return safe_metadata({'sentinel': sentinel, 'process': state})
        await browser(base, receipt, metadata, args.browser_uid)
        health = json.loads(test_ssh.engine('exec', candidate, 'python3', '-B', ROOT+'/runtime.py', 'health').stdout)
        if health != {'database_ready': True, 'web_ready': True, 'enrolled': True}: raise RuntimeError('Packaged health failed')
        receipt['health'] = health
        if receipt['sources'] != {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in sources}: raise RuntimeError('Sources changed')
        receipt.update(passed=True, phase='complete')
    except BaseException as error:
        receipt['failure_type'] = type(error).__name__
        if isinstance(error, InputMismatch):
            receipt['unicode_received_sha256'] = error.received
    finally:
        if server: server.close(); await server.wait_closed()
        for task in list(tasks): task.cancel()
        if tasks: await asyncio.gather(*list(tasks), return_exceptions=True)
        errors = []
        for item in reversed(containers):
            try: await asyncio.to_thread(test_ssh.cleanup_owned, item, token)
            except Exception as error: errors.append(type(error).__name__)
        if runtime_process:
            try: runtime_process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                try: os.killpg(runtime_process.pid, signal.SIGKILL)
                except ProcessLookupError: pass
                runtime_process.wait(timeout=5)
        receipt['cleanup_verified'] = not errors
        if errors: receipt['cleanup_error_types'] = errors
        (args.directory/'result.json').write_text(json.dumps(receipt, sort_keys=True, indent=2)+'\n')
    print(json.dumps(receipt, sort_keys=True))
    return 0 if receipt['passed'] and receipt['cleanup_verified'] else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--inside', action='store_true', help=argparse.SUPPRESS)
    parser.add_argument('--image'); parser.add_argument('--endpoint-image')
    parser.add_argument('--directory', type=Path)
    parser.add_argument('--native-receipt', type=Path); parser.add_argument('--native-receipt-sha256')
    parser.add_argument('--browser-uid', type=int)
    args = parser.parse_args()
    if args.inside: inside(); return 0
    if not all((args.image, args.endpoint_image, args.directory, args.native_receipt, args.native_receipt_sha256, args.browser_uid)):
        parser.error('Explicit images/new case/native refusal receipt and SHA required')
    browser_identity(args.browser_uid)
    return asyncio.run(asyncio.wait_for(fixture(args), 420))


if __name__ == '__main__': raise SystemExit(main())
