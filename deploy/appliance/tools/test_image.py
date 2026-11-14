#!/usr/bin/env python3
"""Bounded complete-image synthetic HTTP/Angular acceptance, without egress."""
import argparse
import asyncio
import base64
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import secrets
import signal
import struct
import subprocess
import sys
import tempfile
import time

HERE = Path(__file__).resolve().parents[1] if str(Path(__file__)) != '/fixture.py' else Path('/opt/homelab-web-rdp')
ROOT = '/opt/homelab-web-rdp'
LABEL = 'org.dmitryra.portal.image-fixture'


def inside():
    signal.alarm(530)
    os.umask(0o077)
    sys.path.insert(0, ROOT)
    import runtime
    import lifecycle as life
    os.chown('/data', 2000, 2000)
    os.chmod('/data', 0o700)
    for name in ('db-password', 'portal-password', 'desktop-a-password', 'desktop-b-password'):
        runtime.write_private(Path('/secrets')/name, secrets.token_urlsafe(32))
    # Exercise the real integrity/configuration entrypoint, without source overlays.
    subprocess.run(['python3', '-B', ROOT+'/runtime.py', 'prepare'], check=True, timeout=90)
    try:
        life.start_pg()
        life.pg_sql("INSERT INTO guacamole_user_attribute SELECT user_id,'guac-totp-key-secret','AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' FROM guacamole_user; INSERT INTO guacamole_user_attribute SELECT user_id,'guac-totp-key-confirmed','true' FROM guacamole_user;")
    finally:
        life.shutdown()
    os.execv('/usr/bin/python3', ['python3', '-B', ROOT+'/runtime.py', 'serve'])


def podman(*args, timeout=15, **kwargs):
    return subprocess.run(['sudo', '-n', 'podman', *map(str, args)], check=True,
                          timeout=timeout, capture_output=True, text=True, **kwargs)




def browser_value(result):
    """Expose only numeric location and exception class, never browser content."""
    details = result.get('exceptionDetails')
    if details:
        exception = details.get('exception', {})
        name = exception.get('className', 'Unknown')
        if not isinstance(name, str) or not re.fullmatch(r'[A-Za-z0-9_]{1,64}', name):
            name = 'Unknown'
        location = []
        for key in ('lineNumber', 'columnNumber'):
            value = details.get(key)
            if type(value) is int and value >= 0:
                location.append(key + '=' + str(value))
        raise AssertionError('Browser expression failed: class=' + name
                             + (', ' + ', '.join(location) if location else ''))
    return result.get('result', {}).get('value')



def reloaded_home_expression():
    # A reload command can return while the previous document still displays
    # .home. Admit only the replacement document after native Angular is ready.
    return '(window.fixtureBeforeReload!==true && document.readyState==="complete" && typeof angular!=="undefined" && typeof angular.element==="function" && !!angular.element(document.documentElement).injector() && location.hash==="#/" && !!document.querySelector(".home"))'


def invalid_target_expression(injector):
    return 'window.fixtureFatal=false;'+injector+'.get("$rootScope").$on("guacFatalPageError",()=>window.fixtureFatal=true);'+injector+'.get("$rootScope").$apply(()=>'+injector+'.get("$location").search("wrdp-target","unknown"));window.fixtureSettled=false;'+injector+'.get("userPageService").getHomePage().then(()=>window.fixtureSettled=true,()=>window.fixtureSettled=true)'


def code():
    counter = struct.pack('>Q', int(time.time())//30)
    digest = hmac.new(bytes(20), counter, hashlib.sha1).digest()
    offset = digest[-1] & 15
    return str((struct.unpack('>I', digest[offset:offset+4])[0] & 0x7fffffff) % 1000000).zfill(6)


async def acceptance(base, directory, checks):
    import aiohttp
    async with aiohttp.ClientSession() as session:
        async def request(method, path, data=None):
            async with session.request(method, base+path, data=data, timeout=aiohttp.ClientTimeout(total=12)) as r:
                raw = await r.read()
                try:
                    value = json.loads(raw)
                except ValueError:
                    value = None
                return r.status, value, dict(r.headers)
        # Observe the mandatory startup gate through the packaged WAR.
        end = time.monotonic()+100
        first = None
        while time.monotonic() < end:
            try:
                status, result, headers = await request('POST', 'api/tokens', {})
                if status == 503 and headers.get('Retry-After') == '65':
                    first = time.monotonic()
                    break
            except (aiohttp.ClientError, asyncio.TimeoutError):
                pass
            await asyncio.sleep(.5)
        assert first is not None, 'Packaged startup gate not observed'
        await asyncio.sleep(58)
        status, _, headers = await request('POST', 'api/tokens', {})
        assert status == 503 and headers.get('Retry-After') == '65', 'Startup gate ended early'
        while time.monotonic() < first+85:
            status, form, _ = await request('POST', 'api/tokens', {})
            if status != 503:
                break
            await asyncio.sleep(.5)
        fields = form['expected']
        assert status == 403 and [f['name'] for f in fields] == ['username', 'wrdp-target']
        assert fields[1]['options'] == ['desktop-a', 'desktop-b']
        checks.append('packaged_WAR_startup_hold_and_username_optional_alias_no_password')
        status, challenge, _ = await request('POST', 'api/tokens', {'username':'operator'})
        assert status == 403 and any(f['name']=='guac-totp' for f in challenge['expected'])
        wrong = str((int(code())+1)%1000000).zfill(6)
        status, denied, _ = await request('POST', 'api/tokens', {'username':'operator', 'guac-totp':wrong})
        assert status == 400 and 'authToken' not in denied, 'Incorrect OTP was not denied'
        otp = code()
        status, auth, _ = await request('POST', 'api/tokens', {'username':'operator', 'guac-totp':otp})
        assert status == 200, 'Valid native OTP HTTP status '+str(status)
        assert auth['dataSource'] == 'portal' and 'postgresql' in auth['availableDataSources'], 'Native authentication/context origins'
        token = auth['authToken']
        status, denied, _ = await request('POST', 'api/tokens', {'username':'operator', 'guac-totp':otp})
        assert status == 400 and 'authToken' not in denied, 'Replayed OTP was not denied'
        checks.append('native_TOTP_challenge_wrong_valid_and_replay_denial')
        status, tree, _ = await request('GET', 'api/session/data/postgresql/connectionGroups/ROOT/tree?token='+token)
        assert status == 200
        assert sorted((c['identifier'], c['name']) for c in tree['childConnections']) == [('1','desktop-a'),('2','desktop-b')]
        status, _, _ = await request('DELETE', 'api/tokens/'+token)
        assert status in (200,204)
        checks.append('native_authorized_two_connection_tree_and_own_API_logout')
    # Use a separate real browser login in a fresh TOTP period.
    await asyncio.sleep(31 - time.time()%30)
    await browser(base, directory, checks)


async def login_layout(rpc, js, directory, checks):
    """Inspect the packaged, synthetic login before entering any credentials."""
    observations = []
    for name, width, height, scale in [('desktop', 1280, 800, 1),
            ('mobile', 390, 844, 2), ('narrow', 320, 568, 1)]:
        await rpc('Emulation.setDeviceMetricsOverride', {'width': width, 'height': height,
            'deviceScaleFactor': scale, 'mobile': width < 500})
        await js('new Promise(r=>requestAnimationFrame(()=>requestAnimationFrame(r)))', True)
        value = await js('''(()=>{
            const e=document.querySelector('select[name="wrdp-target"]');
            const u=document.querySelector('input[name="username"]');
            const f=e&&e.closest('.labeled-field');
            const h=f&&f.querySelector('.field-header');
            const box=n=>{const b=n.getBoundingClientRect();return {left:b.left,right:b.right,top:b.top,bottom:b.bottom,width:b.width,height:b.height}};
            if(!e||!u||!h)return null;
            return {viewport:innerWidth,scrollWidth:document.documentElement.scrollWidth,
                username:box(u),select:box(e),header:box(h),label:h.textContent.trim(),
                selected:e.options[e.selectedIndex]&&e.options[e.selectedIndex].textContent,
                styled:f.classList.contains('portal-target-labeled-field')};
        })()''')
        assert value and value['styled'] and value['label'] == 'Server', 'Native server label missing'
        assert value['selected'] == 'desktop-a', 'Direct-link selection not visible'
        select, header, username = value['select'], value['header'], value['username']
        assert header['bottom'] <= select['top'] + 1, 'Server label overlaps native select'
        assert abs(select['left']-username['left']) <= 1 and abs(select['right']-username['right']) <= 1, 'Server select not aligned with username'
        assert abs(select['height']-username['height']) <= 2, 'Login fields have inconsistent heights'
        assert select['height'] >= 36 and select['width'] > 100, 'Server select is too small'
        assert select['left'] >= -1 and select['right'] <= value['viewport']+1, 'Server select outside viewport'
        assert value['scrollWidth'] <= value['viewport']+1, 'Login has horizontal overflow'
        shot = await rpc('Page.captureScreenshot', {'format': 'png', 'captureBeyondViewport': False})
        encoded = shot['data']
        assert len(encoded) <= 4*1024*1024, 'Synthetic login capture exceeds bound'
        raw = base64.b64decode(encoded, validate=True)
        assert raw.startswith(b'\x89PNG\r\n\x1a\n')
        path = directory/('login-'+name+'.png')
        with path.open('xb') as out:
            out.write(raw)
        observations.append({'name':name,'width':width,'height':height,'dpr':scale,
            'geometry':value,'png_sha256':hashlib.sha256(raw).hexdigest()})
    (directory/'login-layout.json').write_text(json.dumps({'schema':1,
        'scope':'packaged synthetic native login; no injected CSS or owner data',
        'viewports':observations}, indent=2)+'\n')
    checks.append('packaged_native_login_desktop_mobile_narrow_labels_alignment_and_visible_URL_selection')
    await rpc('Emulation.setDeviceMetricsOverride', {'width':1100,'height':800,
        'deviceScaleFactor':1,'mobile':False})


async def browser(base, directory, checks):
    import aiohttp
    with tempfile.TemporaryDirectory(prefix='portal-image-chrome-') as profile:
        chrome = subprocess.Popen(['/usr/bin/google-chrome', '--headless', '--no-sandbox',
            '--disable-gpu', '--no-first-run', '--disable-background-networking',
            '--disable-extensions', '--disable-dev-shm-usage',
            '--disable-component-update', '--disable-sync', '--no-default-browser-check',
            '--remote-debugging-address=127.0.0.1', '--remote-debugging-port=0',
            '--user-data-dir='+profile, 'about:blank'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
        try:
            portfile = Path(profile)/'DevToolsActivePort'
            for _ in range(100):
                if portfile.exists(): break
                assert chrome.poll() is None
                await asyncio.sleep(.1)
            port = int(portfile.read_text().splitlines()[0])
            async with aiohttp.ClientSession() as session:
                async with session.put(f'http://127.0.0.1:{port}/json/new?about:blank') as response:
                    target = await response.json()
                async with session.ws_connect(target['webSocketDebuggerUrl']) as ws:
                    sequence = 0
                    async def rpc(method, params=None):
                        nonlocal sequence
                        sequence += 1
                        await ws.send_json({'id':sequence,'method':method,'params':params or {}})
                        while True:
                            item = await ws.receive_json(timeout=40)
                            if item.get('id') == sequence:
                                assert 'error' not in item, 'CDP command failed'
                                return item.get('result',{})
                    async def js(expression, await_promise=False):
                        result = await rpc('Runtime.evaluate', {'expression':expression,'returnByValue':True,'awaitPromise':await_promise})
                        return browser_value(result)
                    async def until(expression):
                        for _ in range(120):
                            value = await js(expression)
                            if value: return value
                            await asyncio.sleep(.25)
                        raise AssertionError('Browser stage timeout')
                    async def fill(selector, value):
                        assert await js('(()=>{let e=document.querySelector('+json.dumps(selector)+');if(!e)return false;e.value='+json.dumps(value)+';e.dispatchEvent(new Event("input",{bubbles:true}));e.dispatchEvent(new Event("change",{bubbles:true}));return true})()')
                    async def submit():
                        assert await js('(()=>{let e=[...document.querySelectorAll("button[type=submit],input[type=submit]")].find(e=>e.getClientRects().length&&!e.disabled);if(!e)return false;e.click();return true})()')
                    injector = 'angular.element(document.documentElement).injector()'
                    await rpc('Page.enable')
                    await rpc('Runtime.enable')
                    await rpc('Page.navigate', {'url':base+'#/?wrdp-target=desktop-a'})
                    await until('!!document.querySelector("input[name=username]")')
                    checks.append('own_Chrome_loaded_packaged_login_DOM')
                    assert await js('!document.querySelector("input[type=password]")')
                    assert await js('[...document.querySelectorAll("select[name=wrdp-target] option")].map(e=>e.textContent).filter(x=>x).sort()') == ['desktop-a','desktop-b']
                    await login_layout(rpc, js, directory, checks)
                    await fill('input[name=username]', 'operator')
                    await js('(()=>{let e=document.querySelector("select[name=wrdp-target]");let o=[...e.options].find(o=>o.textContent==="desktop-b");e.value=o.value;e.dispatchEvent(new Event("change",{bubbles:true}));return true})()')
                    await submit()
                    await until('!!document.querySelector("input[name=guac-totp]")')
                    await fill('input[name=guac-totp]', code())
                    await submit()
                    await until('location.hash.startsWith("#/client/")')
                    assert await js('location.hash.split("?")[0]') == '#/client/MgBjAHBvc3RncmVzcWw'
                    checks.append('real_Angular_dynamic_alias_dropdown_overrides_link_through_native_TOTP')
                    # Exercise real decorated service with the existing token. Avoid
                    # opening a second synthetic RDP tunnel while checking the URI.
                    for alias, ident in [('desktop-a','1'),('desktop-b','2')]:
                        await rpc('Page.navigate', {'url':base+'#/?wrdp-target='+alias})
                        encoded = base64.urlsafe_b64encode((ident+'\0c\0postgresql').encode()).decode().rstrip('=')
                        await until('location.hash.split("?")[0]==='+json.dumps('#/client/'+encoded))
                        await js(injector+'.get("$rootScope").$apply(()=>'+injector+'.get("$location").search("wrdp-target",'+json.dumps(alias)+'))')
                        value = await js('Promise.resolve('+injector+'.get("userPageService").getHomePage()).then(p=>p.url)', True)
                        assert value == '/client/'+encoded
                    checks.append('real_Angular_both_selector_URIs_existing_native_token')
                    # General entry must show the chooser even after a client
                    # was selected with this same saved native token.
                    await rpc('Page.navigate', {'url':base+'#/'})
                    await until('location.hash==="#/" && !!document.querySelector(".home")')
                    assert await js('Promise.resolve('+injector+'.get("userPageService").getHomePage()).then(p=>p.url)', True) == '/'
                    await js('window.fixtureBeforeReload=true;true')
                    await rpc('Page.reload')
                    await until(reloaded_home_expression())
                    assert await js('!document.querySelector("input[name=username]")')
                    checks.append('real_Angular_general_entry_saved_token_and_reload_show_chooser')
                    await js(invalid_target_expression(injector))
                    await rpc('Page.navigate', {'url':base+'#/?wrdp-target=unknown'})
                    await until('window.fixtureFatal')
                    await asyncio.sleep(.5)
                    assert await js('!window.fixtureSettled')
                    assert await js('location.hash.startsWith("#/?") && location.hash.includes("wrdp-target=unknown")')
                    checks.append('real_Angular_invalid_link_fatal_pending_no_default_fallback')
                    assert await js('Promise.resolve('+injector+'.get("authenticationService").logout()).then(()=>true)', True)
                    checks.append('own_browser_native_logout')
        finally:
            os.killpg(chrome.pid,signal.SIGTERM)
            try: chrome.wait(timeout=10)
            except subprocess.TimeoutExpired:
                os.killpg(chrome.pid,signal.SIGKILL); chrome.wait(timeout=5)
            # Chromium helpers can outlive the browser parent briefly and keep
            # writing the owned temporary profile. Terminate only our own group.
            try: os.killpg(chrome.pid,signal.SIGKILL)
            except ProcessLookupError: pass
            await asyncio.sleep(.3)


async def fixture(image, directory, publish_target_labels=True):
    if not re.fullmatch('[0-9a-f]{64}', image):
        raise ValueError('Exact image SHA256 required')
    os.umask(0o077)
    directory.mkdir(mode=0o700)
    token = secrets.token_hex(16)
    name = 'portal-image-fixture-'+token[:16]
    cid = None
    server = None
    children = set()
    tasks = set()
    checks = []
    receipt = {'image':image,'checks':checks,'passed':False,'cleanup_verified':False,
        'scope':'clean candidate image startup, native HTTP/TOTP and real Angular browser; no RDP endpoint acceptance'}
    # The catalog is synthetic and root-owned inside its read-only file mount.
    config = directory/'config.json'
    value = json.loads((HERE/'examples/config.json').read_bytes())
    # Explicit synthetic chooser fixture; public examples hide labels by default.
    if type(publish_target_labels) is not bool:
        raise ValueError('Explicit synthetic label policy required')
    value['portal']['publish_target_labels'] = publish_target_labels
    config.write_text(json.dumps(value, indent=2)+'\n')
    config.chmod(0o644)
    subprocess.run(['sudo','-n','chown','root:root',str(config)],check=True,timeout=5)
    try:
        inspected = json.loads(podman('image','inspect',image).stdout)[0]
        assert inspected['Id'].removeprefix('sha256:') == image
        receipt['fixture_sha256'] = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
        receipt['config_sha256'] = hashlib.sha256(config.read_bytes()).hexdigest()
        command = ['run','-d','--name',name,'--label',LABEL+'='+token,'--pull=never',
            '--network=none','--read-only','--pids-limit=192','--memory=1200m','--cpus=2',
            '--tmpfs','/tmp:rw,nosuid,nodev,size=64m','--tmpfs','/data:rw,nosuid,nodev,size=256m',
            '--tmpfs','/run/web-rdp:rw,nosuid,nodev,size=128m','--tmpfs','/secrets:rw,nosuid,nodev,size=1m',
            '--mount','type=bind,src='+str(config.resolve())+',dst=/config/config.json,ro',
            '--mount','type=bind,src='+str(Path(__file__).resolve())+',dst=/fixture.py,ro',
            '-e','WEB_RDP_DURATION_SECONDS=510','-e','WEB_RDP_DEADLINE_EPOCH='+str(time.time()+510),
            '--entrypoint=python3',image,'-B','/fixture.py','--inside']
        cid = podman(*command,timeout=30).stdout.strip()
        assert re.fullmatch('[0-9a-f]{64}',cid)
        receipt['container_id'] = cid
        initial = json.loads(podman('inspect',cid).stdout)[0]
        pid = initial['State']['Pid']
        def namespace_inode():
            return int(subprocess.check_output(['sudo','-n','stat','-Lc','%i','/proc/'+str(pid)+'/ns/net'],timeout=5))
        netns = namespace_inode()
        assert netns != os.stat('/proc/self/ns/net').st_ino
        semaphore = asyncio.Semaphore(8)
        relay = 'import socket,threading,sys; s=socket.create_connection(("127.0.0.1",8080),3)\ndef up():\n try:\n  while True:\n   b=sys.stdin.buffer.read1(65536)\n   if not b: break\n   s.sendall(b)\n except OSError: pass\n try:s.shutdown(socket.SHUT_WR)\n except OSError:pass\nthreading.Thread(target=up,daemon=True).start()\ntry:\n while True:\n  b=s.recv(65536)\n  if not b:break\n  sys.stdout.buffer.write(b);sys.stdout.buffer.flush()\nexcept OSError:pass'
        async def connection(reader, writer):
            task = asyncio.current_task(); tasks.add(task)
            child = None
            try:
                async with semaphore:
                    state = json.loads((await asyncio.to_thread(podman,'inspect',cid)).stdout)[0]
                    assert state['Id']==cid and state['Image'].removeprefix('sha256:')==image
                    assert state['Config']['Labels'][LABEL]==token and state['State']['Running']
                    assert state['State']['Pid']==pid and await asyncio.to_thread(namespace_inode)==netns
                    child = await asyncio.create_subprocess_exec('sudo','-n','nsenter','-t',str(pid),'-n','/usr/bin/python3','-u','-c',relay,stdin=asyncio.subprocess.PIPE,stdout=asyncio.subprocess.PIPE,stderr=asyncio.subprocess.DEVNULL)
                    children.add(child)
                    async def pipe(source, dest):
                        try:
                            while data := await source.read(65536):
                                dest.write(data); await dest.drain()
                        finally:
                            try: dest.write_eof()
                            except (OSError,AttributeError): pass
                    await asyncio.wait_for(asyncio.gather(pipe(reader,child.stdin),pipe(child.stdout,writer)),120)
            except (Exception,asyncio.CancelledError):
                pass
            finally:
                if child:
                    if child.returncode is None: child.terminate()
                    await child.wait(); children.discard(child)
                writer.close(); tasks.discard(task)
        for bind_port in range(10820,10840):
            try:
                server = await asyncio.start_server(connection,'127.0.0.1',bind_port)
                break
            except OSError:
                continue
        if server is None: raise RuntimeError('No private lab loopback port available')
        port = server.sockets[0].getsockname()[1]
        await asyncio.wait_for(acceptance(f'http://127.0.0.1:{port}/guacamole/',directory,checks),350)
        health = json.loads(podman('exec',cid,'python3','-B',ROOT+'/runtime.py','health').stdout)
        assert health == {'database_ready':True,'web_ready':True,'enrolled':True}
        receipt['health'] = health
        receipt['installed_integrity_sha256'] = podman('exec',cid,'sha256sum',ROOT+'/integrity.json').stdout.split()[0]
        checks.append('packaged_runtime_integrity_configuration_and_enrolled_health')
        receipt['passed'] = True
    except BaseException as error:
        receipt['failure_type'] = type(error).__name__
        # Assertion labels contain no request payloads or authentication values.
        if isinstance(error,AssertionError): receipt['failure'] = str(error)
        raise
    finally:
        if server: server.close(); await server.wait_closed()
        for task in list(tasks): task.cancel()
        if tasks: await asyncio.gather(*list(tasks),return_exceptions=True)
        found = podman('ps','-a','--filter','name=^'+name+'$','--format','{{.ID}}').stdout.strip()
        if found:
            owned = json.loads(podman('inspect',name).stdout)[0]
            assert owned['Config']['Labels'][LABEL]==token and owned['Image'].removeprefix('sha256:')==image and (not cid or owned['Id']==cid)
            # Container logs are deliberately not retained: upstream may log
            # requests; receipts contain only assertions and immutable bindings.
            podman('stop','--time','5',owned['Id'],timeout=12)
            podman('rm',owned['Id'])
        assert not podman('ps','-a','--filter','name=^'+name+'$','--format','{{.ID}}').stdout.strip()
        receipt['cleanup_verified'] = True
        (directory/'receipt.json').write_text(json.dumps(receipt,indent=2)+'\n')
    print(json.dumps(receipt))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--inside',action='store_true',help=argparse.SUPPRESS)
    parser.add_argument('--image')
    parser.add_argument('--directory',type=Path)
    args = parser.parse_args()
    if args.inside:
        assert os.geteuid()==0 and Path(__file__)==Path('/fixture.py')
        inside()
    else:
        if not args.image or not args.directory: parser.error('--image and --directory required')
        asyncio.run(fixture(args.image,args.directory))


if __name__ == '__main__': main()
