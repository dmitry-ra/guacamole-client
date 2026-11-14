#!/usr/bin/env python3
"""Bounded complete-image synthetic HTTP/Angular acceptance, without egress."""
import argparse
import asyncio
import base64
import hashlib
import hmac
import json
import math
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
import ipaddress

HERE = Path(__file__).resolve().parents[1] if str(Path(__file__)) != '/fixture.py' else Path('/opt/homelab-web-rdp')
ROOT = '/opt/homelab-web-rdp'
LABEL = 'org.dmitryra.portal.rdp-fixture'
AUDIT_HELPER_SHA256 = 'df2c9043b197754dcbd99671e7233339c293277b3287e45cee8ded0cfd9aa747'


def safe_handshake_record(value):
    """Admit only the collector's bounded numeric/boolean observation schema."""
    def number(item):
        return type(item) in (int, float) and math.isfinite(item) and item > 0
    if not isinstance(value, dict):
        raise ValueError('Invalid handshake observation')
    keys = set(value)
    if keys == {'capture_ready', 'epoch'}:
        valid = value['capture_ready'] is True and number(value['epoch'])
    elif keys == {'finished', 'epoch', 'flows'}:
        valid = value['finished'] is True and number(value['epoch']) and type(value['flows']) is int and 0 <= value['flows'] <= 8
    elif keys == {'rejected'}:
        valid = value['rejected'] is True
    else:
        required = {'flow', 'alias', 'phases', 'equality', 'unknown_parameter_count',
                    'comparison_observed', 'status', 'ready', 'complete'}
        phases = {'syn', 'args', 'select', 'size', 'audio', 'video', 'image', 'timezone',
                  'name', 'connect', 'ready', 'error', 'closed', 'rejected_stream',
                  'unexpected_instruction', 'deadline', 'parent_closed'}
        parameters = {'hostname', 'port', 'username', 'domain', 'security',
                      'cert-fingerprints', 'password', 'enable-drive', 'enable-printing',
                      'resize-method', 'enable-font-smoothing', 'client-name'}
        valid = (required <= keys <= required | {'password_placeholder'}
            and type(value['flow']) is int and 1 <= value['flow'] <= 8
            and value['alias'] in (None, 'desktop-a', 'desktop-b')
            and type(value['unknown_parameter_count']) is int and 0 <= value['unknown_parameter_count'] <= 256
            and all(type(value[key]) is bool for key in ('comparison_observed', 'ready', 'complete'))
            and (value['status'] is None or type(value['status']) is int and 0 <= value['status'] <= 65535)
            and isinstance(value['phases'], dict) and set(value['phases']) <= phases
            and all(number(item) for item in value['phases'].values())
            and isinstance(value['equality'], dict) and set(value['equality']) <= parameters
            and all(type(item) is bool for item in value['equality'].values())
            and ('password_placeholder' not in value or type(value['password_placeholder']) is bool))
    if not valid:
        raise ValueError('Invalid handshake observation')
    return value


class HandshakeAudit:
    """Finite passive observer; EOF is sent before the owned namespace is removed."""
    def __init__(self, directory):
        self.directory = directory
        self.process = None
        self.task = None
        self.records = []
        self.ready = None
        self.started = None

    def save(self):
        (self.directory/'handshake-audit.json').write_text(json.dumps({
            'schema': 1, 'scope': 'native catalog parameter equality and phase boundaries only; NOT full handshake or RDP acceptance',
            'helper_sha256': AUDIT_HELPER_SHA256, 'records': self.records}, indent=2)+'\n')

    async def read(self):
        try:
            while raw := await self.process.stdout.readline():
                if len(raw) > 16384 or len(self.records) >= 11:
                    raise ValueError('Handshake observation limit')
                value = safe_handshake_record(json.loads(raw))
                if not self.records and value.get('capture_ready') is not True:
                    raise ValueError('Handshake observer did not arm')
                if self.records and ('capture_ready' in value or self.records[-1].get('finished')):
                    raise ValueError('Invalid handshake observation order')
                self.records.append(value)
                self.save()
                if value.get('capture_ready'):
                    self.ready.set_result(True)
            if not self.records or self.records[-1].get('finished') is not True:
                raise ValueError('Handshake observer incomplete')
        except BaseException:
            if not self.ready.done():
                self.ready.set_exception(ValueError('Handshake observer did not arm'))
            raise

    async def start(self, admission):
        helper = HERE/'tools/audit_guacd_handshake.py'
        if helper.is_symlink() or hashlib.sha256(helper.read_bytes()).hexdigest() != AUDIT_HELPER_SHA256:
            raise ValueError('Unreviewed handshake helper')
        self.ready = asyncio.get_running_loop().create_future()
        self.started = time.monotonic()
        self.process = await asyncio.create_subprocess_exec('sudo', '-n', 'timeout',
            '--signal=TERM', '--kill-after=2s', '190s', '/usr/bin/python3', '-B', str(helper),
            stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL, limit=16385)
        self.task = asyncio.create_task(self.read())
        self.process.stdin.write((json.dumps(admission, separators=(',', ':'))+'\n').encode('ascii'))
        await self.process.stdin.drain()
        await asyncio.wait_for(asyncio.shield(self.ready), 12)

    async def stop(self):
        if self.process is None:
            return
        if self.process.stdin:
            self.process.stdin.close()
        # GNU timeout owns the root process group and bounds even a failed EOF path.
        remaining = max(1, 200-(time.monotonic()-self.started))
        await asyncio.wait_for(self.process.wait(), remaining)
        await self.task
        if self.process.returncode != 0:
            raise ValueError('Handshake observer failed')


class HttpRelayTelemetry:
    """Observe transport admission without interpreting HTTP or WebSocket bytes."""
    def __init__(self, directory):
        self.directory = directory
        self.count = 0
        self.queued = self.active = self.children = 0
        self.highwater = {'queued': 0, 'active': 0, 'children': 0}
        self.rows = {}

    def save(self):
        for key in self.highwater:
            self.highwater[key] = max(self.highwater[key], getattr(self, key))
        (self.directory/'http-relay.json').write_text(json.dumps({
            'schema': 1, 'scope': 'HTTP transport slot/child counts and epochs only; no request interpretation',
            'limit': 8, 'accepted': self.count, 'queued': self.queued,
            'active': self.active, 'children': self.children, 'highwater': self.highwater,
            'rows_truncated': self.count > 512, 'connections': list(self.rows.values())}, indent=2)+'\n')

    def accepted(self):
        self.count += 1
        self.queued += 1
        row = {'ordinal': self.count, 'accepted_epoch': time.time(),
               'phase': 'queued', 'child_alive': False,
               'client_bytes': 0, 'backend_bytes': 0}
        if self.count <= 512:
            self.rows[self.count] = row
        self.save()
        return row

    def acquired(self, row):
        assert row['phase'] == 'queued'
        self.queued -= 1; self.active += 1
        row.update(phase='active', acquired_epoch=time.time())
        row['queue_wait_ms'] = (row['acquired_epoch']-row['accepted_epoch'])*1000
        self.save()

    def child_started(self, row):
        self.children += 1
        row.update(child_alive=True, child_started_epoch=time.time())
        self.save()

    def backend_connected(self, row):
        row['backend_connected_epoch'] = time.time()
        self.save()

    def data(self, row, direction, size):
        assert direction in ('client', 'backend') and type(size) is int and size >= 0
        row[direction+'_bytes'] += size
        row.setdefault(direction+'_first_byte_epoch', time.time())
        row[direction+'_last_byte_epoch'] = time.time()

    def eof(self, row, direction):
        assert direction in ('client', 'backend')
        row[direction+'_eof_epoch'] = time.time()
        self.save()

    def pipe_finished(self, row, direction):
        assert direction in ('client', 'backend')
        row[direction+'_finished_epoch'] = time.time()
        self.save()

    def released(self, row):
        if row['phase'] == 'queued': self.queued -= 1
        elif row['phase'] == 'active': self.active -= 1
        else: raise ValueError('Relay slot already released')
        row.update(phase='released', released_epoch=time.time())
        self.save()

    def closed(self, row):
        if row['child_alive']:
            self.children -= 1
            row['child_exited_epoch'] = time.time()
        row.update(child_alive=False, phase='closed', closed_epoch=time.time())
        self.save()


async def http_relay_streams(reader, writer, backend_reader, backend_writer, telemetry, row):
    async def pipe(source, dest, direction):
        try:
            while data := await source.read(65536):
                telemetry.data(row, direction, len(data))
                dest.write(data)
                await dest.drain()
            telemetry.eof(row, direction)
        finally:
            telemetry.pipe_finished(row, direction)
            try:
                dest.write_eof()
            except (OSError, AttributeError):
                pass
    upstream = asyncio.create_task(pipe(reader, backend_writer, 'client'))
    try:
        # Client half-close can precede a valid response. Backend EOF ends the
        # response stream, so retaining the other direction would leak a slot.
        await asyncio.wait_for(pipe(backend_reader, writer, 'backend'), 120)
    finally:
        upstream.cancel()
        await asyncio.gather(upstream, return_exceptions=True)



def target_sequence(order='alpha-beta', markers_only=False):
    """Alternate order is diagnostic only; default full acceptance is fixed."""
    normal = [('desktop-a', '1', 'green'), ('desktop-b', '2', 'navy')]
    if order == 'alpha-beta':
        return normal
    if order != 'beta-alpha':
        raise ValueError('Invalid synthetic target order')
    if not markers_only:
        raise ValueError('Alternate target order requires diagnostic mode')
    return list(reversed(normal))


def safe_phase_summary(raw):
    """Reduce private container output to fixed classes/times, never messages."""
    maximum = 256 * 1024
    limited = raw[-maximum:]
    rules = {
        'java_upstream_timeout': r'GuacamoleUpstreamTimeoutException',
        'java_socket_timeout': r'SocketTimeoutException|Read timed out',
        'java_socket_connect_error': r'ConnectException|Connection refused',
        'guacd_client_created': r'Creating new client|Client ID is',
        'guacd_client_removed': r'Removing client|Client.*disconnected',
        'guacd_rdp_connect_error': r'Error connecting to RDP server|RDP server closed',
        'guacd_protocol_error': r'Error (?:reading|parsing).*instruction|Invalid instruction',
        'freerdp_TLS_error': r'ERRCONNECT_TLS_CONNECT_FAILED',
        'freerdp_transport_error': r'ERRCONNECT_CONNECT_TRANSPORT_FAILED',
        'freerdp_logon_error': r'ERRCONNECT_LOGON_FAILURE',
        'thread_creation_error': r'pthread_create|failed to create.*thread|cannot create.*thread|Failed to start thread',
        'resource_exhaustion': r'Resource temporarily unavailable|Cannot allocate memory|unable to create native thread|Cannot fork',
        'java_out_of_memory': r'OutOfMemoryError',
    }
    counts = {phase: 0 for phase in rules}
    events = []
    for line in limited.splitlines()[-1024:]:
        for phase, pattern in rules.items():
            if not re.search(pattern, line, re.I):
                continue
            counts[phase] += 1
            timestamp = re.match(r'^(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,9})?Z) ', line)
            if len(events) < 80:
                events.append({'phase': phase,
                               'timestamp': timestamp.group(1) if timestamp else None})
    return {'schema': 1, 'scope': 'fixed phase classes and timestamps only',
            'captured_epoch': time.time(), 'characters_considered': len(limited),
            'truncated': len(raw) > maximum, 'counts': counts, 'events': events}


def runtime_phase_summary():
    """Sanitize bounded private stderr inside the owned container before export."""
    result = {'schema': 1, 'components': {}}
    for component in ('java', 'guacd'):
        path = Path('/run/web-rdp/diagnostics')/(component+'.stderr.log')
        if path.is_symlink() or not path.is_file():
            result['components'][component] = {'capture': 'unavailable'}
            continue
        with path.open('rb') as stream:
            size = os.fstat(stream.fileno()).st_size
            stream.seek(max(0, size-256*1024))
            raw = stream.read(256*1024).decode('utf-8', errors='replace')
        summary = safe_phase_summary(raw)
        summary['source_bytes'] = size
        result['components'][component] = summary
    return result


RESOURCE_READER = r'''import hashlib,json,pathlib,re,subprocess,sys,time
pid=int(sys.argv[1]);cid,token,image,start_expected,cgroup_expected=sys.argv[2:]
info=json.loads(subprocess.check_output(['podman','inspect',cid],timeout=5))[0]
assert info['Id']==cid and info['State']['Running'] and info['State']['Pid']==pid
assert info['Image'].removeprefix('sha256:')==image
assert info['Config']['Labels']['org.dmitryra.portal.rdp-fixture']==token
proc=pathlib.Path('/proc')/str(pid)
start=int((proc/'stat').read_text().rsplit(')',1)[1].split()[19])
assert start_expected=='-' or start==int(start_expected)
rows=(proc/'cgroup').read_text().splitlines()
paths=[row[3:] for row in rows if row.startswith('0::')]
assert len(paths)==1 and paths[0].startswith('/') and '..' not in pathlib.PurePosixPath(paths[0]).parts
assert cid in paths[0]
cgroup_hash=hashlib.sha256(paths[0].encode()).hexdigest()
assert cgroup_expected=='-' or cgroup_hash==cgroup_expected
cg=pathlib.Path('/sys/fs/cgroup')/paths[0].lstrip('/')
allowed_names={'python3','python','java','guacd','postgres','sh','bash','setpriv','timeout'}
def number(name):
 p=cg/name
 if not p.exists():return None
 value=p.read_text().strip()
 return int(value) if value.isdecimal() else None
def events(name,allowed):
 p=cg/name
 if not p.exists():return {}
 return {key:int(value) for line in p.read_text().splitlines() for key,value in [line.split()] if key in allowed}
ids=[int(value) for value in (cg/'cgroup.procs').read_text().split()]
assert pid in ids and len(ids)<=384
processes=[]
for member in ids:
 try:
  text=(pathlib.Path('/proc')/str(member)/'status').read_text()
  name=re.search(r'^Name:\s+(\S+)',text,re.M).group(1)
  threads=int(re.search(r'^Threads:\s+(\d+)',text,re.M).group(1))
  rss=re.search(r'^VmRSS:\s+(\d+) kB',text,re.M)
  processes.append({'pid':member,'class':name if name in allowed_names else 'other','threads':threads,'rss_kib':int(rss.group(1)) if rss else 0})
 except FileNotFoundError:pass
result={'schema':1,'epoch':time.time(),'init_pid':pid,'init_start_ticks':start,'cgroup_sha256':cgroup_hash,'pids_current':number('pids.current'),'pids_peak':number('pids.peak'),'pids_max':number('pids.max'),'pids_events':events('pids.events',{'max'}),'memory_current':number('memory.current'),'memory_peak':number('memory.peak'),'memory_max':number('memory.max'),'memory_events':events('memory.events',{'low','high','max','oom','oom_kill','oom_group_kill'}),'processes':processes}
assert int((proc/'stat').read_text().rsplit(')',1)[1].split()[19])==start
assert hashlib.sha256([row[3:] for row in (proc/'cgroup').read_text().splitlines() if row.startswith('0::')][0].encode()).hexdigest()==cgroup_hash
print(json.dumps(result))
'''


def host_resource_snapshot(pid, cid, token, image, previous=None):
    previous = previous or {}
    result = subprocess.run(['sudo', '-n', 'python3', '-c', RESOURCE_READER, str(pid),
                             cid, token, image, str(previous.get('init_start_ticks', '-')),
                             previous.get('cgroup_sha256', '-')],
                            check=True, capture_output=True, text=True, timeout=10)
    return json.loads(result.stdout)


def java_properties(values):
    def escape(value):
        if not isinstance(value,str):raise ValueError('Invalid diagnostic property')
        return ''.join({'\\':'\\\\','\n':'\\n','\r':'\\r','\t':'\\t',' ':'\\ '}.get(char,char) for char in value)
    text=''.join(escape(key)+'='+escape(values[key])+'\n' for key in sorted(values))
    if len(text.encode('utf-8'))>65536:raise ValueError('Diagnostic properties too large')
    return text


def numeric_java_report(value):
    common={'result','timestamp_ms','second_started_ms','first_sync_at_second','first_reader_alive','clients'}
    if not isinstance(value,dict):raise ValueError('Invalid numeric Java report')
    if set(value)=={'result','status'}:
        if value!={'result':2,'status':512}:raise ValueError('Invalid Java rejection')
        return value
    if set(value)!=common:raise ValueError('Invalid numeric Java report schema')
    for key in common-{'clients'}:
        if type(value[key]) is not int or not 0<=value[key]<2**63:
            raise ValueError('Invalid numeric Java report value')
    if value['result'] not in (0,1) or value['first_reader_alive'] not in (0,1):
        raise ValueError('Invalid numeric Java state')
    if not isinstance(value['clients'],list) or len(value['clients'])!=2:
        raise ValueError('Invalid numeric Java clients')
    keys={'client','stage','status','alive','instructions','sync','blobs','display','ready_ms','last_read_ms'}
    for ordinal,client in enumerate(value['clients'],1):
        if not isinstance(client,dict) or set(client)!=keys or client['client']!=ordinal:
            raise ValueError('Invalid numeric Java client schema')
        if any(type(item) is not int or not 0<=item<2**63 for item in client.values()):
            raise ValueError('Invalid numeric Java client value')
        if client['stage']>4 or client['status']>65535 or client['alive'] not in (0,1):
            raise ValueError('Invalid numeric Java client state')
    return value


def java_concurrent_inside(order,client_info):
    report={'schema':1,'passed':False,'diagnostic_complete':False,
            'scope':'actual Java Guacamole socket library concurrent diagnostic; NOT browser acceptance',
            'target_order':order,'client_name_is_null':True}
    try:
        sys.path.insert(0,ROOT)
        import runtime
        runtime.integrity()
        registry,config_digest=runtime.configuration()
        runtime.database_health(registry,runtime.check_cluster(registry,config_digest))
        info=validated_client_info(client_info)
        directory=Path('/diagnostic-java')
        manifest=json.loads((directory/'static-result.json').read_text())
        source_hash='886b68f7c32012c13e9530b7399e20d06dee4a36bd0d61622f6745279d455d86'
        assert hashlib.sha256((directory/'GuacamoleTwinProbe.java').read_bytes()).hexdigest()==source_hash
        assert manifest['sources']['GuacamoleTwinProbe.java']==source_hash
        classes={key:value for key,value in manifest['classes'].items() if key.startswith('GuacamoleTwinProbe')}
        assert {path.name for path in directory.glob('GuacamoleTwinProbe*.class')}==set(classes)
        for name,expected in classes.items():
            assert re.fullmatch(r'GuacamoleTwinProbe(?:\$[A-Za-z0-9_$]+)?\.class',name)
            assert hashlib.sha256((directory/name).read_bytes()).hexdigest()==expected
        common=Path('/opt/tomcat/webapps/guacamole/WEB-INF/lib/guacamole-common-1.6.1.jar')
        common_hash=hashlib.sha256(common.read_bytes()).hexdigest()
        assert common_hash==manifest['common_sha256']=='580d9372566530c3d25d280fbe23d72744aa2733f7e383f02d9d657298360f5e'
        report['common_sha256']=common_hash
        report['helper_source_sha256']=source_hash
        properties={'guacd.host':'127.0.0.1','guacd.port':'4822',
                    'client.width':str(info['width']),'client.height':str(info['height']),
                    'client.dpi':str(info['dpi']),'client.timezone':info['timezone']}
        for kind in ('audio','video','image'):
            properties['media.'+kind+'.count']=str(len(info[kind]))
            for index,value in enumerate(info[kind]):properties['media.'+kind+'.'+str(index)]=value
        mounted=json.loads(Path('/targets.json').read_text())['targets']
        expected=dict(zip(('desktop-a','desktop-b'),mounted))
        for index,(alias,ident,marker) in enumerate(target_sequence(order,True),1):
            target=registry.target(alias);item=expected[alias]
            assert target.protocol=='rdp' and target.security=='tls' and target.domain==''
            assert target.hostname=='127.0.0.1' and target.username==item['username']
            assert target.port=={'desktop-a':33389,'desktop-b':33390}[alias]
            assert target.certificate=='sha256:'+':'.join(item['certificate_sha256'][i:i+2] for i in range(0,64,2))
            params=dict(target.parameters());params['password']=runtime.target_secret(target.password_file)
            assert params['password']==item['password']
            for key,value in params.items():properties['target.'+str(index)+'.parameter.'+key]=value
            params.clear()
        payload=java_properties(properties)
        properties.clear()
        classpath='/diagnostic-java:'+str(common)+':/opt/tomcat/webapps/guacamole/WEB-INF/lib/slf4j-api-2.0.18.jar'
        report['started_epoch']=time.time()
        result=subprocess.run(['/opt/java/bin/java','-cp',classpath,'GuacamoleTwinProbe'],
            input=payload.encode('utf-8'),stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=80)
        payload=''
        report['finished_epoch']=time.time();report['helper_exit_code']=result.returncode
        if len(result.stdout)>32768:raise ValueError('Java numeric output too large')
        report['java']=numeric_java_report(json.loads(result.stdout))
        report['diagnostic_complete']=result.returncode==0 and report['java']['result']==0
    except Exception as error:
        report['error_class']=type(error).__name__
    return report


RAW_WEB_BOOTSTRAP = r"""(() => {
    const profile = __PROFILE__;
    let token = null;
    const entries = new Map();
    const manager = () => angular.element(document.documentElement).injector().get('guacClientManager');
    const statusCode = value => Number.isInteger(value?.code) ? value.code : (Number.isInteger(value) ? value : 512);
    if (Object.keys(manager().getManagedClients()).length !== 0 || window.__homelabRawRdp)
        throw new Error('Unexpected client state');
    window.__homelabRawRdp = {
        async login(otp) {
            let status = 0;
            try {
                const response = await fetch('api/tokens', {method:'POST',
                    headers:{'Content-Type':'application/x-www-form-urlencoded'},
                    body:new URLSearchParams({username:'operator','guac-totp':otp})});
                status = response.status;
                const data = await response.json();
                if (status === 200 && typeof data.authToken === 'string' && data.authToken.length > 0 && data.authToken.length <= 1024)
                    token = data.authToken;
            } catch (_) {}
            return {login_status:status,token_acquired:token !== null,
                managed_clients:Object.keys(manager().getManagedClients()).length};
        },
        start(alias, id) {
            if (!token || entries.has(alias) || !((alias==='desktop-b'&&id==='2')||(alias==='desktop-a'&&id==='1')))
                return {started:false};
            const ws = new Guacamole.WebSocketTunnel('websocket-tunnel');
            const http = new Guacamole.HTTPTunnel('tunnel');
            const tunnel = new Guacamole.ChainedTunnel(ws,http);
            const client = new Guacamole.Client(tunnel);
            const entry = {client,ws,http,tunnel,client_state:0,client_error:0,tunnel_error:0,
                tunnel_state:2,instructions:0,sync:0,blob:0,required:0,argv:0};
            entries.set(alias,entry);
            const originalClientState=client.onstatechange, originalClientError=client.onerror;
            const originalTunnelError=tunnel.onerror, originalTunnelState=tunnel.onstatechange;
            client.onstatechange = function(state) {
                entry.client_state=state;
                if(originalClientState)originalClientState.apply(this,arguments);
            };
            client.onerror = function(status) {
                entry.client_error=statusCode(status);
                if(originalClientError)originalClientError.apply(this,arguments);
            };
            tunnel.onerror = function(status) {
                entry.tunnel_error=statusCode(status);
                if(originalTunnelError)originalTunnelError.apply(this,arguments);
            };
            tunnel.onstatechange = function(state) {
                entry.tunnel_state=state;
                if(originalTunnelState)originalTunnelState.apply(this,arguments);
            };
            const dispatch = tunnel.oninstruction;
            tunnel.oninstruction = function(opcode,elements) {
                entry.instructions++;
                if (['sync','blob','required','argv'].includes(opcode)) entry[opcode]++;
                if(dispatch)dispatch.apply(this,arguments);
            };
            const parameters = new URLSearchParams({token,GUAC_DATA_SOURCE:'postgresql',GUAC_ID:id,GUAC_TYPE:'c',
                GUAC_WIDTH:String(profile.width),GUAC_HEIGHT:String(profile.height),GUAC_DPI:String(profile.dpi),GUAC_TIMEZONE:profile.timezone});
            for (const kind of ['audio','video','image'])
                for (const value of profile[kind]) parameters.append('GUAC_'+kind.toUpperCase(),value);
            try {client.connect(parameters.toString());return {started:true};}
            catch (_) {entry.client_error=512;return {started:false};}
        },
        observe(alias) {
            const e=entries.get(alias);
            const v=e.client.getDisplay().flatten();
            let green=0,navy=0,nonblack=0,canvas_error=0;
            try {
                if(v.width>0&&v.height>0) {
                    const d=v.getContext('2d').getImageData(0,0,v.width,v.height).data;
                    for(let i=0;i<d.length;i+=4) {
                        const r=d[i],g=d[i+1],b=d[i+2];
                        if(r+g+b>30)nonblack++;
                        if(r<15&&g>70&&g<130&&b<15)green++;
                        if(r<15&&g<15&&b>100&&b<160)navy++;
                    }
                }
            } catch (_) {canvas_error=1;}
            return {client_state:e.client_state,client_error:e.client_error,tunnel_error:e.tunnel_error,
                tunnel_state:e.tunnel_state,ws_state:e.ws.state,http_state:e.http.state,
                instructions:e.instructions,sync:e.sync,blob:e.blob,required:e.required,argv:e.argv,
                width:v.width,height:v.height,green,navy,nonblack,canvas_error,
                managed_clients:Object.keys(manager().getManagedClients()).length};
        },
        async close() {
            for(const e of entries.values()) {try{e.client.disconnect();}catch(_){}}
            let logout_status=0;
            if(token) {
                try {logout_status=(await fetch('api/tokens/'+encodeURIComponent(token),{method:'DELETE'})).status;}
                catch(_){}
                token=null;
            }
            return {logout_status,raw_client_count:entries.size,
                managed_clients:Object.keys(manager().getManagedClients()).length};
        }
    };
    return {initialized:true,managed_clients:0};
})()"""


def raw_web_observation(alias, marker, values, polls):
    if (alias,marker) not in (('desktop-a','green'),('desktop-b','navy')):
        raise ValueError('Unknown raw synthetic alias')
    keys={'client_state','client_error','tunnel_error','tunnel_state','ws_state','http_state',
          'instructions','sync','blob','required','argv','width','height','green','navy','nonblack',
          'canvas_error','managed_clients'}
    if not isinstance(values,dict) or set(values)!=keys:
        raise ValueError('Invalid raw numeric schema')
    if any(type(value) is not int or not 0<=value<=0xffffffff for value in values.values()):
        raise ValueError('Invalid raw numeric value')
    if (values['client_state']>5 or any(values[key]>3 for key in ('tunnel_state','ws_state','http_state'))
            or values['canvas_error']>1 or type(polls) is not int or not 1<=polls<=180):
        raise ValueError('Invalid raw numeric state')
    result={'alias':alias,'expected_marker':marker,'polls':polls,'epoch':time.time(),**values}
    result['transport']=('websocket' if values['ws_state'] in (1,3) else
                         'http' if values['http_state'] in (1,3) else 'none')
    return result


def raw_web_ready(row):
    return (row['client_state']==3 and row['client_error']==0 and row['tunnel_error']==0
            and row['managed_clients']==0 and row['canvas_error']==0
            and row['tunnel_state'] in (1,3) and row['transport'] in ('websocket','http')
            and row['sync']>0 and row[row['expected_marker']]>5000 and row['nonblack']>10000)


async def raw_web_probe(rpc,js,until,base,directory,checks,profile,order,transport_events):
    await rpc('Network.enable')
    await rpc('Page.navigate',{'url':base})
    await until('typeof angular!=="undefined"&&!!angular.element(document.documentElement).injector()&&!!document.querySelector("input[name=username]")')
    initialized=await js(RAW_WEB_BOOTSTRAP.replace('__PROFILE__',json.dumps(profile)))
    assert initialized=={'initialized':True,'managed_clients':0},'Raw client initialization failed'
    observations=[]
    report={'schema':1,'mode':'raw-web-concurrent-diagnostic','passed':False,
            'diagnostic_complete':False,'scope':'real HTTP/TOTP/JDBC/portal and raw common-JS Client/tunnels/canvas; NOT full browser acceptance',
            'remaining_layers':'Guacamole.Client, ChainedTunnel(WS/HTTP), canvas/audio; no ManagedClient/router/view attachment',
            'shared_token':True,'profile':profile,'observations':observations,
            'websocket_handshakes':transport_events}
    try:
        auth=await js('window.__homelabRawRdp.login('+json.dumps(code())+')',True)
        assert auth=={'login_status':200,'token_acquired':True,'managed_clients':0},'Raw synthetic API authentication failed'
        report['login_status']=auth['login_status']
        for alias,ident,marker in target_sequence(order,True):
            started=await js('window.__homelabRawRdp.start('+json.dumps(alias)+','+json.dumps(ident)+')')
            assert started=={'started':True},'Raw synthetic connection dispatch failed'
            for poll in range(180):
                values=await js('window.__homelabRawRdp.observe('+json.dumps(alias)+')')
                row=raw_web_observation(alias,marker,values,poll+1)
                if raw_web_ready(row):break
                await asyncio.sleep(.25)
            observations.append(row)
            (directory/'raw-web-result.json').write_text(json.dumps(report,indent=2)+'\n')
        first_alias,_,first_marker=target_sequence(order,True)[0]
        values=await js('window.__homelabRawRdp.observe('+json.dumps(first_alias)+')')
        report['first_after_second']=raw_web_observation(first_alias,first_marker,values,1)
        report['diagnostic_complete']=all(raw_web_ready(row) for row in observations) and raw_web_ready(report['first_after_second'])
    finally:
        try:report['cleanup']=await js('window.__homelabRawRdp.close()',True)
        except Exception as error:report['cleanup']={'error_class':type(error).__name__}
        (directory/'raw-web-result.json').write_text(json.dumps(report,indent=2)+'\n')
    assert report['diagnostic_complete'],'Raw synthetic marker diagnostic incomplete'
    assert report['cleanup']=={'logout_status':204,'raw_client_count':2,'managed_clients':0} or report['cleanup']=={'logout_status':200,'raw_client_count':2,'managed_clients':0},'Raw synthetic API logout incomplete'
    checks.append('two_raw_commonJS_clients_real_markers_first_survives_second')


def validated_client_info(value):
    """Only public capability values from the isolated login page may survive."""
    keys = {'audio','video','image','timezone','width','height','dpi'}
    if not isinstance(value,dict) or set(value)!=keys:
        raise ValueError('Invalid public client information schema')
    allowed = {'audio':{'audio/L8','audio/L16'},'video':set(),
               'image':{'image/jpeg','image/png','image/webp'}}
    result = {}
    for kind, supported in allowed.items():
        values = value[kind]
        if (not isinstance(values,list) or len(values)>len(supported)
                or any(not isinstance(item,str) or item not in supported for item in values)
                or len(set(values))!=len(values)):
            raise ValueError('Unsupported public capability value')
        result[kind]=list(values)
    for key,expected in (('width',1100),('height',800),('dpi',96)):
        if type(value[key]) is not int or value[key]!=expected:
            raise ValueError('Unexpected controlled browser geometry')
        result[key]=value[key]
    timezone=value['timezone']
    if not isinstance(timezone,str) or not re.fullmatch(r'[A-Za-z0-9_+./-]{1,64}',timezone):
        raise ValueError('Invalid public timezone')
    result['timezone']=timezone
    return result


async def collect_browser_client_info(base):
    """Read only public login-page capabilities; never authenticate or connect."""
    import aiohttp
    with tempfile.TemporaryDirectory(prefix='portal-capability-chrome-') as profile:
        chrome = subprocess.Popen(['/usr/bin/google-chrome','--headless','--no-sandbox',
            '--disable-gpu','--no-first-run','--disable-background-networking',
            '--disable-extensions','--disable-dev-shm-usage','--disable-component-update',
            '--disable-sync','--no-default-browser-check','--remote-debugging-address=127.0.0.1',
            '--remote-debugging-port=0','--user-data-dir='+profile,'about:blank'],
            stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,start_new_session=True)
        try:
            portfile=Path(profile)/'DevToolsActivePort'
            for _ in range(100):
                if portfile.exists():break
                assert chrome.poll() is None
                await asyncio.sleep(.1)
            port=int(portfile.read_text().splitlines()[0])
            async with aiohttp.ClientSession() as session:
                async with session.put(f'http://127.0.0.1:{port}/json/new?about:blank') as response:
                    target=await response.json()
                async with session.ws_connect(target['webSocketDebuggerUrl']) as ws:
                    sequence=0
                    async def rpc(method,params=None):
                        nonlocal sequence
                        sequence+=1
                        await ws.send_json({'id':sequence,'method':method,'params':params or {}})
                        while True:
                            message=await ws.receive_json(timeout=30)
                            if message.get('id')==sequence:
                                assert 'error' not in message,'Capability CDP command failed'
                                return message.get('result',{})
                    async def evaluate(expression,wait=False):
                        r=await rpc('Runtime.evaluate',{'expression':expression,'returnByValue':True,'awaitPromise':wait})
                        assert 'exceptionDetails' not in r,'Capability expression failed'
                        return r.get('result',{}).get('value')
                    await rpc('Page.enable')
                    await rpc('Runtime.enable')
                    await rpc('Emulation.setDeviceMetricsOverride',{'width':1100,'height':800,'deviceScaleFactor':1,'mobile':False})
                    await rpc('Page.navigate',{'url':base})
                    ready='typeof angular!=="undefined"&&!!angular.element(document.documentElement).injector()&&!!document.querySelector("input[name=username]")'
                    for _ in range(120):
                        if await evaluate(ready):break
                        await asyncio.sleep(.25)
                    else:raise AssertionError('Public login capability page not ready')
                    expression='(async()=>{let i=angular.element(document.documentElement).injector();if(Object.keys(i.get("guacClientManager").getManagedClients()).length!==0)throw new Error("Unexpected managed client");return {audio:[...i.get("guacAudio").supported],video:[...i.get("guacVideo").supported],image:[...await i.get("guacImage").getSupportedMimetypes()],timezone:i.get("preferenceService").preferences.timezone,width:Math.floor(window.innerWidth*window.devicePixelRatio),height:Math.floor(window.innerHeight*window.devicePixelRatio),dpi:Math.floor(96*window.devicePixelRatio)}})()'
                    return validated_client_info(await evaluate(expression,True))
        finally:
            try:os.killpg(chrome.pid,signal.SIGTERM)
            except ProcessLookupError:pass
            try:chrome.wait(timeout=10)
            except subprocess.TimeoutExpired:
                os.killpg(chrome.pid,signal.SIGKILL);chrome.wait(timeout=5)
            try:os.killpg(chrome.pid,signal.SIGKILL)
            except ProcessLookupError:pass
            await asyncio.sleep(.3)


def native_concurrent_inside(order, client_info=None):
    """Two direct, overlapping synthetic TLS consumers; never browser acceptance."""
    import importlib.util
    import socket
    import threading
    sys.path.insert(0, ROOT)
    import runtime
    spec = importlib.util.spec_from_file_location('synthetic_protocol', '/probe-library.py')
    library = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(library)
    report = {'schema':1,'passed':False,'diagnostic_complete':False,
              'scope':'direct concurrent synthetic TLS protocol only; NOT browser acceptance',
              'geometry':[1100,800,96],'target_order':order,'attempts':[],
              'media_configuration':{'audio':[],'video':[],'image':['image/png','image/jpeg'],'timezone':'Etc/UTC'},
              'acknowledged_delta':'Browser-advertised media MIME lists may differ; this is not an identical web handshake.'}
    media=None
    geometry=(1100,800,96)
    if client_info is not None:
        client_info=validated_client_info(client_info)
        media={key:client_info[key] for key in ('audio','video','image','timezone')}
        geometry=tuple(client_info[key] for key in ('width','height','dpi'))
        report['media_configuration']=media
        report['client_info_source']='measured unauthenticated owned browser'
        report['acknowledged_delta']='Media/geometry/timezone matched; direct consumer still bypasses Java/browser tunnel implementation.'
    sockets = []
    stop = threading.Event()
    reader = None
    first_drain = {'unexpected_close':False,'instructions':0,'sync_acks':0,'blob_acks':0}
    def expired(signum, frame):
        raise TimeoutError()
    signal.signal(signal.SIGALRM, expired)
    signal.alarm(75)
    try:
        runtime.integrity()
        registry, config_digest = runtime.configuration()
        mapping = runtime.check_cluster(registry, config_digest)
        runtime.database_health(registry, mapping)
        mounted = json.loads(Path('/targets.json').read_text())['targets']
        expected = {alias:item for alias,item in zip(('desktop-a','desktop-b'),mounted)}
        selected = target_sequence(order, True)
        for index, (alias, ident, marker) in enumerate(selected):
            target = registry.target(alias)
            item = expected[alias]
            assert target.protocol=='rdp' and target.security=='tls'
            assert target.username==item['username'] and target.hostname=='127.0.0.1'
            assert target.domain==''
            assert target.port==({'desktop-a':33389,'desktop-b':33390}[alias])
            fingerprint = 'sha256:'+':'.join(item['certificate_sha256'][i:i+2] for i in range(0,64,2))
            assert target.certificate==fingerprint
            params = dict(target.parameters())
            params['password'] = runtime.target_secret(target.password_file)
            assert params['password']==item['password']
            attempt = {'alias':alias,'ordinal':index+1,'started_epoch':time.time(),
                       'stage':'guacd_socket','outcome':'probe_failure','status':None,
                       'instructions':0,'display_instructions':0,'display_payload_characters':0}
            report['attempts'].append(attempt)
            deadline = time.monotonic()+29
            sock = socket.create_connection(('127.0.0.1',4822),timeout=5)
            sockets.append(sock)
            if index == 1:
                report['first_reader_alive_at_second_start'] = reader.is_alive()
            try:
                protocol = library.exchange(sock,params,deadline,attempt,
                    geometry=geometry,return_protocol=True,media=media)
            except (TimeoutError,socket.timeout):
                attempt['outcome']='timeout'
                protocol=None
            except EOFError:
                attempt['outcome']='eof'
                protocol=None
            except Exception as error:
                attempt['error_class']=type(error).__name__
                protocol=None
            finally:
                params.clear()
                attempt['finished_epoch']=time.time()
                if index == 1:
                    report['first_reader_alive_at_second_result']=reader.is_alive()
                    report['first_still_open_until_second_result']=reader.is_alive() and not first_drain['unexpected_close']
            if attempt['outcome']!='display_activity':
                break
            if index == 0:
                # Preserve buffered protocol bytes and continue ACK/sync traffic
                # on the SAME first socket while the second exchange runs.
                protocol.deadline=time.monotonic()+31
                def drain(first_protocol):
                    try:
                        while not stop.is_set():
                            message=first_protocol.read()
                            first_drain['instructions']+=1
                            if message[0]=='sync':
                                first_protocol.send('sync',message[1]);first_drain['sync_acks']+=1
                            elif message[0]=='blob':
                                first_protocol.send('ack',message[1],'OK','0');first_drain['blob_acks']+=1
                            elif message[0] in ('error','disconnect'):
                                first_drain['unexpected_close']=True
                                break
                    except Exception as error:
                        if not stop.is_set():
                            first_drain['unexpected_close']=True
                            first_drain['error_class']=type(error).__name__
                reader=threading.Thread(target=drain,args=(protocol,),daemon=True)
                reader.start()
            else:
                time.sleep(1)
                report['first_reader_alive_at_second_result']=reader.is_alive()
                report['first_still_open_until_second_result']=reader.is_alive() and not first_drain['unexpected_close']
        report['diagnostic_complete']=(len(report['attempts'])==2
            and all(a['outcome']=='display_activity' for a in report['attempts'])
            and report.get('first_still_open_until_second_result') is True)
    except Exception as error:
        report['error_class']=type(error).__name__
    finally:
        stop.set()
        for sock in sockets:
            try:sock.shutdown(socket.SHUT_RDWR)
            except OSError:pass
            sock.close()
        if reader:reader.join(timeout=2)
        report['first_drain']=first_drain
        signal.alarm(0)
    return report


def marker_pixels_expression(getter):
    # CONNECTED can precede the first display size/frame. Preserve the bounded
    # polling loop and marker thresholds while an empty canvas is still pending.
    return '(()=>{let c='+getter+';let v=c.client.getDisplay().flatten();let green=0,navy=0,nonblack=0;if(v.width>0&&v.height>0){let d=v.getContext("2d").getImageData(0,0,v.width,v.height).data;for(let i=0;i<d.length;i+=4){let r=d[i],g=d[i+1],b=d[i+2];if(r+g+b>30)nonblack++;if(r<15&&g>70&&g<130&&b<15)green++;if(r<15&&g<15&&b>100&&b<160)navy++;}}return {state:c.clientState.connectionState,status:c.clientState.statusCode,width:v.width,height:v.height,green,navy,nonblack}})()'


def marker_observation(alias, marker, pixels, polls):
    """Return only bounded synthetic state/count telemetry, never desktop data."""
    if (alias, marker) not in (('desktop-a', 'green'), ('desktop-b', 'navy')):
        raise ValueError('Unknown synthetic marker alias')
    state = pixels.get('state')
    if state not in ('IDLE', 'CONNECTING', 'WAITING', 'CONNECTED',
                     'DISCONNECTED', 'TUNNEL_ERROR', 'CLIENT_ERROR'):
        raise ValueError('Invalid synthetic connection state')
    result = {'alias': alias, 'expected_marker': marker, 'state': state, 'polls': polls}
    limits = {'status': 0xFFFFFFFF, 'width': 65536, 'height': 65536,
              'green': 0xFFFFFFFF, 'navy': 0xFFFFFFFF, 'nonblack': 0xFFFFFFFF}
    for key, limit in limits.items():
        value = pixels.get(key)
        if type(value) is not int or not 0 <= value <= limit:
            raise ValueError('Invalid synthetic pixel telemetry')
        result[key] = value
    if type(polls) is not int or not 1 <= polls <= 100:
        raise ValueError('Invalid synthetic poll count')
    return result



def finish_receipt(receipt, markers_only):
    """A diagnostic can finish successfully without becoming acceptance proof."""
    receipt['passed'] = not markers_only
    receipt['diagnostic_complete'] = bool(markers_only)



def connected_stage(directory, states, markers_only):
    """Only full acceptance may emit the parent beta-stop stage event."""
    if markers_only:
        return
    for alias, marker in (('desktop-a', 'green'), ('desktop-b', 'navy')):
        pixels = states.get(alias, {})
        if (pixels.get('state') != 'CONNECTED' or pixels.get('status') != 0
                or pixels.get(marker, 0) <= 5000 or pixels.get('nonblack', 0) <= 10000):
            raise AssertionError('Incomplete synthetic connected stage')
    (directory/'both-connected.json').write_text(json.dumps(states, indent=2)+'\n')


def credentials(path, expected, address):
    raw = path.read_bytes()
    assert hashlib.sha256(raw).hexdigest() == expected, 'Synthetic credentials digest'
    assert path.stat().st_mode & 0o077 == 0, 'Private credentials permissions'
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result: raise ValueError('Duplicate credential field')
            result[key] = value
        return result
    value = json.loads(raw, object_pairs_hook=pairs)
    assert set(value) == {'targets'} and len(value['targets']) == 2
    assert str(ipaddress.IPv4Address(address)) == address
    for item, alias, port in zip(value['targets'], ('alpha','beta'), (3389,3390)):
        assert set(item) == {'alias','username','password','address','port','certificate_sha256'}
        assert item['alias'] == alias and item['address'] == address and item['port'] == port
        assert re.fullmatch('portal[0-9a-f]+[ab]', item['username']) or re.fullmatch('[a-z][a-z0-9_-]{1,31}', item['username'])
        assert isinstance(item['password'], str) and 32 <= len(item['password']) <= 128
        assert re.fullmatch('[0-9a-f]{64}', item['certificate_sha256'])
    return value['targets']


def inside():
    signal.alarm(530)
    os.umask(0o077)
    sys.path.insert(0, ROOT)
    import runtime
    import lifecycle as life
    os.chown('/data', 2000, 2000)
    os.chmod('/data', 0o700)
    for name in ('db-password', 'portal-password'):
        runtime.write_private(Path('/secrets')/name, secrets.token_urlsafe(32))
    targets = json.loads(Path('/targets.json').read_bytes())['targets']
    for target, alias in zip(targets, ('desktop-a','desktop-b')):
        runtime.write_private(Path('/secrets')/(alias+'-password'), target['password'])
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


def code():
    counter = struct.pack('>Q', int(time.time())//30)
    digest = hmac.new(bytes(20), counter, hashlib.sha1).digest()
    offset = digest[-1] & 15
    return str((struct.unpack('>I', digest[offset:offset+4])[0] & 0x7fffffff) % 1000000).zfill(6)


async def wait_ready(base):
    import aiohttp
    async with aiohttp.ClientSession() as session:
        end = time.monotonic()+150
        while time.monotonic()<end:
            try:
                async with session.post(base+'api/tokens',data={},timeout=aiohttp.ClientTimeout(total=5)) as response:
                    if response.status == 403: break
            except (aiohttp.ClientError, asyncio.TimeoutError): pass
            await asyncio.sleep(.5)
        else: raise AssertionError('Portal readiness timeout')


async def acceptance(base, directory, checks, markers_only=False, target_order='alpha-beta'):
    await wait_ready(base)
    await browser(base,directory,checks,markers_only,target_order)


async def browser(base, directory, checks, markers_only=False, target_order='alpha-beta', raw_web=False, raw_profile=None):
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
                    transport_events = []
                    async def rpc(method, params=None):
                        nonlocal sequence
                        sequence += 1
                        await ws.send_json({'id':sequence,'method':method,'params':params or {}})
                        while True:
                            item = await ws.receive_json(timeout=40)
                            if raw_web and item.get('method')=='Network.webSocketHandshakeResponseReceived':
                                status=item.get('params',{}).get('response',{}).get('status')
                                if type(status) is int and 100<=status<=599 and len(transport_events)<16:
                                    transport_events.append({'status':status,'epoch':time.time()})
                            if item.get('id') == sequence:
                                assert 'error' not in item, 'CDP command failed'
                                return item.get('result',{})
                    async def js(expression, await_promise=False):
                        result = await rpc('Runtime.evaluate', {'expression':expression,'returnByValue':True,'awaitPromise':await_promise})
                        assert 'exceptionDetails' not in result, 'Browser expression failed'
                        return result.get('result',{}).get('value')
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
                    await rpc('Emulation.setDeviceMetricsOverride', {'width':1100,'height':800,'deviceScaleFactor':1,'mobile':False})
                    if raw_web:
                        await raw_web_probe(rpc,js,until,base,directory,checks,raw_profile,target_order,transport_events)
                        return
                    states = {}
                    observations = []
                    attempt_events = []
                    marker_failures = []
                    for index, (alias, ident, marker) in enumerate(target_sequence(target_order, markers_only)):
                        attempt_started = time.time()
                        attempt_events.append({'ordinal':index+1,'alias':alias,
                            'phase':'attempt_start','epoch':attempt_started})
                        (directory/'attempt-events.json').write_text(json.dumps(attempt_events,indent=2)+'\n')
                        await rpc('Page.navigate', {'url':base+'#/?wrdp-target='+alias})
                        if index == 0:
                            await until('!!document.querySelector("input[name=username]")')
                            await fill('input[name=username]', 'operator')
                            await submit()
                            await until('!!document.querySelector("input[name=guac-totp]")')
                            await fill('input[name=guac-totp]', code())
                            await submit()
                        encoded = base64.urlsafe_b64encode((ident+'\0c\0postgresql').encode()).decode().rstrip('=')
                        await until('location.hash.split("?")[0]==='+json.dumps('#/client/'+encoded))
                        getter = injector+'.get("guacClientManager").getManagedClients()['+json.dumps(encoded)+']'
                        if markers_only:
                            await until('!!('+getter+')')
                        else:
                            await until('(()=>{let c='+getter+';return c&&c.clientState.connectionState==="CONNECTED"})()')
                        expression = marker_pixels_expression(getter)
                        for poll in range(100):
                            pixels = await js(expression)
                            if pixels[marker]>5000 and pixels['nonblack']>10000: break
                            await asyncio.sleep(.25)
                        observation = marker_observation(alias, marker, pixels, poll + 1)
                        observation.update(attempt_started_epoch=attempt_started, observed_epoch=time.time())
                        observations.append(observation)
                        attempt_events.append({'ordinal':index+1,'alias':alias,'phase':'observation',
                            'epoch':observation['observed_epoch'],'status':pixels['status']})
                        (directory/'attempt-events.json').write_text(json.dumps(attempt_events,indent=2)+'\n')
                        (directory/'marker-observations.json').write_text(json.dumps({
                            'schema': 1, 'scope': 'synthetic states and pixel counts only',
                            'observations': observations}, indent=2)+'\n')
                        marker_ready = pixels[marker]>5000 and pixels['nonblack']>10000
                        if markers_only and (not marker_ready or pixels['status'] != 0
                                             or pixels['state'] != 'CONNECTED'):
                            marker_failures.append(alias)
                            states[alias] = pixels
                            checks.append(alias+'_diagnostic_marker_or_connection_not_ready')
                            continue
                        assert marker_ready, 'Distinct synthetic marker canvas missing'
                        assert pixels['status'] == 0, 'Native protocol status'
                        states[alias]=pixels
                        checks.append(alias+'_native_RDP_CONNECTED_status0_distinct_'+marker+'_canvas')
                    connected_stage(directory, states, markers_only)
                    if markers_only:
                        assert await js('Promise.resolve('+injector+'.get("authenticationService").logout()).then(()=>true)', True)
                        checks.append('diagnostic_own_browser_logout')
                        assert not marker_failures, 'Synthetic marker diagnostic failed; see numeric observations'
                        return
                    # Parent stops only beta after observing this durable stage.
                    end = time.monotonic()+100
                    while not (directory/'beta-stopped.json').exists() and time.monotonic()<end:
                        await asyncio.sleep(.5)
                    assert (directory/'beta-stopped.json').exists(), 'Independent beta-stop control absent'
                    alpha_id = base64.urlsafe_b64encode(b'1\0c\0postgresql').decode().rstrip('=')
                    beta_id = base64.urlsafe_b64encode(b'2\0c\0postgresql').decode().rstrip('=')
                    clients = injector+'.get("guacClientManager").getManagedClients()'
                    await until('(()=>{let c='+clients+'['+json.dumps(beta_id)+'];return c&&["DISCONNECTED","TUNNEL_ERROR","CLIENT_ERROR"].includes(c.clientState.connectionState)})()')
                    final_states = await js('Object.fromEntries(Object.entries('+clients+').map(([k,v])=>[k,{state:v.clientState.connectionState,status:v.clientState.statusCode}]))')
                    assert final_states[alpha_id]['state']=='CONNECTED', 'Alpha did not survive independent beta failure'
                    # Send an actual input event to alpha and observe its retained marker.
                    await js(clients+'['+json.dumps(alpha_id)+'].client.sendMouseState(new Guacamole.Mouse.State(20,20,false,false,false,false,false))')
                    await asyncio.sleep(1)
                    (directory/'failure-control.json').write_text(json.dumps(final_states,indent=2)+'\n')
                    checks.append('independent_beta_stop_disconnects_only_beta_alpha_CONNECTED')
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


async def fixture(image, directory, targets_path, expected, address, markers_only=False, target_order='alpha-beta', native_concurrent=False, match_browser_info=False, java_concurrent=False, java_classes=None, java_client_info=None, raw_web=False, raw_client_info=None, audit_handshake=False):
    target_sequence(target_order, markers_only)
    if audit_handshake and (not raw_web or not markers_only or native_concurrent or java_concurrent):
        raise ValueError('Handshake audit requires exclusive raw web diagnostic mode')
    if raw_web and (not markers_only or java_concurrent or native_concurrent):
        raise ValueError('Raw web mode requires exclusive diagnostic mode')
    if raw_web:
        if raw_client_info is None or raw_client_info.is_symlink() or raw_client_info.stat().st_size>8192:
            raise ValueError('Raw public profile required')
        raw_profile_bytes=raw_client_info.read_bytes()
        raw_profile=validated_client_info(json.loads(raw_profile_bytes))
    if java_concurrent and (not markers_only or native_concurrent):
        raise ValueError('Java mode requires exclusive diagnostic mode')
    if java_concurrent:
        if java_classes is None or java_client_info is None:
            raise ValueError('Java diagnostic inputs required')
        if java_client_info.is_symlink() or java_client_info.stat().st_size>8192:
            raise ValueError('Invalid public client profile file')
        java_profile_raw=java_client_info.read_bytes()
        java_profile=validated_client_info(json.loads(java_profile_raw))
    if native_concurrent and not markers_only:
        raise ValueError('Native concurrent mode requires diagnostic mode')
    if match_browser_info and not native_concurrent:
        raise ValueError('Client information matching requires native diagnostic mode')
    if not re.fullmatch('[0-9a-f]{64}', image):
        raise ValueError('Exact image SHA256 required')
    os.umask(0o077)
    targets = credentials(targets_path, expected, address)
    directory.mkdir(mode=0o700)
    token = secrets.token_hex(16)
    name = 'portal-rdp-fixture-'+token[:16]
    cid = None
    server = None
    children = set()
    tasks = set()
    rdp_servers = []
    namespace_child = None
    resource_task = None
    handshake_audit = None
    http_telemetry = HttpRelayTelemetry(directory)
    resource_samples = []
    checks = []
    receipt = {'image':image,'checks':checks,'passed':False,'cleanup_verified':False,
        'diagnostic_complete':False, 'target_order':target_order,
        'mode':'markers-only-diagnostic' if markers_only else 'full-acceptance',
        'scope':('synthetic marker comparison only; NOT independent beta failure or full RDP acceptance'
                 if markers_only else 'exact clean image, synthetic TLS RDP, two native desktop canvases and independent beta failure')
        ,'targets_sha256':expected}
    if native_concurrent:
        receipt['mode']='native-concurrent-diagnostic'
        receipt['scope']='two overlapping direct synthetic TLS protocol consumers; NOT browser acceptance'
    if java_concurrent:
        receipt['mode']='java-concurrent-diagnostic'
        receipt['scope']='actual Java library two-consumer diagnostic; NOT browser acceptance'
        receipt['client_info_sha256']=hashlib.sha256(java_profile_raw).hexdigest()
    if raw_web:
        receipt['mode']='raw-web-concurrent-diagnostic'
        receipt['scope']='real HTTP/TOTP/JDBC/portal and raw common-JS clients; NOT full acceptance'
        receipt['client_info_sha256']=hashlib.sha256(raw_profile_bytes).hexdigest()
    # The catalog is synthetic and root-owned inside its read-only file mount.
    config = directory/'config.json'
    value = json.loads((HERE/'examples/config.json').read_bytes())
    # Explicit synthetic chooser coverage, independent of private-safe examples.
    value['portal']['publish_target_labels'] = True
    for target, alias, port in zip(targets, ('desktop-a','desktop-b'), (33389,33390)):
        row = value['targets'][alias]
        row.update(hostname='127.0.0.1',port=port,username=target['username'],security='tls',
            certificate_fingerprint='sha256:'+':'.join(target['certificate_sha256'][i:i+2] for i in range(0,64,2)))
    config.write_text(json.dumps(value,indent=2)+'\n')
    config.chmod(0o644)
    subprocess.run(['sudo','-n','chown','root:root',str(config)],check=True,timeout=5)
    try:
        inspected = json.loads(podman('image','inspect',image).stdout)[0]
        assert inspected['Id'].removeprefix('sha256:') == image
        receipt['fixture_sha256'] = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
        receipt['config_sha256'] = hashlib.sha256(config.read_bytes()).hexdigest()
        library_mount = (['--mount','type=bind,src='+str((HERE/'tools/probe_login.py').resolve())+',dst=/probe-library.py,ro']
                         if native_concurrent else [])
        if java_concurrent:
            library_mount += ['--mount','type=bind,src='+str(java_classes.resolve())+',dst=/diagnostic-java,ro']
        command = ['run','-d','--name',name,'--label',LABEL+'='+token,'--pull=never',
            '--network=none','--read-only','--pids-limit=192','--memory=1200m','--cpus=2',
            '--cap-drop=all','--cap-add=CHOWN,DAC_OVERRIDE,FOWNER,SETGID,SETUID,KILL',
            '--tmpfs','/tmp:rw,nosuid,nodev,size=64m','--tmpfs','/data:rw,nosuid,nodev,size=256m',
            '--tmpfs','/run/web-rdp:rw,nosuid,nodev,size=128m','--tmpfs','/secrets:rw,nosuid,nodev,size=1m',
            '--mount','type=bind,src='+str(config.resolve())+',dst=/config/config.json,ro',
            '--mount','type=bind,src='+str(Path(__file__).resolve())+',dst=/fixture.py,ro',
            '--mount','type=bind,src='+str(targets_path.resolve())+',dst=/targets.json,ro',
            *library_mount, '-e','WEB_RDP_DURATION_SECONDS=510','-e','WEB_RDP_DEADLINE_EPOCH='+str(time.time()+510),
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
        async def validate():
            state = json.loads((await asyncio.to_thread(podman,'inspect',cid)).stdout)[0]
            assert state['Id']==cid and state['Image'].removeprefix('sha256:')==image
            assert state['Config']['Labels'][LABEL]==token and state['State']['Running']
            assert state['State']['Pid']==pid and await asyncio.to_thread(namespace_inode)==netns
        await validate()
        async def sample_resources():
            previous = None
            deadline = time.monotonic()+370
            while time.monotonic()<deadline and len(resource_samples)<190:
                try:
                    await validate()
                    sample = await asyncio.to_thread(host_resource_snapshot,
                        pid, cid, token, image, previous)
                    previous = sample
                    resource_samples.append(sample)
                except Exception as sample_error:
                    resource_samples.append({'epoch':time.time(),
                        'capture':'unavailable','error_class':type(sample_error).__name__})
                (directory/'resource-samples.json').write_text(json.dumps({
                    'schema':1,'scope':'exact owned cgroup counts and process classes only',
                    'samples':resource_samples},indent=2)+'\n')
                await asyncio.sleep(2)
        resource_task = asyncio.create_task(sample_resources())
        rdp_semaphore = asyncio.Semaphore(8)
        async def rdp_connection(reader, writer, target):
            task=asyncio.current_task(); tasks.add(task)
            remote=None
            try:
                async with rdp_semaphore:
                    await validate()
                    rr,remote=await asyncio.wait_for(asyncio.open_connection(address,target['port']),5)
                    async def forward(source,dest):
                        while data := await source.read(65536):
                            dest.write(data); await dest.drain()
                    done,pending=await asyncio.wait([asyncio.create_task(forward(reader,remote)),asyncio.create_task(forward(rr,writer))],timeout=120,return_when=asyncio.FIRST_COMPLETED)
                    for pending_task in pending: pending_task.cancel()
                    await asyncio.gather(*done,*pending,return_exceptions=True)
            except (Exception,asyncio.CancelledError): pass
            finally:
                if remote: remote.close()
                writer.close(); tasks.discard(task)
        for target in targets:
            socket_path=directory/(target['alias']+'.sock')
            rdp_servers.append(await asyncio.start_unix_server(lambda r,w,t=target: rdp_connection(r,w,t),path=str(socket_path)))
        await validate()
        namespace_child=await asyncio.create_subprocess_exec('sudo','-n','nsenter','-t',str(pid),'-n','/usr/bin/python3','-B',str(Path(__file__).resolve()),'--namespace-relay',str(directory.resolve()),stdout=asyncio.subprocess.DEVNULL,stderr=asyncio.subprocess.DEVNULL)
        await asyncio.sleep(.5)
        assert namespace_child.returncode is None, 'Namespace relay startup'
        semaphore = asyncio.Semaphore(8)
        relay = 'import socket,threading,sys\ntry:s=socket.create_connection(("127.0.0.1",8080),3)\nexcept OSError:sys.exit(2)\nsys.stderr.write("B");sys.stderr.flush()\ndef up():\n try:\n  while True:\n   b=sys.stdin.buffer.read1(65536)\n   if not b: break\n   s.sendall(b)\n except OSError: pass\n try:s.shutdown(socket.SHUT_WR)\n except OSError:pass\nthreading.Thread(target=up,daemon=True).start()\ntry:\n while True:\n  b=s.recv(65536)\n  if not b:break\n  sys.stdout.buffer.write(b);sys.stdout.buffer.flush()\nexcept OSError:pass'
        async def connection(reader, writer):
            task = asyncio.current_task(); tasks.add(task)
            observation = http_telemetry.accepted()
            child = None
            try:
                async with semaphore:
                    http_telemetry.acquired(observation)
                    state = json.loads((await asyncio.to_thread(podman,'inspect',cid)).stdout)[0]
                    assert state['Id']==cid and state['Image'].removeprefix('sha256:')==image
                    assert state['Config']['Labels'][LABEL]==token and state['State']['Running']
                    assert state['State']['Pid']==pid and await asyncio.to_thread(namespace_inode)==netns
                    child = await asyncio.create_subprocess_exec('sudo','-n','nsenter','-t',str(pid),'-n','/usr/bin/python3','-u','-c',relay,stdin=asyncio.subprocess.PIPE,stdout=asyncio.subprocess.PIPE,stderr=asyncio.subprocess.PIPE)
                    children.add(child)
                    http_telemetry.child_started(observation)
                    if await asyncio.wait_for(child.stderr.readexactly(1),5) != b'B':
                        raise ValueError('Relay backend did not connect')
                    http_telemetry.backend_connected(observation)
                    await http_relay_streams(reader,writer,child.stdout,child.stdin,
                                             http_telemetry,observation)
            except (Exception,asyncio.CancelledError):
                pass
            finally:
                http_telemetry.released(observation)
                if child:
                    if child.returncode is None: child.terminate()
                    await child.wait(); children.discard(child)
                http_telemetry.closed(observation)
                writer.close(); tasks.discard(task)
        for bind_port in range(10820,10840):
            try:
                server = await asyncio.start_server(connection,'127.0.0.1',bind_port)
                break
            except OSError:
                continue
        if server is None: raise RuntimeError('No private lab loopback port available')
        port = server.sockets[0].getsockname()[1]
        if native_concurrent or java_concurrent:
            await wait_ready(f'http://127.0.0.1:{port}/guacamole/')
            client_info=java_profile if java_concurrent else None
            if match_browser_info:
                client_info=await collect_browser_client_info(f'http://127.0.0.1:{port}/guacamole/')
                (directory/'client-info.json').write_text(json.dumps(client_info,indent=2)+'\n')
                receipt['client_info_sha256']=hashlib.sha256((directory/'client-info.json').read_bytes()).hexdigest()
            with (directory/'native.intent.json').open('x') as stream:
                json.dump({'image':image,'container_id':cid,'target_order':target_order,
                           'geometry':[1100,800,96],'at':time.time()},stream)
                stream.flush();os.fsync(stream.fileno())
            command=['exec']+(['-i'] if client_info is not None else [])+[cid,'python3','-B','/fixture.py',
                '--java-concurrent-inside' if java_concurrent else '--native-concurrent-inside','--target-order',target_order]
            if client_info is not None:command.append('--native-client-info-stdin')
            kwargs={'input':json.dumps(client_info)} if client_info is not None else {}
            result = await asyncio.to_thread(podman,*command,timeout=80,**kwargs)
            native = json.loads(result.stdout)
            (directory/'native-result.json').write_text(json.dumps(native,indent=2)+'\n')
            assert native['passed'] is False and native['diagnostic_complete'], 'Direct concurrent native diagnostic incomplete'
            checks.append('two_actual_Java_connections_with_first_reader_alive' if java_concurrent
                          else 'two_direct_native_connections_with_first_socket_alive')
        elif raw_web:
            await wait_ready(f'http://127.0.0.1:{port}/guacamole/')
            if audit_handshake:
                await validate()
                previous = next((sample for sample in reversed(resource_samples)
                                 if 'init_start_ticks' in sample), None)
                identity_sample = await asyncio.to_thread(host_resource_snapshot,
                    pid, cid, token, image, previous)
                handshake_audit = HandshakeAudit(directory)
                admission = {'cid': cid, 'image': image, 'token': token, 'pid': pid,
                    'start_ticks': identity_sample['init_start_ticks'], 'netns_inode': netns,
                    'config_path': '/proc/'+str(pid)+'/root/config/config.json',
                    'config_sha256': receipt['config_sha256'],
                    'targets_path': '/proc/'+str(pid)+'/root/targets.json',
                    'targets_sha256': expected, 'seconds': 180}
                await handshake_audit.start(admission)
                receipt['handshake_audit_armed'] = True
                receipt['handshake_catalog_sha256'] = hashlib.sha256((HERE/'catalog.py').read_bytes()).hexdigest()
            await asyncio.wait_for(browser(f'http://127.0.0.1:{port}/guacamole/',directory,checks,
                True,target_order,True,raw_profile),180)
            if handshake_audit:
                await handshake_audit.stop()
                receipt['handshake_audit_cleanup_verified'] = True
        else:
            await asyncio.wait_for(acceptance(f'http://127.0.0.1:{port}/guacamole/',directory,checks,markers_only,target_order),350)
        health = json.loads(podman('exec',cid,'python3','-B',ROOT+'/runtime.py','health').stdout)
        assert health == {'database_ready':True,'web_ready':True,'enrolled':True}
        receipt['health'] = health
        receipt['installed_integrity_sha256'] = podman('exec',cid,'sha256sum',ROOT+'/integrity.json').stdout.split()[0]
        checks.append('packaged_runtime_integrity_configuration_and_enrolled_health')
        finish_receipt(receipt, markers_only)
    except BaseException as error:
        receipt['failure_type'] = type(error).__name__
        # Assertion labels contain no request payloads or authentication values.
        if isinstance(error,AssertionError): receipt['failure'] = str(error)
        raise
    finally:
        if handshake_audit and not receipt.get('handshake_audit_cleanup_verified'):
            try:
                await handshake_audit.stop()
                receipt['handshake_audit_cleanup_verified'] = True
            except Exception as audit_error:
                receipt['handshake_audit_cleanup_verified'] = False
                receipt['handshake_audit_error_class'] = type(audit_error).__name__
                receipt['diagnostic_complete'] = False
            handshake_audit.save()
        if resource_task:
            resource_task.cancel()
            await asyncio.gather(resource_task,return_exceptions=True)
        if server: server.close(); await server.wait_closed()
        for rdp_server in rdp_servers: rdp_server.close(); await rdp_server.wait_closed()
        if namespace_child:
            if namespace_child.returncode is None: namespace_child.terminate()
            await namespace_child.wait()
        for task in list(tasks): task.cancel()
        if tasks: await asyncio.gather(*list(tasks),return_exceptions=True)
        found = podman('ps','-a','--filter','name=^'+name+'$','--format','{{.ID}}').stdout.strip()
        if found:
            owned = json.loads(podman('inspect',name).stdout)[0]
            assert owned['Config']['Labels'][LABEL]==token and owned['Image'].removeprefix('sha256:')==image and (not cid or owned['Id']==cid)
            try:
                previous = next((sample for sample in reversed(resource_samples)
                                 if 'init_start_ticks' in sample), None)
                final_sample = await asyncio.to_thread(host_resource_snapshot,
                    pid, owned['Id'], token, image, previous)
                final_sample['phase'] = 'before_cleanup'
                resource_samples.append(final_sample)
                (directory/'resource-samples.json').write_text(json.dumps({
                    'schema':1,'scope':'exact owned cgroup counts and process classes only',
                    'samples':resource_samples},indent=2)+'\n')
            except Exception as sample_error:
                receipt['resource_final_capture_error'] = type(sample_error).__name__
            # Read a bounded tail before removal but never persist raw output:
            # upstream messages can contain endpoints, usernames or requests.
            try:
                summary = podman('exec', owned['Id'], 'python3', '-B', '/fixture.py',
                                 '--phase-summary', timeout=10)
                phases = json.loads(summary.stdout)
            except Exception as capture_error:
                phases = {'schema': 1, 'capture': 'unavailable',
                          'error_class': type(capture_error).__name__}
            (directory/'phase-summary.json').write_text(json.dumps(phases, indent=2)+'\n')
            podman('stop','--time','5',owned['Id'],timeout=12)
            podman('rm',owned['Id'])
        assert not podman('ps','-a','--filter','name=^'+name+'$','--format','{{.ID}}').stdout.strip()
        receipt['cleanup_verified'] = True
        (directory/'receipt.json').write_text(json.dumps(receipt,indent=2)+'\n')
    print(json.dumps(receipt))


async def namespace_relay(directory):
    signal.alarm(480)
    semaphore=asyncio.Semaphore(8)
    async def connection(reader,writer,alias):
        peer=None
        async with semaphore:
            try:
                rr,peer=await asyncio.wait_for(asyncio.open_unix_connection(str(directory/(alias+'.sock'))),3)
                async def pipe(source,dest):
                    while data:=await source.read(65536):
                        dest.write(data); await dest.drain()
                done,pending=await asyncio.wait([asyncio.create_task(pipe(reader,peer)),asyncio.create_task(pipe(rr,writer))],timeout=120,return_when=asyncio.FIRST_COMPLETED)
                for task in pending: task.cancel()
                await asyncio.gather(*done,*pending,return_exceptions=True)
            except (Exception,asyncio.CancelledError): pass
            finally:
                if peer: peer.close()
                writer.close()
    servers=[]
    try:
        for alias,port in [('alpha',33389),('beta',33390)]:
            servers.append(await asyncio.start_server(lambda r,w,a=alias: connection(r,w,a),'127.0.0.1',port))
        await asyncio.sleep(450)
    finally:
        for server in servers: server.close(); await server.wait_closed()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--inside',action='store_true',help=argparse.SUPPRESS)
    parser.add_argument('--phase-summary',action='store_true',help=argparse.SUPPRESS)
    parser.add_argument('--native-concurrent-inside',action='store_true',help=argparse.SUPPRESS)
    parser.add_argument('--java-concurrent-inside',action='store_true',help=argparse.SUPPRESS)
    parser.add_argument('--java-concurrent',action='store_true',help='Actual Java socket diagnostic; requires --markers-only')
    parser.add_argument('--java-classes',type=Path)
    parser.add_argument('--java-client-info',type=Path)
    parser.add_argument('--raw-web',action='store_true',help='Raw common-JS web diagnostic; requires --markers-only')
    parser.add_argument('--raw-client-info',type=Path)
    parser.add_argument('--audit-handshake',action='store_true',help='Passive catalog/guacd boundary audit; requires raw web diagnostic')
    parser.add_argument('--native-client-info-stdin',action='store_true',help=argparse.SUPPRESS)
    parser.add_argument('--match-browser-client-info',action='store_true',
                        help='Read public login-page capabilities and match native diagnostic media')
    parser.add_argument('--native-concurrent',action='store_true',
                        help='Direct concurrent protocol diagnostic; requires --markers-only')
    parser.add_argument('--namespace-relay',type=Path,help=argparse.SUPPRESS)
    parser.add_argument('--targets',type=Path)
    parser.add_argument('--targets-sha256')
    parser.add_argument('--address')
    parser.add_argument('--markers-only', action='store_true',
                        help='Diagnostic marker comparison only; never full acceptance')
    parser.add_argument('--target-order', choices=('alpha-beta', 'beta-alpha'), default='alpha-beta',
                        help='Beta-first is available only with --markers-only')
    parser.add_argument('--image')
    parser.add_argument('--directory',type=Path)
    args = parser.parse_args()
    if args.java_concurrent_inside:
        assert os.geteuid()==0 and Path(__file__)==Path('/fixture.py')
        raw=sys.stdin.read(8193)
        if len(raw)>8192:raise ValueError('Client information input too large')
        print(json.dumps(java_concurrent_inside(args.target_order,validated_client_info(json.loads(raw))))); return
    if args.native_concurrent_inside:
        assert os.geteuid()==0 and Path(__file__)==Path('/fixture.py')
        raw=sys.stdin.read(8193) if args.native_client_info_stdin else None
        if raw is not None and len(raw)>8192:raise ValueError('Client information input too large')
        info=validated_client_info(json.loads(raw)) if raw is not None else None
        print(json.dumps(native_concurrent_inside(args.target_order,info))); return
    if args.phase_summary:
        assert os.geteuid()==0 and Path(__file__)==Path('/fixture.py')
        print(json.dumps(runtime_phase_summary())); return
    if args.namespace_relay:
        asyncio.run(namespace_relay(args.namespace_relay)); return
    if args.inside:
        assert os.geteuid()==0 and Path(__file__)==Path('/fixture.py')
        inside()
    else:
        if not args.image or not args.directory: parser.error('--image and --directory required')
        if args.target_order != 'alpha-beta' and not args.markers_only:
            parser.error('--target-order beta-alpha requires --markers-only')
        if args.native_concurrent and not args.markers_only:
            parser.error('--native-concurrent requires --markers-only')
        if args.match_browser_client_info and not args.native_concurrent:
            parser.error('--match-browser-client-info requires --native-concurrent')
        if args.java_concurrent and (not args.markers_only or args.native_concurrent):
            parser.error('--java-concurrent requires exclusive --markers-only mode')
        if args.raw_web and (not args.markers_only or args.native_concurrent or args.java_concurrent):
            parser.error('--raw-web requires exclusive --markers-only mode')
        if args.audit_handshake and (not args.raw_web or not args.markers_only or args.native_concurrent or args.java_concurrent):
            parser.error('--audit-handshake requires exclusive --raw-web --markers-only mode')
        import aiohttp  # Fail before any container or lab access if unavailable.
        asyncio.run(fixture(args.image,args.directory,args.targets,args.targets_sha256,args.address,args.markers_only,args.target_order,args.native_concurrent,args.match_browser_client_info,args.java_concurrent,args.java_classes,args.java_client_info,args.raw_web,args.raw_client_info,args.audit_handshake))


if __name__ == '__main__': main()
