#!/usr/bin/env python3
"""Isolated already-MIXED PG16 physical backup/restore and native browser gate."""
import argparse
import asyncio
import hashlib
import json
import os
from pathlib import Path
import secrets
import signal
import stat
import subprocess
import sys
import time

HERE = Path(__file__).resolve().parent
ROOT = '/opt/homelab-web-rdp'


def require(value, reason):
    if not value: raise RuntimeError(reason)


def digest(raw): return hashlib.sha256(raw).hexdigest()


def inside(mode):
    require(Path(__file__) == Path('/restore-fixture.py') and os.geteuid() == 0
        and Path('/run/.containerenv').is_file() and os.environ.get('PORTAL_SSH_FIXTURE'),
        'Owned isolated fixture container required')
    signal.alarm(120)
    sys.path.insert(0, ROOT)
    import runtime
    import lifecycle as life
    import current_migration
    runtime.integrity()
    registry, config_sha = runtime.configuration()
    error = None
    try:
        if mode == 'prepare':
            runtime.prepare(registry, config_sha)
            life.pg_sql("INSERT INTO guacamole_user_attribute SELECT user_id,'guac-totp-key-secret','AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' FROM guacamole_user; INSERT INTO guacamole_user_attribute SELECT user_id,'guac-totp-key-confirmed','true' FROM guacamole_user;")
        else:
            life.start_pg()
        mapping = runtime.check_cluster(registry, config_sha)
        require(mapping == {'desktop-a':1,'desktop-b':2,'terminal-c':3}, 'Mixed connection identities differ')
        require(runtime.enrolled(registry) and runtime.database_health(registry,mapping), 'Enrolled mixed census required')
        census = json.loads(life.pg_sql(runtime.snapshot_query(),app=True))
        runtime.validate_snapshot(registry,mapping,census)
        identity = json.loads(life.pg_sql(current_migration.IDENTITY_QUERY,app=True))
        proof = dict(schema=1,config_sha256=config_sha,connections=mapping,enrolled=True,
            identity_sha256=digest(json.dumps(identity,sort_keys=True).encode()),
            census_sha256=digest(json.dumps(census,sort_keys=True).encode()),
            prepared_sha256=digest(runtime.DATA.joinpath('prepared.json').read_bytes()))
    except BaseException as caught: error = caught
    try: life.shutdown()
    except BaseException as caught:
        if error is None: error = caught
        else: error.add_note('Owned PG shutdown failed: '+type(caught).__name__)
    if error is not None: raise error
    require(not (runtime.DATA/'pgdata/postmaster.pid').exists(), 'Actual PG shutdown unconfirmed')
    if mode == 'prepare':
        print(json.dumps(proof,sort_keys=True))
        return
    runtime.write_private(Path('/run/restored-proof.json'),json.dumps(proof,sort_keys=True))
    signal.alarm(0)
    os.execv('/usr/bin/python3',['python3','-B',ROOT+'/runtime.py','serve'])


def validate_proof(value):
    require(isinstance(value,dict) and set(value) == {'schema','config_sha256','connections','enrolled',
        'identity_sha256','census_sha256','prepared_sha256'} and type(value['schema']) is int and value['schema']==1
        and value['enrolled'] is True and value['connections']=={'desktop-a':1,'desktop-b':2,'terminal-c':3}
        and all(type(v) is int for v in value['connections'].values()),
        'Exact mixed identity/census proof required')
    import re
    require(all(isinstance(value[k],str) and re.fullmatch('[a-f0-9]{64}',value[k]) for k in
        ('config_sha256','identity_sha256','census_sha256','prepared_sha256')), 'Only exact mixed proof hashes allowed')
    return dict(value)


def application_images(image, source_image=None):
    """Bind producer and restored roles to explicit immutable local images."""
    import test_ssh
    restored = test_ssh.exact_image(image)
    producer = restored if source_image is None else test_ssh.exact_image(source_image)
    return {'producer': producer, 'restored': restored}


async def fixture(args):
    import aiohttp
    import cold_copy
    import host
    import prepare_instance as files
    import terminal_launcher
    import test_mixed_image as mixed
    import test_ssh
    selected_images = application_images(args.image, args.source_image)
    image, endpoint_image = selected_images['restored'], test_ssh.exact_image(args.endpoint_image)
    case = files.literal(args.directory)
    require(os.geteuid()==0 and not os.path.lexists(case), 'Root and new private fixture case required')
    require(not any(cold_copy.overlaps(case,path) for path in (host.PERSIST,host.ROOT,host.CONFIG.parent)),
            'Fixture must not overlap production DATA/secrets/code/configuration')
    mixed.browser_identity(args.browser_uid)
    refusal = mixed.refusal_proof(args.native_receipt,image,args.native_receipt_sha256)
    files.new_directory(case)
    token = secrets.token_hex(16)
    paths = [Path(__file__),HERE/'test_mixed_image.py',HERE/'test_ssh.py',HERE/'ssh_fixture.py',
             HERE/'terminal_launcher.py',Path(cold_copy.__file__),Path(files.__file__)]
    sources = {p.name:digest(p.read_bytes()) for p in paths}
    result = dict(schema=1,image=image,source_image=selected_images['producer'],
        application_images=selected_images,endpoint_image=endpoint_image,run_id=token,passed=False,cleanup_verified=False,
        scope='isolated already-MIXED stopped physical copy primitives and restored native browser; no production backup CLI or RDP endpoint acceptance',
        sources=sources,native_refusal_sha256=refusal,phase='start')
    files.json_new(case/'intent.json',result)
    containers=[];server=None;tasks=set();children=set();app=None;app_stopped=False
    source,backup,restored=(case/name for name in ('source-data','backup-data','restored-data'))
    secret_dir=case/'synthetic-secrets';files.new_directory(secret_dir)
    config=case/'config.json'
    def state(item):
        info=json.loads(test_ssh.engine('inspect',item['cid']).stdout)[0]
        require(test_ssh.owned(info,cid=item['cid'],image=item['image'],token=token,name=item['name']), 'Owned fixture binding changed')
        require(info['HostConfig']['NetworkMode']==item['network'], 'Owned fixture network mode changed')
        return info
    def start(role, selected, network_mode, command, extra=()):
        item=dict(name='portal-mixed-restore-'+token+'-'+role,cid=None,image=selected,network=network_mode)
        containers.append(item)
        raw=test_ssh.engine('run','-d','--pull=never','--name',item['name'],'--label',test_ssh.LABEL+'='+token,
            '--env','PORTAL_SSH_FIXTURE='+token,'--network',network_mode,'--cpus=2','--memory=1400m','--pids-limit=256',
            '--tmpfs','/tmp:rw,nosuid,nodev,mode=1777,size=64m',*extra,selected,*command).stdout.decode().strip()
        require(len(raw)==64 and all(c in '0123456789abcdef' for c in raw), 'Full owned fixture CID required')
        item['cid']=raw;state(item)
        return item
    def application(role,data,network_mode,mode):
        require(role in selected_images, 'Unknown application image role')
        return start(role,selected_images[role],network_mode,['-B','/restore-fixture.py','--inside',mode],[
            '--entrypoint=python3','--read-only','--tmpfs','/run:rw,nosuid,nodev,size=160m',
            '--volume',str(data)+':/data:rw','--volume',str(secret_dir)+':/secrets:ro',
            '--volume',str(config)+':/config/config.json:ro','--volume',str(Path(__file__).resolve())+':/restore-fixture.py:ro',
            '--env','WEB_RDP_DURATION_SECONDS=300','--env','WEB_RDP_DEADLINE_EPOCH='+str(time.time()+300)])
    try:
        for selected in dict.fromkeys(selected_images.values()):
            observed = json.loads(test_ssh.engine('image','inspect',selected).stdout)[0]
            require(test_ssh.exact_image(observed['Id']) == selected, 'Application image changed')
        endpoint_info=json.loads(test_ssh.engine('image','inspect',endpoint_image).stdout)[0]
        require(test_ssh.exact_image(endpoint_info['Id'])==endpoint_image
            and endpoint_info.get('Labels',{}).get('guacamole.ssh-fixture.source-sha256')==digest((HERE/'ssh-endpoint.Containerfile').read_bytes()),
            'Exact source-bound endpoint image required')
        endpoint=start('endpoint',endpoint_image,'none',['400'],['--entrypoint=sleep','--tmpfs','/run:rw,nosuid,nodev,size=32m'])
        launcher=terminal_launcher.render(launcher='/run/fixture/launcher',socket='/run/fixture/home/portal.sock',
            config='/run/fixture/tmux.conf',home='/run/fixture/home',username='fixture')
        test_ssh.inner(endpoint['cid'],{'mode':'initialize','launcher':launcher})
        test_ssh.engine('exec','-i',endpoint['cid'],'python3','-c',
            'from pathlib import Path;import sys;p=Path("/run/fixture/control.py");p.write_text(sys.stdin.read());p.chmod(0o644)',data=mixed.CONTROL.encode())
        keys=test_ssh.inner(endpoint['cid'],{'mode':'export'})
        config.write_bytes(mixed.catalog_bytes(keys['host-key']));config.chmod(0o600)
        result['config_sha256']=digest(config.read_bytes())
        for name in ('db-password','portal-password','desktop-a-password','desktop-b-password'):
            files.write_new(secret_dir/name,secrets.token_urlsafe(32).encode())
        files.write_new(secret_dir/'terminal-c-key',keys['private-key'].encode());keys.clear()
        source.mkdir(mode=0o700);os.chown(source,2000,2000)
        result['phase']='mixed_producer'
        producer=application('producer',source,'none','prepare')
        code=test_ssh.engine('wait',producer['cid'],timeout=120).stdout.strip()
        observed=state(producer)
        require(code==b'0' and observed['State']['Running'] is False and observed['State']['Pid']==0,
                'Actual mixed producer must stop successfully')
        output=test_ssh.engine('logs',producer['cid']).stdout
        require(len(output)<=32768, 'Mixed producer proof exceeds bound')
        before=validate_proof(json.loads(output));require(before['config_sha256']==result['config_sha256'],'Producer config differs')
        test_ssh.cleanup_owned(producer,token);containers.remove(producer)
        require(not (source/'pgdata/postmaster.pid').exists(),'Producer PG is not cleanly stopped')
        cold_copy.stopped_and_exclusive(source);cold_copy.validate_cluster(source,require_receipt=True)
        frozen=cold_copy.manifest(source);files.json_new(case/'source-manifest.json',frozen)
        result['phase']='physical_backup'
        cold_copy.copy_tree(source,backup);cold_copy.stopped_and_exclusive(source);cold_copy.stopped_and_exclusive(backup)
        require(cold_copy.manifest(source)==frozen==cold_copy.manifest(backup),'Actual physical backup differs')
        files.json_new(case/'backup-manifest.json',cold_copy.manifest(backup))
        result['phase']='normal_mixed_restore'
        cold_copy.copy_tree(backup,restored)
        for data in (source,backup,restored):
            cold_copy.stopped_and_exclusive(data);cold_copy.validate_cluster(data,require_receipt=True)
            require(cold_copy.manifest(data)==frozen,'Complete pre-start mixed restore manifest differs')
        files.json_new(case/'restored-manifest.json',cold_copy.manifest(restored))
        identities={name:{'device':path.stat().st_dev,'inode':path.stat().st_ino}
            for name,path in [('source',source),('backup',backup),('restored',restored)]}
        require(len({(v['device'],v['inode']) for v in identities.values()})==3,'Three independent physical DATA identities required')
        require(all(not cold_copy.overlaps(a,b) for a,b in ((source,backup),(source,restored),(backup,restored))), 'Distinct DATA namespaces required')
        result.update(data_identities=identities,before_backup=before,manifest_sha256=digest((case/'source-manifest.json').read_bytes()),
            normal_current_prepared_preserved=True,secrets_scope='separate generated synthetic files; excluded from physical DATA copies')
        app=application('restored',restored,'container:'+endpoint['cid'],'serve')
        result['containers']={'restored':app['cid'],'endpoint':endpoint['cid']}
        result['phase']='restored_startup'
        await restored_browser(app,endpoint,state,case,result,tasks,children,args,before)
        state(app)
        test_ssh.engine('stop','--time=30',app['cid'],timeout=35)
        stopped=state(app)
        require(stopped['State']['Running'] is False and stopped['State']['Pid']==0
            and not (restored/'pgdata/postmaster.pid').exists(),'Restored PG clean shutdown required')
        test_ssh.cleanup_owned(app,token);containers.remove(app);app_stopped=True
        for data in (source,backup,restored):cold_copy.stopped_and_exclusive(data)
        require(cold_copy.manifest(source)==frozen==cold_copy.manifest(backup),'Original source or backup changed after restored browser')
        require(sources=={p.name:digest(p.read_bytes()) for p in paths},'Fixture sources changed')
        result.update(passed=True,phase='complete',source_backup_unchanged=True,restored_clean_shutdown=True)
    except BaseException as error:result['failure_type']=type(error).__name__
    finally:
        for task in list(tasks):task.cancel()
        if tasks:await asyncio.gather(*list(tasks),return_exceptions=True)
        errors=[]
        if app and not app_stopped:
            try:
                state(app);test_ssh.engine('stop','--time=30',app['cid'],timeout=35)
            except Exception as error:errors.append(type(error).__name__)
        for item in reversed(containers):
            try:test_ssh.cleanup_owned(item,token)
            except Exception as error:errors.append(type(error).__name__)
        result['cleanup_verified']=not errors
        if errors:result['cleanup_error_types']=errors
        files.json_new(case/'result.json',result)
    print(json.dumps(result,sort_keys=True))
    return 0 if result['passed'] and result['cleanup_verified'] else 1


async def restored_browser(app,endpoint,state,case,result,tasks,children,args,before):
    """Reuse the accepted browser and guarded namespace relay, not product code."""
    import aiohttp
    import test_mixed_image as mixed
    import test_ssh
    initial=state(app);pid=initial['State']['Pid'];endpoint_state=state(endpoint)
    netns=os.stat('/proc/'+str(pid)+'/ns/net').st_ino
    require(netns!=os.stat('/proc/self/ns/net').st_ino
        and netns==os.stat('/proc/'+str(endpoint_state['State']['Pid'])+'/ns/net').st_ino,'Exact isolated shared endpoint namespace required')
    semaphore=asyncio.Semaphore(8)
    relay='import socket,threading,sys;s=socket.create_connection(("127.0.0.1",8080),3)\ndef up():\n try:\n  while True:\n   b=sys.stdin.buffer.read1(65536)\n   if not b:break\n   s.sendall(b)\n except OSError:pass\n try:s.shutdown(socket.SHUT_WR)\n except OSError:pass\nthreading.Thread(target=up,daemon=True).start()\ntry:\n while True:\n  b=s.recv(65536)\n  if not b:break\n  sys.stdout.buffer.write(b);sys.stdout.buffer.flush()\nexcept OSError:pass'
    async def connection(reader,writer):
        task=asyncio.current_task();tasks.add(task);child=None
        try:
            async with semaphore:
                current=await asyncio.to_thread(state,app)
                require(current['State']['Running'] and current['State']['Pid']==pid
                    and os.stat('/proc/'+str(pid)+'/ns/net').st_ino==netns,'Owned restored namespace changed')
                child=await asyncio.create_subprocess_exec('nsenter','-t',str(pid),'-n','/usr/bin/python3','-u','-c',relay,
                    stdin=asyncio.subprocess.PIPE,stdout=asyncio.subprocess.PIPE,stderr=asyncio.subprocess.DEVNULL)
                children.add(child)
                async def pipe(source,destination):
                    try:
                        while data:=await source.read(65536):destination.write(data);await destination.drain()
                    finally:
                        try:destination.write_eof()
                        except (OSError,AttributeError):pass
                await asyncio.wait_for(asyncio.gather(pipe(reader,child.stdin),pipe(child.stdout,writer)),180)
        except (Exception,asyncio.CancelledError):pass
        finally:
            if child:
                if child.returncode is None:child.terminate()
                await child.wait();children.discard(child)
            writer.close();tasks.discard(task)
    server=None
    try:
        for port in range(10860,10880):
            try:server=await asyncio.start_server(connection,'127.0.0.1',port);break
            except OSError:continue
        require(server is not None,'Private lab port unavailable')
        base='http://127.0.0.1:'+str(port)+'/guacamole/'
        async with aiohttp.ClientSession() as session:
            deadline=time.monotonic()+150
            while time.monotonic()<deadline:
                try:
                    async with session.post(base+'api/tokens',data={},timeout=aiohttp.ClientTimeout(total=5)) as response:
                        if response.status==403:
                            value=await response.json();require(value['expected'][1]['options']==['desktop-a','desktop-b','terminal-c'],'Restored native selector differs');break
                except (aiohttp.ClientError,asyncio.TimeoutError):pass
                await asyncio.sleep(.5)
            else:raise RuntimeError('Restored runtime startup timed out')
        after=validate_proof(json.loads(test_ssh.engine('exec',app['cid'],'cat','/run/restored-proof.json').stdout))
        require(after==before,'Full account/TOTP identity, census or preparation changed across normal restore')
        result['after_restore_before_auth']=after
        async def metadata():
            sentinel=(await asyncio.to_thread(test_ssh.inner,endpoint['cid'],{'mode':'metadata'}))['sentinel']
            raw=await asyncio.to_thread(test_ssh.engine,'exec',endpoint['cid'],'python3','-c',
                'from pathlib import Path;p=Path("/run/fixture/home/mixed-state.json");print(p.read_text() if p.exists() else "null")')
            value=json.loads(raw.stdout)
            return None if value is None else mixed.safe_metadata({'sentinel':sentinel,'process':value})
        browser_result={'phase':'restored_browser','scope':'restored complete-image mixed native browser'}
        result['browser']=browser_result
        await mixed.browser(base,browser_result,metadata,args.browser_uid)
        health=json.loads(test_ssh.engine('exec',app['cid'],'python3','-B',ROOT+'/runtime.py','health').stdout)
        require(health=={'database_ready':True,'web_ready':True,'enrolled':True},'Restored post-browser health failed')
        result['health']=health
    finally:
        if server:server.close();await server.wait_closed()


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--inside',choices=('prepare','serve'),help=argparse.SUPPRESS)
    parser.add_argument('--image');parser.add_argument('--endpoint-image')
    parser.add_argument('--source-image',help='Exact producer image SHA256; default is --image')
    parser.add_argument('--directory',type=Path);parser.add_argument('--browser-uid',type=int)
    parser.add_argument('--native-receipt',type=Path);parser.add_argument('--native-receipt-sha256')
    args=parser.parse_args()
    if args.inside:inside(args.inside);return 0
    require(all((args.image,args.endpoint_image,args.directory,args.browser_uid,args.native_receipt,args.native_receipt_sha256)),
            'Explicit isolated images/new case/browser UID/native refusal evidence required')
    def expired(*unused):raise TimeoutError('Whole isolated fixture deadline')
    signal.signal(signal.SIGALRM,expired);signal.alarm(360)
    return asyncio.run(asyncio.wait_for(fixture(args),340))


if __name__=='__main__':raise SystemExit(main())
