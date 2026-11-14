"""Reviewed process supervision primitives; no deployment bindings."""
import argparse
import base64
import hashlib
import json
import math
import os
from pathlib import Path
import re
import secrets
import shutil
import signal
import socket
import stat
import subprocess
import sys
import threading
import time
import urllib.request

ROOT=Path('/opt/homelab-web-rdp'); DATA=Path('/data'); RUN=Path('/run/web-rdp')
PG=Path('/usr/lib/postgresql/16/bin'); UIDS={'pg':2000,'java':2001,'guacd':2002}
PROCESSES={}; ACCESS_GROUPS=set(); STOP=False
DIAGNOSTICS=[]; DIAGNOSTIC_LIMIT=64*1024

def die(message):raise RuntimeError(message)

def sql(value):return "'"+str(value).replace("'","''")+"'"

def identity(user):
    uid=UIDS[user]
    # Built-in subprocess UID handling is safe while stderr drain threads run;
    # Python preexec_fn callbacks after fork are not safe in threaded processes.
    return {'user':uid,'group':uid,'extra_groups':[]}

def command(args,user=None,**kwargs):
    return subprocess.run(list(map(str,args)),check=True,timeout=kwargs.pop('timeout',20),**(identity(user) if user else {}),**kwargs)

def diagnostic_sink(component):
    if component not in ('pg','java','guacd'):die('Unknown diagnostic component')
    directory=RUN/'diagnostics'
    directory.mkdir(mode=0o700,parents=True,exist_ok=True)
    st=directory.lstat()
    if directory.is_symlink() or not directory.is_dir() or st.st_uid!=os.geteuid() or stat.S_IMODE(st.st_mode)!=0o700:
        die('Private diagnostics directory required')
    path=directory/(component+'.stderr.log')
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_APPEND|os.O_NOFOLLOW,0o600)
    st=os.fstat(fd)
    if not stat.S_ISREG(st.st_mode) or st.st_uid!=os.geteuid() or stat.S_IMODE(st.st_mode)!=0o600:
        os.close(fd);die('Private diagnostic file required')
    if st.st_size>DIAGNOSTIC_LIMIT:os.ftruncate(fd,DIAGNOSTIC_LIMIT)
    return fd,min(st.st_size,DIAGNOSTIC_LIMIT)

def drain_diagnostics(pipe,fd,retained):
    """Continuously drain, retaining a bounded prefix; never mirror to output.

    Even after the cap or a full-tmpfs write error, keep reading and discarding
    so child stderr cannot deadlock startup or shutdown.
    """
    writable=True
    try:
        while True:
            try:block=os.read(pipe.fileno(),8192)
            except OSError:break
            if not block:break
            keep=block[:max(0,DIAGNOSTIC_LIMIT-retained)]
            if keep and writable:
                try:
                    while keep:
                        count=os.write(fd,keep)
                        if count<=0:raise OSError('Diagnostic write made no progress')
                        retained+=count;keep=keep[count:]
                except OSError:writable=False
    finally:
        pipe.close();os.close(fd)

def start_process(component,args,user,**kwargs):
    if component in ('java','guacd'):
        kwargs['start_new_session']=True
    fd,retained=diagnostic_sink(component)
    try:
        proc=subprocess.Popen(list(map(str,args)),stdout=subprocess.DEVNULL,
                              stderr=subprocess.PIPE,**identity(user),**kwargs)
    except BaseException:
        os.close(fd);raise
    if component in ('java','guacd'):
        ACCESS_GROUPS.add(proc.pid)
    thread=threading.Thread(target=drain_diagnostics,args=(proc.stderr,fd,retained),
                            name='rdp-'+component+'-stderr',daemon=True)
    try:thread.start()
    except BaseException:
        if component in ('java','guacd'):
            stop_access_groups([proc.pid],timeout=1)
        else:proc.kill()
        proc.wait(timeout=1);proc.stderr.close();os.close(fd);raise
    DIAGNOSTICS.append(thread)
    return proc

def secret(name):
    p=Path('/secrets')/name
    if p.is_symlink() or not p.is_file() or p.stat().st_mode&0o077:die('Secret missing or permissions unsafe: '+name)
    value=p.read_text().rstrip('\n')
    if not 16<=len(value)<=512 or any(c in value for c in '\r\n\x00'):die('Invalid secret size or encoding')
    return value

def mkdir(path,uid,mode=0o700):
    path.mkdir(parents=True,exist_ok=True);os.chown(path,uid,uid);os.chmod(path,mode)

def runtime_dirs():
    RUN.mkdir(mode=0o755,exist_ok=True)
    for name,uid in UIDS.items():mkdir(RUN/name,uid)

def pg_sql(query,app=False,capture=True):
    env=dict(os.environ)
    if app:
        env['PGPASSWORD']=secret('db-password');args=['psql','-h','127.0.0.1','-U','guacamole','-d','guacamole']
    else:args=['psql','-h',str(RUN/'pg'),'-U','webpg','-d','guacamole']
    return command(args+['-X','-v','ON_ERROR_STOP=1','-At'],user='pg' if not app else None,input=query,text=True,capture_output=capture,env=env).stdout if capture else None

def start_pg(preparing=False):
    runtime_dirs();pgdata=DATA/'pgdata'
    if pgdata.is_symlink() or not pgdata.is_dir() or (pgdata/'PG_VERSION').read_text().strip()!='16':die('Prepared PostgreSQL16 cluster required')
    PROCESSES['pg']=start_process('pg',[str(PG/'postgres'),'-D',str(pgdata),'-c','listen_addresses=127.0.0.1','-c','port=5432','-c','unix_socket_directories='+str(RUN/'pg'),'-c','logging_collector=off','-c','log_statement=none','-c','log_min_error_statement=panic','-c','log_connections=off','-c','shared_buffers=64MB','-c','max_connections=20','-c','max_wal_size=256MB'],'pg')
    deadline=time.monotonic()+30
    while time.monotonic()<deadline:
        if PROCESSES['pg'].poll() is not None:die('PostgreSQL failed during startup')
        check=subprocess.run([str(PG/'pg_isready'),'-h',str(RUN/'pg'),'-U','webpg'],capture_output=True,timeout=3)
        if check.returncode==0:return
        time.sleep(.1)
    die('PostgreSQL readiness timeout')

def stopped(signum=None,frame=None):
    global STOP;STOP=True

def access_groups_alive(groups):
    """Return live members, including forked RDP handlers, of our access groups.

    Zombies cannot retain sockets. A successful kill(2) only queues SIGKILL;
    acknowledgement must wait for the actual live process groups to disappear.
    """
    alive=[]
    for item in Path('/proc').iterdir():
        if not item.name.isdigit():continue
        try:
            fields=(item/'stat').read_text().rsplit(')',1)[1].split()
            if int(fields[2]) in groups and fields[0] not in ('Z','X'):
                alive.append(int(item.name))
        except FileNotFoundError:pass
        except ProcessLookupError:pass
    return alive

def stop_access_groups(groups,timeout=.25):
    if any(type(pid) is not int or pid<=1 or pid==os.getpgrp() for pid in groups):
        die('Invalid access process group identity')
    for pid in groups:
        try:os.killpg(pid,signal.SIGKILL)
        except ProcessLookupError:pass
    deadline=time.monotonic()+timeout
    while access_groups_alive(set(groups)):
        if time.monotonic()>=deadline:
            die('Access process groups did not terminate within cutoff budget')
        time.sleep(.005)

def shutdown():
    # Keep the PGID recorded at creation even if the leader has exited.
    # Do not infer ownership from arbitrary PIDs or the current process table.
    failure=None
    try:stop_access_groups(ACCESS_GROUPS,timeout=2)
    except RuntimeError as exc:failure=exc
    for key in ('java','guacd'):
        proc=PROCESSES.get(key)
        if proc:
            try:proc.wait(timeout=1)
            except subprocess.TimeoutExpired:pass
    if not failure:ACCESS_GROUPS.clear()
    proc=PROCESSES.get('pg')
    if proc and proc.poll() is None:
        try:command([PG/'pg_ctl','-D',DATA/'pgdata','stop','-m','fast','-t','10'],user='pg',timeout=11,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        except Exception:
            proc.kill()
        try:proc.wait(timeout=2)
        except subprocess.TimeoutExpired:proc.kill()
    for thread in DIAGNOSTICS:thread.join(timeout=.1)
    DIAGNOSTICS[:]=[thread for thread in DIAGNOSTICS if thread.is_alive()]
    if failure:raise failure
