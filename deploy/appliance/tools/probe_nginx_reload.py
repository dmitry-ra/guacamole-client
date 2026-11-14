#!/usr/bin/env python3
"""Measure reload visibility using an owned isolated loopback nginx only."""
import argparse
import json
import os
from pathlib import Path
import re
import signal
import socket
import subprocess
import time
import urllib.error
import urllib.request


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--directory', type=Path, required=True)
    p.add_argument('--port', type=int, default=10479)
    a = p.parse_args()
    if (not a.directory.is_absolute() or '..' in a.directory.parts
            or not re.fullmatch('/[A-Za-z0-9_./-]+', str(a.directory)) or not 10000 <= a.port <= 10999):
        raise ValueError('New absolute case and laboratory port required')
    os.umask(0o077)
    a.directory.mkdir(mode=0o700)
    # Refuse an occupied port; never signal or reuse its owner.
    with socket.socket() as s:
        s.bind(('127.0.0.1', a.port))
    config = a.directory / 'nginx.conf'
    def select(status):
        config.write_text('daemon off; master_process on; pid '+str(a.directory/'nginx.pid')+';\n'
            'error_log '+str(a.directory/'error.log')+' notice; events {}\n'
            'http { access_log off; server { listen 127.0.0.1:'+str(a.port)+'; '
            'location / { return '+str(status)+'; } } }\n')
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    def status():
        try:
            with opener.open(urllib.request.Request('http://127.0.0.1:'+str(a.port)+'/',
                    headers={'Connection':'close'}), timeout=1) as r:
                return r.status
        except urllib.error.HTTPError as e:
            return e.code
        except OSError:
            return 0
    select(200)
    proc = subprocess.Popen(['/usr/sbin/nginx','-p',str(a.directory),'-c',str(config)],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
    report = {'schema':1, 'production_untouched':True, 'observations':[], 'cleanup':False}
    try:
        end = time.monotonic()+5
        while status() != 200:
            if proc.poll() is not None or time.monotonic()>end:
                raise RuntimeError('Isolated nginx startup failed')
            time.sleep(.02)
        for expected in (503,200,503,200,503,200):
            select(expected)
            start = time.monotonic()
            proc.send_signal(signal.SIGHUP)
            values = []
            while True:
                observed = status()
                values.append({'milliseconds':round((time.monotonic()-start)*1000,3),'status':observed})
                if observed == expected:
                    break
                if time.monotonic()-start>5:
                    raise RuntimeError('Isolated reload visibility timeout')
                time.sleep(.005)
            report['observations'].append({'expected':expected,'values':values})
    finally:
        if proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                os.killpg(proc.pid,signal.SIGKILL)
                proc.wait(timeout=3)
        report['cleanup'] = proc.poll() is not None
        (a.directory/'result.json').write_text(json.dumps(report,sort_keys=True)+'\n')
    print(json.dumps(report,sort_keys=True))


if __name__ == '__main__':
    main()
