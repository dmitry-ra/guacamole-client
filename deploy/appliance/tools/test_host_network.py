#!/usr/bin/env python3
"""Finite owned-container test of the actual installed bridge and HTTP mapping."""
import argparse
import json
import os
from pathlib import Path
import secrets
import sys
import time
import urllib.request

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import host
import network_service

LABEL = 'guacamole.portal.network-probe'
SERVER = '''import socket,signal
signal.alarm(25)
s=socket.socket();s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
s.bind(('0.0.0.0',8080));s.listen(8)
print('PROBE_LISTENING',flush=True)
while True:
 c,_=s.accept();c.settimeout(2)
 try:
  c.recv(4096);c.sendall(b'HTTP/1.1 200 OK\\r\\nContent-Length: 20\\r\\nConnection: close\\r\\n\\r\\nportal-network-probe')
 except OSError:pass
 finally:c.close()
'''


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image', required=True)
    parser.add_argument('--directory', type=Path, required=True)
    parser.add_argument('--port', type=int, required=True)
    parser.add_argument('--discriminate-route-localnet', action='store_true')
    args = parser.parse_args()
    if os.geteuid() != 0 or not 10000 <= args.port <= 10999:
        raise ValueError('Root and lab loopback port required')
    image = host.image_id(args.image)
    os.umask(0o077)
    name, cfg, _, binding = network_service.selection()
    network_service.policy_command('check')
    network_service.empty(name, cfg)
    host.directory(args.directory.parent)
    args.directory.mkdir(mode=0o700)
    run_id = secrets.token_hex(16)
    case = {'image': image, 'run_id': run_id, 'binding': binding,
            'passed': False, 'cleanup_verified': False}
    host.write(args.directory/'intent.json', case)
    cid = None
    try:
        result = host.engine('run', '--detach', '--pull=never', '--read-only',
            '--memory=128m', '--memory-swap=128m', '--cpus=1', '--pids-limit=32',
            '--cap-drop=all', '--security-opt=no-new-privileges',
            '--security-opt=apparmor=guacamole-portal', '--label='+LABEL+'='+run_id,
            '--network='+name, '--ip='+cfg.source_ipv4,
            '--publish=127.0.0.1:%d:8080' % args.port,
            '--entrypoint=python3', image, '-u', '-c', SERVER, timeout=15)
        cid = host.identifier(result.stdout.decode().strip())
        case['container_id'] = cid
        host.write(args.directory/'created.json', case)
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        def request(address, port):
            try:
                with opener.open('http://%s:%d/' % (address, port), timeout=1) as response:
                    return response.status == 200 and response.read(100) == b'portal-network-probe'
            except OSError:
                return False
        if args.discriminate_route_localnet:
            for _ in range(12):
                if request(cfg.source_ipv4, 8080):
                    case['direct_http_before'] = True; break
                time.sleep(.3)
            setting = Path('/proc/sys/net/ipv4/conf')/cfg.bridge/'route_localnet'
            case['route_localnet_before'] = setting.read_text().strip()
            case['published_http_before'] = request('127.0.0.1', args.port)
            network_service.policy_command('check')
            if (case.get('direct_http_before') is not True
                    or case['route_localnet_before'] != '0' or case['published_http_before']):
                raise RuntimeError('Discriminating baseline differs; refuse sysctl change')
            host.write(args.directory/'sysctl-intent.json', case)
            setting.write_text('1\n')
            case['route_localnet_after'] = setting.read_text().strip()
            case['http_reply'] = request('127.0.0.1', args.port)
            case['only_change'] = 'owned bridge route_localnet 0 to 1'
        else:
            for _ in range(12):
                if request('127.0.0.1', args.port):
                    case['http_reply'] = True; break
                time.sleep(.3)
        network_service.policy_command('check')
        if not case.get('http_reply'):
            raise RuntimeError('Actual published HTTP reply failed')
        case['passed'] = True
    except BaseException as error:
        case['error_type'] = type(error).__name__
        raise
    finally:
        if cid:
            value = host.one(host.engine('inspect', cid).stdout)
            if (value.get('Id') != cid or host.inspected_image(value.get('Image')) != image
                    or value.get('Config', {}).get('Labels', {}).get(LABEL) != run_id):
                raise RuntimeError('Foreign probe; refuse stop')
            case['state_before_cleanup'] = {key: value.get('State', {}).get(key)
                for key in ('Running', 'Status', 'ExitCode', 'Error')}
            log = host.engine('logs', cid, check=False)
            with (args.directory/'container.log').open('xb') as output:
                output.write(log.stdout[:32768] + log.stderr[:32768])
            host.engine('stop', '--time=3', cid, timeout=7)
            host.engine('rm', cid)
            case['cleanup_verified'] = host.engine('container', 'exists', cid, check=False).returncode == 1
        host.write(args.directory/'receipt.json', case)
    print(json.dumps(case))


if __name__ == '__main__':
    main()
