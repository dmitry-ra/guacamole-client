#!/usr/bin/env python3
"""Real additive firewall transaction/rollback in owned isolated kernel namespaces."""
import argparse
import base64
import contextlib
import hashlib
import io
import json
import os
from pathlib import Path
import selectors
import signal
import socket
import subprocess
import sys
import threading
import time

import test_network_namespace as base
import upgrade_network as upgrade
import network_upgrade as contract
import network
import prepare_instance as files

HERE = Path(__file__).resolve().parents[1]
SELF = Path(__file__).resolve()
BASE_SCRIPT = '/src/tools/test_network_namespace.py'
SSH_PORT = 10475


def ssh_listener():
    """Synthetic TCP/UDP listeners, not SSH authentication or tmux acceptance."""
    base.require_inner()
    signal.alarm(145)
    selector = selectors.DefaultSelector()
    for family, kind, address in ((socket.AF_INET, socket.SOCK_STREAM, '192.0.2.1'),
                                  (socket.AF_INET, socket.SOCK_DGRAM, '192.0.2.1'),
                                  (socket.AF_INET6, socket.SOCK_STREAM, '2001:db8:1::1')):
        server = socket.socket(family, kind)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        if family == socket.AF_INET6:
            server.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
        server.bind((address, SSH_PORT))
        if kind == socket.SOCK_STREAM:
            server.listen(16)
        selector.register(server, selectors.EVENT_READ, kind)
    print('ready', flush=True)
    while True:
        for key, unused in selector.select(1):
            if key.data == socket.SOCK_DGRAM:
                unused, peer = key.fileobj.recvfrom(4096)
                key.fileobj.sendto(json.dumps({'peer': peer[0]}).encode(), peer)
            else:
                connection, peer = key.fileobj.accept()
                def respond(connection=connection, peer=peer):
                    try:
                        with connection:
                            for sequence in range(3):
                                connection.sendall((json.dumps({'peer': peer[0], 'sequence': sequence})+'\n').encode())
                                time.sleep(.03)
                    except OSError:
                        pass
                threading.Thread(target=respond, daemon=True).start()


def policies():
    old_network = {'schema_version': 1, 'bridge': 'portalb0', 'subnet_ipv4': '192.0.2.0/29',
        'source_ipv4': '192.0.2.2', 'gateway_ipv4': '192.0.2.1', 'forward_interface': 'uplink0',
        'snat_ipv4': '198.51.100.1', 'host_backend_port': 8080,
        'local_endpoints': [{'hostname': '192.0.2.1', 'port': 10222}]}
    target = {'protocol': 'rdp', 'hostname': '198.51.100.7', 'port': 3389, 'username': 'synthetic',
              'certificate_fingerprint': 'sha256:'+':'.join(['00']*32), 'password_file': 'desktop-password'}
    old_catalog = {'schema_version': 1, 'portal': {'username': 'synthetic'}, 'targets': {
        'desktop': target, 'second': {**target, 'hostname': '198.51.100.8', 'port': 3390,
                                     'password_file': 'second-password'},
        'gateway': {**target, 'hostname': '192.0.2.1', 'port': 10222, 'password_file': 'gateway-password'}}}
    public = b'\0\0\0\x0bssh-ed25519\0\0\0\x20'+bytes(range(32))
    new_catalog = json.loads(json.dumps(old_catalog))
    new_catalog['schema_version'] = 2
    new_catalog['targets']['terminal'] = {'protocol': 'ssh', 'hostname': '192.0.2.1', 'port': SSH_PORT,
        'username': 'synthetic-terminal', 'host_key': '[192.0.2.1]:'+str(SSH_PORT)+' ssh-ed25519 '+base64.b64encode(public).decode(),
        'private_key_file': 'terminal-key', 'command': '/usr/local/libexec/portal-tmux'}
    new_network = {**old_network, 'local_endpoints': old_network['local_endpoints']+
                   [{'hostname': '192.0.2.1', 'port': SSH_PORT}]}
    return contract.extension(old_network, new_network, old_catalog, new_catalog)


def suite(proof):
    signal.signal(signal.SIGALRM, base.deadline)
    signal.alarm(145)
    processes, checks = [], []
    python = '/usr/bin/python3'

    def start(args):
        process = subprocess.Popen(list(map(str, args)), stdin=subprocess.PIPE,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        processes.append(process)
        selector = selectors.DefaultSelector()
        selector.register(process.stdout, selectors.EVENT_READ)
        if not selector.select(5):
            raise RuntimeError('Owned fixture child readiness timeout')
        line = process.stdout.readline().strip()
        selector.close()
        if not line:
            raise RuntimeError('Owned fixture child failed before readiness')
        return process, line

    def within(pid, *args):
        return ['/usr/bin/nsenter', '--net=/proc/'+str(pid)+'/ns/net', *map(str, args)]

    def ip(*args):
        base.run(['/usr/sbin/ip', *args])

    def peer_ip(pid, *args):
        base.run(within(pid, '/usr/sbin/ip', *args))

    def peer():
        process, line = start(['/usr/bin/unshare', '--net', python, '-B', '-S', BASE_SCRIPT, '--hold'])
        inode = int(line)
        if inode in (proof['host_net'], proof['fixture_net']) or base.namespace('mnt', process.pid) != proof['fixture_mount']:
            raise RuntimeError('Peer namespace proof failed')
        return process.pid, inode

    def attempt(pid, address, port, expected, label, protocol='tcp', source=None, snat=None):
        args = [python, '-B', '-S', BASE_SCRIPT, '--probe', '--host', address, '--port', str(port), '--protocol', protocol]
        if port in (8080, 10474):
            args += ['--http']
        if source:
            args += ['--source', source]
        result = json.loads(base.run(within(pid, *args) if pid else args).stdout)
        if result.get('connected') is not expected:
            raise AssertionError(label+': synthetic packet outcome differed')
        if snat and any(item['peer'] != snat for item in result['responses']):
            raise AssertionError(label+': synthetic SNAT source differed')
        checks.append({'check': label, 'result': result})

    def old_connections(phase):
        attempt(source_pid, '198.51.100.7', 3389, True, phase+'_first_rdp_tcp_snat', snat='198.51.100.1')
        attempt(source_pid, '198.51.100.8', 3390, True, phase+'_second_rdp_tcp_snat', snat='198.51.100.1')
        attempt(source_pid, '192.0.2.1', 10222, True, phase+'_old_gateway_rdp_tcp')
        attempt(None, '192.0.2.2', 8080, True, phase+'_direct_backend_http_reply')
        attempt(None, '127.0.0.1', 10474, True, phase+'_loopback_published_backend_http_reply')

    def unrelated():
        return base.run(['/usr/sbin/nft', '-j', 'list', 'table', 'inet', 'fixture_unrelated']).stdout

    try:
        source_pid, source_ns = peer()
        target_pid, target_ns = peer()
        other_pid, other_ns = peer()
        proof.update(source_net=source_ns, target_net=target_ns, untrusted_net=other_ns)
        if len({source_ns, target_ns, other_ns}) != 3:
            raise RuntimeError('Peer namespace collision')
        ip('link', 'set', 'lo', 'up')
        ip('link', 'add', 'portalb0', 'type', 'bridge')
        ip('address', 'add', '192.0.2.1/29', 'dev', 'portalb0')
        ip('-6', 'address', 'add', '2001:db8:1::1/64', 'dev', 'portalb0', 'nodad')
        ip('link', 'set', 'portalb0', 'up')
        for local, remote, pid in (('brpeer0', 'src0', source_pid), ('uplink0', 'dst0', target_pid),
                                   ('untrusted0', 'other0', other_pid)):
            ip('link', 'add', local, 'type', 'veth', 'peer', 'name', remote)
            ip('link', 'set', remote, 'netns', str(pid))
            ip('link', 'set', local, 'up')
            peer_ip(pid, 'link', 'set', 'lo', 'up')
            peer_ip(pid, 'link', 'set', remote, 'up')
        ip('link', 'set', 'brpeer0', 'master', 'portalb0')
        ip('address', 'add', '198.51.100.1/24', 'dev', 'uplink0')
        ip('address', 'add', '203.0.113.1/30', 'dev', 'untrusted0')
        peer_ip(other_pid, 'address', 'add', '203.0.113.2/30', 'dev', 'other0')
        peer_ip(other_pid, 'route', 'add', 'default', 'via', '203.0.113.1')
        for address in ('192.0.2.2/29', '192.0.2.3/29'):
            peer_ip(source_pid, 'address', 'add', address, 'dev', 'src0')
        peer_ip(source_pid, '-6', 'address', 'add', '2001:db8:1::2/64', 'dev', 'src0', 'nodad')
        peer_ip(source_pid, 'route', 'add', 'default', 'via', '192.0.2.1')
        peer_ip(source_pid, '-6', 'route', 'add', 'default', 'via', '2001:db8:1::1')
        for address in ('198.51.100.7/24', '198.51.100.8/24'):
            peer_ip(target_pid, 'address', 'add', address, 'dev', 'dst0')
        peer_ip(target_pid, 'route', 'add', 'default', 'via', '198.51.100.1')
        def mac(pid, device):
            args = ['/usr/sbin/ip', '-j', 'link', 'show', 'dev', device]
            return json.loads(base.run(within(pid, *args) if pid else args).stdout)[0]['address']
        # IPv6 denial has a proven reachable listener and stable ND, so a failed
        # probe cannot be attributed to absent neighbors or listener startup.
        for pid, address, peer_mac in ((None, '2001:db8:1::2', mac(source_pid, 'src0')),
                                      (source_pid, '2001:db8:1::1', mac(None, 'portalb0'))):
            args = ['-6', 'neigh', 'replace', address, 'lladdr', peer_mac, 'nud', 'permanent',
                    'dev', 'portalb0' if pid is None else 'src0']
            peer_ip(pid, *args) if pid else ip(*args)
        Path('/proc/sys/net/ipv4/ip_forward').write_text('1\n')
        Path('/proc/sys/net/ipv4/conf/portalb0/route_localnet').write_text('1\n')
        for pid in (None, source_pid, target_pid):
            args = [python, '-B', '-S', BASE_SCRIPT, '--listen']
            start(within(pid, *args) if pid else args)
        ssh, unused = start([python, '-B', '-S', '/src/tools/test_network_upgrade_namespace.py', '--ssh-listen'])
        for pid, address, protocol, source, name in (
                (source_pid, '192.0.2.1', 'tcp', None, 'baseline_app_ssh_tcp'),
                (source_pid, '192.0.2.1', 'tcp', '192.0.2.3', 'baseline_foreign_bridge_ssh_tcp'),
                (None, '192.0.2.1', 'tcp', None, 'baseline_router_loopback_ssh_tcp'),
                (other_pid, '192.0.2.1', 'tcp', None, 'baseline_other_interface_ssh_tcp'),
                (source_pid, '192.0.2.1', 'udp', None, 'baseline_app_ssh_port_udp'),
                (source_pid, '2001:db8:1::1', 'tcp', None, 'baseline_app_ssh_port_ipv6')):
            attempt(pid, address, SSH_PORT, True, name, protocol, source)
        ssh.terminate(); ssh.wait(timeout=2)
        p, q = policies()
        upgrade.no_added_listeners(p, q)
        # All following nft/iptables operations are real kernel commands within
        # the freshly proved private router namespace, never mocks or host dumps.
        base.run(['/usr/sbin/nft', '-f', '-'], input='''table inet fixture_unrelated {
 chain keep { type filter hook output priority 100; policy accept;
  ip daddr 198.18.0.1 tcp dport 9 drop;
 }
}
''')
        for binary in ('iptables-nft', 'ip6tables-nft'):
            base.run(['/usr/sbin/'+binary, '-A', 'INPUT', '-m', 'comment', '--comment', 'fixture-unrelated', '-j', 'ACCEPT'])
            base.run(['/usr/sbin/'+binary, '-A', 'FORWARD', '-j', 'REJECT'])
        base.run(['/usr/sbin/iptables-nft', '-t', 'nat', '-A', 'OUTPUT', '-d', '127.0.0.1/32', '-p', 'tcp',
                  '--dport', '10474', '-j', 'DNAT', '--to-destination', '192.0.2.2:8080'])
        base.run(['/usr/sbin/iptables-nft', '-t', 'nat', '-A', 'POSTROUTING', '-s', '127.0.0.1/32', '-d', '192.0.2.2/32',
                  '-p', 'tcp', '--dport', '8080', '-j', 'SNAT', '--to-source', '192.0.2.1'])
        unrelated_before = unrelated()
        network.apply(p)
        old_guard, before = network.guard_hash(), upgrade.chains(p)
        old_connections('old_policy')
        attempt(None, '192.0.2.1', 10222, False, 'old_gateway_denies_router_loopback')
        # A valid delete/recreate followed by a semantic error must commit none
        # of the batch. This checks kernel transaction atomicity, not only -c.
        failed = network.run(['nft', '-f', '-'], check=False,
            input=upgrade.guard_transaction(q)+'add rule inet fixture_missing absent accept\n')
        if failed.returncode == 0 or network.guard_hash() != old_guard or upgrade.chains(p) != before:
            raise AssertionError('Invalid nft transaction changed old kernel policy')
        checks.append({'check': 'real_invalid_nft_batch_preserves_old_guard_and_chains', 'returncode': failed.returncode})
        old_connections('after_rejected_atomic_batch')
        network.run(['nft', '-c', '-f', '-'], input=upgrade.guard_transaction(q))
        if network.guard_hash() != old_guard:
            raise AssertionError('nft syntax-only check mutated guard')
        network.run(['nft', '-f', '-'], input=upgrade.guard_transaction(q))
        new_guard = network.guard_hash()
        if not new_guard or new_guard == old_guard:
            raise AssertionError('Real additive nft guard did not replace owned table')
        commands = upgrade.insertion_commands(p, q)
        expected = upgrade.states(before, commands)
        for index, args in enumerate(commands):
            if upgrade.chains(p) != expected[index]:
                raise AssertionError('Unexpected live chain prefix before insertion')
            network.run(args)
            if upgrade.chains(p) != expected[index+1]:
                raise AssertionError('Actual exact insertion differs from derived state')
        network.verify_host(q); network.verify(q, new_guard)
        if unrelated() != unrelated_before:
            raise AssertionError('Unrelated nft table changed during additive upgrade')
        checks.append({'check': 'real_guard_and_exact_insertions_preserve_unrelated_rules', 'commands': commands})
        ssh, unused = start([python, '-B', '-S', '/src/tools/test_network_upgrade_namespace.py', '--ssh-listen'])
        old_connections('upgraded_policy')
        attempt(source_pid, '192.0.2.1', SSH_PORT, True, 'added_ssh_gateway_allows_only_app_tuple')
        for pid, address, port, protocol, source, name in (
                (None, '192.0.2.1', SSH_PORT, 'tcp', None, 'deny_router_loopback_added_ssh'),
                (other_pid, '192.0.2.1', SSH_PORT, 'tcp', None, 'deny_other_interface_added_ssh'),
                (source_pid, '192.0.2.1', SSH_PORT, 'tcp', '192.0.2.3', 'deny_foreign_bridge_source_added_ssh'),
                (source_pid, '192.0.2.1', SSH_PORT, 'udp', None, 'deny_app_udp_added_ssh_port'),
                (source_pid, '2001:db8:1::1', SSH_PORT, 'tcp', None, 'deny_app_ipv6_added_ssh_port'),
                (source_pid, '192.0.2.1', 10223, 'tcp', None, 'deny_app_unconfigured_gateway_port'),
                (source_pid, '198.51.100.7', 3391, 'tcp', None, 'deny_app_unconfigured_forward_port'),
                (source_pid, '198.51.100.7', 3389, 'udp', None, 'deny_app_udp_rdp_port')):
            attempt(pid, address, port, False, name, protocol, source)
        attempt(other_pid, '192.0.2.1', 10223, True, 'unrelated_gateway_listener_preserved')
        # The real wrapper refuses rollback while its newly protected listener
        # remains live. Verify the same kernel listener census before removing it.
        try:
            upgrade.no_added_listeners(p, q)
        except ValueError:
            pass
        else:
            raise AssertionError('Rollback listener precondition failed open')
        if network.guard_hash() != new_guard or upgrade.chains(p) != expected[-1]:
            raise AssertionError('Listener refusal mutated kernel state')
        checks.append({'check': 'real_listener_census_refuses_rollback_without_kernel_mutation'})
        ssh.terminate(); ssh.wait(timeout=2)
        upgrade.no_added_listeners(p, q)
        for index in range(len(commands)-1, -1, -1):
            if upgrade.chains(p) != expected[index+1]:
                raise AssertionError('Unexpected state before exact inverse deletion')
            args = commands[index][:]
            args[5] = '-D'
            del args[7]
            network.run(args)
            if upgrade.chains(p) != expected[index]:
                raise AssertionError('Rollback changed unrelated or original rules')
        network.run(['nft', '-c', '-f', '-'], input=upgrade.guard_transaction(p))
        network.run(['nft', '-f', '-'], input=upgrade.guard_transaction(p))
        network.verify_host(p); network.verify(p, old_guard)
        if upgrade.chains(p) != before or unrelated() != unrelated_before:
            raise AssertionError('Rollback did not restore exact old rules/unrelated table')
        old_connections('rolled_back_policy')
        attempt(None, '192.0.2.1', 10222, False, 'rollback_old_gateway_denies_router_loopback')
        checks.append({'check': 'real_reverse_spec_deletion_and_atomic_old_guard_restore'})
        return {'passed': True, 'namespaces': proof, 'checks': checks,
                'old_guard_sha256': old_guard, 'new_guard_sha256': new_guard,
                'scope': 'real isolated kernel transactions and packets; no systemd/Podman boot or SSH authentication',
                'versions': {name: base.run(['/usr/sbin/'+name, '--version']).stdout.strip()
                             for name in ('nft', 'iptables-nft', 'ip6tables-nft')}}
    finally:
        for process in reversed(processes):
            if process.poll() is None:
                process.terminate()
        for process in reversed(processes):
            try:
                process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                process.kill(); process.wait(timeout=2)
        signal.alarm(0)


def source_hashes():
    paths = [SELF, Path(base.__file__), Path(upgrade.__file__), Path(contract.__file__), Path(network.__file__),
             Path(files.__file__), HERE/'host.py', HERE/'catalog.py', HERE/'network_service.py']
    return {str(path.resolve()): hashlib.sha256(path.read_bytes()).hexdigest() for path in paths}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--directory', type=Path)
    parser.add_argument('--isolate', action='store_true', help=argparse.SUPPRESS)
    parser.add_argument('--host-net', type=int, help=argparse.SUPPRESS)
    parser.add_argument('--host-mount', type=int, help=argparse.SUPPRESS)
    parser.add_argument('--ssh-listen', action='store_true', help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.ssh_listen:
        ssh_listener()
    elif args.isolate:
        base.suite = suite
        print(json.dumps(base.isolate(args)))
    elif args.directory:
        files.protected_directory(args.directory.parent)
        before = source_hashes()
        # Reuse the exact existing namespace/root/proc/group/deadline wrapper;
        # only the child script and its confined suite differ.
        base.SELF = SELF
        with contextlib.redirect_stdout(io.StringIO()):
            base.fixture(args.directory)
        unchanged = source_hashes() == before
        raw = (args.directory/'receipt.json').read_bytes()
        files.json_new(args.directory/'upgrade-sources.json', {'schema': 1, 'sources': before,
            'receipt_sha256': hashlib.sha256(raw).hexdigest(), 'sources_unchanged': unchanged})
        if not unchanged:
            raise RuntimeError('Upgrade fixture dependencies changed during execution')
        print(json.dumps({'passed': True, 'kernel_receipt': str(args.directory/'receipt.json'),
                          'source_receipt': str(args.directory/'upgrade-sources.json')}))
    else:
        parser.error('--directory is required')


if __name__ == '__main__':
    main()
