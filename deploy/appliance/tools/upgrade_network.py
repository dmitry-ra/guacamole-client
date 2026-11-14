#!/usr/bin/env python3
"""Reviewed one-time additive gateway SSH firewall upgrade; no activation."""
import argparse
import contextlib
import fcntl
import json
import os
from pathlib import Path
import signal
import stat
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import catalog
import host
import network
import network_service as bootstrap
import network_upgrade as contract
import prepare_instance as files

UNIT = 'guacamole-portal.service'
TRANSPORT = 'portal-rdp-transport.service'
INPUTS = ('old-network.json', 'new-network.json', 'old-catalog.json', 'new-catalog.json')
PLAN_KEYS = {'schema', 'operation', 'files', 'snapshot', 'sources', 'commands', 'prepared_at'}


def inactive(unit):
    raw = host.command(['/usr/bin/systemctl', 'show', unit,
        '--property=LoadState,ActiveState,MainPID'], timeout=5).stdout.decode('ascii')
    if dict(line.split('=', 1) for line in raw.splitlines()) != {
            'LoadState': 'loaded', 'ActiveState': 'inactive', 'MainPID': '0'}:
        raise ValueError('Portal and transport must already be inactive')


def sources():
    return {str(path): contract.sha(network.protected_read(path, 256 * 1024)) for path in
        (Path(__file__).resolve(), Path(files.__file__).resolve(), Path(catalog.__file__).resolve(),
         Path(host.__file__).resolve(), Path(network.__file__).resolve(),
         Path(bootstrap.__file__).resolve(), Path(contract.__file__).resolve())}


@contextlib.contextmanager
def locked():
    """Use the existing host/bootstrap/firewall lock order; never create locks."""
    with contextlib.ExitStack() as stack:
        for path in (host.STATE/'lock', bootstrap.STATE/'lock', network.STATE/'lock'):
            files.protected_directory(path.parent, private=True)
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
            stream = stack.enter_context(os.fdopen(fd))
            info = os.fstat(fd)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_nlink != 1
                    or stat.S_IMODE(info.st_mode) != 0o600):
                raise ValueError('Exact existing private lock required')
            fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
        yield


def environment(name, cfg, selected, original):
    inactive(UNIT); inactive(TRANSPORT)
    if os.path.lexists(host.PUBLIC/'ready'):
        raise ValueError('Portal readiness must already be absent')
    if bootstrap.engine('ps', '--all', '--no-trunc', '--filter=label='+host.LABEL+'=1',
                        '--format={{.ID}}').stdout.strip():
        raise ValueError('No appliance containers may remain')
    bootstrap.inspect_network(name, cfg, selected, original)
    if not bootstrap.inspect_bridge(cfg, selected, original):
        raise ValueError('Exact empty owned bridge must already exist')
    bootstrap.empty(name, cfg)


def no_added_listeners(p, q):
    """Wildcard/IPv6 listeners also block rollback, regardless of bind address."""
    ports = {port for _, port in q['config']['local_endpoints']} - {
        port for _, port in p['config']['local_endpoints']}
    raw = host.command(['/usr/bin/ss', '-H', '-ltn'], timeout=5).stdout.decode('ascii')
    for line in raw.splitlines():
        columns = line.split()
        if len(columns) < 5:
            raise ValueError('Malformed TCP listener census')
        try:
            port = int(columns[3].rsplit(':', 1)[1])
        except (ValueError, IndexError):
            raise ValueError('Unresolved TCP listener census') from None
        if port in ports:
            raise ValueError('Added TCP listener must be absent before guard rollback')


def chains(p):
    keys = {(binary, table, chain) for binary, table, chain, _ in p['rules']}
    keys.update(network.shared_groups(p))
    return [{'binary': binary, 'table': table, 'chain': chain,
             'lines': [network.normalize(line) for line in network.chain_lines(binary, table, chain)]}
            for binary, table, chain in sorted(keys)]


def insertion_commands(p, q):
    """Insert only new exact rules; do not flush/rebuild even owned chains."""
    commands = []
    old = {(b, t, c): rules for b, t, c, rules in p['rules']}
    for b, t, c, rules in q['rules']:
        previous = old[(b, t, c)]
        retained = [rule for rule in rules if rule in previous]
        if retained != previous:
            raise ValueError('Every existing chain rule must remain in order')
        for index, rule in enumerate(rules, 1):
            if rule not in previous:
                commands.append(network.command(b, t, '-I', c, str(index), *rule))
    before = network.shared_groups(p)
    for (b, t, c), rules in network.shared_groups(q).items():
        previous = before[(b, t, c)]
        if [rule for rule in rules if rule in previous] != previous:
            raise ValueError('Every existing shared jump must remain in order')
        for index, rule in enumerate(rules, 1):
            if rule not in previous:
                commands.append(network.command(b, t, '-I', c, str(index), *rule[2:]))
    return commands


def states(snapshot, commands):
    value = json.loads(json.dumps(snapshot))
    result = [json.loads(json.dumps(value))]
    for args in commands:
        b, _, _, _, t, _, c, index, *spec = args
        row = next(row for row in value if (row['binary'], row['table'], row['chain']) == (b, t, c))
        # -N declaration occupies row0 only for an owned chain.
        offset = 1 if row['lines'] and row['lines'][0][0] in ('-N', '-P') else 0
        row['lines'].insert(int(index)-1+offset, network.normalize(['-A', c, *spec]))
        result.append(json.loads(json.dumps(value)))
    return result


def guard_transaction(p):
    return 'delete table inet ' + network.NFT_TABLE + '\n' + network.guard_text(p)


def read_case(directory, reviewed_sha):
    files.protected_directory(directory, private=True)
    raw = files.private_bytes(directory/'plan.json', 256*1024)
    if contract.sha(raw) != contract.hash_value(reviewed_sha):
        raise ValueError('Exact independently reviewed network plan required')
    plan = contract.load(raw)
    if (not isinstance(plan, dict) or set(plan) != PLAN_KEYS or type(plan['schema']) is not int
            or plan['schema'] != 1 or plan['operation'] != 'add-local-ssh'
            or plan['sources'] != sources() or set(plan['files']) != set(INPUTS) | {
                'old-bootstrap.json', 'old-firewall.json'}):
        raise ValueError('Exact prepared network plan and current sources required')
    archived = {}
    for name, checksum in plan['files'].items():
        archived[name] = files.private_bytes(directory/name, 128*1024)
        if contract.sha(archived[name]) != contract.hash_value(checksum):
            raise ValueError('Prepared original/candidate archive changed')
    p, q = contract.extension(*(contract.load(archived[name]) for name in INPUTS))
    if plan['commands'] != insertion_commands(p, q):
        raise ValueError('Prepared command derivation changed')
    original = contract.load(archived['old-bootstrap.json'])
    old_binding = contract.binding(original['binding'], archived['old-catalog.json'], archived['old-network.json'], p)
    new_binding = {**old_binding, 'config_sha256': contract.sha(archived['new-catalog.json']),
        'network_sha256': contract.sha(archived['new-network.json']), 'policy_hash': network.digest(q)}
    if ({'definition_binding', 'upgrade_proof'} & set(original)
            or original.get('phase') != 'ready' or original.get('schema') != 1
            or original.get('network_id') != plan['snapshot']['network_id']
            or original.get('boot_id') != plan['snapshot']['bootstrap_boot_id']):
        raise ValueError('One original unupgraded owned ready bootstrap required')
    return plan, archived, p, q, old_binding, new_binding, original


def prepare(directory, old_network, new_network, old_catalog, new_catalog):
    archived = {name: network.protected_read(path) for name, path in zip(INPUTS,
        (old_network, new_network, old_catalog, new_catalog))}
    p, q = contract.extension(*(contract.load(archived[name]) for name in INPUTS))
    name, cfg, selected_policy, selected = bootstrap.selection()
    if (selected_policy != p or network.protected_read(host.CONFIG) != archived['old-catalog.json']
            or network.protected_read(host.NETWORK) != archived['old-network.json']):
        raise ValueError('Installed selection must be the exact original inputs')
    original = bootstrap.saved()
    if (not original or original.get('phase') != 'ready' or original.get('binding') != selected
            or {'definition_binding', 'upgrade_proof'} & set(original)):
        raise ValueError('One unupgraded ready bootstrap required')
    environment(name, cfg, selected, original)
    network.check(p)
    previous = network.saved_state()
    if previous.get('boot_id') != network.boot_id() or previous.get('policy_hash') != network.digest(p):
        raise ValueError('Exact current-boot ready firewall required')
    no_added_listeners(p, q)
    archived['old-bootstrap.json'] = files.private_bytes(bootstrap.RECEIPT, 128*1024)
    archived['old-firewall.json'] = files.private_bytes(network.STATE/'state.json', 128*1024)
    if contract.load(archived['old-bootstrap.json']) != original or contract.load(archived['old-firewall.json']) != previous:
        raise ValueError('Original receipts changed during inspection')
    commands = insertion_commands(p, q)
    snapshot = {'boot_id': network.boot_id(), 'bootstrap_boot_id': original['boot_id'],
        'network_id': original['network_id'], 'chains': chains(p),
        'release_sha256': contract.sha(network.protected_read(host.RELEASE))}
    network.run(['nft', '-c', '-f', '-'], input=guard_transaction(q))
    files.new_directory(directory)
    files.json_new(directory/'prepare-intent.json', {'schema': 1, 'operation': 'add-local-ssh'})
    for filename, raw in archived.items():
        files.write_new(directory/filename, raw)
    files.json_new(directory/'plan.json', {'schema': 1, 'operation': 'add-local-ssh',
        'files': {key: contract.sha(value) for key, value in archived.items()},
        'snapshot': snapshot, 'sources': sources(), 'commands': commands, 'prepared_at': time.time()})


def approval(raw, reviewed_sha):
    return contract.review(contract.load(raw), reviewed_sha, time.time())


def checkpoint(plan, original, selected, p, review_raw, reviewed_sha):
    approval(review_raw, reviewed_sha)
    if (network.boot_id() != plan['snapshot']['boot_id']
            or contract.sha(network.protected_read(host.RELEASE)) != plan['snapshot']['release_sha256']
            or sources() != plan['sources']):
        raise ValueError('Boot, release or reviewed source changed')
    cfg = network.parse_config({**p['config'], 'schema_version': 1,
        'local_endpoints': [{'hostname': h, 'port': port} for h, port in p['config']['local_endpoints']]})
    environment(selected['podman_network'], cfg, selected, original)
    return cfg


def terminal(directory, name, phase, error=None, **extra):
    value = dict(schema=1, phase=phase, finished_at=time.time(), **extra)
    if error is not None:
        value['error_type'] = type(error).__name__
    files.json_new(directory/name, value)


def checked_replace(path, raw, check, tag):
    """Restore archived receipt bytes through a private durable replacement."""
    files.private_bytes(path, 128*1024)
    if tag not in {'apply-intent', 'apply-ready', 'bootstrap-ready', 'rollback-firewall', 'rollback-bootstrap'}:
        raise ValueError('Fixed receipt replacement phase required')
    temporary = path.with_name(path.name+'.upgrade-'+tag)
    check()
    files.write_new(temporary, raw)
    check()
    os.replace(temporary, path)
    files.fsync_directory(path.parent)


def apply(directory, reviewed_sha, review_path):
    plan, archived, p, q, before, after, original = read_case(directory, reviewed_sha)
    if any(os.path.lexists(directory/name) for name in ('apply-intent.json', 'result.json', 'upgrade-proof.json', 'rollback-intent.json')):
        raise ValueError('Attempted network upgrade is never replayed')
    raw_review = files.private_bytes(review_path, 16384)
    checkpoint(plan, original, before, p, raw_review, reviewed_sha)
    no_added_listeners(p, q)
    if (files.private_bytes(bootstrap.RECEIPT, 128*1024) != archived['old-bootstrap.json']
            or files.private_bytes(network.STATE/'state.json', 128*1024) != archived['old-firewall.json']
            or chains(p) != plan['snapshot']['chains']):
        raise ValueError('Original network state changed')
    network.check(p)
    network.run(['nft', '-c', '-f', '-'], input=guard_transaction(q))
    expected = states(plan['snapshot']['chains'], plan['commands'])
    state = {'phase': 'intent', 'operation': 'add-local-ssh', 'upgrade_plan_sha256': reviewed_sha,
             'boot_id': plan['snapshot']['boot_id'], 'policy': q, 'policy_hash': network.digest(q)}
    new_guard = None
    intent_written = False
    check = lambda: checkpoint(plan, original, before, p, raw_review, reviewed_sha)
    try:
        checkpoint(plan, original, before, p, raw_review, reviewed_sha)
        files.json_new(directory/'apply-intent.json', {'schema': 1, 'plan_sha256': reviewed_sha,
            'review_sha256': contract.sha(raw_review), 'started_at': time.time()})
        intent_written = True
        evidence = {}
        for key in ('closed_route', 'session_census'):
            entry = approval(raw_review, reviewed_sha)[key]
            raw = network.protected_read(entry['path'])
            if contract.sha(raw) != entry['sha256']:
                raise ValueError('Maintenance evidence changed before archive')
            checkpoint(plan, original, before, p, raw_review, reviewed_sha)
            files.write_new(directory/(key+'-evidence'), raw)
            evidence[key] = contract.sha(raw)
        checkpoint(plan, original, before, p, raw_review, reviewed_sha)
        checked_replace(network.STATE/'state.json', json.dumps(state, sort_keys=True).encode(), check, 'apply-intent')
        checkpoint(plan, original, before, p, raw_review, reviewed_sha)
        network.run(['nft', '-f', '-'], input=guard_transaction(q))
        new_guard = contract.hash_value(network.guard_hash())
        files.json_new(directory/'new-guard.json', {'sha256': new_guard})
        for index, args in enumerate(plan['commands']):
            checkpoint(plan, original, before, p, raw_review, reviewed_sha)
            if network.guard_hash() != new_guard or chains(p) != expected[index]:
                raise ValueError('Firewall changed before exact insertion')
            files.json_new(directory/('step-'+str(index)+'-intent.json'), {'argv': args})
            checkpoint(plan, original, before, p, raw_review, reviewed_sha)
            network.run(args)
        checkpoint(plan, original, before, p, raw_review, reviewed_sha)
        network.verify_host(q); network.verify(q, new_guard)
        finished = time.time()
        proof = {'schema': 1, 'operation': 'add-local-ssh', 'plan_sha256': reviewed_sha,
            'files': plan['files'], 'old_binding': before, 'new_binding': after,
            'network_id': original['network_id'], 'creation_boot_id': original['boot_id'],
            'upgrade_boot_id': plan['snapshot']['boot_id'], 'review': approval(raw_review, reviewed_sha),
            'finished_at': finished, 'evidence': evidence}
        checkpoint(plan, original, before, p, raw_review, reviewed_sha)
        files.json_new(directory/'upgrade-proof.json', proof)
        upgraded = {**original, 'binding': after, 'definition_binding': before,
            'boot_id': plan['snapshot']['boot_id'], 'finished_at': finished,
            'upgrade_proof': {'path': str(directory/'upgrade-proof.json'),
                              'sha256': contract.sha(files.private_bytes(directory/'upgrade-proof.json', 128*1024))}}
        contract.definition_binding(upgraded, after)
        checkpoint(plan, original, before, p, raw_review, reviewed_sha)
        state.update(phase='ready', guard_hash=new_guard, finished_at=finished)
        checked_replace(network.STATE/'state.json', json.dumps(state, sort_keys=True).encode(), check, 'apply-ready')
        checkpoint(plan, original, before, p, raw_review, reviewed_sha)
        checked_replace(bootstrap.RECEIPT, (json.dumps(upgraded, sort_keys=True)+'\n').encode(), check, 'bootstrap-ready')
        checkpoint(plan, original, before, p, raw_review, reviewed_sha)
        terminal(directory, 'result.json', 'ready', guard_hash=new_guard, activated=False)
    except BaseException as error:
        # Cleanup records may be written after approval expiry, but no policy
        # mutation is retried and the original dispatch error stays primary.
        try:
            if intent_written:
                state.update(phase='failed', error_type=type(error).__name__)
                if new_guard is not None: state['guard_hash'] = new_guard
                network.save(state)
            terminal(directory, 'result.json', 'failed', error, guard_hash=new_guard, activated=False)
        except BaseException:
            pass
        raise


def rollback(directory, reviewed_sha, review_path):
    plan, archived, p, q, before, after, original = read_case(directory, reviewed_sha)
    if not os.path.lexists(directory/'apply-intent.json') or any(os.path.lexists(directory/name)
            for name in ('rollback-intent.json', 'rollback-result.json')):
        raise ValueError('Only one explicit rollback of an attempted upgrade is allowed')
    raw_review = files.private_bytes(review_path, 16384)
    checkpoint(plan, original, before, p, raw_review, reviewed_sha)
    no_added_listeners(p, q)
    saved = network.saved_state()
    if saved.get('upgrade_plan_sha256') != reviewed_sha or saved.get('policy') != q:
        raise ValueError('Foreign or unresolved firewall receipt')
    current_bootstrap = bootstrap.saved()
    if current_bootstrap != original:
        if (current_bootstrap.get('binding') != after
                or contract.definition_binding(current_bootstrap, after) != before):
            raise ValueError('Foreign or unresolved bootstrap receipt')
    expected = states(plan['snapshot']['chains'], plan['commands'])
    actual = chains(p)
    matches = [index for index, value in enumerate(expected) if value == actual]
    if len(matches) != 1:
        raise ValueError('Unknown partial firewall state; manual containment required')
    for index in range(matches[0]):
        step = contract.load(files.private_bytes(directory/('step-'+str(index)+'-intent.json'), 8192))
        if step != {'argv': plan['commands'][index]}:
            raise ValueError('Inserted rule lacks exact durable dispatch intent')
    guard = network.guard_hash()
    old_guard = contract.load(archived['old-firewall.json'])['guard_hash']
    new_guard = (contract.load(files.private_bytes(directory/'new-guard.json', 1024))['sha256']
                 if os.path.lexists(directory/'new-guard.json') else None)
    if guard not in {old_guard, new_guard} or guard is None:
        raise ValueError('Unknown independent guard; manual containment required')
    if matches[0] and guard != new_guard:
        raise ValueError('Inserted accepts without the new independent guard')
    try:
        checkpoint(plan, original, before, p, raw_review, reviewed_sha)
        no_added_listeners(p, q)
        files.json_new(directory/'rollback-intent.json', {'schema': 1, 'plan_sha256': reviewed_sha,
            'started_at': time.time(), 'steps': matches[0]})
        for index in range(matches[0]-1, -1, -1):
            checkpoint(plan, original, before, p, raw_review, reviewed_sha)
            no_added_listeners(p, q)
            if chains(p) != expected[index+1] or network.guard_hash() != guard:
                raise ValueError('Firewall changed during rollback')
            args = plan['commands'][index][:]
            args[5] = '-D'
            # Delete by exact full specification; an index could target a
            # concurrently inserted foreign rule after the inspection.
            del args[7]
            network.run(args)
        checkpoint(plan, original, before, p, raw_review, reviewed_sha)
        no_added_listeners(p, q)
        if chains(p) != expected[0] or network.guard_hash() != guard:
            raise ValueError('Original rules not restored exactly')
        if guard != old_guard:
            network.run(['nft', '-c', '-f', '-'], input=guard_transaction(p))
            checkpoint(plan, original, before, p, raw_review, reviewed_sha)
            no_added_listeners(p, q)
            network.run(['nft', '-f', '-'], input=guard_transaction(p))
        network.verify_host(p); network.verify(p, old_guard)
        checkpoint(plan, original, before, p, raw_review, reviewed_sha)
        def check_restore():
            checkpoint(plan, original, before, p, raw_review, reviewed_sha)
            no_added_listeners(p, q)
        checked_replace(network.STATE/'state.json', archived['old-firewall.json'], check_restore, 'rollback-firewall')
        checkpoint(plan, original, before, p, raw_review, reviewed_sha)
        checked_replace(bootstrap.RECEIPT, archived['old-bootstrap.json'], check_restore, 'rollback-bootstrap')
        checkpoint(plan, original, before, p, raw_review, reviewed_sha)
        terminal(directory, 'rollback-result.json', 'restored', activated=False)
    except BaseException as error:
        try: terminal(directory, 'rollback-result.json', 'failed', error, activated=False)
        except BaseException: pass
        raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('prepare', 'apply', 'rollback'))
    parser.add_argument('--directory', type=Path, required=True)
    for name in ('old-network', 'new-network', 'old-catalog', 'new-catalog', 'review'):
        parser.add_argument('--'+name, type=Path)
    parser.add_argument('--plan-sha256')
    args = parser.parse_args()
    if os.geteuid() != 0: raise ValueError('Root required')
    directory = files.literal(args.directory)
    signal.signal(signal.SIGTERM, lambda *_: (_ for _ in ()).throw(InterruptedError('Terminated')))
    signal.signal(signal.SIGALRM, lambda *_: (_ for _ in ()).throw(TimeoutError('Deadline')))
    signal.alarm(180)
    with locked():
        if args.action == 'prepare':
            if any(getattr(args, key) is None for key in ('old_network', 'new_network', 'old_catalog', 'new_catalog')):
                raise ValueError('Four exact input paths required')
            prepare(directory, args.old_network, args.new_network, args.old_catalog, args.new_catalog)
        else:
            if args.plan_sha256 is None or args.review is None:
                raise ValueError('Reviewed plan SHA and fresh external review required')
            (apply if args.action == 'apply' else rollback)(directory, args.plan_sha256, args.review)
    print(json.dumps({'success': True, 'action': args.action, 'activated': False}))


if __name__ == '__main__':
    try: main()
    except BaseException as error:
        print(json.dumps({'success': False, 'error_type': type(error).__name__}), file=sys.stderr)
        sys.exit(1)
