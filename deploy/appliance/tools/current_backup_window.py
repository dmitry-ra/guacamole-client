#!/usr/bin/env python3
"""Stage one reviewed current-PG16 backup window and restore its original service."""
import argparse
import contextlib
import fcntl
import json
import os
from pathlib import Path
import re
import signal
import stat
import sys
import time
import urllib.parse

OPERATING_ROOT = Path('/opt/guacamole-portal')
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parent))
if (OPERATING_ROOT/'host.py').is_file():
    # Staged operator helpers must inspect the actual installed controller,
    # not silently select a newer staged host/catalog/network implementation.
    sys.path.insert(0, str(OPERATING_ROOT))
import host
import catalog
import network
import public_cutover as pc
import cold_copy
import prepare_instance as files

TRANSPORT_ROOT = Path('/etc/portal-rdp-transport')
LOCK = Path('/run/portal-current-backup-window.lock')
require = pc.require


def parse_config(value):
    catalog.fields(value, {'schema', 'snippet_path', 'public_base', 'legacy_unit'})
    require(type(value['schema']) is int and value['schema'] == 1, 'Backup-window schema1 required')
    snippet = pc.literal(value['snippet_path'])
    require(snippet.parent == Path('/etc/nginx/snippets') and snippet.suffix == '.conf',
            'Dedicated external nginx snippet required')
    unit = value['legacy_unit']
    require(isinstance(unit, str) and re.fullmatch('[a-z][a-z0-9_.@-]{0,95}\\.service', unit)
            and unit not in (pc.NEW_UNIT, pc.TRANSPORT, 'nginx.service', 'guacamole-portal-network.service'),
            'Distinct existing legacy unit required')
    base = urllib.parse.urlsplit(value['public_base'])
    require(base.scheme == 'https' and base.hostname and base.port in (None, 443)
            and base.path == '/desktop/app/' and not base.username and not base.password
            and not base.query and not base.fragment, 'Normal public TLS application URL required')
    return dict(value)


def source_hashes(units):
    require(Path(host.__file__).resolve() == OPERATING_ROOT/'host.py'
            and Path(catalog.__file__).resolve() == OPERATING_ROOT/'catalog.py'
            and Path(network.__file__).resolve() == OPERATING_ROOT/'network.py',
            'Actual installed operating modules required')
    paths = [OPERATING_ROOT/name for name in ('host.py', 'catalog.py', 'network.py', 'network_service.py', 'network_upgrade.py')]
    paths += [OPERATING_ROOT/'tools'/name for name in
              ('public_cutover.py', 'cold_copy.py', 'prepare_instance.py', 'render_proxy.py')]
    paths += [Path(module.__file__).resolve() for module in (pc, cold_copy, files)]
    paths += [Path(__file__).resolve(), Path(pc.render_proxy.__file__).resolve()]
    paths += [pc.literal(value['FragmentPath']) for value in units.values()]
    paths += [TRANSPORT_ROOT/name for name in ('client.conf', 'known_hosts', 'identity.pub')]
    return {str(path): host.sha(network.protected_read(path)) for path in paths}


def transport_identity():
    files.protected_directory(TRANSPORT_ROOT, private=True)
    info = (TRANSPORT_ROOT/'identity').lstat()
    require(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and info.st_nlink == 1
            and stat.S_IMODE(info.st_mode) == 0o600, 'Existing root-private transport identity required')
    # Never open, hash or print the private key.
    return {key: getattr(info, key) for key in
            ('st_dev', 'st_ino', 'st_uid', 'st_gid', 'st_mode', 'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns')}


def nginx_scope(cfg):
    raw = pc.run([pc.NGINX, '-T']).stdout
    marker = ('# configuration file '+cfg['snippet_path']+':\n').encode()
    require(raw.count(marker) == 1, 'Exact snippet must belong to active nginx configuration')
    start = raw.index(marker)+len(marker)
    end = raw.find(b'\n# configuration file ', start)
    if end == -1:
        end = len(raw)
    snippet = network.protected_read(Path(cfg['snippet_path']))
    require(raw[start:end].rstrip(b'\n') == snippet.rstrip(b'\n'), 'Actual nginx snippet bytes differ')
    # Bind every other active nginx byte while allowing only this owned snippet
    # to transition between its staged original and the fixed closed response.
    return host.sha(raw[:start]+b'<owned-portal-snippet>\n'+raw[end:])


def static_binding(cfg):
    release, unused, binding = host.selection()
    units = {unit: pc.service(unit) for unit in (pc.NEW_UNIT, pc.TRANSPORT, cfg['legacy_unit'])}
    require(pc.active(units[pc.TRANSPORT]), 'Existing transport must remain active')
    snippet = Path(cfg['snippet_path']).lstat()
    require(stat.S_ISREG(snippet.st_mode) and snippet.st_uid == 0 and snippet.st_gid == 0
            and snippet.st_nlink == 1 and not snippet.st_mode & 0o022, 'Root-owned protected snippet required')
    raw = cold_copy.prepared_receipt(host.PERSIST/'data/prepared.json')
    prepared = json.loads(raw, object_pairs_hook=catalog.unique_object)
    require(set(prepared) == {'schema', 'postgres_major', 'guacamole', 'config_sha256', 'connections'}
            and prepared['config_sha256'] == release['config_sha256'], 'Current preparation/config binding required')
    registry = catalog.parse(host.read_json(host.CONFIG))
    registry.parameters(prepared['connections'])
    return {'release': release, 'release_sha256': binding[0], 'data_identity': list(binding[1]),
            'prepared_sha256': binding[2], 'secrets_identity': list(binding[3]),
            'authentication_fields': binding[4], 'preserved_units': {unit: units[unit] for unit in
                (pc.TRANSPORT, cfg['legacy_unit'])},
            'portal_unit': {key: units[pc.NEW_UNIT].get(key) for key in
                            ('LoadState', 'FragmentPath', 'UnitFileState')},
            'sources': source_hashes(units), 'transport_identity': transport_identity(),
            'nginx_scope_sha256': nginx_scope(cfg),
            'snippet_mode': stat.S_IMODE(snippet.st_mode)}


def snapshot(cfg):
    binding = static_binding(cfg)
    record = pc.candidate()
    require(pc.active(pc.service(pc.NEW_UNIT)), 'Current portal service must be active')
    pc.no_sessions(record['container_id'])
    pc.wait_public_status(cfg['public_base'], 200)
    return {'binding': binding, 'record': record}


def stage(config_path, case):
    cfg_raw = files.private_bytes(config_path, 16384)
    cfg = parse_config(json.loads(cfg_raw, object_pairs_hook=catalog.unique_object))
    data = host.PERSIST/'data'
    require(not cold_copy.overlaps(case, data), 'Window case must be independent of current DATA')
    current = snapshot(cfg)
    snippet = network.protected_read(Path(cfg['snippet_path']))
    require(snippet != pc.CLOSED, 'Original portal route must be open')
    pc.run([pc.NGINX, '-t'])
    # Bind a second fresh native read before publishing the operator plan.
    require(snapshot(cfg) == current, 'Current deployment changed during stage')
    files.new_directory(case)
    files.json_new(case/'stage.intent.json', {'schema': 1, 'config_sha256': host.sha(cfg_raw)})
    for name, raw in (('config.json', cfg_raw), ('original-snippet.conf', snippet)):
        files.write_new(case/name, raw)
    plan = {'schema': 1, 'phase': 'staged', 'snapshot': current,
            'files': {'config.json': host.sha(cfg_raw), 'original-snippet.conf': host.sha(snippet)},
            'at': time.time()}
    files.json_new(case/'plan.json', plan)
    return host.sha(files.private_bytes(case/'plan.json', 131072))


def load_case(case, expected):
    files.protected_directory(case, private=True)
    host.identifier(expected)
    raw = files.private_bytes(case/'plan.json', 131072)
    require(host.sha(raw) == expected, 'Exact independently reviewed window plan required')
    plan = json.loads(raw, object_pairs_hook=catalog.unique_object)
    catalog.fields(plan, {'schema', 'phase', 'snapshot', 'files', 'at'})
    require(type(plan['schema']) is int and plan['schema'] == 1 and plan['phase'] == 'staged'
            and set(plan['files']) == {'config.json', 'original-snippet.conf'}, 'Exact staged window plan required')
    for name, digest in plan['files'].items():
        require(host.sha(files.private_bytes(case/name, 131072)) == digest, 'Staged original bytes changed')
    cfg = parse_config(json.loads(files.private_bytes(case/'config.json', 16384),
                                 object_pairs_hook=catalog.unique_object))
    return cfg, plan


def review(raw, expected):
    value = json.loads(raw, object_pairs_hook=catalog.unique_object)
    catalog.fields(value, {'schema', 'scope', 'plan_sha256', 'operator_reference',
                          'allow_fixed_original_recovery', 'reviewed_at', 'expires_at'})
    now = time.time()
    require(type(value['schema']) is int and value['schema'] == 1
            and value['scope'] == 'one current backup window'
            and value['plan_sha256'] == expected and value['allow_fixed_original_recovery'] is True
            and type(value['reviewed_at']) in (int, float) and type(value['expires_at']) in (int, float)
            and value['reviewed_at'] <= now < value['expires_at']
            and 0 < value['expires_at']-value['reviewed_at'] <= 300,
            'Fresh reviewed window and fixed original recovery authority required')
    pc.reference(value['operator_reference'])


def progress(case, state, phase):
    state['phase'] = phase
    state['at'] = time.time()
    host.write(case/'progress.json', state)


def unchanged(cfg, plan):
    require(static_binding(cfg) == plan['snapshot']['binding'], 'Original deployment or preserved host bindings changed')


def backup(case, record):
    target = case/'cold-backup'
    # Use the genuine helper's own overall600second deadline and real inactive
    # service/census checks. The launcher normally removes the old CID on stop;
    # cold_copy independently proves absence by both exact name and pinned CID.
    pc.run(['/usr/bin/python3', '-B', str(Path(cold_copy.__file__).resolve()), 'backup',
            '--source', str(host.PERSIST/'data'), '--service', pc.NEW_UNIT,
            '--container', host.NAME, '--legacy-container-id', record['container_id'],
            '--directory', str(target)], timeout=610)
    result = json.loads(files.private_bytes(target/'result.json', 16384), object_pairs_hook=catalog.unique_object)
    require(result.get('operation') == 'backup' and result.get('phase') == 'ready'
            and type(result.get('schema')) is int and result['schema'] == 1
            and result.get('source') == str(host.PERSIST/'data')
            and result.get('target') == str(target/'data')
            and result.get('legacy_cid') == record['container_id']
            and result.get('for_migration') is False and result.get('legacy_receipt_archived') is False
            and result.get('allowed_stopped_consumers') == [] and result.get('stopped_consumer_census') == {},
            'Exact successful current cold backup result required')
    raw = files.private_bytes(target/'manifest.json', 64*1024*1024)
    require(host.sha(raw) == result.get('manifest_sha256'), 'Cold backup manifest binding differs')
    expected = json.loads(raw, object_pairs_hook=catalog.unique_object)
    cold_copy.validate_cluster(target/'data', require_receipt=True)
    require(cold_copy.manifest(target/'data', seconds=60) == expected
            and cold_copy.manifest(host.PERSIST/'data', seconds=60) == expected,
            'Independent full backup/source census differs')
    return {'case': str(target), 'manifest_sha256': host.sha(raw),
            'result_sha256': host.sha(files.private_bytes(target/'result.json', 16384))}


def observe_ready(case, cfg, plan, state):
    deadline = time.monotonic()+180
    while True:
        unchanged(cfg, plan)
        try:
            current = pc.candidate()
        except (pc.Refused, FileNotFoundError):
            current = None
        if current is not None and pc.active(pc.service(pc.NEW_UNIT)):
            original = plan['snapshot']['record']
            if state.get('start_dispatched'):
                require(current['container_id'] != original['container_id'] and current['run_id'] != original['run_id']
                        and type(current.get('ready_at')) in (int, float)
                        and current['ready_at'] >= state['start_at']+65
                        and time.time() >= state['start_at']+65,
                        'Fresh original-image run and mandatory65second readiness hold required')
            else:
                require(current == original, 'Unexpected service replacement before owned restart')
            require(current['image_id'] == original['image_id']
                    and current['release_sha256'] == original['release_sha256'], 'Original service identity changed')
            return current
        require(time.monotonic() < deadline, 'Original service readiness unconfirmed; remain closed')
        time.sleep(1)


def restore_original(case, cfg, plan, state):
    unchanged(cfg, plan)
    status = pc.service(pc.NEW_UNIT)
    if status['ActiveState'] in ('inactive', 'failed'):
        require(state.get('stop_dispatched') and not state.get('start_dispatched'),
                'Original start requires owned stop and cannot be replayed')
        pc.stopped(pc.NEW_UNIT, host.PUBLIC/'ready')
        cold_copy.stopped_and_exclusive(host.PERSIST/'data')
        cold_copy.validate_cluster(host.PERSIST/'data', require_receipt=True)
        state.update(start_dispatched=True, start_at=time.time())
        progress(case, state, 'original_start_intent')
        pc.run([pc.SYSTEMCTL, 'start', pc.NEW_UNIT], timeout=140)
    else:
        require(pc.active(status) or status['ActiveState'] == 'activating',
                'Original service state uncertain; no blind lifecycle retry')
    current = observe_ready(case, cfg, plan, state)
    identity = {'container_id': current['container_id'], 'run_id': current['run_id']}
    # One empty native challenge only. Never retry an uncertain/429 response,
    # nor use a positive result for another run during failure recovery.
    if state.get('challenge_dispatched'):
        require(state.get('challenge_passed') is True and state.get('challenge_deployment') == identity,
                'Prior empty native challenge failed or is uncertain; no replay')
    else:
        state.update(challenge_dispatched=True, challenge_deployment=identity)
        progress(case, state, 'empty_native_challenge_intent')
        binding = plan['snapshot']['binding']
        require(host.authentication_ready(binding['release']['backend_loopback_port'], binding['authentication_fields']),
                'Original empty native authentication challenge failed; no retry')
        state['challenge_passed'] = True
        progress(case, state, 'original_ready')
    unchanged(cfg, plan)
    require(pc.candidate() == current, 'Ready original run changed before reopening')
    allowed = {plan['files']['original-snippet.conf'], host.sha(pc.CLOSED)}
    snippet = Path(cfg['snippet_path'])
    if host.sha(network.protected_read(snippet)) != plan['files']['original-snippet.conf']:
        progress(case, state, 'original_route_restore_intent')
        pc.restore_file(case, 'original-snippet.conf', snippet, allowed)
        pc.reload_nginx()
    else:
        # A prior original-file restore may have reached disk but not loaded.
        # A fresh known503 is evidence for one fixed-original recovery reload;
        # an already observed200 does not dispatch another reload.
        status = pc.public_status(cfg['public_base'], timeout=1)
        require(status in (200, 503), 'Original route load state uncertain; no blind reload')
        if status == 503:
            pc.reload_nginx()
    pc.wait_public_status(cfg['public_base'], 200, state)
    unchanged(cfg, plan)
    require(pc.candidate() == current, 'Original run changed after reopening')
    state['restored_deployment'] = identity
    progress(case, state, 'original_restored')


def run(case, expected, review_path):
    cfg, plan = load_case(case, expected)
    require(not os.path.lexists(case/'run.intent.json'), 'Prior window attempt must never be replayed')
    require(snapshot(cfg) == plan['snapshot'], 'Live current deployment changed after review')
    review_raw = files.private_bytes(review_path, 16384)
    review(review_raw, expected)
    state = {'schema': 1, 'plan_sha256': expected, 'maintenance_review_sha256': host.sha(review_raw)}
    files.json_new(case/'run.intent.json', state)
    try:
        unchanged(cfg, plan)
        require(pc.candidate() == plan['snapshot']['record'], 'Current ready run changed before closing')
        pc.no_sessions(plan['snapshot']['record']['container_id'])
        review(review_raw, expected)
        progress(case, state, 'public_close_intent')
        review(review_raw, expected)
        pc.replace(Path(cfg['snippet_path']), pc.CLOSED, {plan['files']['original-snippet.conf']})
        pc.run([pc.NGINX, '-t'])
        review(review_raw, expected)
        pc.run([pc.SYSTEMCTL, 'reload', 'nginx.service'])
        pc.wait_public_status(cfg['public_base'], 503, state)
        unchanged(cfg, plan)
        require(pc.candidate() == plan['snapshot']['record'], 'Current run changed while closing')
        pc.no_sessions(plan['snapshot']['record']['container_id'])
        review(review_raw, expected)
        state['stop_dispatched'] = True
        progress(case, state, 'current_stop_intent')
        review(review_raw, expected)
        pc.run([pc.SYSTEMCTL, 'stop', pc.NEW_UNIT], timeout=50)
        pc.stopped(pc.NEW_UNIT, host.PUBLIC/'ready')
        unchanged(cfg, plan)
        progress(case, state, 'current_backup_intent')
        review(review_raw, expected)
        state['backup'] = backup(case, plan['snapshot']['record'])
        progress(case, state, 'current_backup_verified')
        restore_original(case, cfg, plan, state)
        files.json_new(case/'result.json', {**state, 'phase': 'ready', 'original_restored': True})
    except BaseException as error:
        # The original exception is always re-raised, even when diagnostics or
        # fixed-state restoration fail. Expiry cannot strand an owned outage.
        failure = {'schema': 1, 'phase': state.get('phase'), 'error_type': type(error).__name__}
        if isinstance(error, pc.Refused):
            failure['reason'] = error.safe_reason
        try:
            files.json_new(case/'failure.json', failure)
        except Exception:
            pass
        try:
            signal.alarm(200)
            restore_original(case, cfg, plan, state)
            files.json_new(case/'recovery.result.json', {'schema': 1, 'original_restored': True,
                           'primary_error_type': type(error).__name__, 'deployment': state['restored_deployment']})
        except BaseException as recovery_error:
            try:
                files.json_new(case/'recovery.failure.json', {'schema': 1,
                    'primary_error_type': type(error).__name__, 'recovery_error_type': type(recovery_error).__name__,
                    'operator_reconciliation_required': True})
            except Exception:
                pass
        raise


def reconcile(case, expected):
    """Read-only diagnosis; never turns an uncertain action into another attempt."""
    cfg, plan = load_case(case, expected)
    unchanged(cfg, plan)
    digest = host.sha(network.protected_read(Path(cfg['snippet_path'])))
    require(digest in {plan['files']['original-snippet.conf'], host.sha(pc.CLOSED)}, 'Foreign route must remain untouched')
    current = host.private_json(host.STATE/'current.json')
    cid = host.identifier(current.get('container_id'))
    owned = host.owned(current, cid)
    return {'schema': 1, 'service': pc.service(pc.NEW_UNIT),
            'route': 'original' if digest == plan['files']['original-snippet.conf'] else 'closed',
            'current': {key: current.get(key) for key in ('container_id', 'run_id', 'image_id', 'phase')},
            'owned_container_present': owned is not None,
            'owned_container_running': bool(owned and owned.get('State', {}).get('Running') is True),
            'run_attempted': os.path.lexists(case/'run.intent.json'),
            'result_present': os.path.lexists(case/'result.json'), 'no_actions_performed': True}


@contextlib.contextmanager
def locked():
    fd = os.open(LOCK, os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        info = os.fstat(fd)
        require(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and info.st_nlink == 1
                and stat.S_IMODE(info.st_mode) == 0o600, 'Protected window lock required')
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        yield
    finally:
        os.close(fd)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('stage', 'run', 'reconcile'))
    parser.add_argument('--case', required=True, type=Path)
    parser.add_argument('--config', type=Path)
    parser.add_argument('--expected-plan-sha256')
    parser.add_argument('--maintenance-review', type=Path)
    args = parser.parse_args()
    require(os.geteuid() == 0 and os.getegid() == 0, 'Root operator required')
    os.umask(0o077)
    def expired(*unused):
        raise TimeoutError('Current backup window deadline exceeded')
    signal.signal(signal.SIGALRM, expired)
    signal.alarm(1200 if args.action == 'run' else 120)
    case = files.literal(args.case)
    if args.action == 'stage':
        require(args.config is not None and not args.expected_plan_sha256 and not args.maintenance_review,
                'Stage requires external config only')
        result = {'staged': True, 'host_mutated': False, 'plan_sha256': stage(args.config, case)}
    else:
        require(args.expected_plan_sha256 is not None and args.config is None, 'Exact reviewed plan required')
        if args.action == 'run':
            require(args.maintenance_review is not None, 'Fresh maintenance review required')
            with locked(), pc.locked(case):
                run(case, args.expected_plan_sha256, args.maintenance_review)
            result = {'completed': True, 'original_restored': True}
        else:
            require(args.maintenance_review is None, 'Reconcile is read-only')
            result = reconcile(case, args.expected_plan_sha256)
    signal.alarm(0)
    print(json.dumps(result))


if __name__ == '__main__':
    try:
        main()
    except SystemExit:
        raise
    except BaseException as error:
        print('Current backup window refused or failed: '+type(error).__name__, file=sys.stderr)
        raise SystemExit(1)
