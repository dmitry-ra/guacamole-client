#!/usr/bin/env python3
"""Reviewed shutdown and explicit fixed-original recovery; no mixed activation."""
# Import this first: it selects the installed operating host/catalog/network
# before any newer staged helper can cache those module names.
import current_backup_window as window

import argparse
import json
import math
import os
from pathlib import Path
import signal
import stat
import sys
import time

pc, host, network, catalog, files = window.pc, window.host, window.network, window.catalog, window.files
require = pc.require


def source_sha():
    return host.sha(network.protected_read(Path(__file__).resolve()))


def review(raw, expected, recovery_sha=None):
    value = json.loads(raw, object_pairs_hook=catalog.unique_object)
    keys = {'schema', 'scope', 'plan_sha256', 'shutdown_source_sha256',
        'operator_reference', 'allow_fixed_original_recovery', 'reviewed_at', 'expires_at'}
    if recovery_sha is not None: keys.add('recovery_plan_sha256')
    catalog.fields(value, keys)
    now = time.time()
    require(type(value['schema']) is int and value['schema'] == 1
        and value['scope'] == ('one current upgrade shutdown' if recovery_sha is None else 'one fixed original recovery')
        and (recovery_sha is None or value['recovery_plan_sha256'] == recovery_sha) and value['plan_sha256'] == expected
        and value['shutdown_source_sha256'] == source_sha() and value['allow_fixed_original_recovery'] is True
        and all(type(value[k]) in (int, float) and math.isfinite(value[k]) for k in ('reviewed_at', 'expires_at'))
        and value['reviewed_at'] <= now < value['expires_at']
        and 0 < value['expires_at']-value['reviewed_at'] <= 300,
        'Fresh exact shutdown/source review and fixed-original recovery authority required')
    pc.reference(value['operator_reference'])
    require(value['reviewed_at'] <= time.time() < value['expires_at'], 'Shutdown/recovery review expired during source check')
    return value


def selection_binding():
    release, unused, binding = host.selection()
    raw = window.cold_copy.prepared_receipt(host.PERSIST/'data/prepared.json')
    prepared = json.loads(raw, object_pairs_hook=catalog.unique_object)
    require(set(prepared) == {'schema', 'postgres_major', 'guacamole', 'config_sha256', 'connections'}
        and prepared['config_sha256'] == release['config_sha256'], 'Original preparation/config binding changed')
    catalog.parse(host.read_json(host.CONFIG)).parameters(prepared['connections'])
    return {'release': release, 'release_sha256': binding[0], 'data_identity': list(binding[1]),
        'prepared_sha256': binding[2], 'secrets_identity': list(binding[3]), 'authentication_fields': binding[4]}


def inactive(value):
    return value.get('ActiveState') == 'inactive' and value.get('SubState') == 'dead' and value.get('MainPID') == '0'


def binding(cfg, plan, transport_stopped=False, fresh_transport=None):
    """Preserve the staged binding while allowing only the owned stop state."""
    expected = plan['snapshot']['binding']
    if not transport_stopped and fresh_transport is None:
        window.unchanged(cfg, plan)
        return
    actual = selection_binding()
    require(all(actual[key] == expected[key] for key in actual), 'Original selected files or DATA identity changed')
    units = {unit: pc.service(unit) for unit in (pc.NEW_UNIT, pc.TRANSPORT, cfg['legacy_unit'])}
    require(units[cfg['legacy_unit']] == expected['preserved_units'][cfg['legacy_unit']], 'Legacy service changed')
    require({key: units[pc.NEW_UNIT].get(key) for key in expected['portal_unit']} == expected['portal_unit'],
        'Portal installed unit identity changed')
    original = expected['preserved_units'][pc.TRANSPORT]
    current = units[pc.TRANSPORT]
    require(set(current) == set(original)
        and all(current.get(key) == original.get(key) for key in ('LoadState', 'FragmentPath', 'UnitFileState')),
        'Transport immutable unit identity changed')
    if fresh_transport is None:
        require(inactive(current) and current.get('InvocationID') in ('', original.get('InvocationID')),
            'Transport stop state or invocation changed')
    else:
        host.identifier(current.get('InvocationID'), 32)
        require(current == fresh_transport and pc.active(current)
            and current['InvocationID'] != original.get('InvocationID')
            and current.get('MainPID', '').isdigit() and int(current['MainPID']) > 0
            and current['MainPID'] != original.get('MainPID'), 'Fresh original transport invocation changed')
    require(window.source_hashes(units) == expected['sources']
        and window.transport_identity() == expected['transport_identity']
        and window.nginx_scope(cfg) == expected['nginx_scope_sha256'], 'Preserved operating sources, transport or nginx changed')
    info = Path(cfg['snippet_path']).lstat()
    require(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and info.st_gid == 0 and info.st_nlink == 1
        and stat.S_IMODE(info.st_mode) == expected['snippet_mode'], 'Owned snippet metadata changed')


def stopped_portal(plan):
    status = pc.service(pc.NEW_UNIT)
    require(inactive(status) and not os.path.lexists(host.PUBLIC/'ready'), 'Portal must be inactive with no readiness')
    original = plan['snapshot']['record']
    current = host.private_json(host.STATE/'current.json')
    require(current.get('phase') == 'stopped' and all(current.get(key) == original.get(key) for key in
        ('container_id', 'run_id', 'image_id', 'release_sha256')), 'Original stopped controller identity changed')
    code = host.engine('container', 'exists', original['container_id'], check=False).returncode
    require(type(code) is int and code == 1, 'Exact original CID absence requires exists returncode1')
    members = host.engine('ps', '--all', '--no-trunc', '--filter=label='+host.LABEL+'=1', '--format={{.ID}}').stdout
    require(not members.strip(), 'No appliance container may remain')
    window.cold_copy.stopped_and_exclusive(host.PERSIST/'data')
    return status


def census(record):
    """Persist the actual native response, not an inferred process count."""
    cid = host.identifier(record['container_id']); run_id = host.identifier(record['run_id'], 32)
    result = pc.run([host.PODMAN, 'exec', cid, 'python3', '-B', '-c', pc.SESSION_PROBE], timeout=5)
    value = json.loads(result.stdout, object_pairs_hook=catalog.unique_object)
    require(isinstance(value, dict) and value == {'guacd_processes': 1}
        and type(value['guacd_processes']) is int, 'Post-close native desktop census is active or unknown')
    return {'schema': 1, 'container_id': cid, 'run_id': run_id, 'guacd_processes': value['guacd_processes'],
        'closed_before_census': True, 'at': time.time()}


def run(case, expected, review_path):
    cfg, plan = window.load_case(case, expected)
    require(not any(os.path.lexists(case/name) for name in
        ('run.intent.json', 'result.json', 'upgrade-close.intent.json', 'upgrade-close.result.json', 'upgrade-close.failure.json')),
        'Fresh unused window case required; shutdown never replays')
    require(window.snapshot(cfg) == plan['snapshot'], 'Current deployment changed after shutdown review')
    raw_review = files.private_bytes(review_path, 16384)
    review(raw_review, expected)
    state = {'schema': 1, 'operation': 'close current for upgrade', 'plan_sha256': expected,
        'shutdown_source_sha256': source_sha(), 'maintenance_review_sha256': host.sha(raw_review),
        'original_container_id': plan['snapshot']['record']['container_id'],
        'original_run_id': plan['snapshot']['record']['run_id'], 'transport_stop_dispatched': False,
        'portal_stop_dispatched': False}
    review(raw_review, expected)
    files.json_new(case/'upgrade-close.intent.json', state)
    try:
        binding(cfg, plan)
        require(pc.candidate() == plan['snapshot']['record'], 'Current ready run changed before closing')
        pc.no_sessions(plan['snapshot']['record']['container_id'])
        review(raw_review, expected)
        window.progress(case, state, 'public_close_intent')
        review(raw_review, expected)
        pc.replace(Path(cfg['snippet_path']), pc.CLOSED, {plan['files']['original-snippet.conf']})
        pc.run([pc.NGINX, '-t'])
        review(raw_review, expected)
        pc.run([pc.SYSTEMCTL, 'reload', 'nginx.service'])
        pc.wait_public_status(cfg['public_base'], 503, state)
        binding(cfg, plan)
        require(pc.candidate() == plan['snapshot']['record'], 'Current run changed during route close')
        actual = census(plan['snapshot']['record'])
        files.json_new(case/'session-census.json', actual)
        files.write_new(case/'closed-route.conf', pc.CLOSED)
        files.json_new(case/'closed-route.json', {'schema': 1, 'snippet_path': cfg['snippet_path'],
            'snippet_sha256': host.sha(pc.CLOSED), 'public_base': cfg['public_base'],
            'observed_status': 503, 'confirmed_at': actual['at'], 'plan_sha256': expected})
        # Repeat the entire active binding and identity after the census, before
        # the only portal stop. Closed routing prevents new browser admission.
        binding(cfg, plan)
        require(pc.candidate() == plan['snapshot']['record'], 'Current identity changed after session census')
        require(network.protected_read(Path(cfg['snippet_path'])) == pc.CLOSED, 'Closed route changed before stop')
        review(raw_review, expected)
        state['portal_stop_dispatched'] = True
        # Preserve the existing window recovery primitive's explicit once-only
        # stop flag. This tool never calls that recovery primitive itself.
        state['stop_dispatched'] = True
        window.progress(case, state, 'current_stop_intent')
        review(raw_review, expected)
        pc.run([pc.SYSTEMCTL, 'stop', pc.NEW_UNIT], timeout=50)
        stopped_portal(plan)
        binding(cfg, plan)
        review(raw_review, expected)
        state['transport_stop_dispatched'] = True
        window.progress(case, state, 'transport_stop_intent')
        review(raw_review, expected)
        pc.run([pc.SYSTEMCTL, 'stop', pc.TRANSPORT], timeout=30)
        binding(cfg, plan, transport_stopped=True)
        stopped_portal(plan)
        require(network.protected_read(Path(cfg['snippet_path'])) == pc.CLOSED, 'Closed route changed after stops')
        pc.wait_public_status(cfg['public_base'], 503, state)
        state.update(phase='stopped', portal_inactive=True, transport_inactive=True, original_cid_absent=True,
            route_closed=True, original_data_selection_preserved=True, activated=False, at=time.time(),
            closed_route={'path': str(case/'closed-route.conf'), 'sha256': host.sha(files.private_bytes(case/'closed-route.conf', 16384))},
            session_census={'path': str(case/'session-census.json'), 'sha256': host.sha(files.private_bytes(case/'session-census.json', 16384))})
        review(raw_review, expected)
        files.json_new(case/'upgrade-close.result.json', state)
    except BaseException as error:
        failure = {**state, 'phase': state.get('phase'), 'error_type': type(error).__name__,
            'operator_reconciliation_required': True, 'automatic_recovery_attempted': False}
        if isinstance(error, pc.Refused): failure['reason'] = error.safe_reason
        try: files.json_new(case/'upgrade-close.failure.json', failure)
        except BaseException: pass
        raise
    return state


def reconcile(case, expected):
    """Read-only observations, without another stop/reload/start or receipt write."""
    cfg, plan = window.load_case(case, expected)
    transport = pc.service(pc.TRANSPORT)
    if pc.active(transport): binding(cfg, plan)
    else: binding(cfg, plan, transport_stopped=True)
    route = host.sha(network.protected_read(Path(cfg['snippet_path'])))
    require(route in (plan['files']['original-snippet.conf'], host.sha(pc.CLOSED)), 'Foreign route must remain untouched')
    original = plan['snapshot']['record']
    current = host.private_json(host.STATE/'current.json')
    require(all(current.get(key) == original.get(key) for key in
        ('container_id', 'run_id', 'image_id', 'release_sha256')), 'Foreign controller run must remain untouched')
    value = host.owned(current, host.identifier(current['container_id']))
    return {'schema': 1, 'portal': pc.service(pc.NEW_UNIT), 'transport': transport,
        'route': 'closed' if route == host.sha(pc.CLOSED) else 'original',
        'observed_public_status': pc.public_status(cfg['public_base'], timeout=1),
        'current': {key: current.get(key) for key in ('container_id', 'run_id', 'image_id', 'phase')},
        'container_present': value is not None, 'container_running': bool(value and value.get('State', {}).get('Running') is True),
        'ready_marker_present': os.path.lexists(host.PUBLIC/'ready'),
        'attempted': os.path.lexists(case/'upgrade-close.intent.json'), 'no_actions_performed': True}


def recovery_stopped(case, cfg, plan, expected):
    raw = files.private_bytes(case/'upgrade-close.result.json', 32768)
    value = json.loads(raw, object_pairs_hook=catalog.unique_object)
    original = plan['snapshot']['record']
    require(value.get('schema') == 1 and value.get('operation') == 'close current for upgrade'
        and value.get('phase') == 'stopped' and value.get('plan_sha256') == expected
        and value.get('shutdown_source_sha256') == source_sha() and value.get('portal_inactive') is True
        and value.get('transport_inactive') is True and value.get('original_cid_absent') is True
        and value.get('original_container_id') == original['container_id']
        and value.get('original_run_id') == original['run_id'], 'Complete original shutdown proof required')
    binding(cfg, plan, transport_stopped=True); stopped_portal(plan)
    require(network.protected_read(Path(cfg['snippet_path'])) == pc.CLOSED, 'Recovery requires exact closed route')
    pc.wait_public_status(cfg['public_base'], 503)
    window.cold_copy.validate_cluster(host.PERSIST/'data', require_receipt=True)
    return host.sha(raw)


def stage_recovery(case, expected, recovery_case):
    cfg, plan = window.load_case(case, expected)
    require(not window.cold_copy.overlaps(recovery_case, case)
        and not window.cold_copy.overlaps(recovery_case, host.PERSIST/'data'), 'Independent new recovery case required')
    proof = recovery_stopped(case, cfg, plan, expected)
    files.new_directory(recovery_case)
    files.json_new(recovery_case/'recovery-plan.json', {'schema': 1, 'operation': 'recover fixed original',
        'window_case': str(case), 'window_plan_sha256': expected, 'shutdown_result_sha256': proof,
        'shutdown_source_sha256': source_sha(), 'at': time.time()})
    return host.sha(files.private_bytes(recovery_case/'recovery-plan.json', 16384))


def load_recovery(case, expected, recovery_case, recovery_sha):
    cfg, plan = window.load_case(case, expected)
    files.protected_directory(recovery_case, private=True)
    raw = files.private_bytes(recovery_case/'recovery-plan.json', 16384)
    require(host.sha(raw) == host.identifier(recovery_sha), 'Exact independently reviewed recovery plan required')
    value = json.loads(raw, object_pairs_hook=catalog.unique_object)
    catalog.fields(value, {'schema', 'operation', 'window_case', 'window_plan_sha256',
        'shutdown_result_sha256', 'shutdown_source_sha256', 'at'})
    require(type(value['schema']) is int and value['schema'] == 1 and value['operation'] == 'recover fixed original'
        and value['window_case'] == str(case) and value['window_plan_sha256'] == expected
        and value['shutdown_source_sha256'] == source_sha()
        and host.sha(files.private_bytes(case/'upgrade-close.result.json', 32768)) == value['shutdown_result_sha256'],
        'Original shutdown proof, source or recovery binding changed')
    return cfg, plan


def recovery_ready(cfg, plan, state):
    deadline = time.monotonic()+180
    while True:
        binding(cfg, plan, transport_stopped=True)
        current = None
        try: current = pc.candidate()
        except (pc.Refused, FileNotFoundError): pass
        if current is not None and pc.active(pc.service(pc.NEW_UNIT)):
            original = plan['snapshot']['record']
            require(current['container_id'] != original['container_id'] and current['run_id'] != original['run_id']
                and current['image_id'] == original['image_id'] and current['release_sha256'] == original['release_sha256']
                and type(current.get('ready_at')) in (int, float) and math.isfinite(current['ready_at'])
                and current['ready_at'] >= state['start_at']+65 and time.time() >= state['start_at']+65,
                'Fresh exact-original run and actual65second readiness hold required')
            return current
        require(time.monotonic() < deadline, 'Original guarded service readiness unconfirmed; remain closed')
        time.sleep(1)


def recover(case, expected, recovery_case, recovery_sha, review_path):
    cfg, plan = load_recovery(case, expected, recovery_case, recovery_sha)
    require(not any(os.path.lexists(recovery_case/name) for name in
        ('recovery.intent.json', 'recovery.result.json', 'recovery.failure.json')), 'Original recovery is single-use')
    recovery_stopped(case, cfg, plan, expected)
    raw_review = files.private_bytes(review_path, 16384)
    review(raw_review, expected, recovery_sha)
    state = {'schema': 1, 'operation': 'recover fixed original', 'recovery_plan_sha256': recovery_sha,
        'plan_sha256': expected, 'maintenance_review_sha256': host.sha(raw_review), 'activated_mixed': False}
    review(raw_review, expected, recovery_sha)
    files.json_new(recovery_case/'recovery.intent.json', state)
    try:
        recovery_stopped(case, cfg, plan, expected)
        review(raw_review, expected, recovery_sha)
        state.update(start_dispatched=True, start_at=time.time())
        window.progress(recovery_case, state, 'original_start_intent')
        review(raw_review, expected, recovery_sha)
        # The original guarded host unit bootstraps its own original bridge.
        # Keeping transport stopped until then avoids unreviewed network calls.
        pc.run([pc.SYSTEMCTL, 'start', pc.NEW_UNIT], timeout=140)
        current = recovery_ready(cfg, plan, state)
        state['restored_deployment'] = {key: current[key] for key in ('container_id', 'run_id')}
        binding(cfg, plan, transport_stopped=True)
        require(pc.candidate() == current, 'Fresh original run changed before transport start')
        review(raw_review, expected, recovery_sha)
        state['transport_start_dispatched'] = True
        window.progress(recovery_case, state, 'original_transport_start_intent')
        review(raw_review, expected, recovery_sha)
        pc.run([pc.SYSTEMCTL, 'start', pc.TRANSPORT], timeout=30)
        transport = pc.service(pc.TRANSPORT)
        binding(cfg, plan, fresh_transport=transport)
        state['fresh_transport'] = transport
        state['challenge_dispatched'] = True
        window.progress(recovery_case, state, 'empty_native_challenge_intent')
        review(raw_review, expected, recovery_sha)
        selected = plan['snapshot']['binding']
        require(host.authentication_ready(selected['release']['backend_loopback_port'], selected['authentication_fields']),
            'Original empty native challenge failed; no retry')
        state['challenge_passed'] = True
        binding(cfg, plan, fresh_transport=transport)
        require(pc.candidate() == current and network.protected_read(Path(cfg['snippet_path'])) == pc.CLOSED,
            'Original run or closed route changed before reopening')
        review(raw_review, expected, recovery_sha)
        window.progress(recovery_case, state, 'original_route_restore_intent')
        review(raw_review, expected, recovery_sha)
        pc.restore_file(case, 'original-snippet.conf', Path(cfg['snippet_path']), {host.sha(pc.CLOSED)})
        pc.run([pc.NGINX, '-t'])
        review(raw_review, expected, recovery_sha)
        pc.run([pc.SYSTEMCTL, 'reload', 'nginx.service'])
        pc.wait_public_status(cfg['public_base'], 200, state)
        binding(cfg, plan, fresh_transport=transport)
        require(pc.candidate() == current, 'Original run changed after reopening')
        state.update(phase='original restored', original_restored=True, at=time.time())
        review(raw_review, expected, recovery_sha)
        files.json_new(recovery_case/'recovery.result.json', state)
    except BaseException as error:
        failure = {**state, 'error_type': type(error).__name__, 'operator_reconciliation_required': True}
        if isinstance(error, pc.Refused): failure['reason'] = error.safe_reason
        try: files.json_new(recovery_case/'recovery.failure.json', failure)
        except BaseException: pass
        raise
    return state


def reconcile_recovery(case, expected, recovery_case, recovery_sha):
    cfg, plan = load_recovery(case, expected, recovery_case, recovery_sha)
    progress = host.private_json(recovery_case/'progress.json')
    transport = pc.service(pc.TRANSPORT)
    if inactive(transport): binding(cfg, plan, transport_stopped=True)
    else:
        require(progress.get('transport_start_dispatched') is True, 'Unowned transport start')
        known = progress.get('fresh_transport', transport)
        binding(cfg, plan, fresh_transport=known)
    route = host.sha(network.protected_read(Path(cfg['snippet_path'])))
    require(route in (plan['files']['original-snippet.conf'], host.sha(pc.CLOSED)), 'Foreign recovery route')
    current = host.private_json(host.STATE/'current.json')
    original = plan['snapshot']['record']
    require(current.get('image_id') == original['image_id'] and current.get('release_sha256') == original['release_sha256'],
        'Foreign recovery image or release')
    if current.get('run_id') != original['run_id']:
        require(progress.get('start_dispatched') is True and type(current.get('at')) in (int, float)
            and math.isfinite(current['at']) and current['at'] >= progress['start_at'],
            'Unowned fresh original run')
    value = host.owned(current, host.identifier(current['container_id']))
    return {'schema': 1, 'portal': pc.service(pc.NEW_UNIT), 'transport': transport,
        'current': {key: current.get(key) for key in ('container_id', 'run_id', 'image_id', 'phase')},
        'container_present': value is not None, 'route': 'closed' if route == host.sha(pc.CLOSED) else 'original',
        'observed_public_status': pc.public_status(cfg['public_base'], timeout=1), 'no_actions_performed': True}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('stage', 'run', 'reconcile', 'stage-recovery', 'recover', 'reconcile-recovery'))
    parser.add_argument('--case', type=Path, required=True)
    parser.add_argument('--config', type=Path)
    parser.add_argument('--expected-plan-sha256')
    parser.add_argument('--maintenance-review', type=Path)
    parser.add_argument('--recovery-case', type=Path)
    parser.add_argument('--expected-recovery-plan-sha256')
    args = parser.parse_args()
    require(os.geteuid() == 0 and os.getegid() == 0, 'Root operator required')
    def expired(*unused): raise TimeoutError('Current upgrade shutdown deadline exceeded')
    signal.signal(signal.SIGALRM, expired)
    signal.alarm(300 if args.action == 'recover' else 180 if args.action == 'run' else 120)
    os.umask(0o077); case = files.literal(args.case)
    if args.action == 'stage':
        require(args.config is not None and not args.expected_plan_sha256 and not args.maintenance_review
            and args.recovery_case is None and args.expected_recovery_plan_sha256 is None,
            'Stage requires external B window configuration only')
        result = {'plan_sha256': window.stage(args.config, case), 'shutdown_source_sha256': source_sha(), 'host_mutated': False}
    else:
        require(args.expected_plan_sha256 is not None and args.config is None, 'Exact reviewed plan required')
        if args.action in ('stage-recovery', 'recover', 'reconcile-recovery'):
            require(args.recovery_case is not None, 'Separate recovery case required')
            recovery_case = files.literal(args.recovery_case)
            if args.action == 'stage-recovery':
                require(args.maintenance_review is None and args.expected_recovery_plan_sha256 is None,
                    'Stage recovery requires no activation authority')
                with window.locked(), pc.locked(case):
                    result = {'recovery_plan_sha256': stage_recovery(case, args.expected_plan_sha256, recovery_case),
                              'host_mutated': False}
            else:
                require(args.expected_recovery_plan_sha256 is not None, 'Exact reviewed recovery plan required')
                if args.action == 'recover':
                    require(args.maintenance_review is not None, 'Fresh fixed-original recovery review required')
                    with window.locked(), pc.locked(case), pc.locked(recovery_case):
                        result = recover(case, args.expected_plan_sha256, recovery_case,
                            args.expected_recovery_plan_sha256, args.maintenance_review)
                else:
                    require(args.maintenance_review is None, 'Recovery reconcile is read-only')
                    result = reconcile_recovery(case, args.expected_plan_sha256, recovery_case,
                        args.expected_recovery_plan_sha256)
        elif args.action == 'run':
            require(args.recovery_case is None and args.expected_recovery_plan_sha256 is None, 'Shutdown has no recovery arguments')
            require(args.maintenance_review is not None, 'Fresh shutdown review required')
            with window.locked(), pc.locked(case): result = run(case, args.expected_plan_sha256, args.maintenance_review)
        else:
            require(args.maintenance_review is None and args.recovery_case is None
                and args.expected_recovery_plan_sha256 is None, 'Reconcile performs observations only')
            result = reconcile(case, args.expected_plan_sha256)
    signal.alarm(0)
    print(json.dumps(result, sort_keys=True))


if __name__ == '__main__':
    try: main()
    except SystemExit: raise
    except BaseException as error:
        print('Current upgrade shutdown refused or failed: '+type(error).__name__, file=sys.stderr)
        raise SystemExit(1)
