#!/usr/bin/env python3
"""Reviewed, reversible RDP route cutover. No authentication or Windows changes."""
import argparse
import contextlib
import fcntl
import json
import os
from pathlib import Path
import re
import stat
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import host
import catalog
import network
import render_proxy

SYSTEMCTL = '/usr/bin/systemctl'
NGINX = '/usr/sbin/nginx'
NEW_UNIT = 'guacamole-portal.service'
TRANSPORT = 'portal-rdp-transport.service'
RATE = b'limit_req_zone $binary_remote_addr zone=guacamole_portal_auth:1m rate=6r/m;\n'
CLOSED = b'# Reviewed temporary closed portal route.\nlocation = /desktop { return 503; }\nlocation ^~ /desktop/ { return 503; }\n'
PRIMARY_NAMES = {'build', 'auth', 'synthetic-rdp', 'kernel', 'cold-backup',
                 'rehearsal-restore', 'rehearsal-migration', 'promotion-restore',
                 'promotion-migration', 'network-normal', 'transport'}
BROWSER_CHECKS = {'native_username_TOTP', 'authenticated_JDBC_tree',
    'both_aliases_same_native_token_CONNECTED_status0_nonblack', 'native_authenticated_refresh'}
SESSION_PROBE = '''import json,pathlib
n=0
for p in pathlib.Path('/proc').iterdir():
 if not p.name.isdigit(): continue
 try:
  a=(p/'cmdline').read_bytes().split(b'\\0')[0]
  if a.rsplit(b'/',1)[-1]==b'guacd': n+=1
 except (FileNotFoundError,ProcessLookupError): pass
print(json.dumps({'guacd_processes':n}))
'''


class Refused(RuntimeError):
    """Known refusal; only require() marks reviewed source messages safe."""
    safe_reason = None


def require(value, message):
    if not value:
        error = Refused(message)
        error.safe_reason = message
        raise error


def reference(value):
    require(isinstance(value, str) and re.fullmatch('[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}', value),
            'Reviewed operator reference required')
    return value


def literal(value):
    require(isinstance(value, str), 'Literal absolute path required')
    path = Path(value)
    require(path.is_absolute() and '..' not in path.parts and path != Path('/'), 'Literal absolute path required')
    return path


def artifact(value):
    catalog.fields(value, {'path', 'sha256'})
    literal(value['path']); host.identifier(value['sha256'])
    return value


def read_artifact(item):
    artifact(item)
    raw = network.protected_read(Path(item['path']))
    require(host.sha(raw) == item['sha256'], 'Reviewed evidence bytes changed')
    return json.loads(raw, object_pairs_hook=catalog.unique_object)


def parse_config(value):
    catalog.fields(value, {'schema', 'legacy_unit', 'legacy_container', 'legacy_label',
        'legacy_record_path', 'legacy_ready_path', 'legacy_data_path', 'snippet_path',
        'rate_limit_path', 'public_base', 'private_base', 'private_review', 'private_windows',
        'browser_driver_sha256', 'session_clearance_reference', 'private_windows_review_reference'})
    require(type(value['schema']) is int and value['schema'] == 1, 'Cutover schema 1 required')
    for key in ('legacy_unit', 'legacy_container', 'legacy_label'):
        require(isinstance(value[key], str) and re.fullmatch('[a-z][a-z0-9_.-]{0,95}', value[key]),
                'Literal legacy identity required')
    require(value['legacy_unit'].endswith('.service') and value['legacy_unit'] not in (NEW_UNIT, TRANSPORT, 'nginx.service'),
            'Distinct legacy service required')
    for key in ('legacy_record_path', 'legacy_ready_path', 'legacy_data_path', 'snippet_path', 'rate_limit_path'):
        literal(value[key])
    require(Path(value['snippet_path']).parent == Path('/etc/nginx/snippets')
            and Path(value['rate_limit_path']).parent == Path('/etc/nginx/conf.d')
            and value['snippet_path'].endswith('.conf') and value['rate_limit_path'].endswith('.conf'),
            'Dedicated nginx configuration paths required')
    data = Path(value['legacy_data_path'])
    require(data != host.PERSIST/'data' and data not in (host.PERSIST/'data').parents
            and host.PERSIST/'data' not in data.parents, 'Legacy and candidate DATA must be independent')
    url = urllib.parse.urlsplit(value['public_base'])
    require(url.scheme == 'https' and url.hostname and not url.username and not url.password
            and not url.query and not url.fragment and url.path == '/desktop/app/'
            and url.port in (None, 443), 'Normal TLS public application base required')
    private = urllib.parse.urlsplit(value['private_base'])
    require(private.scheme == 'http' and private.hostname in ('127.0.0.1','::1','localhost')
            and private.port is not None and 10000 <= private.port <= 10999
            and not private.username and not private.password and not private.query and not private.fragment
            and private.path == '/guacamole/', 'Exact private loopback application base required')
    artifact(value['private_review']); artifact(value['private_windows'])
    host.identifier(value['browser_driver_sha256']); reference(value['session_clearance_reference'])
    reference(value['private_windows_review_reference'])
    return dict(value)


def deployment(release, release_sha, cid, run_id):
    return {'container_id':host.identifier(cid), 'run_id':host.identifier(run_id,32),
            'image_id':host.image_id(release['image_id']),
            'config_sha256':host.identifier(release['config_sha256']),
            'network_sha256':host.identifier(release['network_sha256']),
            'release_sha256':host.identifier(release_sha)}


def validate_browser(receipt, image, aliases, driver, observed_base, expected_deployment):
    """Actual test_live.py results, not a wrapper containing success flags only."""
    require(isinstance(receipt, dict) and type(receipt.get('schema')) is int and receipt.get('schema') == 1
            and receipt.get('passed') is True and receipt.get('phase') == 'complete'
            and receipt.get('expected_image') == image.removeprefix('sha256:')
            and receipt.get('driver_sha256') == driver
            and BROWSER_CHECKS <= set(receipt.get('checks', [])), 'Complete actual two-Windows browser result required')
    require(receipt.get('observed_base') == observed_base
            and receipt.get('deployment_before') == expected_deployment
            and receipt.get('deployment_after') == expected_deployment,
            'Actual browser origin and unchanged deployment proof required')
    require(all(receipt.get(k) is True for k in ('own_logout_204', 'owned_chrome_group_cleanup', 'owned_profile_removed')),
            'Actual browser logout and cleanup required')
    desktops = receipt.get('desktops')
    require(isinstance(desktops, list) and len(desktops) == 2
            and {d.get('alias') for d in desktops if isinstance(d, dict)} == set(aliases),
            'Both exact catalog aliases must pass')
    clients = []
    for desktop in desktops + [receipt.get('refresh', {})]:
        require(isinstance(desktop, dict) and desktop.get('state') == 'CONNECTED'
                and type(desktop.get('status')) is int and desktop['status'] == 0
                and type(desktop.get('nonblack')) is int and desktop['nonblack'] > 10000
                and type(desktop.get('width')) is int and desktop['width'] > 0
                and type(desktop.get('height')) is int and desktop['height'] > 0,
                'Native connected nonblack desktops and refresh required')
    for desktop in desktops:
        require(isinstance(desktop.get('client_id'), str) and re.fullmatch('[1-9][0-9]*', desktop['client_id']),
                'Native JDBC connection identity required')
        clients.append(desktop['client_id'])
    require(len(set(clients)) == 2, 'Distinct native desktop connections required')
    require(type(receipt.get('started_at')) in (int, float) and type(receipt.get('finished_at')) in (int, float)
            and receipt['finished_at'] >= receipt['started_at'], 'Actual browser timestamps required')


def admission_candidate(cfg, release, registry, sources, private_deployment):
    review = read_artifact(cfg['private_review'])
    require(review.get('schema') == 1 and review.get('scope') == 'private restored rehearsal only'
            and review.get('public_admitted') is False and review.get('image_id') == release['image_id'],
            'Actual private restored review required; it is not public admission')
    primaries = review.get('primary_receipts')
    require(isinstance(primaries, dict) and set(primaries) == {n+'.json' for n in PRIMARY_NAMES},
            'Complete primary rehearsal receipts required')
    root = Path(cfg['private_review']['path']).parent
    for name, digest in primaries.items():
        host.identifier(digest)
        require(host.sha(network.protected_read(root/name)) == digest, 'Primary rehearsal bytes changed')
    aliases = [target.alias for target in registry.targets]
    require(len(aliases) == 2 and all(target.security == 'nla' for target in registry.targets),
            'Current actual-Windows cutover requires two NLA targets')
    windows = read_artifact(cfg['private_windows'])
    validate_browser(windows, release['image_id'], aliases, cfg['browser_driver_sha256'],
                     cfg['private_base'], private_deployment)
    return {'schema': 1, 'scope': 'public RDP candidate pending operator review',
        'public_rdp_admitted': False, 'ssh_tmux_admitted': False,
        'image_id': release['image_id'], 'config_sha256': release['config_sha256'],
        'network_sha256': release['network_sha256'],
        'apparmor_profile_sha256': release['apparmor_profile_sha256'],
        'host_sources': sources, 'private_review': cfg['private_review'],
        'primary_receipts': primaries, 'actual_windows_private': cfg['private_windows'],
        'private_windows_review_reference':cfg['private_windows_review_reference'],
        'private_deployment':private_deployment, 'private_observed_base':cfg['private_base'],
        'browser_driver_sha256': cfg['browser_driver_sha256'], 'aliases': aliases}


def run(argv, timeout=10):
    result = host.command(argv, timeout=timeout, check=False)
    require(result.returncode == 0, 'Host command returned failure')
    return result


def service(unit):
    raw = run([SYSTEMCTL, 'show', unit, '--property=LoadState,ActiveState,SubState,UnitFileState,InvocationID,FragmentPath,MainPID']).stdout
    value = dict(line.split('=', 1) for line in raw.decode().splitlines() if '=' in line)
    require(value.get('LoadState') == 'loaded', 'Installed service required')
    return value


def active(value):
    return value.get('ActiveState') == 'active' and value.get('SubState') == 'running'


def health(cid):
    value = json.loads(run([host.PODMAN, 'exec', cid, 'python3', '-B', host.RUNTIME, 'health'], timeout=5).stdout)
    require(isinstance(value, dict) and all(value.get(k) is True for k in host.COMPONENTS), 'Actual native health required')


def no_sessions(cid):
    value = json.loads(run([host.PODMAN, 'exec', cid, 'python3', '-B', '-c', SESSION_PROBE], timeout=5).stdout)
    require(value == {'guacd_processes': 1}, 'Active or uninspectable desktop sessions; do not stop')


def legacy(cfg, expected_image=None):
    record = host.read_json(Path(cfg['legacy_record_path']))
    cid = host.identifier(record.get('container_id')); instance = host.identifier(record.get('instance'), 32)
    value = host.one(run([host.PODMAN, 'inspect', '--type=container', cid]).stdout)
    image = host.inspected_image(value.get('Image'))
    require(value.get('Id') == cid and value.get('Name', '').lstrip('/') == cfg['legacy_container']
            and value.get('Config', {}).get('Labels', {}).get(cfg['legacy_label']) == '1'
            and value['Config']['Labels'].get(cfg['legacy_label']+'.instance') == instance
            and value.get('State', {}).get('Running') is True
            and (expected_image is None or image == expected_image), 'Exact running legacy consumer required')
    require(any(m.get('Type') == 'bind' and m.get('Source') == cfg['legacy_data_path']
                and m.get('Destination') == '/data' and m.get('RW') is True for m in value.get('Mounts', [])),
            'Legacy DATA mount differs')
    raw = network.protected_read(Path(cfg['legacy_ready_path']))
    require(raw.endswith((instance+'\n').encode()) and len(raw) <= 128, 'Owned legacy readiness marker required')
    prefix = raw[:-33].decode('ascii')
    require(re.fullmatch('[a-z0-9-]+:', prefix), 'Exact legacy marker format required')
    health(cid)
    return {'container_id': cid, 'image_id': image, 'instance': instance, 'marker_prefix': prefix}


def candidate():
    record = host.private_json(host.STATE/'current.json')
    selected, _, binding = host.selection()
    require(record.get('image_id') == selected['image_id'] and record.get('release_sha256') == binding[0],
            'Running candidate must match admitted image and release')
    require(record.get('phase') == 'ready', 'Candidate controller must be ready')
    value = host.owned(record, host.identifier(record.get('container_id')))
    require(value and value.get('State', {}).get('Running') is True and host.ready_owned(record['run_id']),
            'Exact running candidate and owned readiness required')
    health(record['container_id'])
    return record


def source_hashes():
    paths = [host.ROOT/n for n in ('host.py', 'network.py', 'network_service.py', 'network_upgrade.py', 'catalog.py')]
    paths += [Path(__file__).absolute(), Path(render_proxy.__file__).absolute()]
    return {str(path): host.sha(network.protected_read(path)) for path in paths}


def snapshot(cfg):
    release, _, binding = host.selection()
    new = candidate(); old = legacy(cfg)
    units = {u: service(u) for u in (cfg['legacy_unit'], NEW_UNIT, TRANSPORT)}
    require(all(active(v) for v in units.values()), 'Old portal, private candidate and transport must be active')
    require(units[cfg['legacy_unit']]['UnitFileState'] == 'enabled'
            and all(units[u]['UnitFileState'] == 'disabled' for u in (NEW_UNIT, TRANSPORT)),
            'Cutover requires retained old enable and disabled new consumers')
    data = host.directory(Path(cfg['legacy_data_path']), mode=0o700, uid=2000, gid=2000)
    require(tuple(data) != tuple(binding[1]), 'Independent DATA identities required')
    sources = source_hashes()
    for value in units.values():
        path = literal(value['FragmentPath']); sources[str(path)] = host.sha(network.protected_read(path))
    no_sessions(old['container_id']); no_sessions(new['container_id'])
    nginx = run([NGINX, '-T']).stdout
    require(('# configuration file '+cfg['snippet_path']+':').encode() in nginx,
            'Legacy snippet must belong to the actual nginx configuration')
    old_snippet = network.protected_read(Path(cfg['snippet_path']))
    ports = set(re.findall(rb'proxy_pass\s+http://127\.0\.0\.1:([0-9]+)/guacamole/',old_snippet))
    require(len(ports)==1, 'One exact legacy loopback backend required')
    old_port = int(next(iter(ports)))
    require(1024 <= old_port <= 65535, 'Legacy loopback backend port invalid')
    return {'release_sha256': binding[0], 'release': release, 'old': old,
            'new_container_id': new['container_id'], 'new_run_id': new['run_id'],
            'legacy_data_identity': list(data), 'candidate_data_identity': list(binding[1]),
            'nginx_configuration_sha256':host.sha(nginx),
            'legacy_backend_port':old_port,
            'units': units, 'sources': sources}


def write_new(path, raw, mode=0o600):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    with os.fdopen(fd, 'wb') as stream:
        os.fchmod(stream.fileno(), mode); stream.write(raw); stream.flush(); os.fsync(stream.fileno())
    host.sync_directory(path.parent)


def json_new(path, value):
    write_new(path, (json.dumps(value, sort_keys=True)+'\n').encode())


def replace(path, raw, allowed):
    require(host.sha(network.protected_read(path)) in allowed, 'Existing destination differs; no overwrite')
    info = path.lstat()
    require(info.st_nlink == 1 and stat.S_ISREG(info.st_mode) and info.st_uid == 0, 'Single-link owned destination required')
    fd, name = tempfile.mkstemp(prefix='.'+path.name+'-', dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as stream:
            os.fchmod(stream.fileno(), stat.S_IMODE(info.st_mode))
            stream.write(raw); stream.flush(); os.fsync(stream.fileno())
        os.replace(name, path); host.sync_directory(path.parent)
    finally:
        if os.path.exists(name): os.unlink(name)


def stage(config_path, case):
    cfg_raw = network.protected_read(config_path)
    cfg = parse_config(json.loads(cfg_raw, object_pairs_hook=catalog.unique_object))
    current = snapshot(cfg)
    require(not os.path.lexists(Path(cfg['rate_limit_path'])), 'New rate-limit file must not exist')
    registry = catalog.parse(host.read_json(host.CONFIG))
    private_deployment = deployment(current['release'],current['release_sha256'],
                                    current['new_container_id'],current['new_run_id'])
    admission = admission_candidate(cfg, current['release'], registry, current['sources'],private_deployment)
    old_snippet = network.protected_read(Path(cfg['snippet_path']))
    old_release = network.protected_read(host.RELEASE)
    new_snippet = render_proxy.render(registry, current['release']['backend_loopback_port']).encode()
    require(current['release']['acceptance_evidence_path'] == cfg['private_review']['path']
            and current['release']['acceptance_evidence_sha256'] == cfg['private_review']['sha256'],
            'Current private release must bind the reviewed private evidence')
    run([NGINX, '-t'])
    host.directory(case.parent)
    case.mkdir(mode=0o700); host.sync_directory(case.parent)
    host.directory(case, mode=0o700)
    json_new(case/'stage.intent.json', {'schema': 1, 'at': time.time(), 'config_sha256':host.sha(cfg_raw)})
    values = {'config.json':cfg_raw, 'old-snippet.conf':old_snippet, 'old-release.json':old_release,
              'new-snippet.conf':new_snippet, 'new-rate.conf':RATE, 'closed-snippet.conf':CLOSED,
              'admission-candidate.json':(json.dumps(admission, sort_keys=True)+'\n').encode()}
    for unit, value in current['units'].items():
        values['unit-'+unit] = network.protected_read(Path(value['FragmentPath']))
    for name, raw in values.items(): write_new(case/name, raw)
    syntax = (f'pid {case}/syntax.pid; error_log /dev/null crit; events {{}}\nhttp {{ '
              f'include {case}/new-rate.conf; server {{ listen 127.0.0.1:10479; '
              f'include {case}/new-snippet.conf; }} }}\n').encode()
    write_new(case/'syntax.conf', syntax)
    run([NGINX, '-t', '-p', str(case), '-c', str(case/'syntax.conf')])
    plan = {'schema': 1, 'at':time.time(), 'config_sha256':host.sha(cfg_raw), 'snapshot':current,
            'files':{name:host.sha(raw) for name,raw in values.items()},
            'candidate_syntax_tested':True, 'public_switched':False}
    json_new(case/'plan.json', plan)
    return host.sha(network.protected_read(case/'plan.json'))


def load_case(case, expected):
    host.directory(case, mode=0o700); host.identifier(expected)
    raw = network.protected_read(case/'plan.json')
    require(host.sha(raw) == expected, 'Exact reviewed plan SHA required')
    plan = json.loads(raw, object_pairs_hook=catalog.unique_object)
    require(plan.get('schema') == 1, 'Plan schema required')
    for name, digest in plan['files'].items():
        require(re.fullmatch('[a-zA-Z0-9_.-]+', name), 'Literal staged filename required')
        require(host.sha(network.protected_read(case/name)) == digest, 'Staged rollback or candidate bytes changed')
    for path, digest in plan['snapshot']['sources'].items():
        require(host.sha(network.protected_read(Path(path))) == digest, 'Reviewed source or unit changed')
    cfg = parse_config(host.read_json(case/'config.json'))
    return cfg, plan


def progress(case, state, phase):
    state['phase'] = phase; state['at'] = time.time()
    host.write(case/'progress.json', state)


def public_status(base, timeout=8):
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), host.NoRedirect())
    req = urllib.request.Request(base, headers={'Connection':'close'})
    try:
        with opener.open(req, timeout=timeout) as response: return response.status
    except urllib.error.HTTPError as response:
        response.close(); return response.code


def wait_public_status(base, expected, state=None):
    """Read-only GET convergence after reload; never replay a transaction."""
    require(expected in (200, 503), 'Reviewed public status required')
    deadline = time.monotonic() + 5
    if state is not None:
        state['expected_public_status'] = expected
    while True:
        left = deadline - time.monotonic()
        require(left > 0, 'Expected public HTTP status not confirmed within five seconds')
        try:
            status = public_status(base, timeout=min(1, left))
        except (OSError, urllib.error.URLError, TimeoutError):
            status = None
        if state is not None:
            state['last_public_status'] = status if type(status) is int else None
        if status == expected:
            require(time.monotonic() <= deadline, 'Expected public HTTP status not confirmed within five seconds')
            return
        left = deadline - time.monotonic()
        require(left > 0, 'Expected public HTTP status not confirmed within five seconds')
        time.sleep(min(.2, left))


def retain_failure(case, state, error, action):
    """Persist primary provenance before rollback can advance phase/state."""
    state['failure_phase'] = state.get('phase', 'before_mutation')
    state['failure_reason'] = error.safe_reason or 'Unclassified refusal'
    value = {'schema': 1, 'at': time.time(), 'failure_phase': state['failure_phase'],
             'failure_reason': state['failure_reason']}
    for key in ('expected_public_status', 'last_public_status'):
        if key in state:
            value[key] = state[key]
    json_new(case/(action+'.failure.json'), value)


def retain_rollback_failure(case, state, error, action):
    # The already fsynced primary failure remains unchanged even if this write
    # fails. Never copy an arbitrary subprocess message into either receipt.
    value = {'schema': 1, 'at': time.time(), 'failure_phase': state['failure_phase'],
             'failure_reason': state['failure_reason'], 'rollback_error_type': type(error).__name__}
    if isinstance(error, Refused):
        value['rollback_failure_reason'] = error.safe_reason or 'Unclassified refusal'
    try:
        json_new(case/(action+'.rollback-failure.json'), value)
    except Exception:
        state['rollback_diagnostics_unconfirmed'] = True


def reload_nginx():
    run([NGINX, '-t']); run([SYSTEMCTL, 'reload', 'nginx.service'])


def stopped(unit, ready):
    value = service(unit)
    require(value['ActiveState'] in ('inactive', 'failed') and value.get('MainPID') == '0'
            and not os.path.lexists(ready), 'Stopped service and absent readiness must be confirmed')


def restore_file(case, name, path, allowed):
    replace(path, network.protected_read(case/name), allowed)


def rollback_actions(case, cfg, plan, state):
    old_hash, new_hash = plan['files']['old-snippet.conf'], plan['files']['new-snippet.conf']
    if state.get('new_changed'):
        replace(Path(cfg['snippet_path']), CLOSED, {old_hash, new_hash, host.sha(CLOSED)})
        reload_nginx()
        wait_public_status(cfg['public_base'], 503, state)
        if service(NEW_UNIT)['ActiveState'] not in ('inactive','failed'):
            record = host.private_json(host.STATE/'current.json')
            value = host.owned(record,host.identifier(record.get('container_id')))
            require(value and value.get('State',{}).get('Running') is True,
                    'Cannot independently inspect rollback session ownership')
            no_sessions(record['container_id'])
        run([SYSTEMCTL, 'stop', NEW_UNIT], timeout=50)
        stopped(NEW_UNIT, host.PUBLIC/'ready')
    require(list(host.directory(Path(cfg['legacy_data_path']),mode=0o700,uid=2000,gid=2000))
            == plan['snapshot']['legacy_data_identity'], 'Preserved legacy DATA identity changed')
    # Every destination must still be one of this exact case's known values.
    restore_file(case, 'old-snippet.conf', Path(cfg['snippet_path']),
                 {old_hash, new_hash, plan['files']['closed-snippet.conf']})
    rate = Path(cfg['rate_limit_path'])
    if os.path.lexists(rate):
        require(state.get('rate_owned') and host.sha(network.protected_read(rate)) == plan['files']['new-rate.conf'],
                'Foreign rate-limit file must remain untouched')
        rate.unlink(); host.sync_directory(rate.parent)
    if state.get('release_changed'):
        restore_file(case, 'old-release.json', host.RELEASE,
                     {plan['files']['old-release.json'], state['new_release_sha256']})
    reload_nginx()
    old_state = service(cfg['legacy_unit'])
    require(not (state.get('new_changed') and active(old_state)),
            'Unexpected running legacy service after candidate transition; review sessions')
    if not active(old_state):
        started = time.time()
        run([SYSTEMCTL, 'start', cfg['legacy_unit']], timeout=20)
        deadline = time.monotonic()+180
        while True:
            if time.time() >= started+65 and os.path.lexists(cfg['legacy_ready_path']): break
            require(time.monotonic() < deadline, 'Legacy readiness timeout; remain closed')
            time.sleep(1)
        require(host.authentication_ready(plan['snapshot']['legacy_backend_port'],
                [{'name':'username','type':'USERNAME'}]), 'Fresh legacy authentication hold not confirmed')
    legacy(cfg, plan['snapshot']['old']['image_id'])
    require(active(service(cfg['legacy_unit'])), 'Legacy service did not recover')
    if state.get('enablements_changed'):
        for unit, prior in plan['snapshot']['units'].items():
            run([SYSTEMCTL, 'enable' if prior['UnitFileState']=='enabled' else 'disable', unit])
    wait_public_status(cfg['public_base'], 200, state)
    progress(case, state, 'rolled_back')
    json_new(case/'rollback.result.json', {'schema':1, 'restored':True, 'at':time.time(),
                                        'candidate_left_stopped':bool(state.get('new_changed'))})


def contain(case, state):
    """Close only this exact known nginx route; preserve live desktop sessions."""
    try:
        cfg, plan = load_case(case,state['plan_sha256'])
        replace(Path(cfg['snippet_path']), CLOSED,
                {plan['files']['old-snippet.conf'],plan['files']['new-snippet.conf'],host.sha(CLOSED)})
        reload_nginx()
        wait_public_status(cfg['public_base'], 503, state)
    except Exception:
        state['containment_unconfirmed'] = True
    try: progress(case, state, 'uncertain_operator_review_required')
    except Exception: pass


def switch(case, expected, review_reference):
    reference(review_reference)
    cfg, plan = load_case(case, expected)
    require(not os.path.lexists(case/'switch.intent.json'), 'Existing switch intent; no replay')
    require(snapshot(cfg) == plan['snapshot'], 'Live cutover bindings changed since staging')
    require(not os.path.lexists(cfg['rate_limit_path']), 'Rate-limit destination appeared')
    registry = catalog.parse(host.read_json(host.CONFIG))
    private_deployment = deployment(plan['snapshot']['release'],plan['snapshot']['release_sha256'],
                                    plan['snapshot']['new_container_id'],plan['snapshot']['new_run_id'])
    candidate_admission = admission_candidate(cfg, plan['snapshot']['release'], registry,
                                             plan['snapshot']['sources'],private_deployment)
    require(candidate_admission == host.read_json(case/'admission-candidate.json'), 'Fresh admission evidence differs')
    state = {'schema':1, 'plan_sha256':expected, 'review_reference':review_reference}
    json_new(case/'switch.intent.json', state)
    try:
        progress(case, state, 'closing_public_route')
        replace(Path(cfg['snippet_path']), CLOSED, {plan['files']['old-snippet.conf']})
        reload_nginx()
        wait_public_status(cfg['public_base'], 503, state)
        no_sessions(plan['snapshot']['old']['container_id']); no_sessions(plan['snapshot']['new_container_id'])
        progress(case, state, 'stopping_legacy')
        run([SYSTEMCTL, 'stop', cfg['legacy_unit']], timeout=50)
        stopped(cfg['legacy_unit'], cfg['legacy_ready_path'])
        progress(case, state, 'stopping_private_candidate')
        state['new_changed'] = True; progress(case, state, 'candidate_stop_intent')
        run([SYSTEMCTL, 'stop', NEW_UNIT], timeout=50)
        stopped(NEW_UNIT, host.PUBLIC/'ready')
        admission = {**candidate_admission, 'scope':'reviewed public RDP deployment; SSH/tmux pending',
                     'public_rdp_admitted':True, 'review_reference':review_reference, 'plan_sha256':expected}
        json_new(case/'admission.json', admission)
        release = {**plan['snapshot']['release'], 'acceptance_evidence_path':str(case/'admission.json'),
                   'acceptance_evidence_sha256':host.sha(network.protected_read(case/'admission.json'))}
        release_raw = (json.dumps(release, sort_keys=True)+'\n').encode()
        state.update(release_changed=True, new_release_sha256=host.sha(release_raw))
        progress(case, state, 'release_rebind_intent')
        replace(host.RELEASE, release_raw, {plan['files']['old-release.json']})
        started = time.time(); progress(case, state, 'fresh_candidate_start')
        run([SYSTEMCTL, 'start', NEW_UNIT], timeout=140)
        current = candidate()
        require(active(service(NEW_UNIT)) and active(service(TRANSPORT))
                and current['container_id'] != plan['snapshot']['new_container_id']
                and current['run_id'] != plan['snapshot']['new_run_id']
                and current.get('ready_at', 0) >= started+65,
                'Fresh supervised candidate and 65-second replay hold required')
        selected, _, binding = host.selection()
        require(binding[0] == state['new_release_sha256'] and host.authentication_ready(
            selected['backend_loopback_port'], binding[4]), 'Fresh candidate authentication gate failed')
        state['candidate_run_id'] = current['run_id']; state['candidate_cid'] = current['container_id']
        progress(case, state, 'selecting_public_candidate')
        state['rate_owned'] = True; progress(case, state, 'rate_install_intent')
        write_new(Path(cfg['rate_limit_path']), RATE, mode=0o644)
        replace(Path(cfg['snippet_path']), network.protected_read(case/'new-snippet.conf'), {host.sha(CLOSED)})
        reload_nginx()
        wait_public_status(cfg['public_base'], 200, state)
        candidate(); require(active(service(TRANSPORT)), 'Transport health lost')
        progress(case, state, 'awaiting_actual_public_acceptance')
        json_new(case/'switch.result.json', {**state, 'public_switched':True, 'enabled_new':False,
                                            'legacy_disabled':False})
    except Refused as error:
        try:
            retain_failure(case, state, error, 'switch')
        except Exception:
            contain(case, state)
            raise Refused('Known switch failure; diagnostic persistence unconfirmed') from None
        try: rollback_actions(case, cfg, plan, state)
        except Exception as rollback_error:
            retain_rollback_failure(case, state, rollback_error, 'switch')
            contain(case, state)
            raise Refused('Known switch failure; rollback unconfirmed, inspect receipts') from None
        raise Refused('Known switch failure; rollback confirmed') from None
    except BaseException:
        contain(case, state)
        raise


def accept(case, expected, review):
    cfg, plan = load_case(case, expected)
    require(not os.path.lexists(case/'accept.intent.json'), 'Existing acceptance intent; no replay')
    state = host.read_json(case/'progress.json')
    require(state.get('phase') == 'awaiting_actual_public_acceptance', 'Successful switch required')
    proof = read_artifact(review)
    catalog.fields(proof, {'schema', 'scope', 'plan_sha256', 'public_base', 'browser', 'operator_reference'})
    reference(proof['operator_reference'])
    require(proof['schema'] == 1 and proof['scope'] == 'actual public RDP acceptance'
            and proof['plan_sha256'] == expected and proof['public_base'] == cfg['public_base'],
            'Reviewed actual public browser binding required')
    require(proof['browser'] != cfg['private_windows'], 'Independent public browser result required')
    receipt = read_artifact(proof['browser'])
    expected_deployment = deployment(plan['snapshot']['release'],state['new_release_sha256'],
                                    state['candidate_cid'],state['candidate_run_id'])
    validate_browser(receipt, plan['snapshot']['release']['image_id'],
        host.read_json(case/'admission.json')['aliases'], cfg['browser_driver_sha256'],
        cfg['public_base'],expected_deployment)
    require(receipt['started_at'] >= host.read_json(case/'switch.result.json')['at'], 'Public browser must run after route selection')
    current = candidate()
    _, _, binding = host.selection()
    require(binding[0] == state['new_release_sha256']
            and list(binding[1]) == plan['snapshot']['candidate_data_identity']
            and host.sha(network.protected_read(Path(cfg['snippet_path']))) == plan['files']['new-snippet.conf']
            and host.sha(network.protected_read(Path(cfg['rate_limit_path']))) == plan['files']['new-rate.conf'],
            'Exact accepted admission, DATA and public route required')
    require(current['run_id'] == state['candidate_run_id'] and current['container_id'] == state['candidate_cid'],
            'Publicly tested candidate changed')
    require(active(service(TRANSPORT)) and public_status(cfg['public_base']) == 200,
            'Actual candidate/transport/public health required before enable')
    json_new(case/'accept.intent.json', {'schema':1, 'review':review, 'plan_sha256':expected})
    state['enablements_changed'] = True; progress(case, state, 'enabling_accepted_consumers')
    try:
        run([SYSTEMCTL, 'enable', NEW_UNIT, TRANSPORT])
        candidate(); require(active(service(TRANSPORT)), 'Transport lost after enable')
        require(all(service(u)['UnitFileState']=='enabled' for u in (NEW_UNIT, TRANSPORT)), 'New enablements unconfirmed')
        run([SYSTEMCTL, 'disable', cfg['legacy_unit']])
        require(service(cfg['legacy_unit'])['UnitFileState']=='disabled', 'Legacy disable unconfirmed')
        progress(case, state, 'accepted')
        json_new(case/'accept.result.json', {'schema':1, 'accepted':True, 'at':time.time(),
                                          'review':review, 'ssh_tmux_admitted':False})
    except Refused as error:
        try:
            retain_failure(case, state, error, 'accept')
        except Exception:
            contain(case, state)
            raise Refused('Acceptance failure; diagnostic persistence unconfirmed') from None
        try: rollback_actions(case, cfg, plan, state)
        except Exception as rollback_error:
            retain_rollback_failure(case, state, rollback_error, 'accept')
            contain(case, state)
            raise Refused('Acceptance enable failure; rollback unconfirmed') from None
        raise Refused('Acceptance enable failure; rollback confirmed') from None
    except BaseException:
        contain(case, state); raise


@contextlib.contextmanager
def locked(case):
    host.directory(case, mode=0o700)
    fd = os.open(case/'lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        info = os.fstat(fd)
        require(info.st_uid == 0 and stat.S_ISREG(info.st_mode) and info.st_nlink == 1
                and stat.S_IMODE(info.st_mode)==0o600, 'Private root case lock required')
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB); yield
    finally: os.close(fd)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('stage', 'switch', 'accept', 'rollback'))
    parser.add_argument('--case', required=True, type=Path)
    parser.add_argument('--config', type=Path)
    parser.add_argument('--expected-plan-sha256')
    parser.add_argument('--review-reference')
    parser.add_argument('--public-review', type=Path)
    parser.add_argument('--public-review-sha256')
    args = parser.parse_args()
    require(os.geteuid() == 0, 'Root operator required')
    os.umask(0o077)
    case = literal(str(args.case))
    require(re.fullmatch('/[A-Za-z0-9_./-]+', str(case)) and '..' not in case.parts,
            'Simple protected case path required for nginx syntax fixture')
    if args.action == 'stage':
        require(args.config is not None, 'External reviewed config required')
        digest = stage(args.config, case)
        print(json.dumps({'staged':True, 'public_switched':False, 'plan_sha256':digest})); return
    require(args.expected_plan_sha256 is not None, 'Exact reviewed plan SHA required')
    with locked(case):
        if args.action == 'switch':
            switch(case, args.expected_plan_sha256, args.review_reference)
        elif args.action == 'accept':
            require(args.public_review is not None and args.public_review_sha256 is not None,
                    'Actual reviewed public acceptance evidence required')
            accept(case, args.expected_plan_sha256, {'path':str(args.public_review), 'sha256':args.public_review_sha256})
        else:
            reference(args.review_reference)
            cfg, plan = load_case(case, args.expected_plan_sha256)
            require(not os.path.lexists(case/'rollback.intent.json')
                    and not os.path.lexists(case/'rollback.result.json'), 'Prior rollback must not be replayed')
            state = host.read_json(case/'progress.json')
            if active(service(NEW_UNIT)): no_sessions(candidate()['container_id'])
            json_new(case/'rollback.intent.json', {'reference':args.review_reference, 'at':time.time()})
            rollback_actions(case, cfg, plan, state)
    print(json.dumps({'completed':True, 'action':args.action, 'case_retained':True}))


if __name__ == '__main__':
    try: main()
    except SystemExit:
        raise
    except BaseException as error:
        # Fixed exception type only: no subprocess stderr, URLs, credentials or payloads.
        print('Cutover refused or failed: '+type(error).__name__, file=sys.stderr)
        raise SystemExit(1)
