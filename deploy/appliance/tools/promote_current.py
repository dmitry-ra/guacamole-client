#!/usr/bin/env python3
"""Reviewed stopped CURRENT DATA/file promotion; never activates host resources."""
import argparse
import contextlib
import fcntl
import hashlib
import json
import math
import os
from pathlib import Path
import stat
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import catalog
import current_migration
import host
import network
import network_service as bootstrap
import network_upgrade as contract
import cold_copy
import migrate_current
import prepare_instance as files
import upgrade_network
import upgrade_transport_server as transport
import install_terminal_target as terminal

HELPERS = ('host.py', 'catalog.py', 'network_service.py', 'network_upgrade.py')
GATES = {'build', 'auth', 'native-ssh', 'mixed-browser', 'kernel'}
REFS = {'migration', 'restore', 'backup', 'network_plan', 'transport_server_plan',
        'transport_client_plan', 'terminal_plan'}


class Refused(ValueError):
    """Only require() supplies fixed source-controlled diagnostic reasons."""


def require(value, reason):
    if not value: raise Refused(reason)


def sha(raw): return hashlib.sha256(raw).hexdigest()
def load(raw): return json.loads(raw, object_pairs_hook=catalog.unique_object)


def destinations():
    return {'config': host.CONFIG, 'network': host.NETWORK, 'release': host.RELEASE,
            **{name: host.ROOT/name for name in HELPERS}}


def artifact(value):
    catalog.fields(value, {'path', 'sha256'})
    files.literal(value['path']); host.identifier(value['sha256'])
    return value


def read_ref(value, limit=256*1024):
    artifact(value)
    raw = network.protected_read(Path(value['path']), limit)
    require(sha(raw) == value['sha256'], 'Reviewed artifact bytes changed')
    return raw


def metadata(path, missing=False):
    path = files.literal(path); files.protected_directory(path.parent)
    if missing and not os.path.lexists(path): return None
    raw, value = transport.public_file(path, 8*1024*1024)
    return value


def sources():
    paths = [Path(__file__).resolve(), *(Path(m.__file__).resolve() for m in
        (catalog, current_migration, host, network, bootstrap, contract, cold_copy,
         migrate_current, files, upgrade_network, transport, terminal))]
    require(not set(paths) & set(destinations().values()),
            'Run from a protected separate source bundle, not replaced operating modules')
    return {str(path): sha(network.protected_read(path, 8*1024*1024)) for path in paths}


def stopped():
    for unit in ('guacamole-portal.service', 'portal-rdp-transport.service'):
        raw = host.command(['/usr/bin/systemctl', 'show', unit, '--no-pager',
            '--property=LoadState,ActiveState,MainPID'], timeout=5).stdout
        value = dict(line.split('=', 1) for line in raw.decode('ascii').splitlines())
        require(value == {'LoadState': 'loaded', 'ActiveState': 'inactive', 'MainPID': '0'},
                'Both fixed services must already be inactive')
    require(not os.path.lexists(host.PUBLIC/'ready'), 'Portal readiness must already be absent')
    require(not host.engine('ps', '--all', '--no-trunc', '--filter=label='+host.LABEL+'=1',
                            '--format={{.ID}}').stdout.strip(), 'No owned candidate container may remain')


def review(raw, action, binding):
    value = load(raw)
    catalog.fields(value, {'schema', 'operation', 'binding_sha256', 'portal_closed',
        'sessions_cleared', 'closed_route', 'session_census', 'reviewed_at', 'expires_at'})
    require(type(value['schema']) is int and value['schema'] == 1
        and value['operation'] == action and value['binding_sha256'] == binding
        and value['portal_closed'] is True and value['sessions_cleared'] is True
        and all(type(value[k]) in (int, float) and math.isfinite(value[k]) for k in ('reviewed_at', 'expires_at'))
        and value['reviewed_at'] <= time.time() < value['expires_at']
        and 0 < value['expires_at']-value['reviewed_at'] <= 300,
        'Fresh exact closed-route/session review required')
    for key in ('closed_route', 'session_census'): read_ref(value[key])
    require(value['reviewed_at'] <= time.time() < value['expires_at'],
            'Maintenance review expired while checking evidence')
    return value


def specification(value):
    catalog.fields(value, {'schema', 'new_data', 'files', 'primary_gates', *REFS})
    require(type(value['schema']) is int and value['schema'] == 1, 'Promotion input schema1 required')
    files.literal(value['new_data'])
    catalog.fields(value['files'], set(destinations()))
    catalog.fields(value['primary_gates'], GATES)
    for ref in [*value['files'].values(), *value['primary_gates'].values(), *(value[k] for k in REFS)]: artifact(ref)
    return value


def manifest(path):
    cold_copy.validate_cluster(path, require_receipt=True)
    cold_copy.stopped_and_exclusive(path)
    return cold_copy.manifest(path)


def journal_member(data, name):
    require(name in ('previous-prepared.json','previous-config.json','result.json'), 'Fixed migration journal member required')
    # DATA intentionally belongs to PG UID2000. Pin the root-owned journal
    # directory instead of applying an incompatible all-root ancestry rule.
    fd = os.open(data/current_migration.JOURNAL, os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:
        meta = os.fstat(fd)
        require(meta.st_uid == 0 and stat.S_IMODE(meta.st_mode) == 0o700, 'Root-private migration journal required')
        member = os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=fd)
        with os.fdopen(member,'rb') as stream:
            info = os.fstat(stream.fileno())
            require(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and info.st_nlink == 1
                and stat.S_IMODE(info.st_mode) == 0o600 and 0 < info.st_size <= 32768,
                'Bounded private migration journal member required')
            raw = stream.read(32769)
            require(len(raw) <= 32768, 'Migration journal member exceeds bound')
            return raw
    finally: os.close(fd)


def provenance(spec, old_raw, new_raw):
    old_data, new_data = host.PERSIST/'data', Path(spec['new_data'])
    for first, second in ((old_data, new_data), (host.PERSIST/'secrets', new_data), (host.ROOT, new_data)):
        require(not cold_copy.overlaps(first, second), 'Independent restored DATA namespace required')
    files.protected_directory(new_data.parent)
    old_manifest, new_manifest = manifest(old_data), manifest(new_data)
    original = migrate_current.data_identity(old_data); restored = migrate_current.data_identity(new_data)
    require(original != restored and original['device'] == restored['device'], 'Independent same-filesystem DATA required')
    backup, restore, migration = (load(read_ref(spec[k])) for k in ('backup', 'restore', 'migration'))
    backup_data = Path(spec['backup']['path']).parent/'data'
    require(not cold_copy.overlaps(backup_data.parent,old_data)
        and not cold_copy.overlaps(backup_data.parent,new_data), 'Cold backup namespace must be independent of both DATA trees')
    backup_identity = migrate_current.data_identity(backup_data)
    require(len({(v['device'],v['inode']) for v in (original,restored,backup_identity)}) == 3,
            'Original, backup and restored DATA must have distinct identities')
    backup_manifest_raw = files.private_bytes(backup_data.parent/'manifest.json', 64*1024*1024)
    backup_manifest = load(backup_manifest_raw)
    require(backup.get('operation') == 'backup' and backup.get('phase') == 'ready'
        and backup.get('source') == str(old_data) and backup.get('target') == str(backup_data)
        and backup.get('manifest_sha256') == sha(backup_manifest_raw)
        and old_manifest == backup_manifest == manifest(backup_data),
        'Final stopped original must exactly match its complete cold backup')
    require(restore.get('operation') == 'restore' and restore.get('phase') == 'ready'
        and restore.get('for_migration') is False and restore.get('legacy_receipt_archived') is False
        and restore.get('target') == str(new_data) and restore.get('source') == str(backup_data)
        and restore.get('manifest_sha256') == sha(backup_manifest_raw)
        and files.private_bytes(Path(spec['restore']['path']).parent/'manifest.json', 64*1024*1024) == backup_manifest_raw,
        'Exact independent normal CURRENT restore provenance required')
    old_prepared = cold_copy.prepared_receipt(old_data/'prepared.json')
    old_value = load(old_prepared)
    before, after = catalog.parse(load(old_raw['config'])), catalog.parse(load(new_raw['config']))
    mapping, added = current_migration.plan(before, after, old_value['connections'])
    expected = {'schema':1, 'postgres_major':16, 'guacamole':'1.6.0',
                'config_sha256':sha(new_raw['config']), 'connections':mapping}
    proof = migration.get('migration', {})
    require(migration.get('schema') == 1 and migration.get('operation') == 'migrate-current'
        and migration.get('phase') == 'ready' and migration.get('passed') is True
        and migration.get('cleanup_verified') is True and migration.get('data') == str(new_data)
        and migration.get('previous_config_sha256') == sha(old_raw['config'])
        and migration.get('config_sha256') == sha(new_raw['config'])
        and migration.get('image') == load(new_raw['release'])['image_id']
        and migration.get('expected_connections') == mapping and migration.get('added_aliases') == added
        and migration.get('restore') == {'receipt_sha256':spec['restore']['sha256'],
            'manifest_sha256':sha(backup_manifest_raw), 'source':str(backup_data), 'original_source':str(old_data),
            'source_identity':migrate_current.data_identity(backup_data), 'data_identity':restored,
            'prepared_sha256':sha(old_prepared)}
        and set(proof) == migrate_current.RESULT_KEYS and proof.get('phase') == 'ready'
        and migration.get('current_migration_sha256') == proof.get('current_migration_sha256')
        and proof.get('migrated') is True and proof.get('identity_unchanged') is True and proof.get('enrolled') is True
        and proof.get('connections') == mapping and proof.get('previous_connections') == old_value['connections']
        and proof.get('previous_prepared_sha256') == sha(old_prepared)
        and proof.get('previous_config_sha256') == sha(old_raw['config']) and proof.get('config_sha256') == sha(new_raw['config'])
        and old_value['config_sha256'] == sha(old_raw['config'])
        and load(cold_copy.prepared_receipt(new_data/'prepared.json')) == expected,
        'Complete matching CURRENT migration and unchanged identity/TOTP proof required')
    host.identifier(proof['identity_sha256'])
    require(journal_member(new_data,'previous-prepared.json') == old_prepared
        and journal_member(new_data,'previous-config.json') == old_raw['config'],
        'Archived original preparation and configuration changed')
    inner = load(journal_member(new_data,'result.json'))
    require(inner == {k:v for k,v in proof.items() if k != 'current_migration_sha256'},
            'Actual DATA migration journal differs from reviewed completion')
    return {'old_identity':original, 'new_identity':restored, 'old_manifest':old_manifest,
            'new_manifest':new_manifest, 'identity_sha256':proof['identity_sha256'], 'connections':mapping}


def primary_gates(refs, image):
    require(set(refs) == GATES and len({ref['sha256'] for ref in refs.values()}) == len(GATES),
            'Every primary role requires a distinct actual receipt')
    values = {name:load(read_ref(ref)) for name,ref in refs.items()}
    build = values['build']
    require(type(build.get('schema')) is int and build['schema'] == 1 and build.get('image_id') == image
        and isinstance(build.get('sources'),dict) and bool(build['sources'])
        and isinstance(build.get('base_image'),str) and isinstance(build.get('apt_snapshot'),str),
        'Actual frozen build producer receipt required')
    for name,value in values.items():
        if name == 'build': continue
        require(value.get('passed') is True and value.get('cleanup_verified') is True, 'Actual successful primary gate required')
        if name != 'kernel': require(host.inspected_image(value.get('image')) == image, 'Primary image mismatch')
    auth = values['auth']
    required = {'packaged_WAR_startup_hold_and_username_optional_alias_no_password',
        'native_TOTP_challenge_wrong_valid_and_replay_denial','native_authorized_two_connection_tree_and_own_API_logout',
        'real_Angular_dynamic_alias_dropdown_overrides_link_through_native_TOTP',
        'real_Angular_both_selector_URIs_existing_native_token','own_browser_native_logout',
        'packaged_runtime_integrity_configuration_and_enrolled_health'}
    require(auth.get('scope') == 'clean candidate image startup, native HTTP/TOTP and real Angular browser; no RDP endpoint acceptance'
        and isinstance(auth.get('checks'),list) and required <= set(auth['checks'])
        and auth.get('health') == {'database_ready':True,'web_ready':True,'enrolled':True},
        'Actual complete-image native authentication producer evidence required')
    host.identifier(auth.get('fixture_sha256')); host.identifier(auth.get('installed_integrity_sha256'))
    native = values['native-ssh']; checks = native.get('checks',{})
    require(native.get('scope') == 'synthetic native SSH; not browser or JDBC acceptance' and native.get('phase') == 'complete'
        and all(checks.get(k) is True for k in ('ssh_plugin_loadable','none_denied','command_denied',
            'same_process_counter_progress_sentinel_unchanged'))
        and checks.get('wrong_pin',{}).get('outcome') == 'guacd_error' and checks['wrong_pin'].get('status') == 512
        and checks.get('wrong_appkey',{}).get('outcome') == 'guacd_error' and checks['wrong_appkey'].get('status') == 769
        and all(checks.get(k,{}).get('outcome') == 'display_activity' and checks[k].get('status') is None
                and type(checks[k].get('display_instructions')) is int and checks[k]['display_instructions'] > 0
                for k in ('first_connect','reconnect')), 'Actual pinned native SSH denial/persistence producer evidence required')
    def same_process(before,after):
        require(isinstance(before,dict) and isinstance(after,dict) and before.get('sentinel') == after.get('sentinel')
            and isinstance(before.get('sentinel'),dict) and set(before['sentinel']) == {'pid','start'}
            and all(type(v) is int and v > 0 for v in before['sentinel'].values())
            and isinstance(before.get('process'),dict) and isinstance(after.get('process'),dict), 'Actual sentinel/process observations required')
        a,b = before['process'],after['process']
        require(all(type(v.get(k)) is int and v[k] > 0 for v in (a,b) for k in ('pid','start'))
            and all(type(v.get('counter')) is int and v['counter'] >= 0 for v in (a,b))
            and a['pid'] == b['pid'] and a['start'] == b['start'] and a['counter'] < b['counter'],
            'Actual same pane identity and advancing counter required')
    same_process(native.get('process_before'),native.get('process_after'))
    mixed = values['mixed-browser']
    expected_utf8 = sha('synthetic \u0442\u0435\u0441\u0442 \u03bb \u754c'.encode())
    require(mixed.get('scope') == 'complete packaged mixed TOTP/JDBC/SSH browser; RDP alias routing only'
        and mixed.get('phase') == 'complete' and mixed.get('own_logout_204') is True
        and mixed.get('native_refusal_sha256') == refs['native-ssh']['sha256']
        and mixed.get('tree') == [['1','desktop-a'],['2','desktop-b'],['3','terminal-c']]
        and mixed.get('unicode_input_sha256') == expected_utf8
        and mixed.get('unicode_input_mechanism') == 'native Guacamole BMP keyboard events',
        'Actual mixed TOTP/JDBC/BMP UTF-8 browser producer evidence required')
    for key in ('first_canvas','resized_canvas','reconnect_canvas'):
        value = mixed.get(key,{})
        require(all(type(value.get(k)) is int and 0 < value[k] <= 16384 for k in ('width','height'))
            and type(value.get('nonblack')) is int and 1000 < value['nonblack'] <= value['width']*value['height'],
            'Actual mixed SSH canvas observations required')
    a,b = mixed.get('terminal_before_resize',{}).get('process',{}),mixed.get('terminal_after_resize',{}).get('process',{})
    require(all(type(v.get(k)) is int and v[k] > 0 for v in (a,b) for k in ('rows','cols'))
        and (a['rows'],a['cols']) != (b['rows'],b['cols'])
        and a.get('input_sha256') == b.get('input_sha256') == expected_utf8, 'Actual SSH PTY resize and exact input bytes required')
    same_process(mixed.get('terminal_disconnected'),mixed.get('terminal_reconnected'))
    kernel = values['kernel']; actual = kernel.get('result',{})
    require(kernel.get('scope') == 'synthetic isolated kernel namespaces only' and actual.get('passed') is True
        and actual.get('scope') == 'real isolated kernel transactions and packets; no systemd/Podman boot or SSH authentication'
        and isinstance(actual.get('checks'),list) and all(isinstance(v,dict) for v in actual['checks'])
        and {'real_invalid_nft_batch_preserves_old_guard_and_chains','real_guard_and_exact_insertions_preserve_unrelated_rules',
            'added_ssh_gateway_allows_only_app_tuple','real_listener_census_refuses_rollback_without_kernel_mutation',
            'real_reverse_spec_deletion_and_atomic_old_guard_restore'} <= {v.get('check') for v in actual['checks']},
        'Actual isolated additive SSH kernel transaction/packet producer evidence required')
    host.identifier(actual.get('old_guard_sha256')); host.identifier(actual.get('new_guard_sha256'))
    return values


def plans(spec, old_raw, new_raw):
    old_release = host.parse_release(load(old_raw['release']))
    require(old_release['config_sha256'] == sha(old_raw['config'])
        and old_release['network_sha256'] == sha(old_raw['network']), 'Original release/config/network binding changed')
    plan = load(read_ref(spec['network_plan']))
    case = Path(spec['network_plan']['path']).parent
    require(plan.get('operation') == 'add-local-ssh'
        and plan.get('snapshot', {}).get('release_sha256') == sha(old_raw['release']),
        'Exact original release-bound network plan required')
    for name, expected in [('old-catalog.json',old_raw['config']), ('new-catalog.json',new_raw['config']),
                           ('old-network.json',old_raw['network']), ('new-network.json',new_raw['network'])]:
        raw = files.private_bytes(case/name, 128*1024)
        require(raw == expected and sha(raw) == plan['files'][name], 'Network plan input changed')
    p, q = contract.extension(load(old_raw['network']),load(new_raw['network']),load(old_raw['config']),load(new_raw['config']))
    release = host.parse_release(load(new_raw['release']))
    require(release['config_sha256'] == sha(new_raw['config']) and release['network_sha256'] == sha(new_raw['network']),
            'New release must bind exact new configuration and network')
    require(all(release[key] == old_release[key] for key in ('podman_network','backend_loopback_port',
        'apparmor_profile','apparmor_profile_path','apparmor_profile_sha256')),
        'Physical network/backend/AppArmor release bindings must remain unchanged')
    require(sha(network.protected_read(Path(release['apparmor_profile_path']))) == release['apparmor_profile_sha256'],
        'Reviewed unchanged AppArmor source required')
    admission = load(network.protected_read(Path(release['acceptance_evidence_path'])))
    require(sha(network.protected_read(Path(release['acceptance_evidence_path']))) == release['acceptance_evidence_sha256']
        and admission.get('image_id') == release['image_id']
        and admission.get('primary_receipts') == {k:v['sha256'] for k,v in spec['primary_gates'].items()}
        and admission.get('migration_receipt_sha256') == spec['migration']['sha256'],
        'Externally reviewed release evidence must bind actual primary receipts and migration')
    primary_gates(spec['primary_gates'],release['image_id'])
    old_transport = None
    for role in ('server','client'):
        ref = spec['transport_'+role+'_plan']; value = load(read_ref(ref))
        require(value.get('schema') == 1 and value.get('role') == role and value.get('phase') == 'prepared', 'Exact transport role plan required')
        directory = Path(ref['path']).parent
        previous, current = (load(files.private_bytes(directory/name)) for name in ('old.json','new.json'))
        transport.extension(previous,current)
        require(value['old_config_sha256'] == sha(files.private_bytes(directory/'old.json'))
            and value['new_config_sha256'] == sha(files.private_bytes(directory/'new.json')), 'Transport config binding changed')
        if old_transport is not None: require(current == old_transport, 'Server/client new transport catalogs differ')
        old_transport = current
        wanted_paths = {str(transport.ROOT/name) for name in
                        (('sshd.conf','authorized_keys') if role == 'server' else ('client.conf',))}
        require(set(value['files']) == wanted_paths, 'Only fixed role-specific transport files allowed')
        for index, (path, item) in enumerate(value['files'].items()):
            require(set(item) == {'candidate','candidate_sha256','backup','backup_sha256'}
                and item['candidate'] in ('candidate-0','candidate-1') and item['backup'] in ('backup-0','backup-1'),
                'Only fixed candidate/backup archive names allowed')
            require(sha(files.private_bytes(directory/item['candidate'])) == item['candidate_sha256']
                and sha(files.private_bytes(directory/item['backup'])) == item['backup_sha256'], 'Transport candidate/backup changed')
    cfg = network.parse_config(load(new_raw['network']))
    require({(v['listen_address'],v['listen_port']) for v in transport.renderer.normalize(old_transport)['forwards']}
        == set(cfg.local_endpoints), 'Transport listeners must match exact new local policy endpoints')
    terminal_plan = load(read_ref(spec['terminal_plan']))
    directory = Path(spec['terminal_plan']['path']).parent
    require(terminal_plan.get('operation') == 'install-terminal-target', 'Exact terminal installation plan required')
    target_cfg = terminal.configuration(files.private_bytes(directory/'config.json'))
    require(set(terminal_plan['files']) == {'config.json','authorized_keys-backup','public-key','launcher','tmux.conf','authorized_keys-new'}
        and terminal_plan['config_sha256'] == sha(files.private_bytes(directory/'config.json')),
        'Complete terminal candidate/config archives required')
    for name, checksum in terminal_plan['files'].items():
        require(name in {'config.json','authorized_keys-backup','public-key','launcher','tmux.conf','authorized_keys-new'}
            and sha(files.private_bytes(directory/name,256*1024)) == checksum, 'Terminal candidate archive changed')
    ssh = [t for t in catalog.parse(load(new_raw['config'])).targets if t.protocol == 'ssh']
    require(len(ssh) == 1 and ssh[0].username == target_cfg['username'] and ssh[0].command == str(terminal.LAUNCHER),
            'Terminal installation must match the one appended SSH target')
    return p, q, release


def external_guards(spec, old_raw, new_raw):
    p, q, release = plans(spec, old_raw, new_raw)
    selected = {'schema':1, 'podman_network':release['podman_network'],
        'config_sha256':sha(new_raw['config']), 'network_sha256':sha(new_raw['network']), 'policy_hash':network.digest(q)}
    previous = bootstrap.saved()
    require(previous and previous.get('phase') == 'ready' and previous.get('binding') == selected,
            'Completed new bootstrap proof required')
    contract.definition_binding(previous, selected)
    proof_ref = previous['upgrade_proof']; proof = load(read_ref(proof_ref))
    require(proof['plan_sha256'] == spec['network_plan']['sha256'], 'Network completion differs from staged plan')
    cfg = network.parse_config(load(new_raw['network']))
    bootstrap.inspect_network(release['podman_network'],cfg,selected,previous)
    require(bootstrap.inspect_bridge(cfg,selected,previous), 'Exact unchanged owned bridge required')
    bootstrap.empty(release['podman_network'],cfg)
    network.check(q)
    state = network.saved_state(); completed = load(files.private_bytes(Path(spec['network_plan']['path']).parent/'result.json'))
    require(state.get('boot_id') == network.boot_id() and state.get('upgrade_plan_sha256') == spec['network_plan']['sha256']
        and state.get('policy_hash') == network.digest(q) and completed.get('phase') == 'ready'
        and completed.get('guard_hash') == state.get('guard_hash') and completed.get('activated') is False,
        'Actual current network guard must match the completed network operation')
    for role in ('server','client'):
        ref = spec['transport_'+role+'_plan']; plan = load(read_ref(ref))
        result = load(files.private_bytes(Path(ref['path']).parent/'result.json'))
        wanted = {path:item['candidate_sha256'] for path,item in plan['files'].items()}
        require(set(result) == {'schema','phase','role','activated','plan_sha256','files'}
            and result['schema'] == 1 and result['phase'] == 'installed' and result['role'] == role
            and result['activated'] is False and result['plan_sha256'] == ref['sha256'] and result['files'] == wanted,
            'Exact historical transport installation result required')
        if role == 'client':
            for path, checksum in wanted.items():
                require(sha(network.protected_read(Path(path))) == checksum, 'Actual MAIN client transport file changed')
    ref = spec['terminal_plan']; plan = load(read_ref(ref))
    result = load(files.private_bytes(Path(ref['path']).parent/'result.json'))
    require(set(result) == {'schema','phase','plan_sha256','authorized_keys_sha256','authenticated','finished_at'}
        and result['schema'] == 1 and result['phase'] == 'installed' and result['plan_sha256'] == ref['sha256']
        and result['authenticated'] is False and result['authorized_keys_sha256'] == plan['files']['authorized_keys-new'],
        'Exact historical terminal installation result required')


def stage(inputs_path, expected, case, review_path):
    raw = files.private_bytes(inputs_path, 256*1024); require(sha(raw) == expected, 'Exact promotion inputs required')
    spec = specification(load(raw)); approval = files.private_bytes(review_path,16384)
    stopped(); review(approval,'promote-current-stage',expected)
    fixed = destinations(); new_raw = {key:read_ref(ref,8*1024*1024) for key,ref in spec['files'].items()}
    old_meta = {key:metadata(path, key == 'network_upgrade.py') for key,path in fixed.items()}
    old_raw = {key:network.protected_read(path,8*1024*1024) for key,path in fixed.items() if old_meta[key] is not None}
    require(all(Path(ref['path']) not in fixed.values() for ref in spec['files'].values()), 'Separate reviewed source files required')
    require(not cold_copy.overlaps(case,host.PERSIST/'data') and not cold_copy.overlaps(case,Path(spec['new_data']))
        and case.parent.stat().st_dev == (host.PERSIST/'data').stat().st_dev, 'Independent same-filesystem promotion case required')
    require(all(not cold_copy.overlaps(case,Path(spec[key]['path']).parent) for key in ('backup','restore','migration')),
            'Promotion case must not modify backup/restore/migration evidence namespaces')
    require(not cold_copy.overlaps(case,host.PERSIST/'secrets') and not cold_copy.overlaps(case,host.ROOT),
            'Promotion case must remain outside secrets and installed code')
    lineage = provenance(spec,old_raw,new_raw); plans(spec,old_raw,new_raw)
    selected_image = load(new_raw['release'])['image_id']
    inspected = host.one(host.engine('image','inspect',selected_image).stdout)
    require(host.inspected_image(inspected.get('Id')) == selected_image and inspected.get('Architecture') == 'amd64',
            'Exact locally available amd64 candidate image required')
    stopped(); review(approval,'promote-current-stage',expected)
    code = sources(); files.new_directory(case)
    files.write_new(case/'inputs.json',raw)
    for label, values in (('old',old_raw),('new',new_raw)):
        for key, value in values.items(): files.write_new(case/(label+'-'+key),value)
    for key in ('old_manifest','new_manifest'):
        files.json_new(case/(key+'.json'),lineage.pop(key))
    plan = {'schema':1,'operation':'promote-current','inputs_sha256':expected,'old_files':old_meta,
        'new_files':{key:sha(value) for key,value in new_raw.items()},'sources':code,'lineage':lineage,
        'old_manifest_sha256':sha(files.private_bytes(case/'old_manifest.json',64*1024*1024)),
        'new_manifest_sha256':sha(files.private_bytes(case/'new_manifest.json',64*1024*1024))}
    stopped(); review(approval,'promote-current-stage',expected)
    files.json_new(case/'plan.json',plan)
    return sha(files.private_bytes(case/'plan.json',256*1024))


def read_case(case, expected):
    files.protected_directory(case,private=True)
    raw = files.private_bytes(case/'plan.json',256*1024)
    require(sha(raw) == host.identifier(expected), 'Exact independently reviewed promotion plan required')
    plan = load(raw)
    require(plan.get('schema') == 1 and plan.get('operation') == 'promote-current'
        and plan.get('sources') == sources() and set(plan['old_files']) == set(destinations())
        and set(plan['new_files']) == set(destinations()), 'Reviewed promotion/source schema changed')
    spec_raw = files.private_bytes(case/'inputs.json',256*1024)
    require(sha(spec_raw) == plan['inputs_sha256'], 'Promotion input archive changed')
    spec = specification(load(spec_raw))
    old_raw = {key:files.private_bytes(case/('old-'+key),8*1024*1024) for key,meta in plan['old_files'].items() if meta is not None}
    new_raw = {key:files.private_bytes(case/('new-'+key),8*1024*1024) for key in plan['new_files']}
    require(all(sha(raw) == plan['old_files'][key]['sha256'] for key,raw in old_raw.items())
        and all(sha(raw) == plan['new_files'][key] for key,raw in new_raw.items()), 'Promotion file archives changed')
    for label in ('old','new'):
        require(sha(files.private_bytes(case/(label+'_manifest.json'),64*1024*1024)) == plan[label+'_manifest_sha256'],
                'Promotion DATA manifest archive changed')
    return plan, spec, old_raw, new_raw


def data_matches(path, identity, manifest_raw):
    require(migrate_current.data_identity(path) == identity and manifest(path) == load(manifest_raw),
            'Exact stopped DATA identity/full manifest changed')


def replace_file(path, raw, meta, check, case):
    require(path in destinations().values(), 'Only fixed product destination files allowed')
    temporary = path.with_name(path.name+'.promote-current-next')
    require(not os.path.lexists(temporary), 'Unresolved replacement temporary must be reconciled')
    check(); files.write_new(temporary,raw)
    check(); os.chown(temporary, meta['uid'], meta['gid'])
    check(); os.chmod(temporary,meta['mode'])
    with temporary.open('rb') as stream: os.fsync(stream.fileno())
    require(metadata(temporary)['sha256'] == sha(raw), 'Owned replacement temporary changed')
    check(); os.replace(temporary,path); files.fsync_directory(path.parent)


def run(case, expected, review_path, rollback=False):
    plan,spec,old_raw,new_raw = read_case(case,expected)
    action = 'rollback-current' if rollback else 'promote-current-apply'
    approval = files.private_bytes(review_path,16384)
    def check(): stopped(); review(approval,action,expected)
    check()
    intent = case/('rollback-intent.json' if rollback else 'apply-intent.json')
    require(not os.path.lexists(intent), 'Attempted transaction is never replayed')
    old_data, new_data = host.PERSIST/'data', Path(spec['new_data'])
    retained, rejected = case/'original-data', case/'promoted-data'
    old_manifest = files.private_bytes(case/'old_manifest.json',64*1024*1024)
    new_manifest = files.private_bytes(case/'new_manifest.json',64*1024*1024)
    if not rollback:
        require(not os.path.lexists(retained) and not os.path.lexists(rejected), 'Reserved DATA names must be absent')
        require(all(metadata(path,key=='network_upgrade.py') == plan['old_files'][key] for key,path in destinations().items()),
                'Original installed file state changed')
        data_matches(old_data,plan['lineage']['old_identity'],old_manifest)
        data_matches(new_data,plan['lineage']['new_identity'],new_manifest)
        # Recheck actual final backup lineage and every original reviewed source.
        provenance(spec,old_raw,new_raw); external_guards(spec,old_raw,new_raw)
        require(all(not os.path.lexists(path.with_name(path.name+'.promote-current-next'))
                    for path in destinations().values()), 'Unresolved replacement temporary blocks promotion')
    else:
        require(os.path.lexists(case/'apply-intent.json'), 'Only an attempted own promotion can roll back')
        require(not os.path.lexists(rejected), 'Promoted DATA audit destination must be absent')
        if os.path.lexists(retained):
            data_matches(retained,plan['lineage']['old_identity'],old_manifest)
            if os.path.lexists(old_data):
                require(migrate_current.data_identity(old_data) == plan['lineage']['new_identity'],
                        'Foreign DATA at fixed destination blocks rollback')
        else: data_matches(old_data,plan['lineage']['old_identity'],old_manifest)
        new_locations = [path for path in (old_data,new_data) if os.path.lexists(path)
                         and migrate_current.data_identity(path) == plan['lineage']['new_identity']]
        require(len(new_locations) == 1, 'Exactly one original restored DATA identity must remain')
        if os.path.lexists(new_data): data_matches(new_data,plan['lineage']['new_identity'],new_manifest)
        if os.path.lexists(old_data) and migrate_current.data_identity(old_data) == plan['lineage']['new_identity']:
            # A privately tested promoted cluster legitimately gains WAL/history.
            # Retain its exact current tree; never discard it or require stale bytes.
            require(not os.path.lexists(new_data), 'Restored source path unexpectedly reappeared')
            new_manifest = (json.dumps(manifest(old_data),sort_keys=True)+'\n').encode()
            require(load(cold_copy.prepared_receipt(old_data/'prepared.json')) ==
                    {'schema':1,'postgres_major':16,'guacamole':'1.6.0',
                     'config_sha256':sha(new_raw['config']),'connections':plan['lineage']['connections']},
                    'Retained promoted DATA must keep its new preparation binding')
        for key,path in destinations().items():
            meta = metadata(path,key=='network_upgrade.py')
            old = plan['old_files'][key]
            require((meta == old) or (meta is not None and meta['sha256'] == plan['new_files'][key]
                    and meta['mode'] == (old or {'mode':0o600})['mode']
                    and meta['gid'] == (old or {'gid':0})['gid']),
                    'Foreign installed file state cannot be rolled back')
    # Destination state is pinned immediately before every later mutation.
    expected_files = {key:metadata(path,key=='network_upgrade.py') for key,path in destinations().items()}
    basic_check = check
    def check():
        basic_check()
        require(plan['sources'] == sources(), 'Reviewed source bundle changed')
        require(all(metadata(path,key=='network_upgrade.py') == expected_files[key] for key,path in destinations().items()),
                'Installed file state drifted during transaction')
        if not rollback:
            for key,ref in spec['files'].items():
                require(read_ref(ref,8*1024*1024) == new_raw[key], 'Reviewed external source file changed')
        for path in (old_data,new_data,retained):
            if os.path.lexists(path): cold_copy.stopped_and_exclusive(path)
        # All reads above may be slow. Consent and stopped state must still be
        # current when returning directly to a rename/replacement/intent write.
        basic_check()
    check(); files.json_new(intent,{'schema':1,'plan_sha256':expected,'action':action,'started_at':time.time()})
    if rollback:
        check(); files.write_new(case/'rollback-promoted-manifest.json',new_manifest)
    result = {'schema':1,'plan_sha256':expected,'operation':action,'phase':'intent','activated':False}
    def phase(name):
        result['phase'] = name; host.write(case/('rollback-progress.json' if rollback else 'progress.json'),result)
    try:
        if not rollback:
            check(); data_matches(old_data,plan['lineage']['old_identity'],old_manifest)
            phase('retaining_original'); check(); os.rename(old_data,retained); files.fsync_directory(case); files.fsync_directory(old_data.parent)
            data_matches(new_data,plan['lineage']['new_identity'],new_manifest)
            phase('promoting_restored'); check(); os.rename(new_data,old_data); files.fsync_directory(new_data.parent); files.fsync_directory(old_data.parent)
            target = new_raw
        else:
            for key,path in destinations().items():
                temporary = path.with_name(path.name+'.promote-current-next')
                if not os.path.lexists(temporary): continue
                value = metadata(temporary)
                require(value['sha256'] in {sha(raw) for raw in (old_raw.get(key,b''),new_raw[key])}
                    and value['uid'] == 0 and value['mode'] in (0o600,(plan['old_files'][key] or {}).get('mode')),
                    'Foreign replacement temporary cannot be retained')
                target_temp = case/('retained-temp-'+key)
                require(not os.path.lexists(target_temp), 'Retained temporary audit name already exists')
                phase('retaining_temporary_'+key); check(); os.rename(temporary,target_temp)
                files.fsync_directory(path.parent); files.fsync_directory(case)
            if os.path.lexists(retained):
                if os.path.lexists(old_data):
                    data_matches(old_data,plan['lineage']['new_identity'],new_manifest)
                    phase('retaining_promoted'); check(); os.rename(old_data,rejected); files.fsync_directory(case); files.fsync_directory(old_data.parent)
                phase('restoring_original'); check(); os.rename(retained,old_data); files.fsync_directory(case); files.fsync_directory(old_data.parent)
            target = old_raw
        for key in [*HELPERS,'config','network','release']:
            if key not in target: continue  # New unreferenced private helper remains for audit.
            phase(('restoring_' if rollback else 'installing_')+key)
            original = plan['old_files'][key]
            meta = original or {'uid':0,'gid':0,'mode':0o600}
            replace_file(destinations()[key],target[key],meta,check,case)
            expected_files[key] = metadata(destinations()[key])
        data_matches(old_data,plan['lineage']['old_identity' if rollback else 'new_identity'], old_manifest if rollback else new_manifest)
        require(all(metadata(destinations()[key])['sha256'] == sha(raw)
            and metadata(destinations()[key])['mode'] == (plan['old_files'][key] or {'mode':0o600})['mode']
            and metadata(destinations()[key])['gid'] == (plan['old_files'][key] or {'gid':0})['gid']
            for key,raw in target.items()), 'Final installed bytes or modes differ')
        if not rollback: data_matches(retained,plan['lineage']['old_identity'],old_manifest)
        read_case(case,expected)
        check(); phase('rolled-back' if rollback else 'promoted-stopped')
        check()
        files.json_new(case/('rollback-result.json' if rollback else 'result.json'),result)
    except BaseException as error:
        result.update(failure_phase=result['phase'],phase='failed',error_type=type(error).__name__)
        if isinstance(error,Refused): result['failure_reason'] = str(error)
        try: files.json_new(case/('rollback-result.json' if rollback else 'result.json'),result)
        except BaseException as other: error.add_note('Failure receipt: '+type(other).__name__)
        raise
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('operation',choices=('stage','apply','rollback'))
    parser.add_argument('--directory',required=True,type=Path)
    parser.add_argument('--inputs',type=Path); parser.add_argument('--expected-sha256',required=True)
    parser.add_argument('--maintenance-review',required=True,type=Path)
    args = parser.parse_args()
    require(os.geteuid() == 0, 'Root required')
    case = files.literal(args.directory)
    with upgrade_network.locked():
        if args.operation == 'stage':
            require(args.inputs is not None, 'Explicit reviewed input file required')
            result = {'staged':True,'activated':False,'plan_sha256':stage(args.inputs,args.expected_sha256,case,args.maintenance_review)}
        else:
            require(args.inputs is None, 'Apply/rollback consume only the reviewed staged plan')
            result = run(case,args.expected_sha256,args.maintenance_review,args.operation=='rollback')
    print(json.dumps(result,sort_keys=True))


if __name__ == '__main__':
    try: main()
    except SystemExit: raise
    except BaseException as error:
        message = 'Stopped promotion failed: '+type(error).__name__
        if isinstance(error,Refused): message += ': '+str(error)
        print(message,file=sys.stderr)
        raise SystemExit(1)
