"""Append SSH targets or hide labels on a restored CURRENT catalog cluster.

No legacy normalization, account recreation, remote authentication or recovery
of a failed destination is provided. Importing this module has no effects.
"""
import copy
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import time

import catalog

JOURNAL = 'current-migration'
MAX_ID = 2147483647
IDENTITY_QUERY = "SELECT json_build_object('entities',(SELECT json_agg(row_to_json(e) ORDER BY entity_id) FROM guacamole_entity e),'users',(SELECT json_agg(row_to_json(u) ORDER BY user_id) FROM guacamole_user u),'attributes',(SELECT json_agg(row_to_json(a) ORDER BY user_id,attribute_name) FROM guacamole_user_attribute a));"


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def require(condition, reason):
    if not condition: raise RuntimeError(reason)


def exact_hash(value):
    require(isinstance(value, str) and re.fullmatch('[a-f0-9]{64}', value), 'Exact configuration SHA256 required')
    return value


def protocol(target):
    # Schema1 is RDP only. The schema2 parser also supplies explicit protocol.
    return getattr(target, 'protocol', 'rdp')


def target_signature(target):
    secret_file = getattr(target,'secret_file',None)
    if secret_file is None:secret_file = getattr(target,'password_file',None)
    return (protocol(target), target.label, target.parameters(),secret_file)


def plan(previous, registry, mapping):
    """Allow an SSH append or an isolated true-to-false label transition."""
    previous.parameters(mapping)
    require(isinstance(mapping, dict) and all(type(i) is int and 1 <= i <= MAX_ID for i in mapping.values())
            and len(set(mapping.values())) == len(mapping), 'Distinct PostgreSQL integer IDs required')
    for name in ('username', 'default_target', 'trusted_proxy_ipv4'):
        require(getattr(previous, name) == getattr(registry, name), 'Existing portal settings must remain unchanged')
    old = {target.alias:target for target in previous.targets}
    new = {target.alias:target for target in registry.targets}
    require(set(old) <= set(new), 'Existing targets cannot be removed or renamed')
    for alias, target in old.items():
        require(target_signature(target) == target_signature(new[alias]), 'Existing target parameters or secret reference changed')
    added = sorted(set(new)-set(old))
    labels_unchanged = previous.publish_target_labels == registry.publish_target_labels
    if added:
        require(labels_unchanged, 'Appending targets cannot change label visibility')
        require(all(protocol(new[a]) == 'ssh' for a in added), 'Only new SSH targets may be appended')
    else:
        require(previous.publish_target_labels is True and registry.publish_target_labels is False,
                'Only an isolated true-to-false label transition may omit new targets')
    require(max(mapping.values()) + len(added) <= MAX_ID, 'PostgreSQL connection ID overflow')
    result = dict(mapping)
    for index, alias in enumerate(added, max(mapping.values())+1): result[alias] = index
    registry.parameters(result)
    return result, added


def normalize(state):
    """Match PostgreSQL's C-collated JSON row ordering for these census arrays."""
    return {key:sorted(value, key=lambda row:json.dumps(row, ensure_ascii=False, sort_keys=True))
            if isinstance(value, list) else value for key,value in state.items()}


def expected_snapshot(before, registry, mapping, added):
    result = copy.deepcopy(before)
    entity = result['entities'][0][0]
    for target in registry.targets:
        if target.alias not in added: continue
        ident = mapping[target.alias]
        result['connections'].append([ident,target.alias,protocol(target),1,1,None,None,None,None,False,None])
        result['parameters'].extend([ident,key,value] for key,value in target.parameters().items())
        result['permissions'].append([entity,ident,'READ'])
    return normalize(result)


def census_expression(query):
    # Complete normalized JSON, including empty group/sharing/admin censuses.
    return ("(SELECT jsonb_object_agg(k,CASE WHEN jsonb_typeof(v)='array' THEN "
            "(SELECT coalesce(jsonb_agg(e ORDER BY e::text COLLATE \"C\"),'[]'::jsonb) "
            "FROM jsonb_array_elements(v) AS a(e)) ELSE v END) FROM jsonb_each(("
            +query.rstrip().removesuffix(';')+")::jsonb) AS p(k,v))")


def transaction(runtime, registry, mapping, added, before, after):
    tables = ('guacamole_entity','guacamole_user','guacamole_user_attribute',
              'guacamole_connection','guacamole_connection_parameter',
              'guacamole_connection_permission','guacamole_user_permission',*runtime.EMPTY_TABLES)
    census = census_expression(runtime.snapshot_query())
    def census_guard(expected, message):
        body = ('BEGIN IF '+census+' IS DISTINCT FROM '
                +runtime.sql(json.dumps(normalize(expected), ensure_ascii=False, sort_keys=True))
                +'::jsonb THEN RAISE EXCEPTION '+runtime.sql(message)+'; END IF; END;')
        # Ordinary SQL string quoting avoids dollar-delimiter injection from
        # an externally configured SSH command. No identity/TOTP is interpolated.
        return 'DO '+runtime.sql(body)+';\n'
    identity = '('+IDENTITY_QUERY.removesuffix(';')+')::jsonb'
    identity_guard = ('BEGIN IF '+identity+' IS DISTINCT FROM (SELECT value FROM portal_current_identity_guard) '
                      "THEN RAISE EXCEPTION 'Identity or TOTP changed'; END IF; END;")
    return ('BEGIN;\nLOCK TABLE '+','.join(sorted(set(tables)))+' IN ACCESS EXCLUSIVE MODE;\n'
            'CREATE TEMP TABLE portal_current_identity_guard ON COMMIT DROP AS SELECT '+identity+' AS value;\n'
            +census_guard(before,'Prior complete census changed')
            +(runtime.target_sql(registry,mapping,set(added))+'\n' if added else '')
            +census_guard(after,'Appended complete census changed')
            +'DO '+runtime.sql(identity_guard)+';\nCOMMIT;')


def fsync_directory(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try: os.fsync(fd)
    finally: os.close(fd)


def write_new(path, raw):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd,'wb') as output:
        os.fchmod(output.fileno(),0o600); output.write(raw); output.flush(); os.fsync(output.fileno())
    fsync_directory(path.parent)


def json_new(path, value):
    write_new(path,(json.dumps(value,sort_keys=True)+'\n').encode())


def prepared_bytes(data):
    fd = os.open(data/'prepared.json',os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd,'rb') as stream:
        info = os.fstat(stream.fileno())
        require(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and info.st_nlink == 1
                and stat.S_IMODE(info.st_mode) == 0o600 and 0 < info.st_size <= 16384,
                'Current root-private single-link preparation receipt required')
        raw = stream.read(16385)
    require(len(raw) <= 16384,'Preparation receipt exceeds bound')
    return raw


def stopped_data(runtime):
    life = runtime.life
    require(not life.PROCESSES and not life.STOP and not (runtime.RUN/'processes.json').exists(),
            'Stopped independent CURRENT restore required')
    for path in (runtime.DATA,runtime.DATA/'pgdata'):
        info = path.lstat()
        require(stat.S_ISDIR(info.st_mode) and info.st_uid == 2000 and info.st_gid == 2000
                and stat.S_IMODE(info.st_mode) == 0o700,'UID/GID2000 mode0700 data required')
    require(not os.path.lexists(runtime.DATA/'pgdata/postmaster.pid'),'Postmaster PID requires operator review')
    fd = os.open(runtime.DATA/'pgdata/PG_VERSION',os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd,'rb') as stream:
        info = os.fstat(stream.fileno())
        require(stat.S_ISREG(info.st_mode) and info.st_uid == 2000 and info.st_nlink == 1
                and not info.st_mode & 0o077 and info.st_size <= 8,'Protected PostgreSQL version required')
        require(stream.read(9) in (b'16',b'16\n'),'PostgreSQL16 required')


def migrate(registry, config_digest, previous_config_path):
    """Runtime entry point. Caller finally shuts down the owned PostgreSQL.

    The host wrapper proves restoration provenance and exclusive mounts. A
    direct in-container call cannot independently establish host provenance.
    Once the journal is reserved, every failed/uncertain target is single-use.
    """
    import runtime
    exact_hash(config_digest)
    previous_config_path = Path(previous_config_path)
    require(previous_config_path.is_absolute() and '..' not in previous_config_path.parts,
            'Absolute protected previous configuration required')
    require(os.statvfs(previous_config_path).f_flag & os.ST_RDONLY,'Read-only previous configuration required')
    raw_config = runtime.protected_read(previous_config_path)
    previous = catalog.parse(json.loads(raw_config,object_pairs_hook=catalog.unique_object))
    previous_digest = digest(raw_config)
    stopped_data(runtime)
    old_raw = prepared_bytes(runtime.DATA)
    old_value = json.loads(old_raw,object_pairs_hook=catalog.unique_object)
    require(isinstance(old_value,dict) and set(old_value)=={'schema','postgres_major','guacamole','config_sha256','connections'}
            and type(old_value['schema']) is int and old_value['schema']==1
            and type(old_value['postgres_major']) is int and old_value['postgres_major']==16
            and old_value['guacamole']=='1.6.0' and old_value['config_sha256']==previous_digest,
            'A current catalog receipt is required; legacy migration is separate')
    mapping = runtime.check_cluster(previous,previous_digest)
    require(old_value == runtime.receipt(mapping,previous_digest),'Prior receipt binding changed')
    new_mapping, added = plan(previous,registry,mapping)
    require(config_digest != previous_digest,'Changed supported catalog required')
    require(prepared_bytes(runtime.DATA) == old_raw,'Prior receipt changed during validation')
    journal = runtime.DATA/JOURNAL
    journal.mkdir(mode=0o700)  # No exist_ok: never replay an attempted destination.
    os.chmod(journal,0o700);fsync_directory(runtime.DATA)
    write_new(journal/'previous-prepared.json',old_raw)
    write_new(journal/'previous-config.json',raw_config)
    intent = {'schema':1,'phase':'intent','started_at':time.time(),
              'previous_config_sha256':previous_digest,'config_sha256':config_digest,
              'previous_prepared_sha256':digest(old_raw),'previous_connections':mapping,'connections':new_mapping}
    json_new(journal/'intent.json',intent)
    primary_error = None
    outcome = {**intent,'migrated':False,'identity_unchanged':False,'enrolled':False}
    try:
        runtime.life.start_pg()
        before = json.loads(runtime.life.pg_sql(runtime.snapshot_query(),app=True),object_pairs_hook=catalog.unique_object)
        runtime.validate_snapshot(previous,mapping,before)
        require(runtime.enrolled(previous),'Confirmed current TOTP identity required')
        identity_before = json.loads(runtime.life.pg_sql(IDENTITY_QUERY,app=True),object_pairs_hook=catalog.unique_object)
        identity_digest = digest(json.dumps(identity_before,sort_keys=True).encode())
        after_expected = expected_snapshot(before,registry,new_mapping,added)
        runtime.validate_snapshot(registry,new_mapping,after_expected)
        require(prepared_bytes(runtime.DATA) == old_raw,'Prior receipt changed before SQL')
        runtime.life.pg_sql(transaction(runtime,registry,new_mapping,added,before,after_expected))
        after = json.loads(runtime.life.pg_sql(runtime.snapshot_query(),app=True),object_pairs_hook=catalog.unique_object)
        runtime.validate_snapshot(registry,new_mapping,after)
        require(normalize(after) == after_expected,'Post-transaction complete census mismatch')
        identity_after = json.loads(runtime.life.pg_sql(IDENTITY_QUERY,app=True),object_pairs_hook=catalog.unique_object)
        require(identity_before == identity_after and runtime.enrolled(registry),'Account or TOTP changed')
        require(runtime.database_health(registry,new_mapping),'Post-migration native database health failed')
        require(prepared_bytes(runtime.DATA) == old_raw,'Prior receipt changed before finalization')
        # SQL and identity are verified before the only prepared.json replacement.
        runtime.save_receipt(new_mapping,config_digest)
        fsync_directory(runtime.DATA)
        require(runtime.check_cluster(registry,config_digest) == new_mapping,'New preparation receipt unconfirmed')
        outcome.update(phase='ready',migrated=True,identity_unchanged=True,enrolled=True,
                       identity_sha256=identity_digest,finished_at=time.time())
    except BaseException as error:
        primary_error = error
        outcome.update(phase='failed',error_type=type(error).__name__,finished_at=time.time())
    try: json_new(journal/'result.json',outcome)
    except BaseException as error:
        if primary_error is None:primary_error = error
        else:primary_error.add_note('Current migration terminal write failed: '+type(error).__name__)
    if primary_error is not None:raise primary_error
    return outcome
