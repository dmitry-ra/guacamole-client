"""Personal portal supervisor. Configuration and all credentials are external."""
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
import stat
import struct
import subprocess
import sys
import time
import urllib.request

import catalog
import lifecycle as life

ROOT = life.ROOT
DATA = life.DATA
RUN = life.RUN
CONFIG = Path('/config/config.json')
SECRETS = Path('/secrets')
sql = life.sql


def protected_read(path, *, uid=0, private=False, limit=131072):
    """Open without following a final symlink; parents must also be protected."""
    path = Path(path)
    for parent in path.parents:
        info = parent.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise RuntimeError('Root-owned protected parent directory required')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        info = os.fstat(stream.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != uid
                or info.st_mode & (0o077 if private else 0o022)
                or info.st_nlink != 1 or info.st_size > limit):
            raise RuntimeError('Protected regular file required')
        value = stream.read(limit + 1)
    if len(value) > limit:
        raise RuntimeError('File exceeds size limit')
    return value


def configuration():
    if not os.statvfs(CONFIG).f_flag & os.ST_RDONLY:
        raise RuntimeError('Read-only configuration mount required')
    raw = protected_read(CONFIG)
    result = catalog.parse(json.loads(raw, object_pairs_hook=catalog.unique_object))
    return result, hashlib.sha256(raw).hexdigest()


def secret(name):
    if not re.fullmatch('[a-zA-Z0-9][a-zA-Z0-9_-]*', name):
        raise RuntimeError('Literal secret filename required')
    value = protected_read(SECRETS / name, private=True, limit=4096).decode().rstrip('\n')
    if not 16 <= len(value) <= 512 or any(c in value for c in '\r\n\x00'):
        raise RuntimeError('Invalid secret encoding or length')
    return value


def target_secret(name):
    if not re.fullmatch('[a-zA-Z0-9][a-zA-Z0-9_-]*', name):
        raise RuntimeError('Literal secret filename required')
    raw = protected_read(SECRETS / name, private=True, limit=512)
    if not 1 <= len(raw) <= 512 or any(c in raw for c in (b'\r', b'\n', b'\x00')):
        raise RuntimeError('Invalid target secret encoding or length')
    return raw.decode('utf-8')


def ssh_private_key(name):
    if not re.fullmatch('[a-zA-Z0-9][a-zA-Z0-9_-]*', name):
        raise RuntimeError('Literal secret filename required')
    raw = protected_read(SECRETS / name, private=True, limit=16384)
    if not 0 < len(raw) <= 16384:
        raise RuntimeError('Bounded SSH private key required')
    try:
        value = raw.decode('ascii')
        match = re.fullmatch(r'-----BEGIN OPENSSH PRIVATE KEY-----\n([A-Za-z0-9+/=\n]+)-----END OPENSSH PRIVATE KEY-----\n?', value)
        if not match:
            raise ValueError()
        data = base64.b64decode(match[1].replace('\n', ''), validate=True)
        magic = b'openssh-key-v1\0'
        if not data.startswith(magic):
            raise ValueError()
        def field(data, offset):
            if offset+4 > len(data):
                raise ValueError()
            size = struct.unpack_from('>I', data, offset)[0]
            end = offset+4+size
            if end > len(data):
                raise ValueError()
            return data[offset+4:end], end
        offset = len(magic)
        cipher, offset = field(data, offset)
        kdf, offset = field(data, offset)
        options, offset = field(data, offset)
        if cipher != b'none' or kdf != b'none' or options or data[offset:offset+4] != b'\0\0\0\1':
            raise ValueError()
        public, offset = field(data, offset+4)
        private, offset = field(data, offset)
        kind, end = field(public, 0)
        public_key, end = field(public, end)
        if offset != len(data) or kind != b'ssh-ed25519' or len(public_key) != 32 or end != len(public):
            raise ValueError()
        if len(private) < 8 or private[:4] != private[4:8] or len(private) % 8:
            raise ValueError()
        kind, end = field(private, 8)
        repeated, end = field(private, end)
        private_key, end = field(private, end)
        _, end = field(private, end)  # Comment is never exposed.
        padding = private[end:]
        if (kind != b'ssh-ed25519' or repeated != public_key or len(private_key) != 64
                or private_key[32:] != public_key or not 1 <= len(padding) <= 8
                or padding != bytes(range(1, len(padding)+1))):
            raise ValueError()
    except (ValueError, UnicodeError, struct.error, IndexError):
        raise RuntimeError('Unencrypted single Ed25519 OpenSSH private key required') from None
    return value


def target_credential(target):
    return target_secret(target.secret_file) if target.protocol == 'rdp' else ssh_private_key(target.secret_file)


# PostgreSQL helpers use the same strictly validated secret source.
life.secret = secret


def integrity():
    manifest = json.loads(protected_read(ROOT / 'integrity.json'))
    if set(manifest) != {'schema', 'files'} or manifest['schema'] != 1 or not manifest['files']:
        raise RuntimeError('Invalid build integrity manifest')
    for name, expected in manifest['files'].items():
        path = Path(name)
        if path.is_absolute() or '..' in path.parts or not re.fullmatch('[a-f0-9]{64}', expected):
            raise RuntimeError('Invalid build integrity entry')
        if hashlib.sha256(protected_read(ROOT / path, limit=64*1024*1024)).hexdigest() != expected:
            raise RuntimeError('Build integrity mismatch')


def write_private(path, value, uid=0):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'w') as stream:
        os.fchown(stream.fileno(), uid, uid)
        stream.write(value)
        stream.flush()
        os.fsync(stream.fileno())


# This identifies the prepared PostgreSQL schema, not the running client build.
# The selected main has no SQL schema changes from 1.6.0. Keep existing prepared
# DATA bindings intact; exact running source/version belongs to image provenance.
def receipt(mapping, digest):
    return {'schema': 1, 'postgres_major': 16, 'guacamole': '1.6.0',
            'config_sha256': digest, 'connections': mapping}


def save_receipt(mapping, digest):
    path = DATA / 'prepared.json'
    temporary = DATA / ('prepared-' + secrets.token_hex(8) + '.json')
    write_private(temporary, json.dumps(receipt(mapping, digest)) + '\n')
    os.replace(temporary, path)


def check_cluster(registry, digest):
    # Data belongs to the PostgreSQL UID, so its parent cannot satisfy the
    # root-owned mount rule used for configuration/credentials. Database health
    # below always verifies the persisted mapping against the complete census.
    path = DATA / 'prepared.json'
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd) as stream:
        st = os.fstat(stream.fileno())
        if not stat.S_ISREG(st.st_mode) or st.st_uid != 0 or st.st_mode & 0o077 or st.st_size > 16384:
            raise RuntimeError('Protected prepare receipt required')
        value = json.load(stream)
    mapping = value.get('connections')
    registry.parameters(mapping)
    if value != receipt(mapping, digest):
        raise RuntimeError('Prepared release/config binding mismatch')
    return mapping


def target_sql(registry, mapping, aliases=None):
    statements = []
    for target in registry.targets:
        if aliases is not None and target.alias not in aliases:
            continue
        ident = mapping[target.alias]
        statements.append(f"INSERT INTO guacamole_connection(connection_id,connection_name,protocol,max_connections,max_connections_per_user) VALUES({ident},{sql(target.alias)},{sql(target.protocol)},1,1);")
        for key, value in target.parameters().items():
            statements.append(f'INSERT INTO guacamole_connection_parameter VALUES({ident},{sql(key)},{sql(value)});')
        statements.append(f"INSERT INTO guacamole_connection_permission SELECT entity_id,{ident},'READ' FROM guacamole_entity WHERE name={sql(registry.username)} AND type='USER';")
    statements.append("SELECT setval(pg_get_serial_sequence('guacamole_connection','connection_id'),(SELECT max(connection_id) FROM guacamole_connection));")
    return '\n'.join(statements)


def prepare_sql(registry, mapping, dbpass, portalpass, schema):
    salt = secrets.token_bytes(32)
    digest = hashlib.sha256(portalpass.encode() + salt.hex().upper().encode()).hexdigest()
    name = sql(registry.username)
    return ('BEGIN;\n' + schema + f"\nCREATE ROLE guacamole LOGIN PASSWORD {sql(dbpass)};\n"
            + f"INSERT INTO guacamole_entity(name,type) VALUES({name},'USER');\n"
            + f"INSERT INTO guacamole_user(entity_id,password_hash,password_salt,password_date) SELECT entity_id,decode('{digest}','hex'),decode('{salt.hex()}','hex'),CURRENT_TIMESTAMP FROM guacamole_entity WHERE name={name} AND type='USER';\n"
            + target_sql(registry, mapping)
            + f"\nINSERT INTO guacamole_user_permission SELECT e.entity_id,u.user_id,'READ' FROM guacamole_entity e JOIN guacamole_user u USING(entity_id) WHERE e.name={name};\n"
            + 'GRANT SELECT,INSERT,UPDATE,DELETE ON ALL TABLES IN SCHEMA public TO guacamole;\nGRANT USAGE,SELECT ON ALL SEQUENCES IN SCHEMA public TO guacamole;\nCOMMIT;')


def prepare(registry, digest):
    if DATA.is_symlink() or not DATA.is_dir() or list(DATA.iterdir()):
        raise RuntimeError('Prepare requires a new empty data mount')
    st = DATA.stat()
    if st.st_uid != life.UIDS['pg'] or stat.S_IMODE(st.st_mode) != 0o700:
        raise RuntimeError('Data mount requires uid2000 mode0700')
    dbpass, portalpass = secret('db-password'), secret('portal-password')
    mapping = {t.alias: index for index, t in enumerate(registry.targets, 1)}
    life.runtime_dirs()
    life.command([life.PG/'initdb', '-D', DATA/'pgdata', '--username=webpg', '--auth-local=peer', '--auth-host=scram-sha-256', '--encoding=UTF8', '--locale=C.UTF-8'], user='pg', timeout=60, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    life.start_pg(True)
    life.command(['psql', '-h', RUN/'pg', '-U', 'webpg', '-d', 'postgres', '-X', '-v', 'ON_ERROR_STOP=1'], user='pg', input='CREATE DATABASE guacamole;', text=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    life.pg_sql(prepare_sql(registry, mapping, dbpass, portalpass, (ROOT/'schema/001-create-schema.sql').read_text()))
    database_health(registry, mapping)
    save_receipt(mapping, digest)


EMPTY_TABLES = ('guacamole_system_permission', 'guacamole_user_group',
                'guacamole_user_group_member', 'guacamole_user_group_attribute',
                'guacamole_user_group_permission', 'guacamole_connection_group',
                'guacamole_connection_group_permission', 'guacamole_connection_group_attribute',
                'guacamole_sharing_profile', 'guacamole_sharing_profile_parameter',
                'guacamole_sharing_profile_permission', 'guacamole_sharing_profile_attribute',
                'guacamole_connection_attribute')


def snapshot_query():
    parts = {
        'entities': "SELECT coalesce(json_agg(json_build_array(entity_id,name,type)), '[]') FROM guacamole_entity",
        'users': "SELECT coalesce(json_agg(json_build_array(user_id,entity_id,disabled,expired)), '[]') FROM guacamole_user",
        'connections': "SELECT coalesce(json_agg(json_build_array(connection_id,connection_name,protocol,max_connections,max_connections_per_user,parent_id,proxy_hostname,proxy_port,proxy_encryption_method,failover_only,connection_weight)), '[]') FROM guacamole_connection",
        'parameters': "SELECT coalesce(json_agg(json_build_array(connection_id,parameter_name,parameter_value)), '[]') FROM guacamole_connection_parameter",
        'permissions': "SELECT coalesce(json_agg(json_build_array(entity_id,connection_id,permission)), '[]') FROM guacamole_connection_permission",
        'user_permissions': "SELECT coalesce(json_agg(json_build_array(entity_id,affected_user_id,permission)), '[]') FROM guacamole_user_permission",
    }
    parts.update({t: 'SELECT count(*) FROM ' + t for t in EMPTY_TABLES})
    return 'SELECT json_build_object(' + ','.join(sql(k) + ',(' + v + ')' for k, v in parts.items()) + ');'


def validate_snapshot(registry, mapping, state):
    registry.parameters(mapping)
    if len(state['entities']) != 1 or len(state['users']) != 1:
        raise RuntimeError('Exactly one portal identity required')
    entity, name, kind = state['entities'][0]
    user, user_entity, disabled, expired = state['users'][0]
    if (name, kind, user_entity, disabled, expired) != (registry.username, 'USER', entity, False, False):
        raise RuntimeError('Portal identity changed')
    expected = sorted([[mapping[t.alias], t.alias, t.protocol, 1, 1, None, None, None, None, False, None] for t in registry.targets])
    if sorted(state['connections']) != expected:
        raise RuntimeError('Connection census differs from registry')
    params = sorted([[ident, key, value] for ident, values in registry.parameters(mapping).items() for key, value in values.items()])
    if sorted(state['parameters']) != params:
        raise RuntimeError('Connection parameters differ from registry')
    if sorted(state['permissions']) != sorted([[entity, ident, 'READ'] for ident in mapping.values()]):
        raise RuntimeError('Unexpected connection permissions')
    if state['user_permissions'] != [[entity, user, 'READ']] or any(state[t] != 0 for t in EMPTY_TABLES):
        raise RuntimeError('Unexpected administrative, group or sharing state')
    return True


def database_health(registry, mapping):
    return validate_snapshot(registry, mapping, json.loads(life.pg_sql(snapshot_query(), app=True)))


def valid_totp_key(value):
    if not isinstance(value, str) or re.fullmatch('[A-Z2-7]{32}', value) is None:
        return False
    try:
        raw = base64.b32decode(value.rstrip('=') + '=' * ((-len(value.rstrip('='))) % 8))
    except ValueError:
        return False
    return len(raw) == 20 and base64.b32encode(raw).decode().rstrip('=') == value.rstrip('=')


def enrolled(registry):
    attrs = json.loads(life.pg_sql("SELECT coalesce(json_object_agg(attribute_name,attribute_value),'{}') FROM guacamole_user_attribute a JOIN guacamole_user u USING(user_id) JOIN guacamole_entity e USING(entity_id) WHERE e.name=" + sql(registry.username) + ";", app=True))
    return (attrs.get('guac-totp-key-confirmed') == 'true'
            and attrs.get('guac-totp-disabled') != 'true'
            and valid_totp_key(attrs.get('guac-totp-key-secret')))


def migrate(registry, digest, original_alias):
    """Only a stopped/copied legacy cluster is eligible; never recreate identity."""
    if life.PROCESSES or (RUN/'processes.json').exists():
        raise RuntimeError('Migration requires an independently copied stopped cluster')
    registry.target(original_alias)
    if (DATA/'prepared.json').exists():
        raise RuntimeError('Migration destination already has a current receipt')
    life.start_pg()
    state = json.loads(life.pg_sql(snapshot_query(), app=True))
    # Validate the legacy singleton with its original human-readable name and
    # password token normalized solely for comparison; never relax endpoint pins.
    single = catalog.Catalog(registry.username, original_alias, False, (registry.target(original_alias),))
    if len(state['connections']) != 1 or state['connections'][0][0] != 1:
        raise RuntimeError('Legacy original connection must retain ID1')
    state['connections'][0][1] = original_alias
    for row in state['parameters']:
        if row[1] == 'password':
            if row[2] != '${HOMELAB_WINDOWS_PASSWORD}':
                raise RuntimeError('Unexpected legacy credential reference')
            row[2] = single.targets[0].parameters()['password']
    validate_snapshot(single, {original_alias: 1}, state)
    if not enrolled(registry):
        raise RuntimeError('Confirmed legacy TOTP must be retained')
    mapping = {original_alias: 1}
    for t in registry.targets:
        if t.alias != original_alias:
            mapping[t.alias] = len(mapping) + 1
    target = registry.target(original_alias)
    query = "BEGIN;\nLOCK TABLE guacamole_connection IN ACCESS EXCLUSIVE MODE;\n"
    query += f'UPDATE guacamole_connection SET connection_name={sql(original_alias)} WHERE connection_id=1;\n'
    query += f"UPDATE guacamole_connection_parameter SET parameter_value={sql(target.parameters()['password'])} WHERE connection_id=1 AND parameter_name='password';\n"
    query += target_sql(registry, mapping, set(mapping)-{original_alias}) + '\nCOMMIT;'
    life.pg_sql(query)
    database_health(registry, mapping)
    if not enrolled(registry):
        raise RuntimeError('Migration enrollment check failed')
    save_receipt(mapping, digest)


def property_value(value):
    # java.util.Properties consumes backslash escapes and leading spaces.
    return ''.join('\\u%04x' % ord(c) if c in '\\:=#! ' or ord(c) > 126 else c for c in value)


def tomcat_server_xml(trusted_proxy_ipv4=None):
    valve = ''
    if trusted_proxy_ipv4 is not None:
        valve = ('<Valve className="org.apache.catalina.valves.RemoteIpValve" '
                 'internalProxies="' + re.escape(trusted_proxy_ipv4) + '" '
                 'remoteIpHeader="X-Forwarded-For" protocolHeader="X-Forwarded-Proto"/>')
    return ('<Server port="-1"><Service name="Catalina"><Connector address="0.0.0.0" '
            'port="8080" protocol="HTTP/1.1" connectionTimeout="20000" '
            'URIEncoding="UTF-8" maxThreads="30"/><Engine name="Catalina" '
            'defaultHost="localhost"><Host name="localhost" '
            'appBase="/opt/tomcat/webapps" unpackWARs="false" autoDeploy="false">'
            + valve + '</Host></Engine></Service></Server>')


def configure_java(registry, mapping):
    life.runtime_dirs()
    home = RUN/'guacamole'
    life.mkdir(home, 2001)
    for name in ('extensions', 'lib'):
        (home/name).symlink_to(ROOT/name)
    for target in registry.targets:
        write_private(RUN/'java'/('target-' + target.alias + '-' + target.secret_parameter), target_credential(target), 2001)
    properties = [
        'guacd-hostname: 127.0.0.1', 'guacd-port: 4822',
        'postgresql-hostname: 127.0.0.1', 'postgresql-port: 5432',
        'postgresql-database: guacamole', 'postgresql-username: guacamole',
        'postgresql-password: ' + property_value(secret('db-password')),
        'postgresql-auto-create-accounts: false', 'postgresql-user-required: true',
        'extension-priority: portal, postgresql, totp, ban',
        'portal-user: ' + registry.username,
        'portal-targets: ' + ','.join(t.alias for t in registry.targets),
        'portal-publish-target-labels: ' + str(registry.publish_target_labels).lower(),
        'totp-issuer: Personal portal', 'totp-digits: 6', 'totp-period: 30', 'totp-mode: sha1',
        'ban-max-invalid-attempts: 5', 'ban-address-duration: 300',
    ]
    properties.extend('portal-target-' + t.alias + '-id: ' + str(mapping[t.alias]) for t in registry.targets)
    properties.extend('portal-target-' + t.alias + '-protocol: ' + t.protocol for t in registry.targets)
    write_private(home/'guacamole.properties', '\n'.join(properties) + '\n', 2001)
    tomcat = RUN/'tomcat'
    life.mkdir(tomcat, 2001)
    shutil.copytree('/opt/tomcat/conf', tomcat/'conf')
    for name in ('logs', 'temp', 'work'):
        life.mkdir(tomcat/name, 2001)
    (tomcat/'conf/server.xml').write_text(tomcat_server_xml(registry.trusted_proxy_ipv4))
    (tomcat/'conf/logging.properties').write_text('handlers=java.util.logging.ConsoleHandler\n.level=WARNING\njava.util.logging.ConsoleHandler.level=WARNING\n')
    for path in (tomcat/'conf').rglob('*'):
        os.chown(path, 2001, 2001)
        os.chmod(path, 0o700 if path.is_dir() else 0o600)
    os.chown(tomcat/'conf', 2001, 2001)
    os.chmod(tomcat/'conf', 0o700)


def lease():
    if os.environ.get('WEB_RDP_PRODUCTION') == '1':
        if 'WEB_RDP_DURATION_SECONDS' in os.environ or 'WEB_RDP_DEADLINE_EPOCH' in os.environ:
            raise RuntimeError('Production and finite lease modes cannot be combined')
        return math.inf, math.inf
    duration = float(os.environ['WEB_RDP_DURATION_SECONDS'])
    epoch = float(os.environ['WEB_RDP_DEADLINE_EPOCH'])
    left = min(duration, epoch-time.time())
    if not math.isfinite(duration) or not math.isfinite(epoch) or not 0 < duration <= 600 or left <= 0:
        raise RuntimeError('Finite original fixture lease required')
    return time.monotonic()+left, epoch


def serve(registry, digest):
    deadline, epoch = lease()
    mapping = check_cluster(registry, digest)
    life.start_pg()
    database_health(registry, mapping)
    configure_java(registry, mapping)
    if life.STOP or time.monotonic() >= deadline or time.time() >= epoch:
        raise RuntimeError('Lease expired during startup')
    life.PROCESSES['guacd'] = life.start_process('guacd', ['/opt/guacamole/sbin/guacd', '-f', '-b', '127.0.0.1', '-l', '4822', '-L', 'warning'], 'guacd', env=dict(os.environ, HOME=str(RUN/'guacd'), KRB5_CONFIG=str(ROOT/'krb5-local.conf')))
    env = dict(os.environ, CATALINA_HOME='/opt/tomcat', CATALINA_BASE=str(RUN/'tomcat'), GUACAMOLE_HOME=str(RUN/'guacamole'), JAVA_HOME='/opt/java', HOME=str(RUN/'java'), CATALINA_OPTS='-Xms64m -Xmx512m -XX:MaxMetaspaceSize=192m -Djava.awt.headless=true -Djava.io.tmpdir=/run/web-rdp/tomcat/temp')
    life.PROCESSES['java'] = life.start_process('java', ['/opt/tomcat/bin/catalina.sh', 'run'], 'java', env=env)
    write_private(RUN/'processes.json', json.dumps({'supervisor': os.getpid(), 'java': life.PROCESSES['java'].pid, 'guacd': life.PROCESSES['guacd'].pid}))
    while not life.STOP and time.monotonic() < deadline and time.time() < epoch:
        if any(proc.poll() is not None for proc in life.PROCESSES.values()):
            raise RuntimeError('Required component exited')
        managed = {proc.pid for proc in life.PROCESSES.values()}
        for child in Path('/proc').iterdir():
            if not child.name.isdigit() or int(child.name) in managed:
                continue
            try:
                fields = (child/'stat').read_text().rsplit(')', 1)[1].split()
                if int(fields[1]) == os.getpid() and fields[0] == 'Z':
                    os.waitpid(int(child.name), os.WNOHANG)
            except (OSError, ValueError, ChildProcessError):
                pass
        time.sleep(.05)


def health(registry, digest):
    result = {'database_ready': False, 'web_ready': False, 'enrolled': False}
    try:
        mapping = check_cluster(registry, digest)
        result['database_ready'] = database_health(registry, mapping)
        result['enrolled'] = enrolled(registry)
    except Exception:
        pass
    try:
        with urllib.request.urlopen('http://127.0.0.1:8080/guacamole/', timeout=2) as response:
            result['web_ready'] = response.status == 200
    except OSError:
        pass
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=('prepare', 'migrate', 'migrate-current', 'serve', 'health'))
    parser.add_argument('--original-alias')
    parser.add_argument('--previous-config', type=Path)
    args = parser.parse_args()
    os.umask(0o077)
    if os.geteuid() != 0:
        raise RuntimeError('Root container supervisor required')
    signal.signal(signal.SIGTERM, life.stopped)
    signal.signal(signal.SIGINT, life.stopped)
    integrity()
    registry, digest = configuration()
    if args.command == 'health':
        print(json.dumps(health(registry, digest)))
        return
    try:
        if args.command == 'prepare':
            prepare(registry, digest)
        elif args.command == 'migrate':
            migrate(registry, digest, args.original_alias)
        elif args.command == 'migrate-current':
            if args.previous_config is None:
                raise RuntimeError('Previous protected configuration required')
            import current_migration
            print(json.dumps(current_migration.migrate(registry, digest, args.previous_config)))
        else:
            serve(registry, digest)
    finally:
        life.shutdown()


if __name__ == '__main__':
    try:
        main()
    except Exception as exc:
        print(json.dumps({'failed': True, 'error_type': type(exc).__name__}), file=sys.stderr)
        sys.exit(1)
