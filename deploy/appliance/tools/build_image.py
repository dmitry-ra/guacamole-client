#!/usr/bin/env python3
"""Verify selected source-build outputs and assemble the personal appliance."""
import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import subprocess
import time
import zipfile
import xml.etree.ElementTree as ET

HERE = Path(__file__).resolve().parents[1]


def digest(path, algorithm='sha256'):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, algorithm).hexdigest()


def run(command, **kwargs):
    return subprocess.run(list(map(str, command)), check=True,
                          timeout=kwargs.pop('timeout', 120), **kwargs)


def restrict_jdbc(root):
    path = root/'extensions/guacamole-auth-jdbc-postgresql.jar'
    original_sha = digest(path)
    with zipfile.ZipFile(path) as archive:
        names = archive.namelist()
        if len(set(names)) != len(names):
            raise RuntimeError('Duplicate JDBC archive leaf')
        before = {name: archive.read(name) for name in names}
    manifest = before['guac-manifest.json']
    value = json.loads(manifest)
    expected = ['org.apache.guacamole.auth.postgresql.PostgreSQLAuthenticationProvider',
                'org.apache.guacamole.auth.postgresql.PostgreSQLSharedAuthenticationProvider']
    if value['authProviders'] != expected:
        raise RuntimeError('Canonical JDBC providers changed')
    value['authProviders'] = expected[:1]
    replacement = json.dumps(value, sort_keys=True).encode()
    destination = path.with_suffix('.derived.jar')
    with zipfile.ZipFile(destination, 'x', compression=zipfile.ZIP_DEFLATED) as output:
        for name, data in sorted(before.items()):
            entry = zipfile.ZipInfo(name, (2026, 1, 1, 0, 0, 0))
            entry.compress_type = zipfile.ZIP_DEFLATED
            entry.external_attr = 0o100644 << 16
            output.writestr(entry, replacement if name == 'guac-manifest.json' else data)
    with zipfile.ZipFile(destination) as archive:
        if set(archive.namelist()) != set(before):
            raise RuntimeError('Derived JDBC namespace changed')
        for name, data in before.items():
            if archive.read(name) != (replacement if name == 'guac-manifest.json' else data):
                raise RuntimeError('Unexpected JDBC leaf mutation')
    destination.replace(path)
    return {'original_jar_sha256': original_sha, 'derived_jar_sha256': digest(path),
            'original_manifest_sha256': hashlib.sha256(manifest).hexdigest(),
            'derived_manifest_sha256': hashlib.sha256(replacement).hexdigest(),
            'unchanged_leaves': {name: hashlib.sha256(data).hexdigest()
                                 for name, data in before.items() if name != 'guac-manifest.json'}}


def package(source, javac):
    """Compile portal code against the selected source-built application JARs."""
    root = Path('/opt/homelab-web-rdp')
    app = Path('/opt/tomcat/webapps/guacamole')
    jdbc_provenance = restrict_jdbc(root)
    libraries = sorted((app/'WEB-INF/lib').glob('*.jar'))
    libraries += [Path('/opt/tomcat/lib/servlet-api.jar')]
    classes = source/'classes'; classes.mkdir()
    sources = sorted((source/'java').glob('*.java'))
    version = run([javac, '-version'], capture_output=True, text=True).stdout.strip()
    if not re.fullmatch(r'javac 25(?:\.\S+)?', version):
        raise RuntimeError('Java 25 compiler required')
    classpath = os.pathsep.join(map(str, libraries))
    run([javac, '--release', '25', '-cp', classpath, '-d', classes, *sources])
    tests = sorted((source/'java/tests').glob('*.java'))
    if not tests:
        raise RuntimeError('Java acceptance sources missing')
    test_classes = source/'test-classes'; test_classes.mkdir()
    testpath = os.pathsep.join([str(classes), classpath])
    run([javac, '--release', '25', '-cp', testpath, '-d', test_classes, *tests])
    run([javac.with_name('java'), '-cp', os.pathsep.join([str(test_classes), testpath]),
         'org.dmitryra.guacamole.PortalProviderTest'])
    provenance = json.loads((root/'client-source-build.json').read_text())
    guacamole_version = provenance['guacamole_version']
    if not re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+(?:[-.A-Za-z0-9]*)', guacamole_version):
        raise RuntimeError('Invalid selected Guacamole version')
    manifest = {'guacamoleVersion': guacamole_version, 'name': 'Personal Portal',
                'namespace': 'portal',
                'authProviders': ['org.dmitryra.guacamole.PortalAuthenticationProvider'],
                'js': ['target-selection.js'], 'css': ['target-selection.css'],
                'translations': ['translations/en.json']}
    artifacts = [(root/'extensions/portal-auth.jar', True),
                 (app/'WEB-INF/lib/portal-gate.jar', False)]
    for destination, auth in artifacts:
        with zipfile.ZipFile(destination, 'x', compression=zipfile.ZIP_DEFLATED) as jar:
            def put(name, data):
                entry = zipfile.ZipInfo(name, date_time=(2026, 1, 1, 0, 0, 0))
                entry.compress_type = zipfile.ZIP_DEFLATED
                entry.external_attr = 0o100644 << 16
                jar.writestr(entry, data)
            for path in sorted(classes.rglob('*.class')):
                if ('PortalAuthenticationProvider' in path.name) == auth:
                    put(str(path.relative_to(classes)), path.read_bytes())
            if auth:
                put('guac-manifest.json', json.dumps(manifest, sort_keys=True).encode())
                for name in ('target-selection.js', 'target-selection.css', 'translations/en.json'):
                    put(name, (source/'web'/name).read_bytes())
    descriptor = app/'WEB-INF/web.xml'
    text = descriptor.read_text()
    if text.count('<filter>') != 2 or 'PortalGateFilter' in text:
        raise RuntimeError('Unexpected upstream filter descriptor')
    gate = '''<filter>
        <filter-name>portalGateFilter</filter-name>
        <filter-class>org.dmitryra.guacamole.PortalGateFilter</filter-class>
    </filter>
    <filter-mapping>
        <filter-name>portalGateFilter</filter-name>
        <url-pattern>/*</url-pattern>
    </filter-mapping>
    '''
    descriptor.write_text(text.replace('<filter>', gate+'<filter>', 1))
    # The gate lives inside the immutable webapp; retain its exact bytes in the
    # runtime integrity census as well, where startup verifies all entries.
    shutil.copyfile(app/'WEB-INF/lib/portal-gate.jar', root/'portal-gate.jar')
    shutil.copyfile(descriptor, root/'portal-web.xml')
    (root/'portal-build.json').write_text(json.dumps({
        'compiler': version, 'jdbc_manifest_restriction': jdbc_provenance,
        'sources': {str(p.relative_to(source)): digest(p) for p in sources},
        'artifacts': {p.name: digest(p) for p, _ in artifacts}}, sort_keys=True)+'\n')


def regular_input(path):
    if path.is_symlink() or not path.is_file():
        raise RuntimeError('Regular input required: '+str(path))


def verify_and_copy(inputs, destination):
    """Verify external inputs without claiming Git archives are ASF releases."""
    lock = json.loads((HERE/'source-inputs-lock.json').read_text())
    destination.mkdir(mode=0o700)
    for name, record in lock['sources'].items():
        if not re.fullmatch(r'[A-Za-z0-9_.-]+', name):
            raise RuntimeError('Invalid source input name')
        expected = record.get('sha256') or ''
        if not re.fullmatch('[0-9a-f]{64}', expected):
            raise RuntimeError('Reviewed input SHA256 required: '+name)
        path = inputs/name
        regular_input(path)
        if digest(path) != expected:
            raise RuntimeError('Pinned input differs: '+name)
        target = destination/name
        shutil.copyfile(path, target)
        target.chmod(0o644)
        if digest(target) != expected:
            raise RuntimeError('Input changed while freezing: '+name)
    gpg = destination.parent/'gnupg'; gpg.mkdir(mode=0o700)
    key = inputs/'tomcat-KEYS'; regular_input(key)
    # Public-key import and signature verification do not need a private-key
    # agent. Avoid spawning one (including its path-limited Unix sockets).
    run(['gpg', '--no-options', '--no-autostart', '--homedir', gpg, '--batch', '--import', key],
        capture_output=True)
    name = 'apache-tomcat-9.0.123.tar.gz'
    signature = inputs/(name+'.asc'); regular_input(signature)
    result = run(['gpg', '--no-options', '--no-autostart', '--homedir', gpg, '--batch',
                  '--status-fd', '1', '--verify', signature, destination/name],
                 capture_output=True, text=True)
    record = lock['sources'][name]
    if record['signer_fingerprint'] not in re.findall(
            r'\[GNUPG:\] VALIDSIG ([A-F0-9]+)', result.stdout):
        raise RuntimeError('Official Tomcat signer differs')
    if digest(destination/name, 'sha512') != record['release_checksum']['sha512']:
        raise RuntimeError('Official Tomcat release checksum differs')
    server = json.loads((destination/'server-source.json').read_text())
    if (server['commit'] != lock['server']['commit']
            or server['archive_sha256'] != digest(destination/'guacamole-server-source.tar.gz')):
        raise RuntimeError('Server source receipt differs')
    return lock


def freeze_client(build, destination):
    receipt_path = build/'provenance.json'; regular_input(receipt_path)
    receipt_bytes = receipt_path.read_bytes()
    receipt = json.loads(receipt_bytes)
    if (receipt.get('schema') != 1 or receipt.get('status') != 'success'
            or not re.fullmatch('[0-9a-f]{40}', receipt['source']['head'])
            or not re.fullmatch('[0-9a-f]{64}', receipt['source']['tree_sha256'])
            or not re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+(?:[-.A-Za-z0-9]*)',
                                receipt.get('guacamole_version', ''))):
        raise RuntimeError('Successful current-source build receipt required')
    source = receipt['source']
    files = source['files']
    canonical = json.dumps(files, sort_keys=True, separators=(',', ':')).encode('ascii')
    if hashlib.sha256(canonical).hexdigest() != source['tree_sha256']:
        raise RuntimeError('Native source manifest digest differs')
    checkout = HERE.parents[1]
    selected = run(['git', '-C', checkout, 'ls-files', '-z', '--cached',
                    '--others', '--exclude-standard'], capture_output=True).stdout
    native_names = {os.fsdecode(name) for name in selected.split(b'\0') if name}
    native_names = {name for name in native_names
                    if name != 'AGENTS.md' and not name.startswith('deploy/')
                    and ((checkout/name).exists() or (checkout/name).is_symlink())}
    if native_names != set(files):
        raise RuntimeError('Rebuild required; native source namespace changed')
    for name, record in files.items():
        path = PurePosixPath(name)
        if path.is_absolute() or '..' in path.parts or not path.parts:
            raise RuntimeError('Unsafe native source manifest path')
        current = checkout/name; regular_input(current)
        mode = 0o755 if current.stat().st_mode & 0o111 else 0o644
        if digest(current) != record['sha256'] or mode != record['mode']:
            raise RuntimeError('Rebuild required; native source changed: '+name)
    head = run(['git', '-C', checkout, 'rev-parse', 'HEAD'],
               capture_output=True, text=True).stdout.strip()
    if head != source['head']:
        raise RuntimeError('Rebuild required; selected source commit changed')
    if not re.search(r'(?:version |openjdk )"?25(?:\.|[" ])',
                     receipt['toolchain']['java_version']):
        raise RuntimeError('Java 25 source build required')
    revision = ET.parse(checkout/'pom.xml').findtext(
        '{http://maven.apache.org/POM/4.0.0}properties/'
        '{http://maven.apache.org/POM/4.0.0}revision')
    if revision != receipt['guacamole_version']:
        raise RuntimeError('Source build version differs from selected Maven revision')
    expected = {'guacamole.war', 'extensions/guacamole-auth-jdbc-postgresql.jar',
                'extensions/guacamole-auth-totp.jar', 'extensions/guacamole-auth-ban.jar'}
    artifacts = receipt['artifacts']
    schemas = {name for name in artifacts
               if re.fullmatch(r'postgresql/schema/(?:[A-Za-z0-9_.-]+/)*[A-Za-z0-9_.-]+\.sql', name)
               and not any(part in ('.', '..') for part in PurePosixPath(name).parts)}
    schema_prefix = ('extensions/guacamole-auth-jdbc/modules/'
                     'guacamole-auth-jdbc-postgresql/schema/')
    source_schemas = {'postgresql/schema/'+name[len(schema_prefix):]: record
                      for name, record in files.items()
                      if name.startswith(schema_prefix) and name.endswith('.sql')}
    if not schemas or schemas != set(source_schemas) or set(artifacts) != expected | schemas:
        raise RuntimeError('Source-built artifact namespace differs')
    if any(artifacts[name]['sha256'] != source_schemas[name]['sha256'] for name in schemas):
        raise RuntimeError('Source-built SQL differs from native source')
    destination.mkdir(mode=0o700)
    for name, record in artifacts.items():
        source = build/'artifacts'/name; regular_input(source)
        # Reject linked parents, including a linked artifacts directory.
        if any(parent.is_symlink() for parent in source.parents if parent != build.parent):
            raise RuntimeError('Artifact symlink parent refused')
        if source.stat().st_size != record['size'] or digest(source) != record['sha256']:
            raise RuntimeError('Source-built artifact differs: '+name)
        target = destination/name; target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, target); target.chmod(0o644)
        if digest(target) != record['sha256']:
            raise RuntimeError('Artifact changed while freezing: '+name)
    (destination/'client-source-build.json').write_bytes(receipt_bytes)
    return receipt


def build(args):
    os.umask(0o077)
    args.work.mkdir(mode=0o700, parents=True, exist_ok=True)
    frozen = args.work/('attempt-'+str(time.time_ns())); frozen.mkdir(mode=0o700)
    context = frozen/'source'; context.mkdir(mode=0o700)
    names = ['Containerfile', 'runtime.py', 'catalog.py', 'lifecycle.py', 'current_migration.py',
             'krb5-local.conf', 'source-inputs-lock.json',
             'build-provenance.json', 'tools/build_image.py']
    names += [str(p.relative_to(HERE)) for directory in ('java', 'web')
              for p in sorted((HERE/directory).rglob('*')) if p.is_file()]
    hashes = {}
    for name in names:
        path = HERE/name
        if path.is_symlink():
            raise RuntimeError('Source symlink refused')
        target = context/name; target.parent.mkdir(parents=True, exist_ok=True)
        raw = path.read_bytes(); target.write_bytes(raw)
        hashes[name] = hashlib.sha256(raw).hexdigest()
    lock = verify_and_copy(args.inputs, frozen/'release')
    if json.loads((context/'source-inputs-lock.json').read_text()) != lock:
        raise RuntimeError('Source lock changed while freezing')
    client = freeze_client(args.client_build, frozen/'client-source')
    (frozen/'source-sha256.json').write_text(json.dumps(hashes, indent=2)+'\n')
    if args.command == 'verify':
        print(json.dumps({'verified_inputs': len(lock['sources']), 'frozen_context': str(frozen)}))
        return
    command = ['timeout', '--signal=TERM', '--kill-after=15s', '5400s',
               'nice', '-n', '10', 'podman', 'build', '--jobs', '1', '--pull=never',
               '--build-context', 'release='+str((frozen/'release').resolve()),
               '--build-context', 'client_source='+str((frozen/'client-source').resolve()),
               '--tag', args.tag, '--file', context/'Containerfile', context]
    print(json.dumps({'build_log': str(frozen/'build.log'), 'frozen_context': str(frozen)}), flush=True)
    with (frozen/'build.log').open('x') as log:
        run(command, timeout=5430, stdout=log, stderr=subprocess.STDOUT)
    image = json.loads(run(['podman', 'image', 'inspect', args.tag], capture_output=True,
                           text=True).stdout)[0]
    receipt = {'schema': 1, 'image_id': 'sha256:'+image['Id'].removeprefix('sha256:'),
               'tag': args.tag, 'sources': hashes, 'frozen_context': str(frozen),
               'base_image': lock['base_image'], 'apt_snapshot': lock['apt_snapshot'],
               'client_source_head': client['source']['head'],
               'client_source_tree_sha256': client['source']['tree_sha256'],
               'client_provenance_sha256': digest(frozen/'client-source/client-source-build.json'),
               'server_source': lock['server']}
    (frozen/'build-receipt.json').write_text(json.dumps(receipt, indent=2)+'\n')
    print(json.dumps(receipt))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    subs = parser.add_subparsers(dest='command', required=True)
    for name in ('verify', 'build'):
        sub = subs.add_parser(name)
        sub.add_argument('--work', required=True, type=Path)
        sub.add_argument('--inputs', required=True, type=Path)
        sub.add_argument('--client-build', required=True, type=Path)
        sub.add_argument('--tag', default='localhost/private-portal:development')
    sub = subs.add_parser('package')
    sub.add_argument('--source', required=True, type=Path)
    sub.add_argument('--javac', required=True, type=Path)
    args = parser.parse_args()
    if args.command == 'package':
        package(args.source, args.javac)
    else:
        build(args)


if __name__ == '__main__':
    main()
