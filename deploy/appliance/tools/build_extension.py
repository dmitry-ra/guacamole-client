#!/usr/bin/env python3
"""Compile and test the portal using a successful source build and locked Tomcat."""

import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import re
import subprocess
import tarfile
import zipfile

HERE = Path(__file__).resolve().parents[1]
VERSION = re.compile(r'[0-9]+\.[0-9]+\.[0-9]+(?:[-.A-Za-z0-9]*)')


def run(*args, **kwargs):
    return subprocess.run(list(map(str, args)), check=True,
                          timeout=kwargs.pop('timeout', 120), **kwargs)


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def client_input(directory):
    """Bind the compiler input to a completed source-build artifact receipt."""
    path = directory / 'provenance.json'
    provenance_bytes = path.read_bytes()
    receipt = json.loads(provenance_bytes)
    if receipt.get('schema') != 1 or receipt.get('status') != 'success':
        raise ValueError('Successful source-build provenance required')
    version = receipt.get('guacamole_version', '')
    if not isinstance(version, str) or not VERSION.fullmatch(version):
        raise ValueError('Invalid source-built Guacamole version')
    head = receipt.get('source', {}).get('head', '')
    if not isinstance(head, str) or not re.fullmatch(r'[0-9a-f]{40}', head):
        raise ValueError('Source-build commit identity required')
    tests = receipt.get('tests', [])
    if not tests or any(int(test['errors']) or int(test['failures']) for test in tests):
        raise ValueError('Successful native source tests required')
    war_path = directory / 'artifacts/guacamole.war'
    record = receipt.get('artifacts', {}).get('guacamole.war', {})
    war = war_path.read_bytes()
    war_hash = hashlib.sha256(war).hexdigest()
    if record.get('sha256') != war_hash or record.get('size') != len(war):
        raise ValueError('Source-built WAR differs from provenance')
    return war, version, {'head': head, 'war_sha256': war_hash,
                         'provenance_sha256': hashlib.sha256(provenance_bytes).hexdigest()}


def servlet_input(archive_path, lock_path):
    """Extract only the servlet API from the exact publicly locked Tomcat input."""
    lock_bytes = lock_path.read_bytes()
    lock = json.loads(lock_bytes)
    name = archive_path.name
    if not re.fullmatch(r'apache-tomcat-[0-9.]+\.tar\.gz', name):
        raise ValueError('Locked Tomcat archive filename required')
    expected = lock['sources'].get(name)
    data = archive_path.read_bytes()
    actual = hashlib.sha256(data).hexdigest()
    if not expected or expected.get('sha256') != actual:
        raise ValueError('Tomcat archive differs from public input lock')
    member_name = name.removesuffix('.tar.gz') + '/lib/servlet-api.jar'
    with tarfile.open(fileobj=io.BytesIO(data), mode='r:gz') as archive:
        matches = [member for member in archive if member.name == member_name]
        if len(matches) != 1 or not matches[0].isfile():
            raise ValueError('Unique regular Tomcat servlet API required')
        servlet = archive.extractfile(matches[0]).read()
    return servlet, {'archive_sha256': actual,
                     'servlet_sha256': hashlib.sha256(servlet).hexdigest(),
                     'lock_sha256': hashlib.sha256(lock_bytes).hexdigest()}


def war_libraries(war):
    result = {}
    with zipfile.ZipFile(io.BytesIO(war)) as archive:
        for member in archive.infolist():
            if member.filename.startswith('WEB-INF/lib/') and member.filename.endswith('.jar'):
                name = member.filename.removeprefix('WEB-INF/lib/')
                if not re.fullmatch(r'[A-Za-z0-9._-]+\.jar', name) or name in result:
                    raise ValueError('Unsafe or duplicate WAR library path')
                result[name] = archive.read(member)
    if not result:
        raise ValueError('Source-built WAR libraries missing')
    return result


def write_jar(destination, classes, version, auth):
    with zipfile.ZipFile(destination, 'x', compression=zipfile.ZIP_DEFLATED) as jar:
        def put(name, data):
            entry = zipfile.ZipInfo(name, date_time=(2026, 1, 1, 0, 0, 0))
            entry.compress_type = zipfile.ZIP_DEFLATED
            entry.external_attr = 0o100644 << 16
            jar.writestr(entry, data)
        for path in sorted(classes.rglob('*.class')):
            if ('PortalAuthenticationProvider' in path.name) == auth:
                put(path.relative_to(classes).as_posix(), path.read_bytes())
        if auth:
            manifest = {'guacamoleVersion': version, 'name': 'Personal Portal',
                        'namespace': 'portal',
                        'authProviders': ['org.dmitryra.guacamole.PortalAuthenticationProvider'],
                        'js': ['target-selection.js'], 'css': ['target-selection.css'],
                        'translations': ['translations/en.json']}
            put('guac-manifest.json', json.dumps(manifest, sort_keys=True).encode())
            for name in ('target-selection.js', 'target-selection.css', 'translations/en.json'):
                put(name, (HERE / 'web' / name).read_bytes())


def build(client_build, tomcat_archive, java_home, directory, lock_path):
    war, version, client = client_input(client_build)
    servlet, tomcat = servlet_input(tomcat_archive, lock_path)
    libraries = war_libraries(war)
    javac = java_home / 'bin/javac'
    compiler = run(javac, '-version', capture_output=True, text=True).stdout.strip()
    if not re.fullmatch(r'javac 25(?:\.\S+)?', compiler):
        raise ValueError('Java 25 compiler required')
    os.umask(0o077)
    directory.mkdir(mode=0o700)
    inputs = directory / 'libraries'; inputs.mkdir()
    for name, contents in libraries.items():
        (inputs / name).write_bytes(contents)
    servlet_path = directory / 'servlet-api.jar'
    servlet_path.write_bytes(servlet)
    classpath = os.pathsep.join(map(str, [*sorted(inputs.glob('*.jar')), servlet_path]))
    classes = directory / 'classes'; classes.mkdir()
    sources = sorted((HERE / 'java').glob('*.java'))
    tests = sorted((HERE / 'java/tests').glob('*.java'))
    resources = [HERE / 'web' / name for name in
                 ('target-selection.js', 'target-selection.css', 'translations/en.json')]
    hashes = {str(p.relative_to(HERE)): digest(p) for p in [*sources, *tests, *resources]}
    run(javac, '--release', '25', '-cp', classpath, '-d', classes, *sources)
    test_classes = directory / 'test-classes'; test_classes.mkdir()
    run(javac, '--release', '25', '-cp', os.pathsep.join([str(classes), classpath]),
        '-d', test_classes, *tests)
    result = run(java_home / 'bin/java', '-cp', os.pathsep.join([
                 str(test_classes), str(classes), classpath]),
                 'org.dmitryra.guacamole.PortalProviderTest', capture_output=True, text=True)
    (directory / 'tests.stdout').write_text(result.stdout)
    (directory / 'tests.stderr').write_text(result.stderr)
    for auth, name in ((True, 'portal-auth.jar'), (False, 'portal-gate.jar')):
        write_jar(directory / name, classes, version, auth)
    if hashes != {str(p.relative_to(HERE)): digest(p) for p in [*sources, *tests, *resources]}:
        raise RuntimeError('Portal source changed during compilation')
    receipt = {'schema': 1, 'status': 'success', 'client_build': client,
               'guacamole_version': version, 'tomcat': tomcat, 'compiler': compiler,
               'builder_sha256': digest(Path(__file__)), 'sources': hashes,
               'artifacts': {name: digest(directory / name)
                             for name in ('portal-auth.jar', 'portal-gate.jar')}}
    with (directory / 'receipt.json').open('x') as output:
        json.dump(receipt, output, indent=2)
    print(json.dumps(receipt))
    return receipt


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--client-build', type=Path, required=True)
    parser.add_argument('--tomcat-archive', type=Path, required=True)
    parser.add_argument('--java-home', type=Path, required=True)
    parser.add_argument('--directory', type=Path, required=True)
    parser.add_argument('--input-lock', type=Path, default=HERE / 'source-inputs-lock.json')
    args = parser.parse_args()
    build(args.client_build, args.tomcat_archive, args.java_home, args.directory, args.input_lock)


if __name__ == '__main__':
    main()
