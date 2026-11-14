#!/usr/bin/env python3
"""Freeze selected client source and build actual WAR/extensions with JDK25."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import signal
import stat
import subprocess
import tarfile
import urllib.request
import xml.etree.ElementTree as ET

MAVEN_VERSION = '3.9.12'
MAVEN_SHA512 = ('0a1be79f02466533fc1a80abbef8796e4f737c46c6574ede5658b110899942a94d'
                'b634477dfd3745501c80aef9aac0d4f841d38574373f7e2d24cce89d694f70')
MAVEN_URL = ('https://archive.apache.org/dist/maven/maven-3/' + MAVEN_VERSION
             + '/binaries/apache-maven-' + MAVEN_VERSION + '-bin.tar.gz')
MODULES = ['guacamole', 'extensions/guacamole-auth-jdbc/modules/guacamole-auth-jdbc-postgresql',
           'extensions/guacamole-auth-totp', 'extensions/guacamole-auth-ban']


def digest(path, algorithm='sha256'):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, algorithm).hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':')).encode('ascii')


def run(command, **kwargs):
    return subprocess.check_output(command, timeout=60, **kwargs)


def freeze(checkout, destination):
    """Snapshot tracked and nonignored untracked files; refuse links/specials."""
    head = run(['git', '-C', str(checkout), 'rev-parse', 'HEAD'], text=True).strip()
    status = run(['git', '-C', str(checkout), 'status', '--porcelain=v1', '-z'])
    names = run(['git', '-C', str(checkout), 'ls-files', '-z', '--cached',
                 '--others', '--exclude-standard']).split(b'\0')
    destination.mkdir()
    files = {}
    for raw in sorted(set(names) - {b''}):
        name = os.fsdecode(raw)
        relative = Path(name)
        if relative.is_absolute() or '..' in relative.parts:
            raise ValueError('Unsafe source path')
        source = checkout / relative
        # Deleted tracked files are a legitimate selected-source modification.
        if not source.exists() and not source.is_symlink():
            continue
        metadata = source.lstat()
        if not stat.S_ISREG(metadata.st_mode) or any(
                parent.is_symlink() for parent in source.parents if parent != checkout.parent):
            raise ValueError('Source links/special files are unsupported: ' + name)
        before = digest(source)
        target = destination / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, target)
        mode = 0o755 if metadata.st_mode & 0o111 else 0o644
        target.chmod(mode)
        if digest(target) != before or digest(source) != before:
            raise RuntimeError('Source changed while freezing: ' + name)
        files[name] = {'sha256': before, 'mode': mode}
    return {'head': head, 'tree_sha256': hashlib.sha256(canonical(files)).hexdigest(),
            'files': files, 'git_status_sha256': hashlib.sha256(status).hexdigest()}


def split_native_source(source, downstream, identity):
    """Keep independent appliance code outside the upstream Maven/RAT tree."""
    complete = identity['files']
    excluded = {name: value for name, value in complete.items()
                if name == 'AGENTS.md' or name.startswith('deploy/')}
    native = {name: value for name, value in complete.items() if name not in excluded}
    downstream.mkdir()
    for name in ('deploy', 'AGENTS.md'):
        path = source / name
        if path.exists():
            path.rename(downstream / name)
    identity.update(files=native,
                    tree_sha256=hashlib.sha256(canonical(native)).hexdigest(),
                    downstream_files=excluded,
                    downstream_tree_sha256=hashlib.sha256(canonical(excluded)).hexdigest(),
                    selected_tree_sha256=hashlib.sha256(canonical(complete)).hexdigest())
    return identity


def maven(cache):
    cache.mkdir(parents=True, exist_ok=True)
    archive = cache / ('apache-maven-' + MAVEN_VERSION + '-bin.tar.gz')
    if not archive.exists():
        partial = archive.with_suffix('.download')
        with urllib.request.urlopen(MAVEN_URL, timeout=45) as response, partial.open('xb') as output:
            shutil.copyfileobj(response, output)
        if digest(partial, 'sha512') != MAVEN_SHA512:
            raise RuntimeError('Maven archive checksum mismatch')
        partial.rename(archive)
    if archive.is_symlink() or digest(archive, 'sha512') != MAVEN_SHA512:
        raise RuntimeError('Maven archive checksum mismatch')
    # Extract each attempt from verified bytes; never trust cached executable files.
    return archive


def bounded_build(command, source, environment, log, timeout):
    with log.open('xb') as output:
        process = subprocess.Popen(command, cwd=source, env=environment,
                                   stdout=output, stderr=subprocess.STDOUT,
                                   start_new_session=True)
        try:
            result = process.wait(timeout=timeout)
        except BaseException:
            os.killpg(process.pid, signal.SIGTERM)
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait(timeout=10)
            raise
    if result:
        raise RuntimeError('Maven failed; inspect build.log (exit ' + str(result) + ')')


def collect(source, artifacts):
    ns = {'m': 'http://maven.apache.org/POM/4.0.0'}
    version = ET.parse(source / 'pom.xml').findtext('m:properties/m:revision', namespaces=ns)
    if not version or '/' in version or '\\' in version:
        raise ValueError('Invalid Maven revision')
    selected = {'guacamole.war': source / 'guacamole/target' / ('guacamole-' + version + '.war')}
    for module in MODULES[1:]:
        name = Path(module).name
        selected['extensions/' + name + '.jar'] = source / module / 'target' / (name + '-' + version + '.jar')
    schema = source / MODULES[1] / 'schema'
    for path in schema.rglob('*.sql'):
        selected['postgresql/schema/' + path.relative_to(schema).as_posix()] = path
    if len(selected) < 6:
        raise RuntimeError('SQL schema artifacts missing')
    artifacts.mkdir()
    records = {}
    for name, path in sorted(selected.items()):
        if path.is_symlink() or not path.is_file():
            raise RuntimeError('Expected build artifact missing: ' + name)
        target = artifacts / name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(path, target)
        records[name] = {'sha256': digest(target), 'size': target.stat().st_size}
    return records


def build(args):
    checkout = args.checkout.resolve(strict=True)
    work = args.work.absolute()
    if work == checkout or checkout in work.parents:
        raise ValueError('Build work must be outside selected checkout')
    work.mkdir(mode=0o700)
    receipt = {'schema': 1, 'status': 'started'}
    try:
        source = work / 'source'
        receipt['source'] = split_native_source(
            source, work / 'downstream-source', freeze(checkout, source))
        receipt['builder_sha256'] = digest(Path(__file__))
        receipt['guacamole_version'] = ET.parse(source / 'pom.xml').findtext(
            '{http://maven.apache.org/POM/4.0.0}properties/'
            '{http://maven.apache.org/POM/4.0.0}revision')
        environment = dict(os.environ, JAVA_HOME=str(args.java_home))
        environment['PATH'] = str(args.java_home / 'bin') + os.pathsep + os.environ['PATH']
        for tool in ('java', 'javac', 'javadoc'):
            executable = args.java_home / 'bin' / tool
            if not executable.is_file() or not os.access(executable, os.X_OK):
                raise RuntimeError('Complete JDK25 required; missing ' + tool)
        java = run([str(args.java_home / 'bin/java'), '-version'], stderr=subprocess.STDOUT,
                   text=True).strip()
        if not java.splitlines()[0].startswith('openjdk version "25.'):
            raise RuntimeError('JDK25 required')
        archive = maven(args.maven_cache)
        with tarfile.open(archive) as bundle:
            bundle.extractall(work / 'toolchain', filter='data')
        executable = work / 'toolchain' / ('apache-maven-' + MAVEN_VERSION) / 'bin/mvn'
        receipt['toolchain'] = {'java_version': java,
                               'maven_version': run([str(executable), '-version'], env=environment, text=True).strip(),
                               'maven_archive_sha512': MAVEN_SHA512, 'maven_url': MAVEN_URL}
        command = [str(executable), '-B', '-T1', '-Dmaven.repo.local=' + str(args.maven_repository),
                   '-Dproject.build.outputTimestamp=2026-01-01T00:00:00Z',
                   '-pl', ','.join(MODULES), '-am', 'package']
        receipt['command'] = command
        (work / 'source-manifest.json').write_bytes(canonical(receipt['source']) + b'\n')
        bounded_build(command, source, environment, work / 'build.log', args.timeout)
        receipt['artifacts'] = collect(source, work / 'artifacts')
        receipt['tests'] = []
        for path in sorted(source.rglob('target/surefire-reports/TEST-*.xml')):
            report = ET.parse(path).getroot()
            receipt['tests'].append({key: report.attrib[key] for key in
                                     ('name', 'tests', 'failures', 'errors', 'skipped')})
        if not receipt['tests'] or any(int(test['errors']) or int(test['failures']) for test in receipt['tests']):
            raise RuntimeError('Missing or failing Maven test reports')
        receipt['status'] = 'success'
    except BaseException as error:
        receipt['status'] = 'failure'
        receipt['error'] = str(error)
        raise
    finally:
        (work / 'provenance.json').write_bytes(canonical(receipt) + b'\n')
    return receipt


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--checkout', type=Path, required=True)
    parser.add_argument('--work', type=Path, required=True)
    parser.add_argument('--java-home', type=Path, required=True)
    parser.add_argument('--maven-cache', type=Path, required=True)
    parser.add_argument('--maven-repository', type=Path, required=True)
    parser.add_argument('--timeout', type=int, default=1800)
    args = parser.parse_args()
    if not 60 <= args.timeout <= 7200:
        parser.error('timeout must be 60..7200 seconds')
    result = build(args)
    print(json.dumps({'status': result['status'], 'tree_sha256': result['source']['tree_sha256'],
                      'artifact_count': len(result['artifacts'])}, sort_keys=True))


if __name__ == '__main__':
    main()
