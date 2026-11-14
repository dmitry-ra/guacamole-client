#!/usr/bin/env python3
"""Fetch only hash-locked public inputs for the current-source appliance."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import time
import urllib.parse
import urllib.request

HERE = Path(__file__).resolve().parents[1]
MAX_INPUT = 256 * 1024 * 1024
TOMCAT = 'apache-tomcat-9.0.123.tar.gz'
KEYS_URL = 'https://downloads.apache.org/tomcat/tomcat-9/KEYS'


def digest(path):
    with path.open('rb') as source:
        return hashlib.file_digest(source, 'sha256').hexdigest()


def safe_path(path):
    """Do not follow linked parents or leaf files, even in a supplied cache."""
    if any(parent.is_symlink() for parent in (path, *path.parents)):
        raise ValueError('Linked input path refused: ' + str(path))
    if path.exists() and not path.is_file():
        raise ValueError('Regular input file required: ' + str(path))


def https_url(url):
    parsed = urllib.parse.urlsplit(url)
    if (parsed.scheme != 'https' or not parsed.hostname or parsed.username
            or parsed.password or parsed.fragment):
        raise ValueError('Public HTTPS input URL required')
    return url


def download(url, destination, maximum=MAX_INPUT):
    """Retain failed partial files; cap each transfer by bytes and elapsed time."""
    https_url(url)
    started = time.monotonic()
    with urllib.request.urlopen(url, timeout=30) as source, destination.open('xb') as output:
        https_url(source.geturl())
        size = 0
        while True:
            if time.monotonic() - started > 90:
                raise TimeoutError('Public input transfer exceeded 90 seconds')
            block = source.read(min(1024 * 1024, maximum - size + 1))
            if not block:
                break
            size += len(block)
            if size > maximum:
                raise ValueError('Public input size limit exceeded')
            output.write(block)
        output.flush()
        os.fsync(output.fileno())


def checked(path, record):
    safe_path(path)
    return (path.is_file() and digest(path) == record['sha256']
            and ('size' not in record or path.stat().st_size == record['size']))


def install_locked(name, record, inputs, cache, attempt, lock):
    target = inputs / name
    safe_path(target)
    if target.exists():
        if not checked(target, record):
            raise ValueError('Existing input differs; retained unchanged: ' + name)
        return 'reused'
    partial = attempt / (name + '.download')
    if name == 'server-source.json':
        value = {'commit': lock['server']['commit'],
                 'archive_sha256': lock['sources']['guacamole-server-source.tar.gz']['sha256']}
        partial.write_bytes(json.dumps(value, separators=(',', ':')).encode('ascii') + b'\n')
    else:
        candidates = []
        if cache:
            candidates.append(cache / name)
            if name == 'postgresql-42.7.14.jar':
                candidates.append(cache / 'dependencies' / name)
        if name == 'bootstrap-ca-certificates.crt':
            candidates.append(Path('/etc/ssl/certs/ca-certificates.crt'))
        candidate = next((path for path in candidates if checked(path, record)), None)
        if candidate:
            shutil.copyfile(candidate, partial)
        else:
            download(https_url(record['url']), partial)
    if not checked(partial, record):
        raise ValueError('Locked input hash/size mismatch: ' + name)
    partial.chmod(0o644)
    # Never overwrite a file that appeared after the initial existence check.
    os.link(partial, target)
    partial.unlink()
    return 'installed'


def signature_input(name, url, inputs, cache, attempt):
    target = inputs / name
    safe_path(target)
    if target.exists():
        if target.stat().st_size == 0 or target.stat().st_size > 4 * 1024 * 1024:
            raise ValueError('Invalid signature/key input size: ' + name)
        return 'reused_unverified'
    partial = attempt / (name + '.download')
    candidate = cache / name if cache else None
    if candidate:
        safe_path(candidate)
    if candidate and candidate.is_file():
        if candidate.stat().st_size > 4 * 1024 * 1024:
            raise ValueError('Signature/key cache size limit exceeded')
        shutil.copyfile(candidate, partial)
    else:
        download(url, partial, maximum=4 * 1024 * 1024)
    if partial.stat().st_size == 0:
        raise ValueError('Empty signature/key input')
    partial.chmod(0o644)
    os.link(partial, target)
    partial.unlink()
    return 'installed_unverified'


def fetch(inputs, cache=None, lock_path=HERE / 'source-inputs-lock.json'):
    lock = json.loads(lock_path.read_text())
    sources = lock['sources']
    for name, record in sources.items():
        if (not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]*', name)
                or not re.fullmatch('[0-9a-f]{64}', record.get('sha256') or '')):
            raise ValueError('Invalid locked input name/hash')
        if name not in ('server-source.json', 'bootstrap-ca-certificates.crt'):
            https_url(record['url'])
    if any(path.is_symlink() for path in (inputs, *inputs.parents)):
        raise ValueError('Linked input directory refused')
    inputs.mkdir(mode=0o700, parents=True, exist_ok=True)
    if cache and any(path.is_symlink() for path in (cache, *cache.parents)):
        raise ValueError('Linked cache directory refused')
    attempt = inputs / ('fetch-attempt-' + str(time.time_ns()))
    attempt.mkdir(mode=0o700)
    receipt = {'schema': 1, 'status': 'failed', 'inputs': {},
               'lock_sha256': digest(lock_path), 'tomcat_signature': 'not_verified'}
    try:
        for name, record in sources.items():
            receipt['inputs'][name] = install_locked(name, record, inputs, cache, attempt, lock)
        receipt['inputs'][TOMCAT + '.asc'] = signature_input(
            TOMCAT + '.asc', sources[TOMCAT]['url'] + '.asc', inputs, cache, attempt)
        receipt['inputs']['tomcat-KEYS'] = signature_input(
            'tomcat-KEYS', KEYS_URL, inputs, cache, attempt)
        receipt['status'] = 'ready_for_verification'
    except Exception as error:
        receipt['error'] = str(error)
        raise
    finally:
        with (attempt / 'receipt.json').open('x') as stream:
            stream.write(json.dumps(receipt, sort_keys=True, indent=2) + '\n')
            stream.flush()
            os.fsync(stream.fileno())
    return {'status': receipt['status'], 'attempt': str(attempt),
            'tomcat_signature': receipt['tomcat_signature']}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--inputs', required=True, type=Path)
    parser.add_argument('--cache', type=Path)
    args = parser.parse_args()
    print(json.dumps(fetch(args.inputs.absolute(), args.cache.absolute() if args.cache else None)))


if __name__ == '__main__':
    main()
