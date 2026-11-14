#!/usr/bin/env python3
"""Build only the disposable SSH lab endpoint from pinned public project inputs."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess

HERE = Path(__file__).resolve().parent


def inputs(ca):
    lock = json.loads((HERE.parent/'source-inputs-lock.json').read_text())
    raw = ca.read_bytes()
    if hashlib.sha256(raw).hexdigest() != lock['sources']['bootstrap-ca-certificates.crt']['sha256']:
        raise ValueError('Bootstrap CA checksum mismatch')
    source = (HERE/'ssh-endpoint.Containerfile').read_bytes()
    text = source.decode('ascii')
    if ('FROM '+lock['base_image']+'\n' not in text or
            'https://snapshot.ubuntu.com/ubuntu/'+lock['apt_snapshot']+'/' not in text):
        raise ValueError('Endpoint base/snapshot drift')
    return source, raw


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bootstrap-ca', required=True, type=Path)
    parser.add_argument('--directory', required=True, type=Path)
    args = parser.parse_args()
    source, ca = inputs(args.bootstrap_ca)
    case = args.directory
    if os.geteuid() != 0 or not case.is_absolute() or case.exists() or case.is_symlink():
        raise ValueError('Root and new absolute private directory required')
    os.umask(0o077)
    case.mkdir(mode=0o700)
    (case/'Containerfile').write_bytes(source)
    (case/'bootstrap-ca-certificates.crt').write_bytes(ca)
    receipt = {'schema': 1, 'passed': False, 'scope': 'disposable synthetic SSH endpoint only',
               'source_sha256': hashlib.sha256(source).hexdigest(),
               'builder_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest()}
    (case/'intent.json').write_text(json.dumps(receipt)+'\n')
    with (case/'intent.json').open('rb') as stream: os.fsync(stream.fileno())
    try:
        result = subprocess.run(['podman', 'build', '--jobs=1', '--pull=never',
                    '--cpu-quota=200000', '--cpu-period=100000', '--memory=1g',
                    '--iidfile='+str(case/'image-id'),
                    '--label=guacamole.ssh-fixture.source-sha256='+receipt['source_sha256'],
                    str(case)], capture_output=True, timeout=420)
        if result.returncode:
            raise RuntimeError('Endpoint image build failed')
        image = (case/'image-id').read_text().strip()
        if re.fullmatch(r'sha256:[a-f0-9]{64}', image) is None:
            raise RuntimeError('Invalid endpoint image ID')
        verified = subprocess.run(['podman', 'image', 'inspect', image],
                                  capture_output=True, check=True, timeout=10)
        info = json.loads(verified.stdout)[0]
        if ('sha256:'+info['Id'].removeprefix('sha256:') != image or
                info.get('Labels', {}).get('guacamole.ssh-fixture.source-sha256') != receipt['source_sha256']):
            raise RuntimeError('Endpoint image/source mismatch')
        if inputs(args.bootstrap_ca) != (source, ca):
            raise RuntimeError('Build inputs changed')
        receipt.update(passed=True, image=image)
    except Exception as error:
        receipt['error_type'] = type(error).__name__
    finally:
        (case/'result.json').write_text(json.dumps(receipt, sort_keys=True, indent=2)+'\n')
    print(json.dumps(receipt, sort_keys=True))
    return 0 if receipt['passed'] else 1


if __name__ == '__main__': raise SystemExit(main())
