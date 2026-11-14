#!/usr/bin/env python3
"""Export one exact local image into a new private, hash-bound transfer archive."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image', required=True)
    parser.add_argument('--directory', type=Path, required=True)
    args = parser.parse_args()
    if os.geteuid() != 0 or re.fullmatch('[0-9a-f]{64}', args.image) is None:
        raise ValueError('Root and exact local image ID required')
    os.umask(0o077)
    args.directory.mkdir(mode=0o700)
    subprocess.run(['podman', 'image', 'exists', args.image], check=True, timeout=10)
    with (args.directory/'intent.json').open('x') as out:
        json.dump({'image': args.image, 'operation': 'image export'}, out)
        out.flush(); os.fsync(out.fileno())
    archive = args.directory/'image.oci.tar'
    subprocess.run(['nice', '-n', '10', 'podman', 'save', '--format=oci-archive',
                    '--output', str(archive), args.image], check=True, timeout=600,
                   stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    with archive.open('rb') as stream:
        digest = hashlib.file_digest(stream, 'sha256').hexdigest()
    result = {'image': args.image, 'archive_sha256': digest, 'bytes': archive.stat().st_size}
    with (args.directory/'receipt.json').open('x') as out:
        json.dump(result, out); out.flush(); os.fsync(out.fileno())
    print(json.dumps(result))


if __name__ == '__main__':
    main()
