#!/usr/bin/env python3
"""Import an exact companion git snapshot into the offline Go replay cache.

Usage: python3 tools/import-bridge-corpus.py CHECKOUT COMMIT SEALED_DIGEST
A candidate import does not satisfy the merged-release gate.
"""
import hashlib
import json
import pathlib
import shutil
import subprocess
import sys

checkout, revision, digest = sys.argv[1:]
assert len(revision) == 40 and len(digest) == 64

def git(*args):
    return subprocess.check_output(['git', '-C', checkout, *args])

assert git('rev-parse', revision).decode().strip() == revision
prefix = 'protocol/vectors/'
names = git('ls-tree', '-r', '--name-only', revision, '--', prefix).decode().splitlines()
files = {n[len(prefix):]: git('show', f'{revision}:{n}') for n in names if pathlib.PurePosixPath(n).name not in {'README.md', '.gitkeep'}}
manifest = files['SHA256SUMS']
assert hashlib.sha256(manifest).hexdigest() == digest
assert files['MANIFEST.sha256'].decode().strip() == digest
tracked = set()
for line in manifest.decode().splitlines():
    expected, name = line.split('  ', 1)
    assert name not in tracked and '..' not in pathlib.PurePosixPath(name).parts
    assert not pathlib.PurePosixPath(name).is_absolute()
    assert hashlib.sha256(files[name]).hexdigest() == expected
    tracked.add(name)
assert set(files) == tracked | {'SHA256SUMS', 'MANIFEST.sha256'}
root = pathlib.Path(__file__).resolve().parents[1] / 'bridgeprofile/testdata/external-corpus'
if root.exists():
    shutil.rmtree(root)
for name, data in files.items():
    dest = root / 'vectors' / name
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_bytes(data)
(root / 'pin.json').write_text(json.dumps(dict(repository='ristik/native-bridge-plugins', revision=revision, digest=digest, status='sealed-candidate-unmerged'), indent=2) + '\n')
print(f'Imported exact external snapshot {revision}, sealed digest {digest}')
