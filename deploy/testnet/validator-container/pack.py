#!/usr/bin/env python3
"""Make the checksummed docker-load bundle beside the immutable chain release."""
import argparse
import gzip
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import tempfile


def main():
    cli = argparse.ArgumentParser(description=__doc__)
    cli.add_argument('image')
    cli.add_argument('peers', type=Path)
    cli.add_argument('source_release', type=Path)
    cli.add_argument('out', type=Path)
    a = cli.parse_args()
    def digest(path):
        with path.open('rb') as f:
            return hashlib.file_digest(f, 'sha256').hexdigest()
    inspect = subprocess.check_output(['docker','image','inspect',a.image])
    image, = json.loads(inspect)
    if (image['Os'], image['Architecture']) != ('linux','amd64'):
        cli.error('expected the linux/amd64 validator image')
    if a.out.exists():
        cli.error('output already exists')
    with tempfile.TemporaryDirectory(prefix='.validator-image-', dir=a.out.parent) as temp:
        stage = Path(temp)/'bundle'
        stage.mkdir()
        for name in ('root-peers.txt','shard-peers.txt'):
            shutil.copyfile(a.peers/name, stage/name)
        tar = stage/'validator-image.tar.gz'
        with subprocess.Popen(['docker','save',a.image], stdout=subprocess.PIPE) as child:
            with tar.open('wb') as file, gzip.GzipFile(filename='', fileobj=file, mtime=0) as zipped:
                shutil.copyfileobj(child.stdout, zipped)
            if child.wait() != 0:
                raise RuntimeError('docker save failed')
        manifest = {
            'format':'unicity.validator-container.v1',
            'imageId':image['Id'], 'platform':'linux/amd64',
            'archive':tar.name, 'archiveSha256':digest(tar),
            'sourceReleaseSha256':digest(a.source_release/'SHA256SUMS'),
            'utbGenesisId':(a.source_release/'utb-genesis.id').read_text().strip(),
        }
        (stage/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
        files = sorted(stage.iterdir())
        (stage/'SHA256SUMS').write_text(''.join(f'{digest(path)}  {path.name}\n' for path in files))
        stage.chmod(0o755)
        for path in stage.iterdir():
            path.chmod(0o644)
        stage.rename(a.out)
    print(json.dumps({**manifest,'sha256sums':digest(a.out/'SHA256SUMS')}))


if __name__ == '__main__':
    main()
