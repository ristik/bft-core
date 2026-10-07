#!/usr/bin/env python3
"""Verify source/build provenance before creating immutable local image IDs."""
import argparse
import hashlib
import json
import pathlib
import shutil
import subprocess

HERE = pathlib.Path(__file__).resolve().parent
PINS = json.loads((HERE / 'pins.json').read_text())

def run(*args):
    return subprocess.check_output(args, text=True).strip()

def main():
    p = argparse.ArgumentParser()
    for name in ('bft', 'ureth', 'rugregator'):
        p.add_argument('--' + name + '-source', required=True, type=pathlib.Path)
    a = p.parse_args()
    artifacts = HERE / 'artifacts'
    artifacts.mkdir(exist_ok=True)
    records = {}
    for name, binary in (('bft', 'ubft'), ('ureth', 'unicity-reth'), ('rugregator', 'rugregator')):
        src = getattr(a, name + '_source').resolve()
        if run('git', '-C', str(src), 'rev-parse', 'HEAD') != PINS[name]:
            raise SystemExit(name + ' source pin mismatch')
        if run('git', '-C', str(src), 'status', '--porcelain', '--untracked-files=no'):
            raise SystemExit(name + ' dirty source')
        # Build here rather than accepting a binary with unverifiable provenance.
        if name == 'bft':
            subprocess.run(['make', 'build'], cwd=src, check=True)
            path = src / 'build/ubft'
        else:
            args = ['cargo', 'build', '--locked', '--release']
            if name == 'ureth':
                args += ['-p', 'unicity-reth']
            else:
                args += ['-p', 'uni-aggregator', '--bin', 'aggregator']
            subprocess.run(args, cwd=src, check=True)
            path = src / 'target/release' / ('aggregator' if name == 'rugregator' else binary)
        with path.open('rb') as stream:
            if stream.read(4) != b'\x7fELF':
                raise SystemExit('build on Linux for the server, not macOS')
        shutil.copy2(path, artifacts / binary)
        records[binary] = hashlib.sha256(path.read_bytes()).hexdigest()
    shutil.copy2(HERE / 'Dockerfile.node', artifacts / 'Dockerfile')
    subprocess.run(['docker', 'build', '-t', 'tnops-node:verified', str(artifacts)], check=True)
    for binary in ('ubft', 'unicity-reth', 'rugregator'):
        subprocess.run(['docker', 'run', '--rm', '--entrypoint', binary, 'tnops-node:verified', '--help'], check=True, stdout=subprocess.DEVNULL)
    images = {'node': run('docker', 'image', 'inspect', '--format={{.Id}}', 'tnops-node:verified')}
    for kind, dockerfile in (('guard', 'Dockerfile.gateway'), ('signer', 'Dockerfile.backend')):
        tag = 'tnops-' + kind + ':verified'
        subprocess.run(['docker', 'build', '-t', tag, '-f', str(HERE / 'faucet' / dockerfile), str(HERE / 'faucet')], check=True)
        images[kind] = run('docker', 'image', 'inspect', '--format={{.Id}}', tag)
    subprocess.run(['docker', 'build', '-t', 'tnops-rpc:verified', '-f', str(HERE / 'Dockerfile.rpc'), str(HERE)], check=True)
    images['rpc'] = run('docker', 'image', 'inspect', '--format={{.Id}}', 'tnops-rpc:verified')
    (artifacts / 'images.json').write_text(json.dumps({'sources': PINS, 'binary_sha256': records, 'images': images}, indent=2) + '\n')
    print(artifacts / 'images.json')

if __name__ == '__main__':
    main()
