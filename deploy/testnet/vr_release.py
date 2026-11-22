#!/usr/bin/env python3
"""Export the public validator release and authenticated sync seed of a running VR generation."""
import argparse
import hashlib
import ipaddress
import json
from pathlib import Path
import shutil
import subprocess
import tarfile
import tempfile
import uuid

import handoff_ops
import operator_rpc

NETWORK_FILES = (
    'deployment.json', 'vr-deployment.json', 'genesis.json', 'genesis-identities.json',
    'full-shard-conf.json', 'b1-profile.json', 'trust-base.json', 'utb-genesis.cbor',
    'utb-genesis.id', 'ureth-flags.txt', 'fee-collector.txt', 'aggregator-conf.json',
)


def checked(*args):
    return subprocess.check_output(args, text=True).strip()


def digest(file):
    with file.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def export_release(generation, out, ubft, ureth, wallet_dir=None):
    manifest = json.loads((generation / 'manifest.json').read_text())
    if manifest.get('offline_validation_only') or (manifest.get('pos') or {}).get('profile') != 'vr-pos16':
        raise ValueError('a running VR/P85 generation is required')
    compose = handoff_ops.load_compose(generation)
    transport = handoff_ops.DockerTransport(generation)
    cmd = ['docker', 'compose', *transport.files]
    net = generation / 'network'
    pin = manifest['utb']['genesis_id']
    with tempfile.TemporaryDirectory(prefix='.vr-release-', dir=out.parent) as tmp:
        stage = Path(tmp) / 'release'
        stage.mkdir()
        for file in NETWORK_FILES:
            shutil.copyfile(net / file, stage / file)
        shutil.copyfile(generation / 'manifest.json', stage / 'manifest.json')
        for name, source in (('ubft', ubft), ('unicity-reth', ureth)):
            artifact = stage / name
            shutil.copyfile(source, artifact)
            if digest(artifact) != manifest['artifacts']['binary_sha256'][name]:
                raise ValueError(f'{name}: differs from the deployed binary digest')
        root_peers, shard_peers = [], []
        for i in range(1, manifest['validators'] + 1):
            networks = json.loads(checked('docker', 'inspect', '--format={{json .NetworkSettings.Networks}}', transport.holder(i)))
            name = f"{compose['name']}_validators"
            address = ipaddress.IPv4Address(networks[name]['IPAddress'])
            if not address.is_private:
                raise ValueError('Compose validator peer must have a private address')
            root = checked(*cmd, 'exec', '-T', f'root{i}', 'ubft', 'node-id', '--home', '/state').splitlines()[-1]
            shard = checked(*cmd, 'exec', '-T', f'shard{i}', 'ubft', 'node-id', '--home', '/state').splitlines()[-1]
            root_peers.append(f'/ip4/{address}/tcp/8000/p2p/{root}\n')
            shard_peers.append(f'/ip4/{address}/tcp/9000/p2p/{shard}\n')
        (stage / 'root-peers.txt').write_text(''.join(root_peers))
        (stage / 'shard-peers.txt').write_text(''.join(shard_peers))
        if wallet_dir:
            for name in ('nb2-release.json', 'trust-base.bundle.cbor', 'trust-base.genesis.entryid'):
                source = wallet_dir / name
                if source.is_symlink() or not source.is_file():
                    raise ValueError(f'expected regular wallet release file {name}')
                shutil.copyfile(source, stage / name)
        # The shard shares the root's network namespace and already has the
        # certified archive mounted. Only the exported public seed leaves it.
        container_out = '/tmp/public-seed-' + uuid.uuid4().hex
        shard_rpc = operator_rpc.common_urls(compose)[1]
        try:
            print(checked(*cmd, 'exec', '-T', 'shard1', 'ubft', 'seed', 'export',
                '--bundle-url', 'http://127.0.0.1:8011', '--utb-genesis-id', pin, '--archive', '/archive',
                '--shard-status', shard_rpc, '--eth-rpc', 'http://127.0.0.1:8545', '--out', container_out))
            with tempfile.TemporaryFile() as archive:
                subprocess.run([*cmd, 'exec', '-T', 'shard1', 'tar', '-C', container_out, '-cf', '-', '.'],
                    check=True, stdout=archive, stdin=subprocess.DEVNULL)
                archive.seek(0)
                with tarfile.open(fileobj=archive) as exported:
                    if any(not (file.isfile() or file.isdir()) for file in exported.getmembers()):
                        raise ValueError('seed export includes a non-regular file')
                    exported.extractall(stage / 'seed', filter='data')
        finally:
            subprocess.run([*cmd, 'exec', '-T', 'shard1', 'rm', '-rf', '--', container_out], check=True)
        subprocess.run([str(ubft), 'seed', 'restore-pin', '--dir', str(stage / 'seed'), '--utb-genesis-id', pin,
            '--full-shard-conf', str(stage / 'full-shard-conf.json'), '--trust-base', str(stage / 'trust-base.json'),
            '--out', str(Path(tmp) / 'restore-pin')], check=True)
        files = sorted(file for file in stage.rglob('*') if file.is_file())
        sums = ''.join(f'{digest(file)}  {file.relative_to(stage).as_posix()}\n' for file in files)
        (stage / 'SHA256SUMS').write_text(sums)
        if out.exists():
            raise FileExistsError(out)
        stage.rename(out)
    print(json.dumps({'release': str(out), 'sha256sums': digest(out / 'SHA256SUMS'), 'utb_genesis_id': pin}))


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('generation', type=Path)
    p.add_argument('--out', type=Path, required=True)
    p.add_argument('--ubft', type=Path, required=True)
    p.add_argument('--ureth', type=Path, required=True)
    p.add_argument('--wallet-dir', type=Path, help='public files from the NB2 deployment')
    a = p.parse_args()
    export_release(a.generation.resolve(), a.out.absolute(), a.ubft.resolve(), a.ureth.resolve(), a.wallet_dir)


if __name__ == '__main__':
    main()
