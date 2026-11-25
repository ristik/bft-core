#!/usr/bin/env python3
"""Export the public validator release and authenticated sync seed of a running VR generation."""
import argparse
import hashlib
import ipaddress
import json
from pathlib import Path
import re
import shutil
import subprocess
import tarfile
import tempfile
import uuid

import handoff_ops
import root_keys
import operator_rpc
from public_routes import release_file

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


def copy_regular(source, name, destination):
    with release_file(source, name) as src, destination.open('xb') as dst:
        shutil.copyfileobj(src, dst)


def stage_network_files(source, stage, manifest):
    utb = manifest['utb']
    config_digests = manifest.get('config_sha256', {})
    missing = [name for name in ('ureth-flags.txt', 'fee-collector.txt') if not config_digests.get(name)]
    if missing:
        raise ValueError(
            f"generation manifest is missing startup-file digests for {', '.join(missing)}. "
            "Keep the already-verified static release. Re-export starts with the next generation, "
            "whose manifest must pin both files."
        )
    for name in NETWORK_FILES:
        target = stage / name
        copy_regular(source, name, target)
        if name == 'utb-genesis.id':
            matches = target.read_text().strip() == utb['genesis_id']
        else:
            expected = utb['genesis_sha256'] if name == 'utb-genesis.cbor' else config_digests.get(name)
            matches = digest(target) == expected
        if not matches:
            raise ValueError(f'{name}: differs from the generation manifest')
    # #1297: the retired root key hashes of the earlier root histories, which `ubft validator apply/rotate` refuse by default (release/<name>).
    # A generation made before the list existed pins none and ships none.
    if config_digests.get(root_keys.FILE):
        target = stage / root_keys.FILE
        copy_regular(source, root_keys.FILE, target)
        if digest(target) != config_digests[root_keys.FILE]:
            raise ValueError(f'{root_keys.FILE}: differs from the generation manifest')


def copy_bootstrap_seed(source, seed):
    seed.mkdir()
    copy_regular(source, 'manifest.json', seed / 'manifest.json')
    info = json.loads((seed / 'manifest.json').read_text())
    for file in info['files']:
        name = file['name']
        if not re.fullmatch(r'[a-z0-9][a-z0-9.-]*', name) or name == 'manifest.json':
            raise ValueError('bootstrap seed has an invalid member name')
        copy_regular(source, name, seed / name)


def published_peer(entrypoint, bindings):
    if '--announce-addresses' not in entrypoint or not bindings or len(bindings) != 1:
        raise ValueError('expected one running Docker P2P binding with a matching announce address')
    binding, = bindings
    address = f"/ip4/{binding['HostIp']}/tcp/{binding['HostPort']}"
    if address != entrypoint[entrypoint.index('--announce-addresses') + 1]:
        raise ValueError('Docker P2P binding differs from the configured announce address')
    return address


def export_release(generation, out, ubft, ureth, wallet_dir=None, bootstrap_seed=None):
    with release_file(generation, 'manifest.json') as file:
        manifest_bytes = file.read()
    manifest = json.loads(manifest_bytes)
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
        stage_network_files(net, stage, manifest)
        (stage / 'manifest.json').write_bytes(manifest_bytes)
        for name, source in (('ubft', ubft), ('unicity-reth', ureth)):
            artifact = stage / name
            shutil.copyfile(source, artifact)
            if digest(artifact) != manifest['artifacts']['binary_sha256'][name]:
                raise ValueError(f'{name}: differs from the deployed binary digest')
        root_peers, shard_peers = [], []
        for i in range(1, manifest['validators'] + 1):
            holder = transport.holder(i)
            services = compose['services']
            if services[f'pod{i}'].get('ports'):
                ports = json.loads(checked('docker', 'inspect', '--format={{json .NetworkSettings.Ports}}', holder))
                root_address = published_peer(services[f'root{i}']['entrypoint'], ports.get('8000/tcp'))
                shard_address = published_peer(services[f'shard{i}']['entrypoint'], ports.get('9000/tcp'))
            else:
                networks = json.loads(checked('docker', 'inspect', '--format={{json .NetworkSettings.Networks}}', holder))
                address = ipaddress.IPv4Address(networks[f"{compose['name']}_validators"]['IPAddress'])
                if not address.is_private:
                    raise ValueError('Compose validator peer must have a private address')
                root_address = f'/ip4/{address}/tcp/8000'
                shard_address = f'/ip4/{address}/tcp/9000'
            root = checked(*cmd, 'exec', '-T', f'root{i}', 'ubft', 'node-id', '--home', '/state').splitlines()[-1]
            shard = checked(*cmd, 'exec', '-T', f'shard{i}', 'ubft', 'node-id', '--home', '/state').splitlines()[-1]
            root_peers.append(f'{root_address}/p2p/{root}\n')
            shard_peers.append(f'{shard_address}/p2p/{shard}\n')
        (stage / 'root-peers.txt').write_text(''.join(root_peers))
        (stage / 'shard-peers.txt').write_text(''.join(shard_peers))
        if wallet_dir:
            for name in ('nb2-release.json', 'trust-base.bundle.cbor', 'trust-base.genesis.entryid'):
                copy_regular(wallet_dir, name, stage / name)
        # The shard shares the root's network namespace and already has the
        # certified archive mounted. Only the exported public seed leaves it.
        container_out = '/tmp/public-seed-' + uuid.uuid4().hex
        shard_rpc = operator_rpc.common_urls(compose)[1]
        if bootstrap_seed:
            copy_bootstrap_seed(bootstrap_seed, stage / 'seed')
        else:
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
                subprocess.run([*cmd, 'exec', '-T', 'shard1', 'rm', '-rf', '--', container_out], check=True, stdin=subprocess.DEVNULL)
        checkpoint = json.loads((stage / 'seed/manifest.json').read_text())['checkpoint']
        if checkpoint['rootEpoch'] != 1:
            raise ValueError('the release requires an epoch-one seed; pass the verified --bootstrap-seed for later exports')
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
    p.add_argument('--bootstrap-seed', type=Path, help='reuse the previously verified epoch-one seed for a later release update')
    a = p.parse_args()
    export_release(a.generation.resolve(), a.out.absolute(), a.ubft.resolve(), a.ureth.resolve(), a.wallet_dir, a.bootstrap_seed)


if __name__ == '__main__':
    main()
