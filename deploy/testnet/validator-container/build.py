#!/usr/bin/env python3
"""Build a validator image from independently pinned release bytes and the CI Foundry archive."""
import argparse
import hashlib
from ipaddress import IPv4Address
import json
from pathlib import Path
import shutil
import subprocess
import tarfile
import tempfile
from urllib.parse import urlsplit

HERE = Path(__file__).resolve().parent
PUBLIC = {
    'release_url': 'https://pos.staging.unicity.network/release',
    'rpc_url': 'https://pos.staging.unicity.network/rpc',
    'utb_genesis_id': '0xad5246c7ccdee1786417ab5e6e854578bd9450a1163528f9ddc4055ef611dc92',
    'sha256sums': '9e3c82c0c93a99c219c3a9ab5e32c36bf6c912e5dbf2269fca7bbf20668467cf',
}


def sha(path):
    with path.open('rb') as f:
        return hashlib.file_digest(f, 'sha256').hexdigest()


def main():
    cli = argparse.ArgumentParser(description=__doc__)
    cli.add_argument('verified_release', type=Path)
    cli.add_argument('--foundry-archive', required=True, type=Path)
    cli.add_argument('--handoff-ubft', required=True, type=Path, help='this checkout’s validator publication CLI, built for linux/amd64')
    cli.add_argument('--tag', required=True)
    cli.add_argument('--rehearsal-lock', type=Path, help='independent pins for a private loopback release')
    cli.add_argument('--public-peers', type=Path, help='directory of the verified public peer lists for this release')
    a = cli.parse_args()
    release = a.verified_release
    lock = json.loads(a.rehearsal_lock.read_text()) if a.rehearsal_lock else PUBLIC.copy()
    if a.rehearsal_lock:
        for key in ('release_url', 'rpc_url'):
            if not IPv4Address(urlsplit(lock[key]).hostname).is_private:
                cli.error('private rehearsal endpoints must use private IPv4 addresses')
        lock['private_rehearsal'] = True
    checksums = (release/'SHA256SUMS').read_bytes()
    if hashlib.sha256(checksums).hexdigest() != lock['sha256sums']:
        cli.error('release checksums differ from the independent pin')
    entries = {name: digest for digest, name in (line.split('  ',1) for line in checksums.decode('ascii').splitlines())}
    pin_path = release/'utb-genesis.id'
    if sha(pin_path) != entries['utb-genesis.id'] or pin_path.read_text().strip() != lock['utb_genesis_id']:
        cli.error('release UTB pin differs')
    if a.public_peers:
        peer_digests = {}
        for name in ('root-peers.txt', 'shard-peers.txt'):
            original = (release/name).read_text().splitlines()
            public = (a.public_peers/name).read_text().splitlines()
            peer_ids = lambda lines: [line.rsplit('/p2p/',1)[1] for line in lines]
            if len(public) != 4 or peer_ids(public) != peer_ids(original):
                cli.error(f'{name}: public addresses must preserve the verified release peer identities')
            peer_digests[name] = sha(a.public_peers/name)
        lock['public_peers'] = peer_digests
    elif not a.rehearsal_lock:
        cli.error('the public image requires both verified public peer lists')
    foundry = json.loads((HERE.parents[2]/'scripts/ci/lane-pins.json').read_text())['toolchains']['foundry']
    if sha(a.foundry_archive) != foundry['sha256']:
        cli.error('Foundry archive differs from the CI pin')
    with tempfile.TemporaryDirectory(prefix='validator-image-') as temp:
        context = Path(temp)
        for name in ('ubft','unicity-reth'):
            shutil.copyfile(release/name, context/name)
            if sha(context/name) != entries[name]:
                cli.error(f'{name} differs from the pinned release')
        for path in (HERE/'Dockerfile', HERE/'validator.py', HERE.parent/'validator_rpc.py',
                     HERE.parent/'gateway.py', HERE.parent/'public_relay.py'):
            shutil.copyfile(path, context/path.name)
        shutil.copyfile(a.handoff_ubft, context/'handoff-ubft')
        (context/'faucet').mkdir()
        shutil.copyfile(HERE.parent/'faucet/gateway.py', context/'faucet/gateway.py')
        with tarfile.open(a.foundry_archive) as archive:
            member = archive.getmember('cast') if 'cast' in archive.getnames() else archive.getmember('./cast')
            if not member.isfile():
                cli.error('the pinned cast member is not a regular file')
            with archive.extractfile(member) as src, (context/'cast').open('wb') as dst:
                shutil.copyfileobj(src, dst)
        (context/'release-lock.json').write_text(json.dumps(lock, sort_keys=True)+'\n')
        subprocess.run(['docker','build','--platform','linux/amd64','--provenance=false','--build-arg','SOURCE_DATE_EPOCH=0',
                        '--tag',a.tag,str(context)], check=True)


if __name__ == '__main__':
    main()
