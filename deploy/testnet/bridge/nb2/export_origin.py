#!/usr/bin/env python3
"""Export the moving NB2 origin into the operator's HTTPS release directory."""
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile

import deploy_nb2 as bridge

BLOCK_HASH = re.compile(r'0x[0-9a-f]{64}')
SHA256 = re.compile(r'[0-9a-f]{64}')
MAX_BLOCK = (1 << 53) - 1
MAX_WORD = (1 << 64) - 1
MAX_NB2_ORIGIN_BYTES = 4096  # native-bridge-plugin and browser wallet decoder limit


def run(*args):
    return subprocess.check_output(args, text=True, timeout=15).strip()


def pod_cast(gen, cast):
    """Connect to VR's execution RPC inside the validator's network namespace."""
    compose = gen / 'compose.yaml'
    services = json.loads(compose.read_text())['services']
    if services['ureth1'].get('network_mode') != 'service:pod1':
        raise ValueError('expected ureth1 to share the pod1 network namespace')
    pod = run('docker', 'compose', '-f', str(compose), 'ps', '-q', 'pod1')
    if not re.fullmatch(r'[0-9a-f]{64}', pod):
        raise ValueError('expected one running pod1 container')
    pid = int(run('docker', 'inspect', '--format', '{{.State.Pid}}', pod))
    if pid <= 1:
        raise ValueError('pod1 has no live network namespace')

    def query(method, *params):
        return json.loads(run('nsenter', '--target', str(pid), '--net', '--', str(cast), 'rpc',
                              '--rpc-url', 'http://127.0.0.1:8545', '--raw', method, json.dumps(params)))

    def hash_bytes(data):
        return run(str(cast), 'keccak', '0x' + data.hex()).lower()

    return query, hash_bytes


def checkpoint_fields(record):
    block_hash = record['blockHash']
    number = record['blockNumber']
    if not BLOCK_HASH.fullmatch(block_hash) or int(block_hash, 16) == 0:
        raise ValueError('invalid finalized block hash')
    if type(number) is not int or not 0 <= number <= MAX_BLOCK:
        raise ValueError('invalid finalized block number')

    def word(name):
        value = record[name]
        if not re.fullmatch(r'[1-9][0-9]{0,19}', value) or int(value) > MAX_WORD:
            raise ValueError(f'invalid checkpoint {name}')
        return int(value)

    return number, word('usableEpoch'), word('rootRound')


def advance(record, previous):
    current = checkpoint_fields(record)
    held = checkpoint_fields(previous)
    if any(new < old for new, old in zip(current, held, strict=True)):
        raise ValueError('finalized checkpoint rolls back published authority')
    same_number = current[0] == held[0]
    same_hash = record['blockHash'] == previous['blockHash']
    if (same_number or same_hash) and (not same_hash or current != held):
        raise ValueError('checkpoint conflicts with a published finalized block')


def publish(path, record):
    encoded = json.dumps(record, indent=2) + '\n'
    if len(encoded.encode('utf-8')) > MAX_NB2_ORIGIN_BYTES:
        raise ValueError('checkpoint exceeds the wallet byte limit')
    tmp = None
    try:
        with tempfile.NamedTemporaryFile(mode='w', encoding='utf-8', dir=path.parent,
                                         prefix='.nb2-origin-', delete=False) as out:
            tmp = Path(out.name)
            out.write(encoded)
            os.fchmod(out.fileno(), 0o644)
            out.flush()
            os.fsync(out.fileno())
        tmp.replace(path)
    finally:
        if tmp is not None:
            tmp.unlink(missing_ok=True)


def export(gen, release_dir, release_sha256, query, hash_bytes):
    manifest = json.loads((gen / 'manifest.json').read_text())
    release_bytes = (release_dir / 'nb2-release.json').read_bytes()
    if not SHA256.fullmatch(release_sha256) or hashlib.sha256(release_bytes).hexdigest() != release_sha256:
        raise ValueError('staged release SHA-256 differs from the installed pin')
    release = json.loads(release_bytes)
    package = release['package']
    genesis = package['genesisHash']
    if (release['schema'] != 'unicity-nb2-release' or release['version'] != '1.1' or
            release['status'] != 'testnet-provisional' or release['realValueAuthorized'] is not False or
            not BLOCK_HASH.fullmatch(genesis) or
            package['generation'] != manifest['generation'] or genesis != manifest['genesis_hash'] or
            package['chainId'] != manifest['chain_id'] or
            not manifest.get('utb') or release['trust']['genesisEntryId'] != manifest['utb']['genesis_id']):
        raise ValueError('staged release does not match the testnet generation')
    bridge.same('checkpoint execution genesis', query('eth_getBlockByNumber', '0x0', False)['hash'], genesis)
    if int(query('eth_chainId'), 16) != package['chainId']:
        raise ValueError('checkpoint execution chain ID mismatch')
    head = query('eth_getBlockByNumber', 'finalized', False)
    if not head:
        raise ValueError('execution client has no finalized block')
    registry = release['deployment']['contracts']['registry']
    bridge.same('checkpoint seal registry address', registry['address'], bridge.REGISTRY)
    code = query('eth_getCode', bridge.REGISTRY, bridge.canonical_block(head['hash']))
    bridge.same('checkpoint seal registry runtime', hash_bytes(bytes.fromhex(code[2:])), registry['runtimeCodeHash'])
    origin = bridge.read_origin(query, hash_bytes, head=head)
    binding = dict(schema='unicity-nb2-origin', version=1, network=bridge.NETWORK_ID,
                   generation=package['generation'], genesisHash=genesis, releaseSha256=release_sha256)
    record = {**binding, **{name: origin[name] for name in ('blockHash', 'blockNumber', 'usableEpoch', 'rootRound')}}
    advance(record, release['trust']['origin'])
    path = release_dir / 'nb2-origin.json'
    unchanged = False
    if path.exists():
        previous = json.loads(path.read_text())
        if any(previous.get(key) != value for key, value in binding.items()):
            raise ValueError('published checkpoint belongs to a different release')
        advance(record, previous)
        unchanged = all(record[key] == previous[key] for key in ('usableEpoch', 'rootRound'))
    if (release_dir / 'nb2-release.json').read_bytes() != release_bytes:
        raise ValueError('staged release changed during checkpoint export')
    if unchanged:
        return None
    publish(path, record)
    return record


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('generation', type=Path)
    parser.add_argument('release_dir', type=Path, help='the staged /release/ directory')
    parser.add_argument('release_sha256', help='pinned SHA-256 of nb2-release.json')
    parser.add_argument('--pod-cast', type=Path, help='use this host Cast binary in VR pod1 network namespace')
    args = parser.parse_args()
    gen = args.generation.resolve()
    if args.pod_cast is not None:
        query, hash_bytes = pod_cast(gen, args.pod_cast.resolve())
    else:
        def query(method, *params):
            return bridge.rpc(gen, bridge.ETH, method, *params)

        def hash_bytes(data):
            return bridge.keccak(gen, data)

    with (gen / 'bridge/nb2/.origin.lock').open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        record = export(gen, args.release_dir, args.release_sha256, query, hash_bytes)
        if record is not None:
            print(json.dumps(record))


if __name__ == '__main__':
    main()
