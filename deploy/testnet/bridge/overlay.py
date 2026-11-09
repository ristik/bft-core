#!/usr/bin/env python3
"""Write GENERATION/compose.bridge.yaml, the bridge's Compose overlay on a generation (briefs/tnb-without-host.md):

    overlay.py GENERATION [--archive-of N]
    docker compose -f compose.yaml -f compose.bridge.yaml up -d lockproof

Run after deploy_bridge.py, which writes GENERATION/bridge/ (addresses, CFG, trust bundle). Services:
  lockproof  `dnb-tool lockproof-serve`: the stateless, read-only, rate-limited lock-proof endpoint on 127.0.0.1:8090 (the host's nginx publishes it like the
             RPC gateway, as 172.30.89.1). It reads validator N's certified-block archive through a read-only mount and asks that validator's ureth for
             eth_getProof, so a proof is available only while ureth's proof window (--rpc.eth-proof-window) still covers the lock's block.
Replacing the endpoint is stopping it and starting it again, on the same or another validator's archive (--archive-of): it holds no state.
On a PoS generation every shard epoch has its own EVM shard configuration (the handoff writes network/handoff/shard-conf-<epoch>.json): the endpoint is
given the genesis one and each of those, and proves a block under the one its certificate commits to. After a handoff, rerun this and restart the
endpoint, or a lock certified under the new shard epoch is not served.
"""
import argparse
import json
import re
from pathlib import Path

HERE = Path(__file__).resolve().parent
TRUSTED_PROXY = '172.30.89.1'   # the edge network's gateway, the address the host's nginx reaches containers from (generate.py)


def hardened(**svc):
    # the package's service defaults (generate.py topology.service)
    base = dict(restart='unless-stopped', pids_limit=64, read_only=True, cap_drop=['ALL'], security_opt=['no-new-privileges:true'],
                stop_grace_period='10s', tmpfs=['/tmp:size=16m,mode=1777'], logging={'driver': 'json-file', 'options': {'max-size': '10m', 'max-file': '3'}})
    base.update(svc)
    return base


def shard_confs(gen):
    """The EVM shard configurations the endpoint holds, as paths in its /network mount: the genesis one, then each shard epoch's from the handoffs."""
    handoff = sorted((f for f in (gen / 'network' / 'handoff').glob('shard-conf-*.json') if re.fullmatch(r'shard-conf-\d+\.json', f.name)),
                     key=lambda f: int(f.stem.rsplit('-', 1)[1]))
    return ['/network/full-shard-conf.json', *(f'/network/handoff/{f.name}' for f in handoff)]


def main():
    p = argparse.ArgumentParser()
    p.add_argument('generation', type=Path)
    p.add_argument('--archive-of', type=int, default=1, help='the validator whose archive and ureth the endpoint reads')
    a = p.parse_args()
    gen = a.generation.resolve()
    n = json.loads((gen / 'manifest.json').read_text())['validators']
    if not 1 <= a.archive_of <= n:
        raise SystemExit(f'--archive-of must be 1..{n}')
    image = json.loads((HERE.parent / 'artifacts/bridge-images.json').read_text())['images']['bridge']
    if not re.fullmatch(r'sha256:[0-9a-f]{64}', image):
        raise SystemExit('artifacts/bridge-images.json has no verified bridge image (build-bridge-image.py)')
    addr = json.loads((gen / 'bridge/bridge-addresses.json').read_text())
    i = a.archive_of
    confs = shard_confs(gen)
    services = {'lockproof': hardened(
        image=image, mem_limit='256m', cpus=0.5,   # 256m: the archive locator keeps an 8-byte key per archived block
        networks=['validators', 'edge'], ports=['127.0.0.1:8090:8090'],
        entrypoint=['dnb-tool', 'lockproof-serve', '--listen', '0.0.0.0:8090', '--archive', '/archive', '--eth-url', f'http://ureth{i}:8545',
                    '--vault', addr['BridgeVault'], '--cfg', addr['CFG'], *[x for c in confs for x in ('--full-shard-conf', c)],
                    '--trust-bundle', '/bridge/trust-base.bundle.cbor', '--trusted-proxy', TRUSTED_PROXY],
        volumes=[f'./validator{i}/archive:/archive:ro', './network:/network:ro', './bridge:/bridge:ro'],
        healthcheck={'test': ['CMD', 'node', '-e', "fetch('http://127.0.0.1:8090/healthz').then(r=>process.exit(r.ok?0:1),()=>process.exit(1))"],
                     'interval': '30s', 'timeout': '10s', 'retries': 3})}
    # JSON is a YAML subset, accepted directly by Docker Compose (as compose.yaml)
    (gen / 'compose.bridge.yaml').write_text(json.dumps({'services': services}, indent=2) + '\n')
    print(gen / 'compose.bridge.yaml')


if __name__ == '__main__':
    main()
