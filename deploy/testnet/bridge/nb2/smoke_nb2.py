#!/usr/bin/env python3
"""Run the pinned reference-wallet smoke through a disposable generation's gateway."""
import argparse
import json
import os
import subprocess
from pathlib import Path

from deploy_nb2 import ETH, NBP, cast, cast_failure_reasons, image
from release_nb2 import HERE
from deploy_bridge import validators_network


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('generation', type=Path)
    p.add_argument('--evidence', required=True, type=Path)
    p.add_argument('--phase', choices=('all', 'mint', 'return'), default='all')
    a = p.parse_args()
    gen = a.generation.resolve()
    output = a.evidence.resolve()
    output.mkdir(parents=True, exist_ok=True)
    work = gen / 'bridge/nb2/wallet-smoke-private'
    work.mkdir(exist_ok=True, mode=0o700)
    if os.getuid() == 0:
        subprocess.run(['chown', '10001:10001', str(work)], check=True)
    rpc = 'http://rpc:8545'
    command = [
        'docker', 'run', '--rm', '--read-only', '--network', validators_network(gen), '--user', '10001:10001',
        '-e', 'HOME=/tmp/home', '--tmpfs', '/tmp', '-v', f'{gen / "bridge"}:/work',
        '-v', f'{HERE}:{NBP}/tests/live/nb2lane:ro', '-w', NBP, image(gen), 'npx', '--no-install', 'tsx',
        'tests/live/nb2lane/smoke.ts',
    ]

    def run(phase):
        return subprocess.check_output([*command, phase, '/work/nb2/wallet-smoke-private', rpc, ETH], text=True).strip()

    if a.phase in ('all', 'mint'):
        key_address = run('key')
        # The generation's keystore signs a plain, bounded funding transfer. Only
        # the test wallet uses the fresh private key created inside the container.
        if int(cast(gen, 'balance', '--rpc-url', rpc, key_address)) == 0:
            gas_price = cast(gen, 'gas-price', '--rpc-url', rpc)
            try:
                funding = cast(gen, 'send', '--rpc-url', rpc, '--keystore', '/gen/faucet-secrets/keystore.json',
                               '--password-file', '/gen/faucet-secrets/password', '--legacy', '--gas-price', gas_price,
                               '--gas-limit', '21000', '--value', '2000000000000000000', '--json', key_address)
            except subprocess.CalledProcessError as exc:
                raise SystemExit('test-wallet funding failed: ' + ' | '.join(cast_failure_reasons(exc))) from None
            receipt = json.loads(funding)
            if receipt.get('status') not in ('0x1', '1', 1):
                raise SystemExit('wallet funding transaction failed')
            (output / 'funding.json').write_text(funding + '\n')
        (output / 'mint.json').write_text(run('mint') + '\n')
    if a.phase in ('all', 'return'):
        (output / 'returns.json').write_text(run('return') + '\n')


if __name__ == '__main__':
    main()
