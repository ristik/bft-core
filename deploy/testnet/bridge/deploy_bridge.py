#!/usr/bin/env python3
"""Deploy the bridge (TokenVerifier + BridgeVault) on a running generation and write the driver's configuration (briefs/tnb-without-host.md).

    deploy_bridge.py GENERATION --agg-conf CONF[,CONF...] --agg-url URL[,URL...] [--agg-shard HEX,...]

The same steps as scripts/lib/agg-lib.sh bridge_deploy_vault + bridge_write_config, run in the bridge tools image on the generation's internal validators
network against validator 1's execution client (an operator action: the public gateway takes only its allow-listed methods, with X-Forwarded-For):
  1. dnb-tool deployment: the deployment document from the B1 identity document (network/b1-identities.json) and the aggregator shard configurations;
  2. forge script BridgeDeploy.s.sol, which refuses a vault whose rootGenesis, executionGenesis or b1ProfileHash differ from the genesis', signed with the
     generation's genesis-funded faucet keystore (the key never leaves its file);
  3. dnb-tool trust-bundle / pdr, then GENERATION/bridge/lane-config.json for tests/live/anyage.ts and GENERATION/bridge/public/, the one directory
     to publish for testers: the tester page (bridge/tester/index.html), tester-config.json for the bridge tester (native-bridge-plugins tester/), which
     names the endpoints a tester reaches (--tester-*-url; the defaults are the internal names), and the four public files it names;
  4. the bridge release manifest (release.py), GENERATION/bridge/public/bridge-release.json.
Writes everything under GENERATION/bridge/.
"""
import argparse
import json
import os
import subprocess
from pathlib import Path

import release

ETH = 'http://ureth1:8545'
GATEWAY = 'http://rpc:8545'   # the package's public gateway (gateway.py) as the validators network names it
TAG = 'tnops-bridge:verified'
CONTRACTS = '/opt/bridge/contracts'


def validators_network(gen):
    # Compose names a project's networks <project>_<network>; the project is the generation's
    name = json.loads(subprocess.check_output(['docker', 'compose', '-f', str(gen / 'compose.yaml'), 'config', '--format', 'json'], text=True))['name']
    return f'{name}_validators'


def tools(gen, *args, capture=False):
    # only the public network files and the faucet's keystore, read-only (never the validators' or owners' keys); the bridge directory writable at
    # /work; the image itself is read-only. HOME and every scratch copy live on the tmpfs: GENERATION/bridge is backed up with the generation, and
    # backup.py restores plain files and directories only
    cmd = ['docker', 'run', '--rm', '--read-only', '--network', validators_network(gen), '--user', f'{os.getuid()}:{os.getgid()}', '-e', 'HOME=/tmp/home',
           '-v', f'{gen / "network"}:/gen/network:ro', '-v', f'{gen / "faucet-secrets"}:/gen/faucet-secrets:ro', '-v', f'{gen / "bridge"}:/work',
           '--tmpfs', '/tmp', '-w', '/work', TAG, *args]
    return subprocess.run(cmd, check=True, text=True, capture_output=capture).stdout


def main():
    p = argparse.ArgumentParser()
    p.add_argument('generation', type=Path)
    p.add_argument('--agg-conf', required=True, help='aggregator shard configuration files, relative to GENERATION, comma separated, in shard order')
    p.add_argument('--agg-url', required=True, help='each shard\'s aggregator URL as the driver reaches it, comma separated, same order')
    p.add_argument('--agg-partition', type=int, default=7, help='the aggregation partition the bridge profile names (7, the fixed one)')
    p.add_argument('--agg-shard', default='', help='native shard ID bytes of each shard, hex, comma separated (two or more shards)')
    p.add_argument('--tester-eth-url', default=GATEWAY, help='the JSON-RPC endpoint testers use (default: the package\'s public gateway; its public name on a host)')
    p.add_argument('--tester-redeem-eth-url', default='', help='where testers send redemptions, when the --tester-eth-url gateway cannot take them (the package gateway can)')
    p.add_argument('--tester-agg-url', default=GATEWAY + '/aggregator', help='the aggregator endpoint testers use (default: the package gateway\'s /aggregator route)')
    p.add_argument('--tester-lockproof-url', default='http://lockproof:8090', help='the lock-proof endpoint testers use')
    a = p.parse_args()
    gen = a.generation.resolve()
    manifest = json.loads((gen / 'manifest.json').read_text())
    work = gen / 'bridge'
    work.mkdir(parents=True, exist_ok=True)
    confs = a.agg_conf.split(',')
    urls = a.agg_url.split(',')
    shards = [s for s in a.agg_shard.split(',') if s]
    if len(urls) != len(confs) or (len(confs) > 1 and len(shards) != len(confs)):
        raise SystemExit('one --agg-url (and, with several shards, one --agg-shard) per --agg-conf')

    tools(gen, 'dnb-tool', 'deployment', '--identities', '/gen/network/b1-identities.json', '--agg-conf', ','.join('/gen/' + c for c in confs),
          '--out', '/work/bridge-deployment.json')
    secrets = 'faucet-secrets'
    # a writable copy of the built contracts on the tmpfs (out/ and cache/ included: nothing recompiles, and the image's solc is linked in for
    # --offline); only the broadcast record is kept, as bridge-broadcast.json
    tools(gen, 'bash', '-c', f'set -eo pipefail; cp -R {CONTRACTS} /tmp/contracts && '
          'for d in .svm .local/share/svm; do [ ! -e /home/bridge/$d ] || { mkdir -p "$(dirname /tmp/home/$d)" && ln -sfn /home/bridge/$d /tmp/home/$d; }; done && '
          # the script reads its inputs under script/bridge-deploy/ only (foundry.toml fs_permissions), as scripts/lib/agg-lib.sh places them
          'cp /gen/network/b1-identities.json /tmp/contracts/script/bridge-deploy/genesis.json && '
          'cp /work/bridge-deployment.json /tmp/contracts/script/bridge-deploy/deployment.json && '
          'cd /tmp/contracts && BRIDGE_GENESIS=script/bridge-deploy/genesis.json BRIDGE_DEPLOYMENT=script/bridge-deploy/deployment.json '
          f'forge script script/BridgeDeploy.s.sol --offline --rpc-url {ETH} --keystore /gen/{secrets}/keystore.json --password-file /gen/{secrets}/password '
          f'--broadcast --slow 2>&1 | tee /work/vault-deploy.log && cp broadcast/BridgeDeploy.s.sol/{manifest["chain_id"]}/run-latest.json /work/bridge-broadcast.json')
    run = json.loads((work / 'bridge-broadcast.json').read_text())
    addr = {t['contractName']: t['contractAddress'] for t in run['transactions'] if t.get('contractName') in ('BridgeVault', 'TokenVerifier')}
    if set(addr) != {'BridgeVault', 'TokenVerifier'}:
        raise SystemExit(f'the deploy broadcast has no BridgeVault/TokenVerifier: {addr}')
    # the vault's CFG, which every lock proof names (the lock-proof endpoint takes it at start)
    addr['CFG'] = tools(gen, 'cast', 'call', '--rpc-url', ETH, addr['BridgeVault'], 'CFG()(bytes32)', capture=True).strip()
    (work / 'bridge-addresses.json').write_text(json.dumps(addr, indent=2) + '\n')

    tools(gen, 'dnb-tool', 'trust-bundle', '--trust-base', '/gen/network/trust-base.json', '--out', '/work/trust-base.bundle.cbor',
          '--out-pin', '/work/trust-base.genesis.entryid')
    tools(gen, 'dnb-tool', 'pdr', '--full-shard-conf', '/gen/network/full-shard-conf.json', '--out', '/work/evm-pdr.cbor')
    # the driver reads <dir>/evm-full-shard-conf.json (the DN-B lane's name)
    (work / 'evm-full-shard-conf.json').write_bytes((gen / 'network/full-shard-conf.json').read_bytes())
    config = {'dir': '/work', 'ethUrls': [f'http://ureth{i}:8545' for i in range(1, manifest['validators'] + 1)], 'aggUrl': urls[0], 'aggUrls': urls, 'vault': addr['BridgeVault'], 'verifier': addr['TokenVerifier'],
              'chainId': manifest['chain_id'], 'evmPartition': 8, 'aggPartition': a.agg_partition,
              'archive': '/archive'}   # the driver container mounts one validator's certified-block archive read-only at /archive
    if len(shards) > 1:
        config['aggShards'] = [{'shard': s, 'url': u} for s, u in zip(shards, urls)]
    (work / 'lane-config.json').write_text(json.dumps(config, indent=2) + '\n')
    # what an operator publishes for testers, and nothing else (bridge/README.md "The bridge tester")
    public = work / 'public'
    public.mkdir(exist_ok=True)
    files = {'trustBundle': 'trust-base.bundle.cbor', 'trustEntryId': 'trust-base.genesis.entryid', 'evmPdr': 'evm-pdr.cbor', 'deployment': 'bridge-deployment.json'}
    for name in files.values():
        (public / name).write_bytes((work / name).read_bytes())
    (public / 'index.html').write_bytes((Path(__file__).parent / 'tester/index.html').read_bytes())
    # genesisHash: the tester checks block 0 against it before sending anything (a reset generation keeps the chain ID)
    tester = {'ethUrl': a.tester_eth_url, 'aggUrl': a.tester_agg_url, 'lockProofUrl': a.tester_lockproof_url, 'chainId': manifest['chain_id'],
              'genesisHash': manifest['genesis_hash'], 'vault': addr['BridgeVault'], 'files': files}
    if a.tester_redeem_eth_url:
        tester['redeemEthUrl'] = a.tester_redeem_eth_url
    (public / 'tester-config.json').write_text(json.dumps(tester, indent=2) + '\n')
    image = subprocess.check_output(['docker', 'image', 'inspect', '--format={{.Id}}', TAG], text=True).strip()
    ureth = json.loads((gen / 'compose.yaml').read_text())['services']['ureth1']['entrypoint']
    manifest_doc = release.build(gen, lambda *args: tools(gen, *args, capture=True), image, ureth, release.gateway_limits())
    (public / 'bridge-release.json').write_text(json.dumps(manifest_doc, indent=2) + '\n')
    if os.getuid() == 0:   # the package's services run as 10001 (the lock-proof endpoint reads the trust bundle here)
        subprocess.run(['chown', '-R', '10001:10001', str(work)], check=True)
    print(json.dumps(addr))


if __name__ == '__main__':
    main()
