#!/usr/bin/env python3
"""CI/operator probe of a proof-of-stake generation (generate.py --pos); no EVM, no containers.

It proves what a package-level check can, and says what it cannot:
  * the genesis ids agree: the assignment id in the shipped contracts genesis is the one `pos-relayer verify-genesis` recomputes from the shipped plan, trust
    base and FULL shard configuration, and it is not the base configuration's (the first pass, which the roots would never close);
  * a contracts genesis naming another id is refused by verify-genesis with both ids;
  * the EVM genesis carries the custody and election code at the deployed addresses, and the roots' deployment file pins the profile's registry code hash;
  * the roots start with the P85 flags (and without --genesis-identities) from the generated Compose entrypoints and certify rounds on their own: this is the
    start of the epoch-1 chain whose first closure the roots will name against the custody assignment verified above.
NOT covered (needs the EVM shard running, i.e. the containers): the first blocks, the custody's recorded progress, and the election clock; the operator
checks them with OPERATOR.md "PoS smoke".
"""
import json
from pathlib import Path
import re
import subprocess
import tempfile
import time
import urllib.request

import pos


def code_of(genesis, address):
    want = address.lower().removeprefix('0x')
    found = [v for k, v in genesis['alloc'].items() if k.lower().removeprefix('0x') == want]
    assert len(found) == 1 and len(found[0].get('code', '0x')) > 2, f'no code at {address} in the genesis alloc'
    return found[0]['code']


def statics(generation, ubft):
    net = generation / 'network'
    manifest = json.loads((generation / 'manifest.json').read_text())
    info = manifest['pos']
    assert not (net / 'genesis-identities.json').exists(), 'the PoA records are shipped beside the PoS records'
    assert info['genesis_assignment'] != info['first_pass_assignment'], 'the base configuration id was deployed: the reconciliation did not happen'
    assert (net / 'pos-genesis-assignment.txt').read_text().strip() == info['genesis_assignment']
    args = [str(ubft), 'pos-relayer', 'verify-genesis', '--plan', net / 'pos-plan.json', '--trust-base', net / 'trust-base.json',
            '--shard-conf', net / 'full-shard-conf.json', '--contracts-genesis', net / 'pos-contracts-genesis.json']
    done = subprocess.run([str(x) for x in args], text=True, capture_output=True)
    assert done.returncode == 0 and pos.AGREE.findall(done.stderr) == [info['genesis_assignment']], done.stdout + done.stderr
    contracts = json.loads((net / 'pos-contracts-genesis.json').read_text())
    assert contracts['assignmentId'] == info['genesis_assignment']
    # a contracts genesis of another id is refused, naming both
    with tempfile.TemporaryDirectory(prefix='tnops-pos-') as tmp:
        wrong = Path(tmp) / 'contracts-genesis.json'
        contracts['assignmentId'] = info['first_pass_assignment']
        wrong.write_text(json.dumps(contracts))
        bad = subprocess.run([str(x) for x in args[:-1] + [wrong]], text=True, capture_output=True)
        assert bad.returncode != 0 and info['first_pass_assignment'] in bad.stderr + bad.stdout and info['genesis_assignment'] in bad.stderr + bad.stdout, \
            'a contracts genesis of the base configuration id was accepted, or the refusal does not name both ids: ' + bad.stdout + bad.stderr
    genesis = json.loads((net / 'genesis.json').read_text())
    deployment = json.loads((net / 'pos-deployment.json').read_text())
    profile = json.loads((net / 'b1-profile.json').read_text())
    assert deployment['registryCodeHash'] == profile['runtimeHash'] and deployment['registry'] == pos.REGISTRY
    for module in ('custody', 'election'):
        code_of(genesis, deployment[module])
    assert deployment['custody'] == info['custody'] and deployment['election'] == info['election']
    compose = json.loads((generation / 'compose.yaml').read_text())
    for i in range(1, manifest['validators'] + 1):
        root = compose['services'][f'root{i}']['entrypoint']
        assert root[root.index('--pos-deployment') + 1] == '/network/pos-deployment.json'
        assert root[root.index('--pos-genesis-identities') + 1] == '/network/pos-genesis-identities.json'
        assert root[root.index('--pos-evm-rpc') + 1] == f'http://ureth{i}:8545'
        assert '--genesis-identities' not in root and '--q3-lane' in root and '--profile-2' in root
    return manifest


def roots_start(generation, ubft, base_port=24000):
    """The PoS roots, native, from the generated entrypoints (only transport addresses and host paths change), certify rounds without an EVM node."""
    cfg = json.loads((generation / 'compose.yaml').read_text())
    n = json.loads((generation / 'manifest.json').read_text())['validators']
    processes, logs = [], []
    try:
        for i in range(1, n + 1):
            command = cfg['services'][f'root{i}']['entrypoint'].copy()
            command[0] = str(ubft)
            for j, arg in enumerate(command):
                arg = arg.replace('/state', str(generation / f'validator{i}/root')).replace('/network', str(generation / 'network'))
                arg = re.sub(r'/dns4/root(\d+)/tcp/8000', lambda m: f'/ip4/127.0.0.1/tcp/{base_port + int(m[1])}', arg)
                arg = arg.replace('/ip4/0.0.0.0/tcp/8000', f'/ip4/127.0.0.1/tcp/{base_port + i}').replace('0.0.0.0:8002', f'127.0.0.1:{base_port + 100 + i}')
                command[j] = re.sub(r'http://ureth\d+:8545', f'http://127.0.0.1:{base_port + 999}', arg)   # no EVM node: the endpoint is closed
            path = generation / f'pos-root{i}.log'
            logs.append(path)
            log = path.open('w')
            processes.append((subprocess.Popen(command, stdout=log, stderr=log), log))
        url = f'http://127.0.0.1:{base_port + 101}/api/v1/roundInfo'
        seen, deadline = [], time.monotonic() + 90
        while time.monotonic() < deadline:
            assert all(proc.poll() is None for proc, _ in processes), 'a PoS root exited'
            try:
                with urllib.request.urlopen(url, timeout=3) as response:
                    seen.append(int(json.load(response)['roundNumber']))
            except (OSError, ValueError, KeyError):
                pass
            if seen and seen[-1] >= seen[0] + 5:
                return {'pos_roots_certify_rounds': 'PASS', 'rounds': [seen[0], seen[-1]]}
            time.sleep(1)
        raise AssertionError(f'the PoS roots did not advance five rounds: {seen}')
    except BaseException:
        for path in logs:
            print(f'--- {path.name} ---\n{path.read_text()[-12000:]}')
        raise
    finally:
        for proc, _ in processes:
            if proc.poll() is None:
                proc.terminate()
        for proc, log in processes:
            try:
                proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()
            log.close()


def validate(generation, ubft):
    manifest = statics(generation, ubft)
    started = roots_start(generation, ubft)
    return {'pos_genesis_ids_agree': 'PASS', 'genesis_assignment': manifest['pos']['genesis_assignment'],
            'base_configuration_assignment_refused': manifest['pos']['first_pass_assignment'], **started}
