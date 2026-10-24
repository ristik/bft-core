#!/usr/bin/env python3
"""A joiner entity for a generated testnet package (TN-S #437): the fifth validator entity of a four-entity generation, created AFTER the genesis.

The genesis committee is fixed at generation (the genesis names its identities, trust base and shard configuration). A joiner is an entity that is not in
it: its keys, directories and Compose services exist beside the generation and are started only when the stage that joins it runs. This file makes them:

  prepare   the entity's root and execution (shard node) keys, its signing authority's operator credential, its private directories (ureth, archive, jwt)
            and compose.joiner.json, an override with the entity's six services (pod, metrics relay, root, authority, ureth, shard node). The services are the
            LAST genesis entity's, renamed, with the joiner's own node ids and every genesis root and shard node as bootnodes; they are exactly what
            generate.topology would write for that entity in a generation of one more validator (the test compares them).

`prepare` only writes files (the keys come from the pinned ubft, run on the host); starting the services, the owner-key operations of the contract and the
handoff are the stages'. Nothing here touches a running service or any key of the genesis entities.

usage: joiner.py prepare GENERATION --ubft PATH [--index N]
"""
import argparse
import copy
import json
import os
import re
import secrets
import subprocess
from pathlib import Path

PARTS = ('pod', 'metrics', 'root', 'authority', 'ureth', 'shard')
SERVICE = re.compile(r'(?<![\w-])(pod|metrics|root|authority|ureth|shard)(\d+)(?![\w])')
ROOT_ID = re.compile(r'/dns4/root(\d+)/tcp/8000/p2p/(\w+)')
SHARD_ID = re.compile(r'/dns4/shard(\d+)/tcp/9000/p2p/(\w+)')


def entities(compose):
    return sorted(int(n[3:]) for n in compose['services'] if n.startswith('pod') and n[3:].isdigit())


def node_ids(compose):
    """{'root': {i: id}, 'evm': {i: id}} of the genesis entities, as the services' bootnode lists carry them (every entity appears in the others' lists)."""
    ids = {'root': {}, 'evm': {}}
    for name, svc in compose['services'].items():
        if re.fullmatch(r'(root|shard)\d+', name):
            for part in svc['entrypoint']:
                for i, node in ROOT_ID.findall(part):
                    ids['root'][int(i)] = node
                for i, node in SHARD_ID.findall(part):
                    ids['evm'][int(i)] = node
    return ids


def rename(value, source, target):
    """`value` with the entity `source`'s service names, paths and aliases made `target`'s. Only whole service names and the validator directory move."""
    if isinstance(value, str):
        value = SERVICE.sub(lambda m: m.group(0) if int(m.group(2)) != source else f'{m.group(1)}{target}', value)
        value = value.replace(f'validator{source}/', f'validator{target}/').replace(f'paired-evm-{source}', f'paired-evm-{target}')
        return value
    if isinstance(value, list):
        return [rename(v, source, target) for v in value]
    if isinstance(value, dict):
        return {rename(k, source, target): rename(v, source, target) for k, v in value.items()}
    return value


def joiner_services(compose, index, root_id, evm_id):
    """The six services of the entity `index`, cloned from the last genesis entity's. Its ids replace the clone's, and its bootnodes are every genesis root and
    shard node (a genesis entity lists the others, so the clone's lists lack the entity it was cloned from and the joiner's own id would be there)."""
    present = entities(compose)
    if index in present:
        raise ValueError(f'entity {index} already exists in the generation')
    source = present[-1]
    ids = node_ids(compose)
    roots = dict(ids['root'])
    evms = dict(ids['evm'])
    if sorted(roots) != present or sorted(evms) != present:
        raise ValueError(f'the genesis node ids are not all in the bootnode lists: roots {sorted(roots)}, evms {sorted(evms)}, entities {present}')
    out = {}
    for part in PARTS:
        svc = copy.deepcopy(rename(compose['services'][f'{part}{source}'], source, index))
        entry = svc['entrypoint']
        if part == 'root':
            at = entry.index('--bootnodes') + 1
            entry[at] = ','.join(f'/dns4/root{j}/tcp/8000/p2p/{roots[j]}' for j in present)
        if part == 'shard':
            at = entry.index('--bootnodes') + 1
            # a shard node lists every root of its generation, its own entity's included, then the other shard nodes (generate.topology)
            entry[at] = ','.join([f'/dns4/root{j}/tcp/8000/p2p/{roots[j]}' for j in present] + [f'/dns4/root{index}/tcp/8000/p2p/{root_id}']
                                 + [f'/dns4/shard{j}/tcp/9000/p2p/{evms[j]}' for j in present])
        if part == 'authority':
            at = entry.index('--node-id') + 1
            entry[at] = evm_id
        out[f'{part}{index}'] = svc
    return out


def prepare(generation, ubft, index=None):
    """Create the joiner's material in `generation` and write compose.joiner.json; returns {'index', 'root', 'evm', 'override'}."""
    previous = os.umask(0o077)   # as generate.py: every private file and directory of the entity (jwt.hex included) is the owner's alone
    try:
        return _prepare(Path(generation), ubft, index)
    finally:
        os.umask(previous)


def _prepare(generation, ubft, index):
    compose = json.loads((generation / 'compose.yaml').read_text())
    index = index or max(entities(compose)) + 1
    if (generation / f'validator{index}').exists():
        raise ValueError(f'validator{index} exists')
    val = generation / f'validator{index}'
    val.mkdir()
    for kind, group in (('root', 'root-node'), ('evm', 'shard-node')):
        subprocess.run([str(ubft), group, 'init', '--home', str(val / kind), '--generate'], check=True, capture_output=True)
    (val / 'auth').mkdir()
    subprocess.run([str(ubft), 'signing-authority', 'credential', '--out', str(val / 'auth' / 'operator.cred')], check=True, capture_output=True)
    for kind in ('ureth', 'archive', 'jwt'):
        (val / kind).mkdir()
    (val / 'jwt' / 'jwt.hex').write_text(secrets.token_hex(32) + '\n')
    node = {kind: subprocess.run([str(ubft), 'node-id', '--home', str(val / kind)], check=True, capture_output=True, text=True).stdout.strip().splitlines()[-1]
            for kind in ('root', 'evm')}
    services = joiner_services(compose, index, node['root'], node['evm'])
    override = generation / 'compose.joiner.json'
    override.write_text(json.dumps({'services': services}, indent=1, sort_keys=True) + '\n')
    for path in [val, *val.rglob('*')]:   # the generation is root's on a runner: the containers run as 10001
        os.chown(path, 10001, 10001) if os.geteuid() == 0 else None
    return {'index': index, 'root': node['root'], 'evm': node['evm'], 'override': str(override)}


def set_scope(generation, index, root_epoch, shard_epoch, trust_base):
    """Start the joiner's signing authority at the scope of the epoch it will sign in. An authority admits no epoch later than the one it starts with ("a later epoch is
    refused, not followed"), its key exists only while it runs (a restart loses it, and the delegation names the key), and it is enrolled against a shard configuration of
    ITS scope: so the successor scope is fixed before it first starts. `trust_base` is the path INSIDE the container (network/ is mounted at /network)."""
    path = Path(generation) / 'compose.joiner.json'
    override = json.loads(path.read_text())
    entry = override['services'][f'authority{index}']['entrypoint']
    for flag, value in (('--root-epoch', str(root_epoch)), ('--shard-epoch', str(shard_epoch)), ('--trust-base', trust_base)):
        entry[entry.index(flag) + 1] = value
    path.write_text(json.dumps(override, indent=1, sort_keys=True) + '\n')


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument('action', choices=['prepare'])
    p.add_argument('generation', type=Path)
    p.add_argument('--ubft', type=Path, required=True)
    p.add_argument('--index', type=int)
    a = p.parse_args()
    print(json.dumps(prepare(a.generation, a.ubft, a.index), sort_keys=True))


if __name__ == '__main__':
    main()
