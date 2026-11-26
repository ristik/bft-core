#!/usr/bin/env python3
"""Advance the Compose authorities with the roots' authenticated VR activation bundles."""
import argparse
from concurrent.futures import ThreadPoolExecutor
import json
from pathlib import Path
import subprocess
import tempfile
import uuid

import handoff_ops
import operator_rpc
import vr_recover


def advance(generation, epoch, evidence, only=None):
    """Advance the authorities of `only` (default: every validator) to `epoch` and restart their shard nodes."""
    manifest = json.loads((generation / 'manifest.json').read_text())
    if (manifest.get('pos') or {}).get('profile') != 'vr-pos16' or epoch < 2:
        raise ValueError('a VR/P85 Compose generation and an activated epoch of at least two are required')
    compose = handoff_ops.load_compose(generation)
    root_rpc = operator_rpc.common_urls(compose)[0]
    cmd = ['docker', 'compose', *handoff_ops.compose_files(generation)]
    evidence.mkdir(parents=True, exist_ok=True)

    def exec_command(service, *args):
        return subprocess.check_output([*cmd, 'exec', '-T', service, *args])

    bundles = []
    for e in range(2, epoch + 1):
        name = f'activation-{e}.cbor'
        remote = '/tmp/' + uuid.uuid4().hex
        try:
            exec_command('root1', 'ubft', 'q3', 'proof-envelope', '--root-rpc', root_rpc, '--epoch', str(e), '--out', remote)
            payload = exec_command('root1', 'cat', remote)
        finally:
            exec_command('root1', 'rm', '-f', '--', remote)
        (evidence / name).write_bytes(payload)
        bundles.append((name, payload))

    def one(i):
        # the directory the authority runs in now: a recovered entity's is its node slot's (compose.recover.json, vr_recover.py)
        credentials = vr_recover.authority_dir(generation, compose, i)
        proofs = []
        with tempfile.TemporaryDirectory(prefix='advance-', dir=credentials) as tmp:
            work = Path(tmp)
            work.chmod(0o755)
            for name, payload in bundles:
                f = work / name
                f.write_bytes(payload)
                f.chmod(0o644)
                proofs.extend(('--proof', f'/authority/{work.name}/{name}'))
            report = json.loads(exec_command(f'authority{i}', 'ubft', 'signing-authority', 'advance-with-proof',
                '--operator-socket', '/authority/operator.sock', '--operator-credential', '/authority/operator.cred',
                '--client-socket', '/authority/client.sock', '--out', '/authority/client.cred', *proofs))
        (evidence / f'authority{i}-epoch{epoch}.json').write_text(json.dumps(report, indent=2) + '\n')
        if report['rootEpoch'] != epoch or report['retired']:
            raise RuntimeError(f'authority {i} cannot serve epoch {epoch}: {report}')
        return f'shard{i}'

    # Every incumbent advances from the same proof. Restart only the shard
    # clients so they load the new sessions. The authority lifetimes survive.
    chosen = list(only or range(1, manifest['validators'] + 1))
    with ThreadPoolExecutor(max_workers=len(chosen)) as pool:
        shards = list(pool.map(one, chosen))
    subprocess.run([*cmd, 'restart', *shards], check=True)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('generation', type=Path)
    p.add_argument('--epoch', type=int, required=True)
    p.add_argument('--evidence', type=Path, required=True)
    a = p.parse_args()
    advance(a.generation.resolve(), a.epoch, a.evidence.resolve())


if __name__ == '__main__':
    main()
