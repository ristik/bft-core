#!/usr/bin/env python3
"""Packaged operator inputs of a proof-of-stake handoff (#437 item 1). Offline: it writes files, it starts and stops nothing.

The lane's handoff (scripts/p85-recovery-steps.sh, q3-flow-lib.sh) installs an epoch by restarting every root with `--install-handoff-epoch N` (m2_start_root) while
everything else of its command stays. In the package the roots are Compose services whose entrypoint is fixed at generation, so the restart into epoch N is a
Compose override that adds the flag to each root's entrypoint, applied with `docker compose -f compose.yaml -f compose.install-epoch-N.json up -d --force-recreate root<i>`
(a root's state directory is kept: the lane keeps every store of the root, rootchain.db / trustbase.db / root-trust-history.db / orchestration.db, as one set).

    handoff.py install-override <generation> <epoch>
"""
import argparse
import json
from pathlib import Path

FLAG = '--install-handoff-epoch'


def install_override(compose, epoch):
    """The Compose override that restarts every root into `epoch`: its entrypoint plus the install flag, nothing else. The flag is refused below epoch 2."""
    if epoch < 2:
        raise ValueError('--install-handoff-epoch is refused below epoch 2')
    services = {}
    for name, svc in compose['services'].items():
        if name.startswith('root') and name[4:].isdigit():
            entry = list(svc['entrypoint'])
            if FLAG in entry:
                raise ValueError(f'{name} already installs an epoch: {entry[entry.index(FLAG) + 1]}')
            services[name] = {'entrypoint': entry + [FLAG, str(epoch)]}
    if not services:
        raise ValueError('no root services in the compose file')
    return {'services': services}


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument('action', choices=['install-override'])
    p.add_argument('generation', type=Path)
    p.add_argument('epoch', type=int)
    a = p.parse_args()
    compose = json.loads((a.generation / 'compose.yaml').read_text())
    path = a.generation / f'compose.install-epoch-{a.epoch}.json'
    if path.exists():
        p.error(f'{path} exists')
    path.write_text(json.dumps(install_override(compose, a.epoch), indent=1) + '\n')
    print(path)


if __name__ == '__main__':
    main()
