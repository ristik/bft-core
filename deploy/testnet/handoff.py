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
import time
from pathlib import Path

FLAG = '--install-handoff-epoch'

# bft-core#1086: how long the drive waits for a staying root that switches in process to report the successor before it installs it by the restart. The
# switch is one install at the root's own commit (tens of milliseconds), and the drive reaches a root only once it serves its own commit.
SWITCH_WAIT_SECONDS = 5


def switched_in_process(status, target, wait=SWITCH_WAIT_SECONDS, sleep=time.sleep, clock=time.monotonic):
    """bft-core#1086: the root's in-process switch into `target` (its q3/status `switch`, phase running or following, with the target installed), else None.
    `status` is the root's q3/status answer as a dict, or None while it does not answer. A root that reports no `switch` does not switch in process (an older
    image, or --in-process-epoch-switch=false): None at once. A switch that is still switching, or a root still in the old epoch, is asked again until `wait`
    has passed; a faulted switch (the root exits to its recovery) is None at once. None means: install the root by the restart, through the same evidence gate."""
    deadline = clock() + wait
    while True:
        view = status() or {}
        switch = view.get('switch')
        if not switch:
            return None
        if view.get('activeEpoch') == target and switch.get('epoch') == target and switch.get('phase') in ('running', 'following'):
            return switch
        if switch.get('phase') == 'faulted' or clock() >= deadline:
            return None
        sleep(0.1)


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
