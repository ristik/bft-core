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


def switch_complete(view, target):
    """bft-core#1086: whether a root's q3/status answer (a dict, or None) shows `target` published: True for a switch state Running or Following in the
    target, False for any other switch state (Switching, Faulted, still in the old epoch, declined), None when the root reports no switch state at all (an
    older image, --in-process-epoch-switch=false, or no answer). A root that reports a switch state is never taken as installed from its raw activeEpoch:
    the manager's trust base moves to the target inside the install, before the switch is published or after it faulted."""
    switch = (view or {}).get('switch')
    if not switch:
        return None
    return view.get('activeEpoch') == target and switch.get('epoch') == target and switch.get('phase') in ('running', 'following')


def status_epoch(view):
    """The installed epoch a successful q3/status answer establishes: a switch-aware image's published one (Running or Following; None while Switching,
    Faulted or declined-and-not-yet-restarted can show another), an older image's activeEpoch. Never the raw activeEpoch of a root that reports a switch."""
    switch = view.get('switch')
    if not switch:
        return view.get('activeEpoch')
    if switch.get('phase') in ('running', 'following') and switch.get('epoch') == view.get('activeEpoch'):
        return switch.get('epoch')
    return None


def installed_result(view, target):
    """The install step's result for a root whose switch state shows `target` published (switch_complete): whether it got there in process."""
    switch = view['switch']
    if switch.get('target') == target:
        return {'already': True, 'inProcess': True, 'switchMs': switch.get('tookMs')}
    return {'already': True}


def switched_in_process(status, target, wait=None, sleep=time.sleep, clock=time.monotonic):
    """bft-core#1086: the root's in-process switch into `target` (its q3/status `switch`, phase running or following, with the target installed), else None.
    `status` is the root's q3/status answer as a dict, or None while it does not answer (asked again until `wait`). A root that answers without a `switch`
    does not switch in process (an older image, or --in-process-epoch-switch=false): None at once. A switch that is still switching, or a root still in the old epoch, is asked again until `wait`
    has passed; a faulted switch (the root exits to its recovery) and a declined one (no own evidence, or an older image's leaver or successor with joiners) are None at once. None means: install the root by the restart, through the same evidence gate."""
    deadline = clock() + (SWITCH_WAIT_SECONDS if wait is None else wait)
    while True:
        view = status()
        if view is None:   # unavailable: not evidence of anything
            if clock() >= deadline:
                return None
            sleep(0.1)
            continue
        switch = view.get('switch')
        if not switch:
            return None
        if switch_complete(view, target):
            return switch
        if switch.get('phase') == 'faulted' or switch.get('declined') == target or clock() >= deadline:
            return None
        sleep(0.1)


# bft-core#1086 PR 2: how long the drive waits for a root that does not hold the commit itself (a joiner, a follower) to switch in process. It switches
# once the successor's first messages reach it (or its staged poll finds the activation) and a root peer serves it the bundle: over the WAN for a remote
# joiner, after the staying roots switched.
ACQUIRE_WAIT_SECONDS = 15


def acquires(view):
    """bft-core#1086 PR 2: whether the root's image also switches in process without holding the commit itself (q3/status `switch.acquires`): a joiner, a
    follower or a member that lagged fetches the activation from a root peer and switches. An older image installs such a root across a restart."""
    return bool(((view or {}).get('switch') or {}).get('acquires'))


def awaits_switch(view, old_member):
    """How long the drive waits for a root's in-process switch before its install restart, or None to restart at once. A root whose status did not answer
    is asked again (SWITCH_WAIT_SECONDS: an unavailable answer is no evidence); one that reports no switch state (an older image, the switch disabled) is
    restarted; a member of the committee being left (it switches at its own commit) gets SWITCH_WAIT_SECONDS; a follower there (a joiner) is waited for
    only when its image acquires (ACQUIRE_WAIT_SECONDS)."""
    if view is None:
        return SWITCH_WAIT_SECONDS
    switch = view.get('switch')
    if not switch:
        return None
    if old_member and not view.get('follower'):
        return SWITCH_WAIT_SECONDS
    return ACQUIRE_WAIT_SECONDS if switch.get('acquires') else None


def staged_connected(view, target):
    """bft-core#1086 PR 2 (#1082): whether a joiner's committee view (POST /api/v1/committee) shows the staged successor of epoch `target` with every other
    member connected: its readiness before the commit, since it switches into that committee in process and may lead its first rounds."""
    staged = (view or {}).get('staged') or {}
    return staged.get('epoch') == target and not staged.get('missing')


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
