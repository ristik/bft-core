#!/usr/bin/env python3
"""One unattended pass of the handoff drive, for a timer (owner Q35: unattended handoffs on a kept generation):

    handoff_auto.py GENERATION --members 1,2,3,4 --log DIR -- --ubft UBFT [other handoff_drive.py options]

It runs `handoff_drive.py GENERATION --only-if-members MEMBERS ...` once (as root, like the drive). The drive resumes an unfinished drive from
handoff/log.jsonl, refuses when its window is too short, skips a result whose elected committee is not MEMBERS (a join or a retirement stays an operator
act), and holds handoff/drive.lock, so a pass started while another drive runs (a manual one too) does nothing.

It STANDS DOWN, without starting the drive, while a remote joiner (remote_joiner.py, #1023) is registered, bonded, prepared or retiring on the generation
(handoff/remote-joiners/<entity>.json `state`): the join drives its own results, and the timer must not move the epoch under a prepared joiner.

Every pass appends one line to DIR/auto.log (time, exit code, outcome); a pass that drove (or stopped or refused) also keeps its whole output in
DIR/drive-<time>.log. Idle passes exit 0: no open result (3), another drive running (5), a stand-down, and a skip (4: the open or unfinished drive is not
the host committee's, e.g. an operator's join drive that stopped half way). A stand-down or a skip writes its auto.log line at most once an hour for the
same joiner state or result (DIR/auto-state.json), and never a drive log.

A user systemd timer (with `loginctl enable-linger`), e.g. every 2 minutes:
    systemd-run --user --unit=handoff-auto --on-calendar='*:0/2' --timer-property=AccuracySec=10s \\
        sudo -E env PATH=$PATH python3 deploy/testnet/handoff_auto.py GENERATION --members 1,2,3,4 --log DIR -- --ubft UBFT
"""
import argparse
import datetime
import json
import re
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
OUTCOMES = {0: 'driven', 1: 'stopped (rerun continues)', 3: 'refused', 4: 'skipped (not the expected committee)', 5: 'busy (another drive holds the lock)'}
IDLE = 'the election has no open result'
QUIET_SECONDS = 3600   # a repeated stand-down or skip is logged at most this often
JOINING = ('registered', 'bonded', 'preparing', 'prepared', 'retiring')   # remote_entity.STATES before 'member', and the retirement


def joining(generation):
    """[(entity, state)] of the remote joiners of GENERATION that are mid-join or retiring (handoff/remote-joiners/<entity>.json)."""
    found = []
    for path in sorted((Path(generation) / 'handoff' / 'remote-joiners').glob('*.json')):
        if not re.fullmatch(r'\d+\.json', path.name):
            continue
        try:
            state = json.loads(path.read_text()).get('state', 'registered')
        except (OSError, ValueError):
            state = 'unreadable'   # a joiner file the pass cannot read: stand down rather than guess
        if state in JOINING or state == 'unreadable':
            found.append((int(path.stem), state))
    return found


def quiet(log_dir, key, now):
    """True when KEY was already logged within QUIET_SECONDS; otherwise records NOW for it."""
    path = log_dir / 'auto-state.json'
    try:
        seen = json.loads(path.read_text())
    except (OSError, ValueError):
        seen = {}
    if now.timestamp() - seen.get(key, 0) < QUIET_SECONDS:
        return True
    seen[key] = now.timestamp()
    path.write_text(json.dumps(seen) + '\n')
    return False


def outcome(code, output):
    """(summary, idle): idle passes are the ones a timer makes all day: no open result, another drive running, a skipped committee."""
    if code == 3 and IDLE in output:
        return 'idle: no open result', True
    if code == 5:
        return OUTCOMES[5], True
    if code == 4:
        line = next((l for l in output.splitlines() if 'SKIPPED' in l), '')
        return f'{OUTCOMES[4]}: {line.strip()[:300]}', True
    last = [line for line in output.strip().splitlines() if line.strip()]
    return f'{OUTCOMES.get(code, f"exit {code}")}: {last[-1].strip()[:300] if last else ""}', False


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument('generation', type=Path)
    p.add_argument('--members', required=True, help='the committee to drive unattended, entity numbers, comma separated')
    p.add_argument('--log', required=True, type=Path)
    argv = list(sys.argv[1:] if argv is None else argv)
    cut = argv.index('--') if '--' in argv else len(argv)
    a, rest = p.parse_args(argv[:cut]), argv[cut + 1:]   # after --: handoff_drive.py options (--ubft is required there)
    if any(x in rest for x in ('--plan', '--only-if-members', '--allow-unrehearsed-retirement', '--joiner')):
        p.error('the unattended pass sets --only-if-members itself and takes no --plan, --joiner or --allow-unrehearsed-retirement')
    a.log.mkdir(parents=True, exist_ok=True)
    now = datetime.datetime.now(datetime.timezone.utc)
    joiners = joining(a.generation)
    if joiners:
        key = 'stand-down ' + ','.join(f'{e}:{s}' for e, s in joiners)
        if not quiet(a.log, key, now):
            with open(a.log / 'auto.log', 'a') as log:
                log.write(f'{now.isoformat(timespec="seconds")} exit=0 stand down: remote joiner(s) ' + ', '.join(f'{e} {s}' for e, s in joiners)
                          + f' (handoff/remote-joiners); the join drives its own results. Logged at most hourly.\n')
        return 0
    done = subprocess.run([sys.executable, str(HERE / 'handoff_drive.py'), str(a.generation), '--only-if-members', a.members, *rest],
                          text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    summary, idle = outcome(done.returncode, done.stdout)
    stamp = now.strftime('%Y%m%dT%H%M%SZ')
    if done.returncode == 4:
        result = re.search(r'drive (0x[0-9a-f]{64}) by hand', done.stdout)
        if quiet(a.log, 'skip ' + (result.group(1) if result else summary), now):
            return 0
        summary += ' (logged at most hourly)'
    if not idle:
        (a.log / f'drive-{stamp}.log').write_text(done.stdout)
    with open(a.log / 'auto.log', 'a') as log:
        log.write(f'{now.isoformat(timespec="seconds")} exit={done.returncode} {summary}' + ('' if idle else f' (drive-{stamp}.log)') + '\n')
    return 0 if idle else done.returncode


if __name__ == '__main__':
    sys.exit(main())
