#!/usr/bin/env python3
"""One unattended pass of the handoff drive, for a timer (owner Q35: unattended handoffs on a kept generation):

    handoff_auto.py GENERATION --members 1,2,3,4 --log DIR -- --ubft UBFT [other handoff_drive.py options]

It runs `handoff_drive.py GENERATION --only-if-members MEMBERS ...` once (as root, like the drive). The drive resumes an unfinished drive from
handoff/log.jsonl, refuses when its window is too short, skips a result whose elected committee is not MEMBERS (a join or a retirement stays an operator
act), and holds handoff/drive.lock, so a pass started while another drive runs (a manual one too) does nothing. Every pass appends one line to DIR/auto.log
(time, exit code, outcome); a pass that did more than find no open result also keeps its whole output in DIR/drive-<time>.log. The exit code is the drive's,
except that 3 for "no open result" and 5 (busy) are 0: those are the timer's ordinary idle passes.

A user systemd timer (with `loginctl enable-linger`), e.g. every 2 minutes:
    systemd-run --user --unit=handoff-auto --on-calendar='*:0/2' --timer-property=AccuracySec=10s \\
        sudo -E env PATH=$PATH python3 deploy/testnet/handoff_auto.py GENERATION --members 1,2,3,4 --log DIR -- --ubft UBFT
"""
import argparse
import datetime
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
OUTCOMES = {0: 'driven', 1: 'stopped (rerun continues)', 3: 'refused', 4: 'skipped (not the expected committee)', 5: 'busy (another drive holds the lock)'}
IDLE = 'the election has no open result'


def outcome(code, output):
    """(summary, idle): idle passes are the ones a timer makes all day: no open result, or another drive running."""
    if code == 3 and IDLE in output:
        return 'idle: no open result', True
    if code == 5:
        return OUTCOMES[5], True
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
    done = subprocess.run([sys.executable, str(HERE / 'handoff_drive.py'), str(a.generation), '--only-if-members', a.members, *rest],
                          text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    summary, idle = outcome(done.returncode, done.stdout)
    stamp = now.strftime('%Y%m%dT%H%M%SZ')
    if not idle:
        (a.log / f'drive-{stamp}.log').write_text(done.stdout)
    with open(a.log / 'auto.log', 'a') as log:
        log.write(f'{now.isoformat(timespec="seconds")} exit={done.returncode} {summary}' + ('' if idle else f' (drive-{stamp}.log)') + '\n')
    return 0 if idle else done.returncode


if __name__ == '__main__':
    sys.exit(main())
