#!/usr/bin/env python3
"""Check that a ubft binary accepts every flag a generation's Compose files pass it (bft-core#1075). A dry parse: each distinct ubft entrypoint is run
as `ubft <its exact arguments> --help`. cobra parses every flag (hidden ones too, and each value against its type) before it honours --help, so an
unknown or malformed flag fails, while a known command line only prints its help. Nothing is started.

    ubft_flags.py --ubft PATH COMPOSE.json [COMPOSE.json ...]

validate-generation.py runs it on the generations it makes, so the package CI catches a generator flag the pinned ubft does not know."""
import argparse
import json
import subprocess
import sys
from pathlib import Path


def invocations(compose):
    """{command path: set of long flags} for every service entrypoint that runs ubft. The command path is the words after `ubft` up to the first
    flag; a flag's value is never taken for a flag (values do not start with --), and `--flag=value` counts as --flag."""
    out = {}
    for svc in compose.get('services', {}).values():
        entry = svc.get('entrypoint') or []
        if isinstance(entry, str) or not entry or Path(str(entry[0])).name != 'ubft':
            continue
        words = [str(w) for w in entry[1:]]
        path = []
        for w in words:
            if w.startswith('-'):
                break
            path.append(w)
        flags = {w.split('=', 1)[0] for w in words if w.startswith('--')}
        out.setdefault(tuple(path), set()).update(flags)
    return out


def check(ubft, composes, runner=subprocess.run):
    lines = []
    for c in composes:
        for svc in c.get('services', {}).values():
            entry = svc.get('entrypoint') or []
            if isinstance(entry, list) and entry and Path(str(entry[0])).name == 'ubft':
                words = tuple(str(w) for w in entry[1:])
                if words not in lines:
                    lines.append(words)
    errors = []
    for words in lines:
        done = runner([str(ubft), *words, '--help'], capture_output=True, text=True, timeout=60)
        if done.returncode != 0:
            path = []
            for w in words:
                if w.startswith('-'):
                    break
                path.append(w)
            said = (done.stderr or done.stdout).strip()
            line = f'ubft {" ".join(path)}: ' + (said.splitlines()[0][:200] if said else f'exit {done.returncode}')
            if line not in errors:   # the same command line of every validator fails the same way: say it once
                errors.append(line)
    return errors


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument('--ubft', required=True, type=Path)
    p.add_argument('compose', nargs='+', type=Path)
    a = p.parse_args(argv)
    errors = check(a.ubft, [json.loads(c.read_text()) for c in a.compose])
    for e in errors:
        print('ubft flags: ' + e, file=sys.stderr)
    if not errors:
        print(f'ubft flags: every flag of {len(a.compose)} compose file(s) is accepted by {a.ubft}')
    return 1 if errors else 0


if __name__ == '__main__':
    sys.exit(main())
