#!/usr/bin/env python3
"""Measurement only (measure/nb2-consolidation): run measure_consolidation.ts commands on a generation that rehearse_nb2.py deployed and funded
(stages deploy,fund with --keep-keys), and judge its evidence files with the Go reference and the Rust plug-in.

    measure_consolidation.py --generation GEN --evidence DIR --nb2-evidence BIN [--rust BIN] run CMD ARGS...
    measure_consolidation.py ... verdicts LABEL...      Go (nb2ref, nb2-evidence verify-return) and Rust (nb2_verify_return) on LABEL-{raw,pre,post}
    measure_consolidation.py ... finish                 delete the driver keys

Every driver output (out/m-*.json, out/redeem-*.json) is copied into DIR/nb2 after each command; the console line of each command goes to
DIR/measure.log, redacted of the driver keys like the lane's.
"""
import argparse
import json
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import rehearse_nb2   # noqa: E402

VARIANTS = ('raw', 'pre', 'post', 'trim')


class Measure(rehearse_nb2.NB2Rehearsal):
    def mdriver(self, *args, timeout=7200):
        """One measure_consolidation.ts command: driver.ts's container, the other script."""
        orig = rehearse_nb2.release_nb2.driver_cmd

        def cmd(gen, *a, **kw):
            c = orig(gen, *a, **kw)
            return [x.replace('tests/live/nb2lane/driver.ts', 'tests/live/nb2lane/measure_consolidation.ts') for x in c]
        rehearse_nb2.release_nb2.driver_cmd = cmd
        try:
            return self.driver(*args, check=False, timeout=timeout)
        finally:
            rehearse_nb2.release_nb2.driver_cmd = orig

    def collect(self):
        (self.evidence / 'nb2').mkdir(parents=True, exist_ok=True)
        for f in (self.nb2 / 'out').glob('*.json'):
            if f.name.startswith(('m-', 'redeem-')):
                (self.evidence / 'nb2' / f.name).write_bytes(f.read_bytes())

    def xverdicts(self, labels, rust):
        rel = self.release()
        g = self.write_tmp(rel['pins']['gamma'])
        bundle = self.nb2 / 'public/trust-base.bundle.cbor'
        pin = self.nb2 / 'public/trust-base.genesis.entryid'
        res = {}
        for label in labels:
            files = [self.nb2 / 'evidence' / f'{label}-{v}.cbor' for v in VARIANTS]
            files = [f for f in files if f.is_file()]
            t0 = time.monotonic()
            go = subprocess.run([str(self.nb2_evidence), 'verify-return', '-gamma', str(g), '-trust-bundle', str(bundle), '-pin', str(pin), *map(str, files)],
                                text=True, capture_output=True)
            go_s = time.monotonic() - t0
            gl = {Path(json.loads(x)['file']).name: json.loads(x) for x in go.stdout.splitlines() if x.strip()}
            rl = {}
            if rust:
                r = subprocess.run([rust, str(g), str(bundle), str(pin), rel['pins']['build'], *map(str, files)], text=True, capture_output=True)
                rl = {Path(json.loads(x)['file']).name: json.loads(x) for x in r.stdout.splitlines() if x.strip()}
                if r.returncode != 0:
                    rl['error'] = r.stderr[-500:]
            res[label] = {'go': gl, 'goSeconds': round(go_s, 2), 'goStderr': go.stderr[-500:] if go.returncode else '', 'rust': rl}
            self.say(f'  {label}: ' + '; '.join(f'{f.name}: go {"accepts" if gl.get(f.name, {}).get("verdict") else gl.get(f.name, {}).get("rule")}, '
                                                f'rust {"accepts" if rl.get(f.name, {}).get("verdict") else rl.get(f.name, {}).get("rule")}' for f in files))
        out = self.evidence / 'nb2' / f'm-xverdicts-{"-".join(labels)}.json'
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(res, indent=2) + '\n')


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument('--generation', required=True, type=Path)
    p.add_argument('--evidence', required=True, type=Path)
    p.add_argument('--nb2-evidence', required=True, type=Path)
    p.add_argument('--rust')
    p.add_argument('--cast', default='cast')
    p.add_argument('what', choices=('run', 'verdicts', 'finish'))
    p.add_argument('args', nargs='*')
    a, extra = p.parse_known_args()   # the driver's own flags (--model permissive) pass through
    a.args += extra
    m = Measure(a.generation, a.evidence, a.cast)
    m.nb2_evidence = a.nb2_evidence.resolve()
    if a.what == 'run':
        code, _ = m.mdriver(*a.args)
        m.collect()
        return code
    if a.what == 'verdicts':
        m.xverdicts(a.args, a.rust)
        return 0
    m.finalize_keys(False)
    return 0


if __name__ == '__main__':
    sys.exit(main())
