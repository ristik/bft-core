#!/usr/bin/env python3
"""Measurement only (measure/nb2-gas-refit, bft-core#1179): run measure_gas_refit.ts (or a driver.ts) command on a generation that
rehearse_nb2.py deployed and funded (stages deploy,fund with --keep-keys), with the plug-in source under test (--plugin-src, the
native-bridge-plugins packages/native-bridge-plugin/src of the refit branch) mounted over the bridge image's.

    measure_gas_refit.py --generation GEN --evidence DIR --plugin-src DIR run CMD ARGS...    a measure_gas_refit.ts command
    measure_gas_refit.py ... driver CMD ARGS...                                              a driver.ts command (rotate, redeem, ...)
    measure_gas_refit.py ... stage STAGES                                                    rehearse_nb2.py stages (boundary), same mount
    measure_gas_refit.py ... finish                                                          delete the driver keys

Every driver output (out/g-*.json, out/redeem-*.json, out/boundary-*.json) is copied into DIR/nb2 after each command.
"""
import argparse
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import rehearse_nb2   # noqa: E402

PLUGIN_SRC = None


def patch(script=None):
    orig = rehearse_nb2.release_nb2.driver_cmd

    def cmd(gen, *a, extra=(), **kw):
        mount = ('-v', f'{PLUGIN_SRC}:{rehearse_nb2.release_nb2.NBP}/packages/native-bridge-plugin/src:ro')
        c = orig(gen, *a, extra=tuple(extra) + mount, **kw)
        return [x.replace('tests/live/nb2lane/driver.ts', f'tests/live/nb2lane/{script}') for x in c] if script else c
    rehearse_nb2.release_nb2.driver_cmd = cmd


class Measure(rehearse_nb2.NB2Rehearsal):
    def collect(self):
        (self.evidence / 'nb2').mkdir(parents=True, exist_ok=True)
        for f in (self.nb2 / 'out').glob('*.json'):
            if f.name.startswith(('g-', 'redeem-', 'boundary', 'rotate-')):
                (self.evidence / 'nb2' / f.name).write_bytes(f.read_bytes())
        ev = self.evidence / 'evidence-cbor'
        ev.mkdir(parents=True, exist_ok=True)
        for f in (self.nb2 / 'evidence').glob('*.cbor'):
            (ev / f.name).write_bytes(f.read_bytes())


def main():
    global PLUGIN_SRC
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument('--generation', required=True, type=Path)
    p.add_argument('--evidence', required=True, type=Path)
    p.add_argument('--plugin-src', required=True, type=Path)
    p.add_argument('--nb2-evidence', type=Path)
    p.add_argument('--cast', default='cast')
    p.add_argument('what', choices=('run', 'driver', 'stage', 'finish'))
    p.add_argument('args', nargs='*')
    a, extra = p.parse_known_args()
    a.args += extra
    PLUGIN_SRC = a.plugin_src.resolve()
    patch('measure_gas_refit.ts' if a.what == 'run' else None)
    if a.what == 'stage':
        sys.argv = ['rehearse_nb2.py', '--generation', str(a.generation), '--evidence', str(a.evidence), '--nb2-evidence', str(a.nb2_evidence),
                    '--cast', a.cast, '--stages', a.args[0], '--keep-keys', *a.args[1:]]
        return rehearse_nb2.main()
    m = Measure(a.generation, a.evidence, a.cast)
    if a.nb2_evidence:
        m.nb2_evidence = a.nb2_evidence.resolve()
    if a.what in ('run', 'driver'):
        code, _ = m.driver(*a.args, check=False, timeout=7200)
        m.collect()
        return code
    m.finalize_keys(False)
    return 0


if __name__ == '__main__':
    sys.exit(main())
