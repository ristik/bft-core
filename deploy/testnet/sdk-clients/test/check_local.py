#!/usr/bin/env python3
"""Check the JSON the clients printed in a local run (run_local.sh) with the same checks the driver applies, then prove the checks bite: each
mutation of a good result must make at least one check fail.  check_local.py OUTDIR BUNDLE COMMITS_JSON"""
import copy
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import sdkaccept  # noqa: E402
import utbcbor  # noqa: E402

out, bundle, commits = Path(sys.argv[1]), Path(sys.argv[2]), json.loads(sys.argv[3])
network, entries = utbcbor.history(bundle.read_bytes())
served = {utbcbor.entry_fields(e)[2]: utbcbor.entry_id(e).hex() for e in entries}
tip = max(served)
passed = failed = 0
for sdk in sorted(commits):
    runs = {m: json.loads((out / f'{sdk}-{m}.json').read_text()) for m in ('cold', 'warm', 'restart') if (out / f'{sdk}-{m}.json').exists()}
    for ok, what, detail in sdkaccept.check_runs(sdk, commits[sdk], runs, served, (tip, tip), min_tip=3):
        print(('PASS ' if ok else 'FAIL ') + what + ('' if ok else f'  [{detail}]'))
        passed, failed = passed + ok, failed + (not ok)
    # the checks must bite: each mutation of the good result is caught
    mutations = {
        'a wrong EntryID': lambda r: r['cold']['entryIds'].__setitem__('2', '00' * 32),
        'a missing middle epoch': lambda r: r['cold']['entryIds'].pop('2'),
        'a negative that was not refused': lambda r: r['cold']['negatives']['belowQuorum'].update(refused=False),
        'an untyped negative': lambda r: r['cold']['negatives']['wrongNetwork'].update(typed=False),
        'a wrong error name': lambda r: r['cold']['negatives']['missingMiddle'].update(error='Error'),
        'a control that was refused': lambda r: r['cold']['negatives']['missingMiddle']['control'].update(accepted=False),
        'a restart that did not reload': lambda r: r['restart'].update(heldAtOpen=1),
        'a warm start that held more than the genesis': lambda r: r['warm'].update(heldAtOpen=2),
        'an unpersisted history': lambda r: r['cold'].update(persisted=False),
    }
    for label, mutate in mutations.items():
        bad = copy.deepcopy(runs)
        mutate(bad)
        caught = any(not ok for ok, _, _ in sdkaccept.check_runs(sdk, commits[sdk], bad, served, (tip, tip), min_tip=3))
        print(('PASS ' if caught else 'FAIL ') + f'sdk-{sdk}: the checks catch {label}')
        passed, failed = passed + caught, failed + (not caught)
print(f'{passed} passed, {failed} failed')
sys.exit(1 if failed else 0)
