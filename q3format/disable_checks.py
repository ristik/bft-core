#!/usr/bin/env python3
"""Disable each guard of the historical old-commit verification once; its isolated test must fail. Run from the module root."""
from pathlib import Path
import subprocess

H = Path('q3format/history.go'); M = Path('rootchain/consensus/bootstrap_q3.go')
orig = {p: p.read_text() for p in (H, M)}
cases = [
 (H, 'previous_scheme_from_history', 'cfg, err := h.Signing(prior.epoch)\n\tif err != nil {\n\t\treturn handoff.VerifiedRecord{}, err\n\t}',
  'cfg, err := votesig.Config{Scheme: votesig.SchemeLegacy}, error(nil)\n\tif err != nil {\n\t\treturn handoff.VerifiedRecord{}, err\n\t}',
  './q3format', '^TestSuccessiveHandoffUnderSchemeTwo$', 'TestSuccessiveHandoffUnderSchemeTwo'),
 (H, 'unverifiable_scheme', 'if cfg.Scheme != votesig.SchemeLegacy && cfg.Scheme != votesig.SchemeDomainBound {', 'if false {',
  './q3format', '^TestAnUnverifiableSchemeIsRefusedNotDefaulted$', 'TestAnUnverifiableSchemeIsRefusedNotDefaulted'),
 (H, 'committee_from_entry', 'return handoff.VerifyOldCommitProofSigning(p, prior.tb, cfg)', 'return handoff.VerifyOldCommitProofSigning(p, h.entries[0].tb, cfg)',
  './q3format', '^TestSuccessiveHandoffUnderSchemeTwo$', 'TestSuccessiveHandoffUnderSchemeTwo'),
 (M, 'manager_old_scheme', 'oldSigning, err := x.trustBaseStore.SigningConfig(v.Epoch)', 'oldSigning, err := votesig.Config{Scheme: votesig.SchemeLegacy}, error(nil)',
  './rootchain/consensus', '^TestSecondHandoffIsVerifiedUnderSchemeTwo$', 'TestSecondHandoffIsVerifiedUnderSchemeTwo'),
]
try:
    for path, name, needle, replacement, pkg, selector, marker in cases:
        text = orig[path]
        if text.count(needle) != 1:
            raise SystemExit(f'{name}: check not unique ({text.count(needle)})')
        path.write_text(text.replace(needle, replacement))
        result = subprocess.run(['go', 'test', pkg, '-run', selector, '-count=1'], capture_output=True, text=True)
        if result.returncode == 0 or f'--- FAIL: {marker}' not in result.stdout:
            raise SystemExit(f'{name}: matching test did not fail\n{result.stdout[-3000:]}\n{result.stderr[-1500:]}')
        print(f'{name}: matching negative failed', flush=True)
        path.write_text(text)
finally:
    for path, text in orig.items():
        path.write_text(text)
