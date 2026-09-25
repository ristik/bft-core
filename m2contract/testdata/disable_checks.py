#!/usr/bin/env python3
"""Mutation probe: remove each admission check and require its focused negative to fail.

Restores contract.go after every run. Run from the repository root. Stdlib only.
"""
from pathlib import Path
import subprocess

source = Path('m2contract/contract.go')
original = source.read_text()
cases = [
    ('body', 'if err := b.Validate(); err != nil {', 'if err := b.Validate(); false && err != nil {', 'duplicate_key'),
    ('context', 'if b.NetworkID != h.Anchor.NetworkID {', 'if false && b.NetworkID != h.Anchor.NetworkID {', 'wrong_body_network'),
    ('epoch', 'if b.Epoch != priorEpoch+1 {', 'if false && b.Epoch != priorEpoch+1 {', 'gapped_epoch'),
    ('predecessor', 'if !bytes.Equal(b.PredecessorHash, predecessor) {', 'if false && !bytes.Equal(b.PredecessorHash, predecessor) {', 'forged_predecessor'),
    ('unit_weight', 'if member.Weight != 1 {', 'if false && member.Weight != 1 {', 'nonunit_weight'),
    ('activation_body', 'if !bytes.Equal(in.Activation.BodyIdentity, id[:]) {', 'if false && !bytes.Equal(in.Activation.BodyIdentity, id[:]) {', 'wrong_body_activation'),
    ('commit_id', 'if len(in.Activation.ActivationCommitID) != 32 {', 'if false && len(in.Activation.ActivationCommitID) != 32 {', 'missing_commit'),
    ('earliest', 'if in.Activation.EpochStart < in.Body.EarliestActivation {', 'if false && in.Activation.EpochStart < in.Body.EarliestActivation {', 'activation_before_earliest'),
    ('finite_bounds', 'if in.End != 0 && in.Activation.EpochStart >= in.End {', 'if false && in.End != 0 && in.Activation.EpochStart >= in.End {', 'empty_finite_interval'),
    ('contiguity', 'in.Activation.EpochStart != priorEnd ||', '(in.Activation.EpochStart != priorEnd && false) ||', 'overlap'),
    ('reorder', 'if h.Intervals[i].Activation.EpochStart < h.Intervals[i-1].Activation.EpochStart {', 'if false && h.Intervals[i].Activation.EpochStart < h.Intervals[i-1].Activation.EpochStart {', 'reordered_intervals'),
]
try:
    for name, needle, replacement, subtest in cases:
        if original.count(needle) != 1:
            raise SystemExit(f'{name}: expected one check, found {original.count(needle)}')
        source.write_text(original.replace(needle, replacement))
        result = subprocess.run(['go', 'test', './m2contract', '-run', f'^TestTrustHistoryRefusals$/{subtest}$', '-count=1'], capture_output=True, text=True)
        if result.returncode == 0 or f'--- FAIL: TestTrustHistoryRefusals/{subtest}' not in result.stdout:
            raise SystemExit(f'{name}: matching negative did not fail as expected\n{result.stdout}\n{result.stderr}')
        print(f'{name}: matching negative failed')
        source.write_text(original)
finally:
    source.write_text(original)
