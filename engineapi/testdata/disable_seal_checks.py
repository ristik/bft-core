#!/usr/bin/env python3
"""Disable each identity-binder refusal; matching isolated test must fail."""
from pathlib import Path
import subprocess

source=Path('engineapi/sealconfig.go')
original=source.read_text()
cases=[
 ('local_collector','if a.feeCollector == ([20]byte{}) {','if false && a.feeCollector == ([20]byte{}) {','local_collector_unset'),
 ('rpc_read','if err := a.engine.call(ctx, "engine_sealConfigV1", []any{}, &got); err != nil {','if err := a.engine.call(ctx, "engine_sealConfigV1", []any{}, &got); false && err != nil {','rpc_unavailable'),
 ('version','if got.Version != 1 {','if false && got.Version != 1 {','wrong_version'),
 ('collector_shape','if !common.IsHexAddress(got.FeeCollector) {','if false && !common.IsHexAddress(got.FeeCollector) {','malformed_collector'),
 ('companion_collector','if actual == ([20]byte{}) {','if false && actual == ([20]byte{}) {','companion_collector_unset'),
 ('collector_match','if actual != a.feeCollector {','if false && actual != a.feeCollector {','collector_mismatch'),
 ('fee_profile','if errors.Is(err, m2contract.ErrFeeProfile) {','if false && errors.Is(err, m2contract.ErrFeeProfile) {','invalid_profile'),
]
try:
 for name,needle,replacement,subtest in cases:
  if original.count(needle)!=1:raise SystemExit(f'{name}: check not unique')
  source.write_text(original.replace(needle,replacement))
  result=subprocess.run(['go','test','./engineapi','-run',f'^TestCheckedExecutionConfigIdentity$/{subtest}$','-count=1'],capture_output=True,text=True)
  if result.returncode==0 or f'--- FAIL: TestCheckedExecutionConfigIdentity/{subtest}' not in result.stdout:
   raise SystemExit(f'{name}: matching test did not fail\n{result.stdout}\n{result.stderr}')
  print(f'{name}: matching negative failed')
  source.write_text(original)
finally:source.write_text(original)
