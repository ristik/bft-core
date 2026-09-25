#!/usr/bin/env python3
"""Disable M2 descriptor checks and require matching refusal tests to fail."""
from pathlib import Path
import subprocess
source=Path('configuredprogress/codec.go');original=source.read_text()
cases=[
 ('descriptor_version','if got.Version != 3 {','if false && got.Version != 3 {','^TestM2DescriptorVersionRefused$','TestM2DescriptorVersionRefused'),
 ('execution_identity','if !bytes.Equal(p, wp) {','if false && !bytes.Equal(p, wp) {','^TestM2IdentityPinnedOnRestore$','TestM2IdentityPinnedOnRestore'),
]
try:
 for name,needle,replacement,selector,marker in cases:
  if original.count(needle)!=1:raise SystemExit(f'{name}: check not unique')
  source.write_text(original.replace(needle,replacement))
  result=subprocess.run(['go','test','./configuredprogress','-run',selector,'-count=1'],capture_output=True,text=True)
  if result.returncode==0 or f'--- FAIL: {marker}' not in result.stdout:
   raise SystemExit(f'{name}: matching test did not fail\n{result.stdout}\n{result.stderr}')
  print(f'{name}: matching negative failed');source.write_text(original)
finally:source.write_text(original)
