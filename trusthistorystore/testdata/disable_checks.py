#!/usr/bin/env python3
"""Disable each durable admission check; its isolated refusal must fail."""
from pathlib import Path
import subprocess

source=Path('trusthistorystore/store.go')
original=source.read_text()
cases=[
 ('schema','version != schemaVersion','version != schemaVersion && false','^TestSchemaAndAnchorEncodingRefusals$/^schema_version$','TestSchemaAndAnchorEncodingRefusals/schema_version'),
 ('identity','if !bytes.Equal(id, s.identity[:]) {','if false && !bytes.Equal(id, s.identity[:]) {','^TestStoreRestartEvictionAndRefusal$','TestStoreRestartEvictionAndRefusal'),
 ('anchor_pin','!bytes.Equal(a.Anchor.HashIncludingSigs, s.history.Anchor.HashIncludingSigs)','false','^TestStoreRestartEvictionAndRefusal$','TestStoreRestartEvictionAndRefusal'),
 ('anchor_encoding','!bytes.Equal(canonical, a.Canonical)','(!bytes.Equal(canonical, a.Canonical) && false)','^TestSchemaAndAnchorEncodingRefusals$/^anchor_encoding$','TestSchemaAndAnchorEncodingRefusals/anchor_encoding'),
 ('entry_encoding','!bytes.Equal(canonical, e.Canonical)','(!bytes.Equal(canonical, e.Canonical) && false)','^TestPersistedEntryRefusals$/^damaged_encoding$','TestPersistedEntryRefusals/damaged_encoding'),
 ('loaded_proof','if err := s.verifier.VerifyActivation(ctx, e.Body, e.Activation, e.Proof); err != nil {','if err := s.verifier.VerifyActivation(ctx, e.Body, e.Activation, e.Proof); false && err != nil {','^TestPersistedEntryRefusals$/^missing_proof$','TestPersistedEntryRefusals/missing_proof'),
 ('loaded_history','if err := s.history.Validate(); err != nil {','if err := s.history.Validate(); false && err != nil {','^TestPersistedEntryRefusals$/^nonunit_member$','TestPersistedEntryRefusals/nonunit_member'),
 ('append_proof','if err := s.verifier.VerifyActivation(ctx, in.Body, in.Activation, proof); err != nil {','if err := s.verifier.VerifyActivation(ctx, in.Body, in.Activation, proof); false && err != nil {','^TestStoreRestartEvictionAndRefusal$','TestStoreRestartEvictionAndRefusal'),
 ('append_history','if err := next.Validate(); err != nil {','if err := next.Validate(); false && err != nil {','^TestAppendRefusesGappedEpoch$','TestAppendRefusesGappedEpoch'),
 ('unknown_key','default:\n\t\t\treturn ErrIncompatible','default:\n\t\t\tcontinue','^TestSchemaAndAnchorEncodingRefusals$/^extra_key$','TestSchemaAndAnchorEncodingRefusals/extra_key'),
]
try:
 for name,needle,replacement,selector,marker in cases:
  if original.count(needle)!=1:raise SystemExit(f'{name}: check not unique ({original.count(needle)})')
  source.write_text(original.replace(needle,replacement))
  result=subprocess.run(['go','test','./trusthistorystore','-run',selector,'-count=1'],capture_output=True,text=True)
  if result.returncode==0 or f'--- FAIL: {marker}' not in result.stdout:
   raise SystemExit(f'{name}: matching test did not fail\n{result.stdout}\n{result.stderr}')
  print(f'{name}: matching negative failed')
  source.write_text(original)
finally:source.write_text(original)
