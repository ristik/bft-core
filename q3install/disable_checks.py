#!/usr/bin/env python3
"""Disable each journal guard once; its isolated negative must fail. Run from the module root."""
from pathlib import Path
import subprocess

source=Path('q3install/journal.go')
original=source.read_text()
D='^TestDamagedJournalRefusesOpen$/^%s$'
cases=[
 ('key_separator','rest[epochWidth] != \'/\'','false','^TestDamagedJournalRefusesOpen$/^epoch_key_without_separator$','TestDamagedJournalRefusesOpen/epoch_key_without_separator'),
 ('key_canonical_epoch','fmt.Sprintf("%0*x", epochWidth, e) != rest[:epochWidth]','false','^TestDamagedJournalRefusesOpen$/^epoch_key_not_lowercase_hex$','TestDamagedJournalRefusesOpen/epoch_key_not_lowercase_hex'),
 ('stage_canonical','!bytes.Equal(again, raw)','(!bytes.Equal(again, raw) && false)','^TestDamagedJournalRefusesOpen$/^stage_field_order$','TestDamagedJournalRefusesOpen/stage_field_order'),
 ('stage_fields','len(d.BodyID) != 32 || ','','^TestDamagedJournalRefusesOpen$/^stage_fields$','TestDamagedJournalRefusesOpen/stage_fields'),
 ('stage_epoch','d.Epoch != e.epoch','false','^TestDamagedJournalRefusesOpen$/^stage_under_another_epoch$','TestDamagedJournalRefusesOpen/stage_under_another_epoch'),
 ('stage_identity','!bytes.Equal(id[:], d.ID)','(!bytes.Equal(id[:], d.ID) && false)','^TestDamagedJournalRefusesOpen$/^stage_identity$','TestDamagedJournalRefusesOpen/stage_identity'),
 ('marker_needs_stage','st.stage == nil','false','^TestDamagedJournalRefusesOpen$/^marker_without_stage$','TestDamagedJournalRefusesOpen/marker_without_stage'),
 ('marker_owner','!bytes.Equal(e.value, st.stage.ID)','false','^TestDamagedJournalRefusesOpen$/^marker_of_another_activation$','TestDamagedJournalRefusesOpen/marker_of_another_activation'),
 ('step_range','n < 1 || n > numSteps','false','^TestDamagedJournalRefusesOpen$/^step_past_end$','TestDamagedJournalRefusesOpen/step_past_end'),
 ('step_canonical','strconv.Itoa(n) != e.suffix[len("step/"):]','false','^TestDamagedJournalRefusesOpen$/^step_not_canonical$','TestDamagedJournalRefusesOpen/step_not_canonical'),
 ('marker_gap','st.steps[i] && !st.steps[i-1]','false','^TestDamagedJournalRefusesOpen$/^marker_gap$','TestDamagedJournalRefusesOpen/marker_gap'),
 ('done_needs_steps','if !s {\n\t\t\t\t\treturn nil, fmt.Errorf("%w: epoch %d is complete','if !s && false {\n\t\t\t\t\treturn nil, fmt.Errorf("%w: epoch %d is complete','^TestDamagedJournalRefusesOpen$/^complete_with_a_step_missing$','TestDamagedJournalRefusesOpen/complete_with_a_step_missing'),
 ('one_unfinished','len(open) > 1','false','^TestDamagedJournalRefusesOpen$/^two_unfinished$','TestDamagedJournalRefusesOpen/two_unfinished'),
 ('record_match','d.claim() != committed','false','^TestRecordMismatchRefused$','TestRecordMismatchRefused/'),
 ('stored_bundle','if err := j.cfg.Bundles(bytes.Clone(d.Bundle), committed); err != nil {','if err := j.cfg.Bundles(bytes.Clone(d.Bundle), committed); false && err != nil {','^TestBundleMustAuthenticate$','TestBundleMustAuthenticate'),
 ('install_bundle','if err := j.cfg.Bundles(bytes.Clone(bundle), committed); err != nil {','if err := j.cfg.Bundles(bytes.Clone(bundle), committed); false && err != nil {','^TestBundleMustAuthenticate$','TestBundleMustAuthenticate'),
 ('install_size','len(bundle) == 0 || len(bundle) > MaxBundle','false','^TestBundleMustAuthenticate$','TestBundleMustAuthenticate'),
 ('install_same_record','!bytes.Equal(st.stage.ID, id[:])','false','^TestRecordMismatchRefused$/^same_record,_other_bundle$','TestRecordMismatchRefused/same_record,_other_bundle'),
 ('one_in_flight','if !st.done {\n\t\t\treturn fmt.Errorf("%w: epoch %d", ErrBusy','if false {\n\t\t\treturn fmt.Errorf("%w: epoch %d", ErrBusy','^TestOnlyOneActivationInFlight$','TestOnlyOneActivationInFlight'),
 ('skip_marked_steps','if st.steps[i] {\n\t\t\tcontinue','if false {\n\t\t\tcontinue','^TestCrashAtEveryPointThenRestart$','TestCrashAtEveryPointThenRestart'),
 ('verify_before_done','if err := j.verifyAll(ctx, a); err != nil {\n\t\treturn err\n\t}\n\tif err := j.cfg.DB.Write(key(a.Claim.Epoch, "done")','if err := j.verifyAll(ctx, a); false && err != nil {\n\t\treturn err\n\t}\n\tif err := j.cfg.DB.Write(key(a.Claim.Epoch, "done")','^TestStoreConflict$/^verify_fails_after_install$','TestStoreConflict/verify_fails_after_install'),
 ('verify_completed','if st.done {\n\t\treturn j.verifyAll(ctx, a)\n\t}','if st.done {\n\t\treturn nil\n\t}','^TestStoreConflict$/^store_changes_after_completion$','TestStoreConflict/store_changes_after_completion'),
 ('recover_lookup','if !ok {\n\t\t\treturn fmt.Errorf("%w: epoch %d is not in the committed history"','if !ok && false {\n\t\t\treturn fmt.Errorf("%w: epoch %d is not in the committed history"','^TestRecordMismatchRefused$/^zero_record_is_not_a_lookup_hit$','TestRecordMismatchRefused/zero_record_is_not_a_lookup_hit'),
 ('gate_complete','if st == nil || !st.done {','if st == nil {','^TestGateRequiresCompletion$','TestGateRequiresCompletion'),
 ('config_db','cfg.DB == nil || ','','^TestBundleMustAuthenticate$','TestBundleMustAuthenticate'),
 ('config_verifier','cfg.Bundles == nil || ','','^TestBundleMustAuthenticate$','TestBundleMustAuthenticate'),
 ('config_count','len(cfg.Components) != numSteps','false','^TestBundleMustAuthenticate$','TestBundleMustAuthenticate'),
 ('config_steps','if cfg.Components[s] == nil {','if false {','^TestBundleMustAuthenticate$','TestBundleMustAuthenticate'),
]
try:
 for name,needle,replacement,selector,marker in cases:
  if original.count(needle)!=1:raise SystemExit(f'{name}: check not unique ({original.count(needle)})')
  source.write_text(original.replace(needle,replacement))
  result=subprocess.run(['go','test','./q3install','-run',selector,'-count=1'],capture_output=True,text=True)
  if result.returncode==0 or f'--- FAIL: {marker}' not in result.stdout:
   raise SystemExit(f'{name}: matching test did not fail\n{result.stdout}\n{result.stderr}')
  print(f'{name}: matching negative failed')
  source.write_text(original)
finally:source.write_text(original)
