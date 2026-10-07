#!/usr/bin/env python3
"""Disable each q3active guard once; its isolated negative must fail. Run from the module root."""
from pathlib import Path
import subprocess

R=Path('q3active/runtime.go'); T=Path('q3active/trust.go'); H=Path('q3active/handoff.go'); B=Path('q3active/bundle.go')
orig={p:p.read_text() for p in (R,T,H,B)}
def case(path,name,needle,replacement,selector,marker=None):
 return (path,name,needle,replacement,selector,marker or selector.strip('^$').split('/')[0].replace('^','').replace('$',''))
cases=[
 case(R,'new_inputs','if cfg.Genesis == nil {','if false {','^TestStagedBundlesAreAuthenticatedAtStart$/^an_incomplete_configuration$','TestStagedBundlesAreAuthenticatedAtStart/an_incomplete_configuration'),
 case(R,'staged_verified','if h, err = h.VerifyEnvelope(env); err != nil {','if h, err = h.VerifyEnvelope(env); false && err != nil {','^TestStagedBundlesAreAuthenticatedAtStart$/^a_staged_bundle_whose_commit_is_not_authenticated$','TestStagedBundlesAreAuthenticatedAtStart/a_staged_bundle_whose_commit_is_not_authenticated'),
 case(R,'staged_claim','if e, err := h.ForEpoch(a.Claim.Epoch); err != nil || e.Claim() != a.Claim {','if e, err := h.ForEpoch(a.Claim.Epoch); err != nil || e.Claim() != a.Claim && false {','^TestStagedBundlesAreAuthenticatedAtStart$/^a_staged_record_that_is_not_the_one_its_envelope_derives$','TestStagedBundlesAreAuthenticatedAtStart/a_staged_record_that_is_not_the_one_its_envelope_derives'),
 case(R,'attach_complete','if p.Root == nil || p.Safety == nil || p.Shard == nil || p.Authority == nil {','if false {','^TestActivationRefusals$/^before_the_participants_attach$','TestActivationRefusals/before_the_participants_attach'),
 case(R,'attach_once','if !r.parts.CompareAndSwap(nil, &p) {','if r.parts.CompareAndSwap(nil, &p) && false {','^TestActivationRefusals$/^participants_attach_once$','TestActivationRefusals/participants_attach_once'),
 case(R,'participants_required','if p == nil {\n\t\treturn nil, ErrNotAttached','if false {\n\t\treturn nil, ErrNotAttached','^TestActivationRefusals$/^before_the_participants_attach$','TestActivationRefusals/before_the_participants_attach'),
 case(R,'admit_unknown','e, err := r.History().ForEpoch(epoch)\n\tif err != nil {\n\t\treturn err\n\t}\n\tif _, active := e.Config(); !active {\n\t\treturn nil\n\t}\n\tif _, ok := r.completed','e, err := r.History().ForEpoch(epoch)\n\tif err != nil {\n\t\t_ = err\n\t}\n\tif _, active := e.Config(); !active {\n\t\treturn nil\n\t}\n\tif _, ok := r.completed','^TestAnEpochTheHistoryDoesNotHoldIsNeverLegacy$','TestAnEpochTheHistoryDoesNotHoldIsNeverLegacy'),
 case(R,'admit_complete','if _, ok := r.completed.Load(epoch); !ok {','if _, ok := r.completed.Load(epoch); !ok && false {','^TestNothingIsActiveBeforeTheJournalIsComplete$','TestNothingIsActiveBeforeTheJournalIsComplete'),
 case(R,'mode_unknown','e, err := r.History().ForEpoch(epoch)\n\tif err != nil {\n\t\treturn 0, err\n\t}','e, err := r.History().ForEpoch(epoch)\n\tif err != nil {\n\t\t_ = err\n\t}','^TestAnEpochTheHistoryDoesNotHoldIsNeverLegacy$','TestAnEpochTheHistoryDoesNotHoldIsNeverLegacy'),
 case(R,'mode_admit','if err := r.Admit(epoch); err != nil {\n\t\treturn 0, err\n\t}','if err := r.Admit(epoch); err != nil {\n\t\t_ = err\n\t}','^TestNothingIsActiveBeforeTheJournalIsComplete$','TestNothingIsActiveBeforeTheJournalIsComplete'),
 case(R,'verify_derived','if e, err := next.ForEpoch(committed.Epoch); err != nil || e.Claim() != committed {','if e, err := next.ForEpoch(committed.Epoch); err != nil || e.Claim() != committed && false {','^TestVerifyBindsTheBundleToTheRecordItIsStagedFor$','TestVerifyBindsTheBundleToTheRecordItIsStagedFor'),
 case(R,'resolve_last_link','if env.Links[len(env.Links)-1].Claim != a.Claim {','if env.Links[len(env.Links)-1].Claim != a.Claim && false {','^TestResolveTakesTheEntryFromTheHistoryAndNothingElse$','TestResolveTakesTheEntryFromTheHistoryAndNothingElse'),
 case(R,'resolve_entry','if err != nil || e.Claim() != a.Claim {\n\t\treturn q3format.Entry{}, handoff.OldCommitProof{}, Bundle{}, fmt.Errorf("%w: epoch %d", ErrHistory','if err != nil {\n\t\treturn q3format.Entry{}, handoff.OldCommitProof{}, Bundle{}, fmt.Errorf("%w: epoch %d", ErrHistory','^TestResolveTakesTheEntryFromTheHistoryAndNothingElse$','TestResolveTakesTheEntryFromTheHistoryAndNothingElse'),
 case(R,'activate_attached','if _, err := r.participants(); err != nil {\n\t\treturn err\n\t}\n\traw, err := EncodeBundle(b)','if _, err := r.participants(); err != nil && false {\n\t\treturn err\n\t}\n\traw, err := EncodeBundle(b)','^TestActivationRefusals$/^before_the_participants_attach$','TestActivationRefusals/before_the_participants_attach'),
 case(R,'publish_activation','if !ok {\n\t\treturn fmt.Errorf("%w: epoch %d is not an activation"','if !ok && false {\n\t\treturn fmt.Errorf("%w: epoch %d is not an activation"','^TestPublishRefusesAnEntryThatIsNotAnActivationAndAnotherRecordOfThePublishedEpoch$','TestPublishRefusesAnEntryThatIsNotAnActivationAndAnotherRecordOfThePublishedEpoch'),
 case(R,'supersede_epoch','case cur.Epoch() > next.Epoch():','case cur.Epoch() > next.Epoch() && false:','^TestASnapshotMayOnlyBeSupersededForward$','TestASnapshotMayOnlyBeSupersededForward'),
 case(R,'supersede_record','case cur.Epoch() == next.Epoch() && cur.claim != next.claim:','case cur.Epoch() == next.Epoch() && cur.claim != next.claim && false:','^TestASnapshotMayOnlyBeSupersededForward$','TestASnapshotMayOnlyBeSupersededForward'),
 case(R,'consumer_bound','if consumer := c.pick(p); consumer == nil || !consumer.BoundTo(c.r) {','if consumer := c.pick(p); consumer == nil {','^TestActivationRefusals$','TestActivationRefusals'),
 case(R,'snapshot_published','case s == nil || s.Epoch() < a.Claim.Epoch:','case s == nil || s.Epoch() < a.Claim.Epoch && false:','^TestSnapshotStepVerifiesWhatIsPublished$','TestSnapshotStepVerifiesWhatIsPublished'),
 case(R,'snapshot_record','case s.Epoch() == a.Claim.Epoch && s.claim != a.Claim:','case s.Epoch() == a.Claim.Epoch && s.claim != a.Claim && false:','^TestSnapshotStepVerifiesWhatIsPublished$','TestSnapshotStepVerifiesWhatIsPublished'),
 case(T,'guarded_unknown','e, err := g.rt.History().ForEpoch(epoch)\n\tif err != nil {\n\t\treturn nil, err\n\t}\n\tif _, active := e.Config(); active {','e, err := g.rt.History().ForEpoch(epoch)\n\tif err != nil {\n\t\t_ = err\n\t}\n\tif _, active := e.Config(); active {','^TestAnEpochTheHistoryDoesNotHoldIsNeverLegacy$','TestAnEpochTheHistoryDoesNotHoldIsNeverLegacy'),
 case(T,'guarded_admit','if err := g.rt.Admit(epoch); err != nil {\n\t\t\treturn nil, err\n\t\t}\n\t\treturn e.Projection(), nil','if err := g.rt.Admit(epoch); err != nil {\n\t\t\t_ = err\n\t\t}\n\t\treturn e.Projection(), nil','^TestNothingIsActiveBeforeTheJournalIsComplete$','TestNothingIsActiveBeforeTheJournalIsComplete'),
 case(T,'guarded_conflict','if !sameTrust(tb, e.Projection()) {','if !sameTrust(tb, e.Projection()) && false {','^TestGuardedTrustServesTheVerifiedHistory$/^a_legacy_epoch_is_the_base_after_it_agrees_with_the_history$','TestGuardedTrustServesTheVerifiedHistory/a_legacy_epoch_is_the_base_after_it_agrees_with_the_history'),
 case(T,'guarded_bound','ok && rt != nil && rt == g.rt','ok && rt != nil','^TestGuardedTrustServesTheVerifiedHistory$/^binding$','TestGuardedTrustServesTheVerifiedHistory/binding'),
 case(T,'trust_same_nodes','n == nil || m == nil || n.NodeID != m.NodeID || n.Stake != m.Stake || !bytes.Equal(n.SigKey, m.SigKey)','n == nil || m == nil || n.NodeID != m.NodeID || !bytes.Equal(n.SigKey, m.SigKey)','^TestGuardedTrustServesTheVerifiedHistory$/^a_legacy_epoch_is_the_base_after_it_agrees_with_the_history$','TestGuardedTrustServesTheVerifiedHistory/a_legacy_epoch_is_the_base_after_it_agrees_with_the_history'),
 case(H,'legacy_bundle','activated {\n\t\treturn handoffdelivery.Verified{}, fmt.Errorf("%w: epoch %d", ErrLegacyBundle','false && activated {\n\t\treturn handoffdelivery.Verified{}, fmt.Errorf("%w: epoch %d", ErrLegacyBundle','^TestAnOldPeerCannotInstallAnActivatedEpochIntoTheShardHistory$','TestAnOldPeerCannotInstallAnActivatedEpochIntoTheShardHistory'),
 case(H,'epoch_overflow','epoch == ^uint64(0) {','false {','^TestAnOldPeerCannotInstallAnActivatedEpochIntoTheShardHistory$','TestAnOldPeerCannotInstallAnActivatedEpochIntoTheShardHistory'),
 case(B,'bundle_encode_fields','if len(b.Envelope) == 0 || b.Snapshot == nil {\n\t\treturn nil, fmt.Errorf("%w: an envelope and a snapshot are required", ErrBundle)\n\t}\n\traw, err','if false {\n\t\treturn nil, fmt.Errorf("%w: an envelope and a snapshot are required", ErrBundle)\n\t}\n\traw, err','^TestDecodeBundleRefusals$/^a_bundle_without_an_envelope_or_checkpoint_cannot_be_encoded$','TestDecodeBundleRefusals/a_bundle_without_an_envelope_or_checkpoint_cannot_be_encoded'),
 case(B,'bundle_size','if len(raw) == 0 || len(raw) > q3format.MaxEnvelopeBytes {','if false {','^TestDecodeBundleRefusals$/^oversize$','TestDecodeBundleRefusals/oversize'),
 case(B,'bundle_canonical','if again, err := types.Cbor.Marshal(b); err != nil || !bytes.Equal(again, raw) {','if again, err := types.Cbor.Marshal(b); err != nil || !bytes.Equal(again, raw) && false {','^TestDecodeBundleRefusals$/^not_canonical$','TestDecodeBundleRefusals/not_canonical'),
 case(B,'bundle_fields','if len(b.Envelope) == 0 || b.Snapshot == nil {\n\t\treturn Bundle{}, q3format.Envelope{}, fmt.Errorf("%w: an envelope and a snapshot are required", ErrBundle)','if false {\n\t\treturn Bundle{}, q3format.Envelope{}, fmt.Errorf("%w: an envelope and a snapshot are required", ErrBundle)','^TestDecodeBundleRefusals$','TestDecodeBundleRefusals'),
 case(B,'bundle_links','if len(env.Links) == 0 {','if false {','^TestDecodeBundleRefusals$/^an_envelope_without_a_link$','TestDecodeBundleRefusals/an_envelope_without_a_link'),
]
try:
 for path,name,needle,replacement,selector,marker in cases:
  text=orig[path]
  if text.count(needle)!=1:raise SystemExit(f'{name}: check not unique ({text.count(needle)})')
  path.write_text(text.replace(needle,replacement))
  result=subprocess.run(['go','test','./q3active','-run',selector,'-count=1'],capture_output=True,text=True)
  if result.returncode==0 or f'--- FAIL: {marker}' not in result.stdout:
   raise SystemExit(f'{name}: matching test did not fail\n{result.stdout[-3000:]}\n{result.stderr[-1500:]}')
  print(f'{name}: matching negative failed',flush=True)
  path.write_text(text)
finally:
 for path,text in orig.items():path.write_text(text)
