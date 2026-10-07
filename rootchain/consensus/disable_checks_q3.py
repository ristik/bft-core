#!/usr/bin/env python3
"""Disable each Q3 install, gate and anchor guard of the root manager once; its isolated negative must fail. Run from the module root.
Each case compiles the consensus package, so the run is long: run it in the background."""
from pathlib import Path
import subprocess

B=Path('rootchain/consensus/bootstrap_q3.go'); S=Path('rootchain/consensus/safety_module.go'); M=Path('rootchain/consensus/consensus_manager.go')
orig={p:p.read_text() for p in (B,S,M)}
I='^TestInstallVerifiedEpochIsolatedRefusals$/^%s$'
H='^TestHoldsVerifiedEpochChecksTheCommitteeAndTheDurableAnchor$/^%s$'
def iso(name): return I%name, 'TestInstallVerifiedEpochIsolatedRefusals/'+name
def hold(name): return H%name, 'TestHoldsVerifiedEpochChecksTheCommitteeAndTheDurableAnchor/'+name
cases=[
 (B,'profile','if x.params.NetworkProfileVersion != storage.ProfileHandoff {','if x.params.NetworkProfileVersion != storage.ProfileHandoff && false {',*iso('not_the_handoff_profile')),
 (B,'stopped','if x.pacemaker.GetCurrentRound() != 0 {','if false {',*iso('running_consensus')),
 (B,'verified_entry','if !ok {\n\t\treturn nil, ErrNotVerifiedEpoch\n\t}\n\tcfg, _ :=','if !ok && false {\n\t\treturn nil, ErrNotVerifiedEpoch\n\t}\n\tcfg, _ :=','^TestInstallVerifiedEpochRefusals$/^a_legacy_entry$','TestInstallVerifiedEpochRefusals/a_legacy_entry'),
 (B,'no_candidate','if len(candidate) != 0 {','if false {','^TestInstallVerifiedEpochRefusals$/^a_candidate_the_V3_install_does_not_carry$','TestInstallVerifiedEpochRefusals/a_candidate_the_V3_install_does_not_carry'),
 (B,'snapshot_present','head == nil || len(head.ShardInfo) == 0','len(head.ShardInfo) == 0','^TestInstallVerifiedEpochRefusals$/^no_snapshot$','TestInstallVerifiedEpochRefusals/no_snapshot'),
 (B,'snapshot_shards','head == nil || len(head.ShardInfo) == 0','head == nil','^TestInstallVerifiedEpochIsolatedRefusals$/^a_snapshot_with_no_shards$','TestInstallVerifiedEpochIsolatedRefusals/a_snapshot_with_no_shards'),
 (B,'old_proof','if err != nil {\n\t\treturn nil, fmt.Errorf("old handoff commit proof: %w", err)\n\t}','if err != nil {\n\t\t_ = err\n\t}',*iso('a_proof_signed_by_another_old_committee')),
 (B,'record_identity','if !bytes.Equal(verified.RecordID[:], v.RecordID) {','if !bytes.Equal(verified.RecordID[:], v.RecordID) && false {',*iso('the_old_committee\'s_valid_proof_of_another_record')),
 (B,'snapshot_verified','if _, err := handoffdelivery.VerifySnapshot(proof, verified, head, first.Partition, first.Shard, first.ShardConfHash); err != nil {\n\t\treturn nil, err\n\t}','if _, err := handoffdelivery.VerifySnapshot(proof, verified, head, first.Partition, first.Shard, first.ShardConfHash); err != nil {\n\t\t_ = err\n\t}','^TestInstallVerifiedEpochRefusals$/^a_snapshot_that_is_not_the_committed_checkpoint$','TestInstallVerifiedEpochRefusals/a_snapshot_that_is_not_the_committed_checkpoint'),
 (B,'anchor_conflict','existing != nil && existing.Epoch >= g.Epoch && (existing.Epoch != g.Epoch || !bytes.Equal(existing.GenesisID, g.ID()))','existing != nil && existing.Epoch >= g.Epoch && (existing.Epoch != g.Epoch)',*iso('another_record\'s_epoch_anchor_is_already_durable')),
 (B,'anchor_later','existing != nil && existing.Epoch >= g.Epoch && (existing.Epoch != g.Epoch || !bytes.Equal(existing.GenesisID, g.ID()))','existing != nil && existing.Epoch >= g.Epoch && (!bytes.Equal(existing.GenesisID, g.ID()))','^TestInstallVerifiedEpochRefusesWhenALaterEpochIsAnchored$','TestInstallVerifiedEpochRefusesWhenALaterEpochIsAnchored'),
 (B,'trust_installed','newTrust, err := x.trustBaseStore.InstallVerified(projected, signing)\n\tif err != nil {\n\t\treturn nil, err\n\t}','newTrust, err := x.trustBaseStore.InstallVerified(projected, signing)\n\tif err != nil {\n\t\t_ = err\n\t}','^TestInstallVerifiedEpochRefusals$/^a_trust_store_that_is_not_bound_to_the_history$','TestInstallVerifiedEpochRefusals/a_trust_store_that_is_not_bound_to_the_history'),
 (B,'holds_committee','if !sameCommittee(have, entry.Projection()) {','if !sameCommittee(have, entry.Projection()) && false {',*hold('the_stored_committee_is_another_activation\'s')),
 (B,'holds_anchor_present','anchor == nil ||','' ,*hold('a_committee_with_no_durable_anchor')),
 (B,'holds_anchor_record','(anchor.Epoch == g.Epoch && !bytes.Equal(anchor.GenesisID, g.ID()))','(anchor.Epoch == g.Epoch && !bytes.Equal(anchor.GenesisID, g.ID()) && false)',*hold('the_durable_anchor_is_another_record\'s_of_the_epoch')),
 (B,'holds_entry','_, g, ok := entry.Handoff()\n\tif !ok {\n\t\treturn ErrNotVerifiedEpoch\n\t}','_, g, ok := entry.Handoff()\n\tif !ok && false {\n\t\treturn ErrNotVerifiedEpoch\n\t}',*hold('no_verified_activation')),
 (B,'committee_network','a.NetworkID != b.NetworkID','a.NetworkID != b.NetworkID && false','^TestSameCommitteeComparesEveryField$/^network$','TestSameCommitteeComparesEveryField/network'),
 (B,'committee_epoch','a.Epoch != b.Epoch','a.Epoch != b.Epoch && false','^TestSameCommitteeComparesEveryField$/^epoch$','TestSameCommitteeComparesEveryField/epoch'),
 (B,'committee_start','a.EpochStart != b.EpochStart','a.EpochStart != b.EpochStart && false','^TestSameCommitteeComparesEveryField$/^start$','TestSameCommitteeComparesEveryField/start'),
 (B,'committee_threshold','a.QuorumThreshold != b.QuorumThreshold','a.QuorumThreshold != b.QuorumThreshold && false','^TestSameCommitteeComparesEveryField$/^threshold$','TestSameCommitteeComparesEveryField/threshold'),
 (B,'committee_size','len(a.RootNodes) != len(b.RootNodes)','len(a.RootNodes) != len(b.RootNodes) && false','^TestSameCommitteeComparesEveryField$/^a_member$','TestSameCommitteeComparesEveryField/a_member'),
 (B,'committee_id','n.NodeID != m.NodeID ||','false ||','^TestSameCommitteeComparesEveryField$/^a_node_id$','TestSameCommitteeComparesEveryField/a_node_id'),
 (B,'committee_weight','n.Stake != m.Stake ||','false ||','^TestSameCommitteeComparesEveryField$/^a_weight$','TestSameCommitteeComparesEveryField/a_weight'),
 (B,'committee_key','!bytes.Equal(n.SigKey, m.SigKey)','false','^TestSameCommitteeComparesEveryField$/^a_key$','TestSameCommitteeComparesEveryField/a_key'),
 (B,'committee_nil_node','n == nil || m == nil ||','false ||','^TestSameCommitteeComparesEveryField$/^a_nil_node$','TestSameCommitteeComparesEveryField/a_nil_node'),
 (B,'q3_nil','if a == nil || anchor == nil {','if false {','^TestQ3ActivatedNamesAnAnchorOfAnActivatedEpochOnly$','TestQ3ActivatedNamesAnAnchorOfAnActivatedEpochOnly'),
 (B,'q3_identity','return ok && bytes.Equal(g.ID(), anchor.GenesisID)','return ok && (bytes.Equal(g.ID(), anchor.GenesisID) || true)','^TestQ3ActivatedNamesAnAnchorOfAnActivatedEpochOnly$','TestQ3ActivatedNamesAnAnchorOfAnActivatedEpochOnly'),
 (S,'gate_asked','if s.gate != nil {\n\t\tif err := s.gate.Admit(epoch); err != nil {','if s.gate != nil && false {\n\t\tif err := s.gate.Admit(epoch); err != nil {','^TestTheActivationGateRefusesBeforeAnythingIsSignedOrRecorded$','TestTheActivationGateRefusesBeforeAnythingIsSignedOrRecorded'),
 (S,'gate_refusal','if err := s.gate.Admit(epoch); err != nil {','if err := s.gate.Admit(epoch); err != nil && false {','^TestTheActivationGateRefusesBeforeAnythingIsSignedOrRecorded$','TestTheActivationGateRefusesBeforeAnythingIsSignedOrRecorded'),
 (S,'gate_needs_history','if s.signing == nil {\n\t\t\treturn votesig.Config{}, fmt.Errorf("%w: epoch %d", ErrNoSigningHistory','if s.signing == nil && false {\n\t\t\treturn votesig.Config{}, fmt.Errorf("%w: epoch %d", ErrNoSigningHistory','^TestAGatedModuleWithoutSigningHistoryNeverFallsBackToSchemeOne$','TestAGatedModuleWithoutSigningHistoryNeverFallsBackToSchemeOne'),
 (S,'bound_type','return ok && s.gate == g','return (ok || true) && s.gate == g','^TestSafetyModuleBoundTo$','TestSafetyModuleBoundTo'),
 (S,'bound_same','return ok && s.gate == g','return ok && (s.gate == g || true)','^TestSafetyModuleBoundTo$','TestSafetyModuleBoundTo'),
 (M,'manager_gate','if optional.Q3 != nil {\n\t\tsafetyOptions = append(safetyOptions, WithActivationGate(optional.Q3))\n\t}','if optional.Q3 != nil && false {\n\t\tsafetyOptions = append(safetyOptions, WithActivationGate(optional.Q3))\n\t}','^TestTheManagerGivesItsSafetyModuleTheActivationGateOnlyWithTheVerifiedHistory$','TestTheManagerGivesItsSafetyModuleTheActivationGateOnlyWithTheVerifiedHistory'),
 (M,'restart_q3_anchor','installedAnchor != nil && q3Activated(optional.Q3, installedAnchor) {','installedAnchor != nil && false {','^TestRestartAcrossTheBoundary$','TestRestartAcrossTheBoundary'),
]
try:
 for path,name,needle,replacement,selector,marker in cases:
  text=orig[path]
  if text.count(needle)!=1:raise SystemExit(f'{name}: check not unique ({text.count(needle)})')
  path.write_text(text.replace(needle,replacement))
  result=subprocess.run(['go','test','./rootchain/consensus','-run',selector,'-count=1'],capture_output=True,text=True)
  if result.returncode==0 or f'--- FAIL: {marker}' not in result.stdout:
   raise SystemExit(f'{name}: matching test did not fail\n{result.stdout[-3000:]}\n{result.stderr[-1500:]}')
  print(f'{name}: matching negative failed',flush=True)
  path.write_text(text)
finally:
 for path,text in orig.items():path.write_text(text)
