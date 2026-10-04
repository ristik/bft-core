#!/usr/bin/env python3
"""Disable each Q3 selection / mode guard once; its isolated negative must fail. Run from the module root."""
from pathlib import Path
import subprocess

A=Path('rootchain/consensus/storage/assignment.go'); C=Path('certifiedstore/record.go'); M=Path('mintproof/bundle_v2.go'); W=Path('internal/weightvalidation/source.go')
orig={p:p.read_text() for p in (A,C,M,W)}
ST='./rootchain/consensus/storage'
cases=[
 (A,ST,'v3_record','if !bytes.Equal(record.ID(), commit[:]) {','if !bytes.Equal(record.ID(), commit[:]) && false {','^TestWeightedRequestPolicyIsSelectedOnlyByAVerifiedActivation$','TestWeightedRequestPolicyIsSelectedOnlyByAVerifiedActivation'),
 (A,ST,'v3_weighted_mode','projection.ChangeRecordHash, preimage, weightvalidation.ModeWeighted)','projection.ChangeRecordHash, preimage, weightvalidation.ModeUnit)','^TestWeightedRequestPolicyIsSelectedOnlyByAVerifiedActivation$','TestWeightedRequestPolicyIsSelectedOnlyByAVerifiedActivation'),
 (A,ST,'v3_root_size','if len(c.RootMembers) != len(projection.RootNodes) {','if len(c.RootMembers) > len(projection.RootNodes) && false {','^TestAWeightedCandidateThatIsNotTheActivatedCommitteeIsRefused$','TestAWeightedCandidateThatIsNotTheActivatedCommitteeIsRefused'),
 (A,ST,'v3_root_member_weight','m.NodeID != n.NodeID || m.Weight != n.Stake || !bytes.Equal(m.Key, n.SigKey)','m.NodeID != n.NodeID || !bytes.Equal(m.Key, n.SigKey)','^TestAWeightedCandidateThatIsNotTheActivatedCommitteeIsRefused$/^a_root_committee_with_other_weights,_coupled_consistently$','TestAWeightedCandidateThatIsNotTheActivatedCommitteeIsRefused/a_root_committee_with_other_weights,_coupled_consistently'),
 (A,ST,'v3_root_member_key','m.NodeID != n.NodeID || m.Weight != n.Stake || !bytes.Equal(m.Key, n.SigKey)','m.NodeID != n.NodeID || m.Weight != n.Stake','^TestAWeightedCandidateThatIsNotTheActivatedCommitteeIsRefused/^a_root_committee_with_another_key$','TestAWeightedCandidateThatIsNotTheActivatedCommitteeIsRefused/a_root_committee_with_another_key'),
 (A,ST,'v3_coupling','if err := evmassign.ValidateCoupling(c.RootMembers, pdr, c.Bindings); err != nil {\n\t\treturn nil, errors.Join(ErrAssignmentHistory, err)\n\t}\n\tcoupling','if err := evmassign.ValidateCoupling(c.RootMembers, pdr, c.Bindings); err != nil {\n\t\t_ = err\n\t}\n\tcoupling','^TestAWeightedCandidateThatIsNotTheActivatedCommitteeIsRefused$/^an_EVM_weight_that_does_not_mirror_its_root_member$','TestAWeightedCandidateThatIsNotTheActivatedCommitteeIsRefused/an_EVM_weight_that_does_not_mirror_its_root_member'),
 (A,ST,'assign_unit_mode','if mode == weightvalidation.ModeUnit {\n\t\treturn evmassign.ValidateAssignment(succ)','if mode == weightvalidation.ModeUnit && false {\n\t\treturn evmassign.ValidateAssignment(succ)','^TestValidateAssignmentByMode$','TestValidateAssignmentByMode'),
 (A,ST,'assign_weights','if err := weightvalidation.PDR(succ, weightvalidation.RoleEVM, mode); err != nil {','if err := weightvalidation.PDR(succ, weightvalidation.RoleEVM, mode); err != nil && false {','^TestValidateAssignmentByMode$','TestValidateAssignmentByMode'),
 (A,ST,'assign_epoch_start','if succ.EpochStart != 0 {\n\t\treturn fmt.Errorf("%w: activation round is set before commit", evmassign.ErrEpoch)\n\t}\n\treturn nil','if succ.EpochStart != 0 && false {\n\t\treturn fmt.Errorf("%w: activation round is set before commit", evmassign.ErrEpoch)\n\t}\n\treturn nil','^TestValidateAssignmentByMode$','TestValidateAssignmentByMode'),
 (C,'./certifiedstore','cs_mode_error','if err != nil {\n\t\treturn nil, fmt.Errorf("%w: %v", ErrEpoch, err)\n\t}','if err != nil {\n\t\t_ = err\n\t}','^TestAWeightedAssignmentIsAcceptedOnlyUnderAnActivatedRootEpoch$','TestAWeightedAssignmentIsAcceptedOnlyUnderAnActivatedRootEpoch'),
 (C,'./certifiedstore','cs_mode_used','weightvalidation.EVMSet(pdr.Validators, mode)','weightvalidation.EVMSet(pdr.Validators, mode*0+weightvalidation.ModeWeighted)','^TestAWeightedAssignmentIsAcceptedOnlyUnderAnActivatedRootEpoch$','TestAWeightedAssignmentIsAcceptedOnlyUnderAnActivatedRootEpoch'),
 (M,'./mintproof','mp_mode_used','weightvalidation.EVMSet(pdr.Validators, mode)','weightvalidation.EVMSet(pdr.Validators, mode*0+weightvalidation.ModeWeighted)','^TestAWeightedBundleVerifiesOnlyUnderAWeightedTrustBase$','TestAWeightedBundleVerifiesOnlyUnderAWeightedTrustBase'),
 (W,'./internal/weightvalidation','wv_source_mode','if !ok {\n\t\treturn ModeUnit, nil\n\t}','if !ok {\n\t\treturn ModeWeighted, nil\n\t}','^TestModeFor$','TestModeFor'),
 (W,'./internal/weightvalidation','wv_source_err','if err != nil {\n\t\treturn 0, fmt.Errorf("validation mode of root epoch %d: %w", epoch, err)\n\t}','if err != nil {\n\t\t_ = err\n\t}','^TestModeFor$','TestModeFor'),
 (W,'./internal/weightvalidation','wv_source_range','if m < ModeUnit || m > ModeWeighted {\n\t\treturn 0, fmt.Errorf("%w: mode %d", ErrContext, m)\n\t}','if m < ModeUnit || m > ModeWeighted && false {\n\t\treturn 0, fmt.Errorf("%w: mode %d", ErrContext, m)\n\t}','^TestModeFor$','TestModeFor'),
 (W,'./internal/weightvalidation','wv_tb_range','if m := v.ValidationMode(); m >= ModeUnit && m <= ModeWeighted {','if m := v.ValidationMode(); m >= ModeUnit {','^TestModeOfTrustBase$','TestModeOfTrustBase'),
]
try:
 for path,pkg,name,needle,replacement,selector,marker in cases:
  text=orig[path]
  if text.count(needle)!=1:raise SystemExit(f'{name}: check not unique ({text.count(needle)})')
  path.write_text(text.replace(needle,replacement))
  result=subprocess.run(['go','test',pkg,'-run',selector,'-count=1'],capture_output=True,text=True)
  if result.returncode==0 or f'--- FAIL: {marker}' not in result.stdout:
   raise SystemExit(f'{name}: matching test did not fail\n{result.stdout[-3000:]}\n{result.stderr[-1500:]}')
  print(f'{name}: matching negative failed',flush=True)
  path.write_text(text)
finally:
 for path,text in orig.items():path.write_text(text)
