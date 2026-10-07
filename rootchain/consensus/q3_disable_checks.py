#!/usr/bin/env python3
"""Disable each D2b-2 guard once; its isolated named test must fail. Run from the module root."""
from pathlib import Path
import subprocess

P = lambda s: Path(s)
BOOT = P('rootchain/consensus/bootstrap_q3.go'); CM = P('rootchain/consensus/consensus_manager.go')
ASSIGN = P('rootchain/consensus/storage/assignment.go'); SHARD = P('rootchain/consensus/storage/sharding.go')
ORCH = P('rootchain/partitions/orchestration.go'); SAMPLER = P('rootchain/consensus/frontier_sampler.go')
COLLECT = P('rootchain/consensus/frontierclient/collector.go'); RECOVERY = P('network/protocol/abdrc/recovery.go')
CAND = P('evmassign/candidate.go'); HIST = P('q3active/requesthistory.go'); TRUST = P('q3active/trust.go')
CONS, STORE, PARTS, FRONT, ABDRC, WV, QA = ('./rootchain/consensus', './rootchain/consensus/storage', './rootchain/partitions',
    './rootchain/consensus/frontierclient', './network/protocol/abdrc', './internal/weightvalidation', './q3active')
cases = [
 (BOOT, 'omitted_candidate_of_an_assignment', 'case len(candidate) == 0 && !entry.RootOnly():', 'case false:', CONS, '^TestACoupledHandoffIsNotInstalledAsRootOnly$', 'TestACoupledHandoffIsNotInstalledAsRootOnly'),
 (BOOT, 'candidate_of_a_root_only_record', 'case len(candidate) != 0 && entry.RootOnly():', 'case false:', CONS, '^TestCoupledInstallRefusesAnyOtherCandidate$', 'TestCoupledInstallRefusesAnyOtherCandidate'),
 (BOOT, 'candidate_is_the_committed_one', 'x.params.HashAlgorithm, 1); err != nil {', 'x.params.HashAlgorithm, 1); err != nil && false {', CONS, '^TestCoupledInstallRefusesAnyOtherCandidate$', 'TestCoupledInstallRefusesAnyOtherCandidate'),
 (BOOT, 'candidate_is_retained', 'if len(candidate) != 0 { // retained before the anchor', 'if false { // retained before the anchor', CONS, '^TestCoupledActivationInstallsTheWeightedAssignment$', 'TestCoupledActivationInstallsTheWeightedAssignment'),
 (ASSIGN, 'retained_v3_is_weighted', 'changeRecordHash: crh, mode: weightvalidation.ModeWeighted}', 'changeRecordHash: crh, mode: weightvalidation.ModeUnit}', CONS, '^TestCoupledActivationInstallsTheWeightedAssignment$', 'TestCoupledActivationInstallsTheWeightedAssignment'),
 (ASSIGN, 'retained_v3_facts', 'if version, _ := fields[0].(uint64); version != 3 || !eOK || !aOK || !cOK {', 'if version, _ := fields[0].(uint64); version != 3 && false || !eOK || !aOK || !cOK {', STORE, '^TestRetainedV3BodyFacts$', 'TestRetainedV3BodyFacts'),
 (SHARD, 'weighted_evm_has_no_unit_context', 'return slices.ContainsFunc(conf.Validators, func(v *types.NodeInfo) bool { return v != nil && v.Stake != 1 })', 'return false', CONS, '^TestCoupledActivationInstallsTheWeightedAssignment$', 'TestCoupledActivationInstallsTheWeightedAssignment'),
 (SHARD, 'only_the_evm_shard_is_weighted', 'if conf == nil || conf.PartitionTypeID != evmassign.EVMPartitionTypeID {', 'if conf == nil {', STORE, '^TestAWeightedEVMConfigurationHasNoUnitRequestContext$', 'TestAWeightedEVMConfigurationHasNoUnitRequestContext'),
 (SHARD, 'weighted_evm_is_the_committed_one', 'len(committed) == 0 || !bytes.Equal(h, committed) {\n\t\t\treturn fmt.Errorf("request quorum context: %w: configuration is not the committed one"', 'len(committed) == 0 || !bytes.Equal(h, committed) && false {\n\t\t\treturn fmt.Errorf("request quorum context: %w: configuration is not the committed one"', STORE, '^TestAWeightedEVMConfigurationHasNoUnitRequestContext$', 'TestAWeightedEVMConfigurationHasNoUnitRequestContext'),
 (ORCH, 'derived_evm_is_weighted', 'return weightvalidation.PDR(conf, weightvalidation.RoleEVM, weightvalidation.ModeWeighted)', 'return weightvalidation.PDR(conf, weightvalidation.RoleEVM, weightvalidation.ModeUnit)', PARTS, '^TestDerivedConfigurationWeightRules$', 'TestDerivedConfigurationWeightRules'),
 (ORCH, 'derived_aggregator_is_unit', 'return weightvalidation.PDR(conf, weightvalidation.RoleAggregator, weightvalidation.ModeUnit)', 'return weightvalidation.PDR(conf, weightvalidation.RoleEVM, weightvalidation.ModeWeighted)', PARTS, '^TestDerivedConfigurationWeightRules$', 'TestDerivedConfigurationWeightRules'),
 (SAMPLER, 'frontier_profile_is_unit_by_default', 'weightvalidation.RootTrustBase(&trust, c.mode())', 'weightvalidation.RootTrustBase(&trust, weightvalidation.ModeWeighted)', CONS, '^TestFrontierProfileAdmitsAWeightedCommitteeOnlyExplicitly$', 'TestFrontierProfileAdmitsAWeightedCommitteeOnlyExplicitly'),
 (COLLECT, 'collector_profile_is_unit_by_default', 'if mode == 0 {\n\t\tmode = weightvalidation.ModeUnit\n\t}', 'if mode == 0 {\n\t\tmode = weightvalidation.ModeWeighted\n\t}', FRONT, '^TestWeightedProfileIsExplicitAndCountsByWeight$', 'TestWeightedProfileIsExplicitAndCountsByWeight'),
 (RECOVERY, 'verified_record_is_one_variant', 'if historical.V1 != nil || historical.V2 != nil || historical.Verified.Epoch != historical.Epoch {', 'if false {', ABDRC, '^TestStateMsg_Verify$', 'TestStateMsg_Verify'),
 (CM, 'no_v2_authority_for_an_activated_epoch', '} else if !q3Activated(x.q3, x.epochAnchor) {', '} else {', CONS, '^TestARestartedRootRecoversInAnActivatedEpochFromAPeersState$', 'TestARestartedRootRecoversInAnActivatedEpochFromAPeersState'),
 (CM, 'state_history_is_the_verified_lineage', 'if x.q3 != nil {\n\t\treturn x.q3.Lineage(x.recoveryHistory)', 'if false {\n\t\treturn x.q3.Lineage(x.recoveryHistory)', CONS, '^TestTheStateHistoryOfAnActivatedEpochIsTheVerifiedLineage$', 'TestTheStateHistoryOfAnActivatedEpochIsTheVerifiedLineage'),
 (CAND, 'binding_rules_are_the_contexts', 'if b.Rules == nil {\n\t\treturn UnitRules\n\t}\n\treturn b.Rules', 'return UnitRules', WV, '^TestWeightedRulesAdmitAMirroredAssignmentAndUnitRulesDoNot$', 'TestWeightedRulesAdmitAMirroredAssignmentAndUnitRulesDoNot'),
 (HIST, 'history_serves_admitted_epochs_only', 'if err := h.rt.Admit(epoch); err != nil {\n\t\t\treturn nil, errors.Join(ErrRequestHistory, err)\n\t\t}', 'if err := h.rt.Admit(epoch); err != nil {\n\t\t\t_ = err\n\t\t}', QA, '^TestRequestHistoryServesTheActivatedAssignmentOfItsShard$', 'TestRequestHistoryServesTheActivatedAssignmentOfItsShard'),
 (HIST, 'root_identity_is_admitted_only', 'if err := h.rt.Admit(e.Epoch()); err != nil {', 'if err := h.rt.Admit(e.Epoch()); err != nil && false {', QA, '^TestRequestHistoryServesTheActivatedAssignmentOfItsShard$', 'TestRequestHistoryServesTheActivatedAssignmentOfItsShard'),
 (HIST, 'committed_assignment_needs_its_candidate', 'if !e.RootOnly() {\n\t\t\t\treturn nil, fmt.Errorf("%w: epoch %d committed an assignment whose candidate is not retained"', 'if !e.RootOnly() && false {\n\t\t\t\treturn nil, fmt.Errorf("%w: epoch %d committed an assignment whose candidate is not retained"', QA, '^TestRequestHistoryServesTheActivatedAssignmentOfItsShard$', 'TestRequestHistoryServesTheActivatedAssignmentOfItsShard'),
 (HIST, 'history_is_per_shard', 'if evm.PartitionID != partition || !evm.ShardID.Equal(shard) {', 'if false {', QA, '^TestRequestHistoryServesTheActivatedAssignmentOfItsShard$', 'TestRequestHistoryServesTheActivatedAssignmentOfItsShard'),
 (HIST, 'history_is_complete', 'cfg.Candidates == nil || cfg.Anchor == nil || cfg.Network == 0 || cfg.Version == 0 || cfg.HashAlg == 0', 'false', QA, '^TestRequestHistoryServesTheActivatedAssignmentOfItsShard$', 'TestRequestHistoryServesTheActivatedAssignmentOfItsShard'),
 (TRUST, 'lineage_unknown_epoch', 'e, err := l.rt.History().ForEpoch(epoch)\n\tif err != nil {\n\t\treturn trusthistorystore.Record{}, err\n\t}', 'e, err := l.rt.History().ForEpoch(epoch)\n\tif err != nil {\n\t\t_ = err\n\t}', QA, '^TestLineageServesTheVerifiedProjectionOfAnActivatedEpoch$', 'TestLineageServesTheVerifiedProjectionOfAnActivatedEpoch'),
 (TRUST, 'lineage_admitted_only', 'if err := l.rt.Admit(epoch); err != nil {\n\t\treturn trusthistorystore.Record{}, err\n\t}', 'if err := l.rt.Admit(epoch); err != nil {\n\t\t_ = err\n\t}', QA, '^TestLineageServesTheVerifiedProjectionOfAnActivatedEpoch$', 'TestLineageServesTheVerifiedProjectionOfAnActivatedEpoch'),
 (TRUST, 'lineage_base_agrees', 'rec.V1 == nil || rec.V2 != nil || rec.Verified != nil || !sameTrust(rec.V1, e.Projection())', 'false', QA, '^TestLineageServesTheVerifiedProjectionOfAnActivatedEpoch$', 'TestLineageServesTheVerifiedProjectionOfAnActivatedEpoch'),
]
orig = {}
try:
    for path, name, needle, replacement, pkg, selector, marker in cases:
        orig.setdefault(path, path.read_text())
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
