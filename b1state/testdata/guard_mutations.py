import os, pathlib, subprocess, json
root=pathlib.Path(__file__).resolve().parents[2]
# Disable one independent guard at a time, run its named negative test, restore.
cases=[
 ('member-bounds','b1state/types.go','len(e.Members) == 0 || len(e.Members) > MaxMembers','false','./b1state','TestMembersIsolatedRefusals'),
 ('member-identity','b1state/types.go','len(m.NodeID) == 0 || len(m.NodeID) > MaxNodeIDBytes || !utf8.ValidString(m.NodeID) || (i > 0 && bytes.Compare([]byte(e.Members[i-1].NodeID), []byte(m.NodeID)) >= 0) || seen[m.Key] || m.Weight == 0','false && (i>0 || seen[m.Key] || bytes.Compare(nil,nil)>0 || !utf8.ValidString(m.NodeID))','./b1state','TestMembersIsolatedRefusals'),
 ('weight-overflow','b1state/types.go','math.MaxUint64-total < m.Weight','false && math.MaxUint64==0','./b1state','TestMembersIsolatedRefusals'),
 ('entry-identities','b1state/types.go','e.BodyKind < 1 || e.BodyKind > 3 || e.BodyID == ([32]byte{}) || e.SigningConfigHash == ([32]byte{}) || (e.SigningScheme != 1 && e.SigningScheme != 2)','false','./b1state','TestMembersIsolatedRefusals'),
 ('entry-activation','b1state/types.go','(e.BodyKind == 1 && e.ActivationCommitID != ([32]byte{})) || (e.BodyKind != 1 && e.ActivationCommitID == ([32]byte{}))','false','./b1state','TestMembersIsolatedRefusals'),
 ('entry-interval','b1state/types.go','e.End != nil && *e.End <= e.Start','false','./b1state','TestMembersIsolatedRefusals'),
 ('profile-pins','b1state/profile.go','p.Network == 0 || p.RootGenesisID == ([32]byte{}) || p.ExecutionChainID == 0 || p.RuntimeHash == ([32]byte{}) || p.CompilerHash == ([32]byte{}) || p.RestGas == 0 || p.GenesisUCTime == 0 || !p.validHook() || p.DeltaEV >= p.DeltaHold || p.MaxEpochsPerUpdate < MinEpochsPerUpdate','false','./b1state','TestProfileRefusalsAndCapacity'),
 ('profile-capacity','b1state/profile.go','p.SystemGas < required || p.OrdinaryCapacity == 0 || p.SystemGas > p.MaxGas || p.ForcedGas > p.MaxGas-p.SystemGas || p.OrdinaryCapacity != p.MaxGas-p.SystemGas-p.ForcedGas','false && required==0','./b1state','TestProfileRefusalsAndCapacity'),
 ('profile-transport','b1state/profile.go','p.OtherCompanionBytes > p.CompanionBytes || c > p.CompanionBytes-p.OtherCompanionBytes','false && c==0','./b1state','TestProfileRefusalsAndCapacity'),
 ('scan-debit','b1state/codec.go','scanGas > budget','false','./b1state','TestUpdateStagedDebitAndCanonical'),
 ('member-debit','b1state/codec.go','members > (budget-scanGas)/1000','false','./b1state','TestUpdateStagedDebitAndCanonical'),
 ('origin-tail','b1state/codec.go','tail.End != nil || tail.Epoch != u.OriginEpoch','false && tail.Epoch==0','./b1state','TestUpdateStagedDebitAndCanonical'),
 ('system-budget','b1state/profile.go','admit > budget || open > budget-admit || imp > budget-admit-open || finalize > budget-admit-open-imp || hooks > budget-admit-open-imp-finalize','false','./b1state','TestUpdateStagedDebitAndCanonical'),
 ('caller-signature-shape','b1ref/prescan.go','r.err == nil && ((len(sig) != 64 && len(sig) != 65) || (len(sig) == 65 && sig[64] > 1))','false && len(sig)==0','./b1ref','TestCallerScannerRejectsSignatureShape'),
 ('caller-full-debit','b1ref/verify.go','gas < charge','false && charge==0','./b1ref','TestRunReservesChargeBeforeWork'),
 ('caller-claim-order','b1ref/verify.go','i > 0 && compareClaimID(&call.claims[i-1], c) >= 0','false','./b1ref','TestGoldenVectors/cert.shared.order'),
 ('caller-seal-equality','b1ref/verify.go','!bytes.Equal(c.sealRaw, call.claims[0].sealRaw)','false && bytes.Equal(nil,nil)','./b1ref','TestGoldenVectors/cert.shared.mixed-subsets.false'),
 ('caller-epoch-entry','b1ref/verify.go','entry.Epoch != seal.Epoch','false','./b1ref','TestAdmittedRegistryRefusals/wrong-epoch'),
 ('caller-phase','b1ref/verify.go','reg.Phase == 1','false','./b1ref','TestAdmittedRegistryRefusals'),
 ('weighted-quorum','b1ref/verify.go','good < threshold','false && threshold==0','./b1ref','TestGoldenVectors/weighted.below'),
]
cases.extend([
 ('append-start-increasing','b1state/registry.go','if e.Start <= tip.Start {','if false {','./b1state','TestAppendGuards'),
 ('append-closes-usable','b1state/registry.go','if r.Ready && r.Tip == r.U && e.Start <= r.O {','if false {','./b1state','TestAppendGuards'),
 ('origin-epoch-regression','b1state/registry.go','if epoch < r.U {','if false {','./b1state','TestWriteSideGuardsEachFireAlone'),
 ('origin-round-regression','b1state/registry.go','if round < r.O {','if false {','./b1state','TestWriteSideGuardsEachFireAlone'),
 ('origin-before-start','b1state/registry.go','if round < target.Start {','if false {','./b1state','TestWriteSideGuardsEachFireAlone'),
 ('origin-at-or-after-end','b1state/registry.go','if target.End != nil && round >= *target.End {','if false {','./b1state','TestWriteSideGuardsEachFireAlone'),
 ('first-origin-before-genesis','b1state/registry.go','} else if epoch < r.Genesis {','} else if false {','./b1state','TestWriteSideGuardsEachFireAlone'),
 ('imported-usable-mismatch','b1state/registry.go','if next.Ready && next.U != next.Tip {','if false {','./b1state','TestSpanTwoUpdateInstallsBothOrNeither'),
 ('epochs-per-update','b1state/registry.go','if uint64(len(u.NewEntries)) > b {','if false {','./b1state','TestSpanTwoUpdateInstallsBothOrNeither'),
 ('append-successor','b1state/registry.go','if e.Epoch != r.Tip+1 {','if false {','./b1state','TestAppendGuards'),
 ('parent-tip-binding','b1state/registry.go','if u.PriorTipEpoch != r.Tip {','if false {','./b1state','TestAppendGuards'),
 ('member-point','b1state/types.go','if _, err := ethcrypto.DecompressPubkey(m.Key[:]); err != nil {','if _, err := ethcrypto.DecompressPubkey(m.Key[:]); err != nil && false {','./b1state','TestMembersIsolatedRefusals/invalid-point'),
 ('candidate-bindings','b1state/types.go','u.ParentHash != b.ParentHash || u.BlockNumber != b.BlockNumber || u.OriginEpoch != b.OriginEpoch || u.OriginRound != b.OriginRound || u.OriginIdentity != b.OriginIdentity','false','./b1state','TestExactCandidateBindings'),
 ('caller-max-S','b1ref/prescan.go','sig > maxS','false','./b1ref','TestRunGas'),
])
env=os.environ.copy();env['GOCACHE']=os.environ['GOCACHE'] # require the caller's private cache
results=[]
for name,file,old,new,pkg,test in cases:
 p=root/file;original=p.read_text()
 if original.count(old)!=1:raise RuntimeError(f'{name}: occurrence count {original.count(old)}')
 try:
  p.write_text(original.replace(old,new))
  r=subprocess.run(['go','test',pkg,'-run','^'+test+'$','-count=1','-timeout','2m'],cwd=root,env=env,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True)
  output=r.stdout
  killed=r.returncode!=0 and '--- FAIL: '+test.split('/')[0] in output
  result={'guard':name,'test':test,'exit':r.returncode,'killed':killed,'output':output}
  results.append(result);print(name, 'KILLED' if killed else 'SURVIVED/BUILD ERROR',flush=True)
 finally:p.write_text(original)
pathlib.Path('/private/tmp/b1pr1-manual-mutations.json').write_text(json.dumps(results,indent=2))
if not all(r['killed'] for r in results):raise SystemExit(1)
