"""Sequential, reversible guard-removal audit. Run with a private GOCACHE."""
import os, pathlib, subprocess, json, sys
root=pathlib.Path(__file__).resolve().parents[2]
cases=[]
def guard(name,file,condition,pkg,test):
 cases.append((name,file,condition,'false && ('+condition+')',pkg,test))
def replace(name,file,old,new,pkg,test):
 cases.append((name,file,old,new,pkg,test))
A='b1registry/artifact.go'; T='TestMeasuredProfileBoundaries'
guard('artifact-file-identity',A,'hex.EncodeToString(sum[:]) != "c094a1a6d56236474e68e5fda665f3d6fcc2c789743ede6e671c7f4f89279bcb"','b1registry','TestArtifactFileIdentity')
for n,c in [('measured-k','k > MaxMeasuredK'),('runtime-pin','p.RuntimeHash != [32]byte(common.HexToHash(CodeHashHex))'),('compiler-pin','p.CompilerHash != CompilerHash()'),('rest-gas','p.RestGas < 1096500+1141500*k')]:guard(n,A,c,'b1registry',T)
replace('profile-validity',A,'if err := p.Validate(); err != nil {','if err := p.Validate(); err != nil && false {','b1registry',T)
A='q3format/b1.go'
guard('history-present',A,'h == nil || len(h.entries) == 0','q3format','TestB1AuthenticatedPrefixPreservesNativeBodiesWeightsAndActualStarts')
guard('history-prefix-freeze',A,'v.start > origin','q3format','TestB1AuthenticatedPrefixPreservesNativeBodiesWeightsAndActualStarts')
replace('signing-config-validity',A,'if err := cfg.Validate(); err != nil {','if err := cfg.Validate(); err != nil && false {','q3format','TestB1RefusesMissingOrChangedSuccessorConfiguration')
guard('genesis-only-legacy-policy',A,'v.epoch != h.entries[0].epoch || v.version != 1 || v.scheme != 1','q3format','TestB1MissingConfigurationNeverDefaultsToLegacy')
guard('member-key-width',A,'m == nil || len(m.SigKey) != 33','q3format','TestB1MissingConfigurationNeverDefaultsToLegacy')
replace('history-member-validity',A,'if err := e.Validate(); err != nil {','if err := e.Validate(); err != nil && false {','q3format','TestB1MissingConfigurationNeverDefaultsToLegacy')
guard('history-quorum-policy',A,'threshold != v.tb.QuorumThreshold','q3format','TestB1MissingConfigurationNeverDefaultsToLegacy')
guard('history-known-epoch',A,'len(out) == 0','q3format','TestB1AuthenticatedPrefixPreservesNativeBodiesWeightsAndActualStarts')
A='q3active/b1.go'
guard('runtime-present',A,'r == nil','q3active','TestB1RefusesIncompleteInterveningActivation')
guard('runtime-history-present',A,'h == nil','q3active','TestB1RefusesIncompleteInterveningActivation')
replace('all-intervening-installs-complete',A,'if err := r.Admit(e.Epoch); err != nil {','if err := r.Admit(e.Epoch); err != nil && false {','q3active','TestB1RefusesIncompleteInterveningActivation')
A='registryproof/b1.go'
for n,c,t in [('proof-context-and-count','s.r == nil || len(keys) != len(proofs) || len(keys) > 6+524*16','TestFreshB1FixedProofInvariants'),('proof-node-count','len(proof) > 64','TestB1StorageProofResourceGuardsBeforeTrieVerification'),('proof-node-bytes','len(node) > 1<<16','TestB1StorageProofResourceGuardsBeforeTrieVerification'),('proof-bytes','size > 1<<20','TestB1StorageProofResourceGuardsBeforeTrieVerification'),('aggregate-proof-bytes','total > 64<<20','TestB1StorageProofAggregateBound')]:guard(n,A,c,'registryproof',t)
A='registryproof/registryproof.go'
guard('literal-initialization',A,'(lay.version == FreshB1 && s.B1Initialized != 1)','registryproof','TestFreshB1FixedProofInvariants')
for n,c in [('network-nonzero','s.B1Network == 0'),('network-width','s.B1Network > 65535'),('window-measured','s.B1WCert >= 16'),('queue-head','s.B1Head > s.B1WCert'),('queue-count-nonzero','s.B1Count == 0'),('queue-count-cap','s.B1Count > s.B1WCert+1'),('profile-present','s.B1ProfileHash == (common.Hash{})')]:guard(n,A,c,'registryproof','TestB1OrdinaryParentHeadBound' if n == 'queue-head' else 'TestFreshB1FixedProofInvariants')
A='rootinput/b1.go'
guard('pair-evidence-present',A,'c == nil || c.Runtime == nil || !parent.Valid() || !o.Valid()','b1paired','TestPairRejectsMissingAuthorityAndParentProof')
replace('pair-profile-validity',A,'if err := b1registry.ValidateProfile(p); err != nil {','if err := b1registry.ValidateProfile(p); err != nil && false {','b1paired','TestPairRejectsMissingAuthorityAndParentProof')
guard('pair-parent-profile-binding',A,'f.Layout != registryproof.FreshB1 || f.B1Network != uint64(p.Network) || f.B1WCert != p.WCert || f.B1ProfileHash != common.Hash(profileHash) || origin.NetworkID != uint64(p.Network) || parent.VerifiedContext().RegistryCodeHash != common.Hash(p.RuntimeHash)','b1paired','TestPairRejectsMissingAuthorityAndParentProof')
guard('pair-history-root-binding',A,'h.Genesis() != p.RootGenesisID || h.Network() != uint64(p.Network)','b1paired','TestPairRechecksObservationUnderItsOwnRootCommittee')
replace('origin-live-interval',A,'if err = h.Ordinary(origin.RootEpoch, origin.RootRound); err != nil {','if err = h.Ordinary(origin.RootEpoch, origin.RootRound); err != nil && false {','b1paired','TestAuthenticatedSupersessionProjectsOnlySurvivingEpochs')
replace('own-root-committee',A,'if err = o.VerifyRootCommittee(committee.Projection()); err != nil {','if err = o.VerifyRootCommittee(committee.Projection()); err != nil && false {','b1paired','TestPairRechecksObservationUnderItsOwnRootCommittee')
guard('parent-tip-and-count',A,'uint64(len(expected)) != f.B1Count || f.B1Head > p.WCert || (!parent.Genesis() && f.OriginRootEpoch != expected[len(expected)-1].Epoch)','b1paired','TestParentCountClockAndHeightAreIndependentGates')
guard('proof-source-present',A,'c.Proofs == nil','b1paired','TestPairRejectsMissingAuthorityAndParentProof')
guard('parent-authority-exact-words',A,'got[i] != words[k]','b1paired','TestHonestBodyWithAttackerStorageIsRefused')
guard('block-height-overflow',A,'parent.Number() == math.MaxUint64','b1paired','TestParentCountClockAndHeightAreIndependentGates')
for n,c in [('replay-update-equality','!bytes.Equal(expected.Update, raw)'),('replay-hash-equality','!bytes.Equal(expected.Hash[:], hash)')]:guard(n,A,c,'b1paired','TestOwnPairDerivationAndExactReplay')
A='rootinput/v2.go'
guard('shared-api-pair-required',A,'c.B1 == nil','rootinput','TestFreshRootInputCannotBypassOwnPairAdmission')
guard('actual-companion-reservation',A,'other > c.B1.Profile.OtherCompanionBytes || uint64(len(b1Update)) > c.B1.Profile.CompanionBytes-other','engineapi','TestB1ActualCompanionReservation')
replace('own-committee-uc-signature',A,'if err := o.uc.Verify(quorumweight.Checked(tb), crypto.SHA256, o.partition, shard, o.conf); err != nil {','if err := o.uc.Verify(quorumweight.Checked(tb), crypto.SHA256, o.partition, shard, o.conf); err != nil && false {','b1paired','TestPairRechecksObservationUnderItsOwnRootCommittee')
A='engineapi/adapter.go';T='TestB1BuildSealsTheLocallyDerivedUpdate'
for n,c in [('sealed-job-gas','uint64(resp.ExecutionPayload.GasLimit) != a.verifier.B1.Profile.MaxGas'),('sealed-job-update','!bytes.Equal(resp.SealCompanion.B1Update, bc.b1Update)'),('sealed-job-input','!bytes.Equal(resp.SealCompanion.RootInput, bc.b1Input)'),('sealed-job-commitment','!bytes.Equal(resp.ExecutionPayload.ExtraData, bc.b1Commitment[:])'),('binding-gas','a.verifier.B1 != nil && uint64(payload.GasLimit) != a.verifier.B1.Profile.MaxGas'),('import-gas','a.verifier.B1 != nil && uint64(envelope.ExecutionPayload.GasLimit) != a.verifier.B1.Profile.MaxGas'),('import-update','!bytes.Equal(companion.B1Update, derived.B1Update)'),('import-root-input','!bytes.Equal(companion.RootInput, derived.Encoded)'),('quiet-block-gate','a.verifier != nil && a.verifier.B1 != nil')]:guard(n,A,c,'engineapi',T)
A='registrygenesis/b1.go';T='TestB1GenesisBindsRootProfileAndAllStorageWords'
guard('genesis-root-network-gas',A,'h == nil || h.Genesis() != p.RootGenesisID || h.Network() != uint64(p.Network) || config == nil || uint64(config.NetworkID) != uint64(p.Network) || evm.GasLimit != p.MaxGas','registrygenesis',T)
guard('genesis-chain-id',A,'chain != p.ExecutionChainID','registrygenesis',T)
replace('genesis-root-commitment','registrygenesis/registrygenesis.go','g.RootGenesisID.Bytes(), g.B1ProfileHash.Bytes()','common.Hash{}.Bytes(), g.B1ProfileHash.Bytes()','registrygenesis',T)
replace('genesis-profile-commitment','registrygenesis/registrygenesis.go','g.RootGenesisID.Bytes(), g.B1ProfileHash.Bytes()','g.RootGenesisID.Bytes(), common.Hash{}.Bytes()','registrygenesis',T)
A='evmroot/rootorigin_v2.go'; T='TestB1RootInputHasOneCommittedUpdateHash'
guard('root-input-hash-width',A,'ri.B1UpdateHash != nil && len(ri.B1UpdateHash) != 32','evmroot',T)
replace('root-input-hash-encoding',A,'if ri.B1UpdateHash != nil {','if false && ri.B1UpdateHash != nil {','evmroot',T)
A='registryproof/registryproof.go'
replace('fresh-slot-namespace',A,'if version == FreshB1 {','if false && version == FreshB1 {','registryproof','TestFreshB1FixedProofInvariants')
A='registrygenesis/artifact.go';T='TestFreshB1ArtifactGuards'
guard('fresh-artifact-cannot-use-historical-loader',A,'a.b1 == nil','registrygenesis',T)
replace('fresh-artifact-profile-validity',A,'if err := b1registry.ValidateProfile(a.b1.profile); err != nil {','if err := b1registry.ValidateProfile(a.b1.profile); err != nil && false {','registrygenesis',T)
guard('fresh-artifact-runtime-pin',A,'a.CodeHash != common.Hash(a.b1.profile.RuntimeHash)','registrygenesis',T)
A='registrygenesis/b1.go';T='TestB1GenesisBindsRootProfileAndAllStorageWords'
replace('fresh-genesis-profile-validity',A,'if err := b1registry.ValidateProfile(p); err != nil {','if err := b1registry.ValidateProfile(p); err != nil && false {','registrygenesis',T)
guard('genesis-prefix-single-entry',A,'len(entries) != 1','registrygenesis',T)
guard('origin-config-present',A,'full == nil','registrygenesis',T)
A='registrygenesis/registrygenesis.go'
guard('allocation-gas-pin',A,'art.b1 != nil && evm.GasLimit != art.b1.profile.MaxGas','registrygenesis',T)
replace('proof-query-ownership','rootinput/b1.go','c.Proofs(ctx, parent, append([]common.Hash(nil), keys...))','c.Proofs(ctx, parent, keys)','b1paired','TestProofFetcherCannotRewriteAdmissionKeys')
A='b1registry/artifact.go'
replace('artifact-runtime-metadata',A,'if json.Unmarshal(artifact, &a) != nil || a.Profile != "sealRegistry" || a.CodeHash != common.HexToHash(CodeHashHex) || crypto.Keccak256Hash(a.RuntimeBytecode) != a.CodeHash || a.OpenSelector != "0x724236c0" {','if decodeErr := json.Unmarshal(artifact, &a); false && (decodeErr != nil || a.Profile != "sealRegistry" || a.CodeHash != common.HexToHash(CodeHashHex) || crypto.Keccak256Hash(a.RuntimeBytecode) != a.CodeHash || a.OpenSelector != "0x724236c0") {','b1registry','TestArtifactFileIdentity')
guard('artifact-slot-count',A,'len(names) != len(a.SlotKeys)','b1registry','TestArtifactFileIdentity')
guard('artifact-slot-keys',A,'a.SlotKeys[i].Name != n || a.SlotKeys[i].Key != common.Hash(b1state.FixedSlot(n))','b1registry','TestArtifactFileIdentity')
for n,c in [('retention-update','!bytes.Equal(envelope.SealCompanion.B1Update, input.B1Update)'),('retention-input','!bytes.Equal(envelope.SealCompanion.RootInput, input.Encoded)'),('retention-commitment','!bytes.Equal(payload.ExtraData, input.Commitment[:])')]:guard(n,'engineapi/adapter.go',c,'engineapi','TestB1BuildSealsTheLocallyDerivedUpdate')
replace('bootstrap-parent-clock','rootinput/b1.go','if parent.Genesis() {','if false && parent.Genesis() {','b1paired','TestBootstrapInstallsAuthorityBeforeOperationalClock')
replace('export-entry-validity','b1state/storage.go','if err := e.Validate(); err != nil {','if err := e.Validate(); err != nil && false {','b1paired','TestEntryStorageRefusesInvalidAuthorityEntry')
guard('fresh-allocation-config-required','registrygenesis/registrygenesis.go','art.b1 == nil','registrygenesis','TestFreshB1ArtifactGuards')
# Error propagation / duplicated defense guards can be dominated. Record honestly.
if len(sys.argv)>1:cases=[c for c in cases if c[0] in sys.argv[1:]]
env=os.environ.copy();assert env['GOCACHE'].startswith('/private/tmp/')
# Always verify the named tests on restored sources first; a broken baseline
# must never count as a killed mutation.
baseline = subprocess.run(['go', 'test', '-p', '4', *sorted({'./'+c[4] for c in cases}), '-run', '^('+'|'.join(sorted({c[5] for c in cases}))+')$', '-count=1', '-timeout', '3m'], cwd=root, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
print(baseline.stdout, flush=True)
if baseline.returncode != 0: raise SystemExit('Guard audit baseline failed; no mutations applied')
results=[]
for name,file,old,new,pkg,test in cases:
 p=root/file;original=p.read_text()
 if original.count(old)!=1:raise RuntimeError(f'{name}: occurrences={original.count(old)}')
 try:
  p.write_text(original.replace(old,new))
  r=subprocess.run(['go','test','-p','4','./'+pkg,'-run','^'+test+'$','-count=1','-timeout','3m'],cwd=root,env=env,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True)
  killed=r.returncode!=0 and '--- FAIL: '+test.split('/')[0] in r.stdout
  result=dict(guard=name,file=file,test=test,exit=r.returncode,killed=killed,output=r.stdout)
  results.append(result);print(name, 'KILLED' if killed else ('SURVIVED' if r.returncode == 0 else 'BUILD ERROR'),flush=True)
 finally:p.write_text(original)
 pathlib.Path(os.environ.get('B1_MUTATION_RESULTS', '/private/tmp/b1pr1b-manual-mutations.json')).write_text(json.dumps(results,indent=2))
print(f'{sum(r["killed"] for r in results)}/{len(results)} caught',flush=True)
