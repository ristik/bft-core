package evmroot

import (
	"bytes"
	"crypto"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"testing"
	"time"

	drctypes "github.com/unicitynetwork/bft-core/rootchain/consensus/types"
	base "github.com/unicitynetwork/bft-go-base/types"
)

type d4Fixture struct {
	body     TrustBaseBodyV2
	record   OrderedHandoffRecord
	snapshot FullSnapshot
	old      D4TrustBase
	keys     map[string]ed25519.PrivateKey
}

func fixture(t *testing.T) d4Fixture {
	t.Helper()
	ws := d3Assignment()
	w, _ := ws.TotalWeight()
	pred := bytes.Repeat([]byte{0x11}, 32)
	prefreeze := D4PreFreezeSummary(3, pred, 1, 9, bytes.Repeat([]byte{0x88}, 32), bytes.Repeat([]byte{0x99}, 32))
	candidateContext := D4CandidateContextHash(3, pred, 1, bytes.Repeat([]byte{0xaa}, 32), 12)
	body := TrustBaseBodyV2{Version: 2, NetworkID: 3, Epoch: 8, EarliestActivation: 12, Members: ws, RootThreshold: RootQuorumThreshold(w), StateSummary: prefreeze, ChangeRecordHash: candidateContext, PredecessorHash: pred}
	id := body.Identity()
	r := OrderedHandoffRecord{Network: 3, Epoch: 7, Attempt: 1, OrderedRound: 10, ActivationRound: 13, PredecessorBodyID: pred, FrozenID: bytes.Repeat([]byte{0x44}, 32), NextBodyID: id[:], SuccessorTRHash: bytes.Repeat([]byte{0x55}, 32), Kind: "commit"}
	ctl := ControlState{Network: 3, Epoch: 7, Attempt: 1, OrderedRound: 10, PredecessorBodyID: pred, Phase: "committed", RecordBytes: r.Bytes(), PreviousDigest: bytes.Repeat([]byte{0x66}, 32)}
	shard := ShardSnapshot{Partition: 1, InputRecord: []byte("IR-H"), TechnicalRecord: []byte("TR-H"), LastCR: []byte("old-last-cr"), PendingConfig: []byte("cfg-next"), FeeStats: []byte("fees")}
	shard.Root = shard.CalculatedRoot()
	shard2 := ShardSnapshot{Partition: 2, InputRecord: []byte("IR-2"), TechnicalRecord: []byte("TR-2"), LastCR: []byte("last-2")}
	shard2.Root = shard2.CalculatedRoot()
	shard3 := ShardSnapshot{Partition: 3, InputRecord: []byte("IR-3"), TechnicalRecord: []byte("TR-3"), LastCR: []byte("last-3")}
	shard3.Root = shard3.CalculatedRoot()
	s := FullSnapshot{Control: ctl, Shards: []ShardSnapshot{shard, shard2, shard3}}
	old, keys := D4FixtureTrustBase(7, map[string]uint64{"a": 1, "b": 1, "c": 1, "d": 1})
	return d4Fixture{body, r, s, old, keys}
}
func (f d4Fixture) proof(t *testing.T, c uint64) HandoffProof {
	t.Helper()
	root, e := f.snapshot.Root()
	if e != nil {
		t.Fatal(e)
	}
	path, e := f.snapshot.ControlPath()
	if e != nil {
		t.Fatal(e)
	}
	qc := D4QC{Vote: D4VoteInfo{Round: c + 1, Epoch: 7, ParentRound: c, Timestamp: 1700000000, CurrentRoot: bytes.Clone(root)}, Seal: D4Seal{Commit: D4LedgerCommitInfo{Network: 3, Round: c, Epoch: 7, Timestamp: 1699999999, Root: bytes.Clone(root)}}}
	D4SignQC(&qc, f.keys, "a", "b", "c")
	record := f.record
	record.NextBodyID = bytes.Clone(record.NextBodyID)
	record.FrozenID = bytes.Clone(record.FrozenID)
	record.PredecessorBodyID = bytes.Clone(record.PredecessorBodyID)
	record.SuccessorTRHash = bytes.Clone(record.SuccessorTRHash)
	return HandoffProof{Profile: D4Profile, Record: record, Control: f.snapshot.Control, ControlPath: path, CommitQC: qc, Snapshot: f.snapshot}
}
func mustVerified(t *testing.T, p HandoffProof, old D4TrustBase) VerifiedHandoff {
	t.Helper()
	v, e := VerifyHandoff(p, old)
	if e != nil {
		t.Fatal(e)
	}
	return v
}
func assertIs(t *testing.T, e, target error) {
	t.Helper()
	if !errors.Is(e, target) {
		t.Fatalf("got %v, want %v", e, target)
	}
}

func TestD4_SuffixPayloadRefused(t *testing.T) {
	f := fixture(t)
	parent := &D4BranchState{Control: &f.snapshot.Control, Shards: f.snapshot.Shards, PendingWork: [][]byte{[]byte("deferred")}}
	kinds := []string{"shard_success", "shard_repeat", "shard_no_quorum", "shard_timeout", "evm_tx", "governance_tx", "prepare", "freeze", "commit", "abort", "unknown"}
	for _, kind := range kinds {
		t.Run(kind, func(t *testing.T) {
			p := D4Proposal{Epoch: 7, Round: 11, PayloadKind: kind}
			assertIs(t, CanVoteOldSuffix(parent, p), ErrD4Suffix)
			assertIs(t, func() error { _, e := RecoverOldSuffix(parent, p); return e }(), ErrD4Suffix)
		})
	}
	mutations := []D4Proposal{{ScheduledConfig: true}, {NextEpoch: true}, {TimeoutUpdate: true}, {HiddenMutation: true}, {Payload: []byte{1}}}
	for i, p := range mutations {
		t.Run(string(rune('a'+i)), func(t *testing.T) { p.Epoch = 7; p.Round = 11; assertIs(t, CanVoteOldSuffix(parent, p), ErrD4Suffix) })
	}
	empty, e := ExecuteOldSuffix(parent, D4Proposal{Epoch: 7, Round: 100})
	if e != nil {
		t.Fatal(e)
	}
	if !parent.Equal(empty) {
		t.Fatal("old suffix changed state")
	}
	assertIs(t, CanVoteOldSuffix(nil, D4Proposal{Epoch: 7, Round: 11}), ErrD4Unready)
}

// Formula/illustrative: enumerates signer weight, not the runtime vote path.
func TestD4_SuffixPayloadNoQC_Formula(t *testing.T) {
	for _, signers := range [][]D4Signer{{{"a", 1, false, ""}, {"b", 1, false, ""}, {"c", 1, false, ""}, {"d", 1, true, ""}}, {{"a", 10, false, ""}, {"b", 6, false, ""}, {"c", 5, false, ""}, {"d", 2, true, ""}, {"e", 1, true, ""}}} {
		var total uint64
		for _, s := range signers {
			total += s.Weight
		}
		q := total*2/3 + 1
		ids := []string{}
		var sum uint64
		for _, s := range signers {
			ids = append(ids, s.ID)
			sum += s.Weight
			if sum >= q {
				break
			}
		}
		if e := PayloadSuffixQCImpossible(signers, ids, q); e != nil {
			t.Fatal(e)
		}
		r, e := ExploreD4Quorums(signers, q)
		if e != nil || r.BothQuorate {
			t.Fatalf("equivocation formed conflicting QCs: %+v %v", r, e)
		}
		lock := signers[0]
		if !lock.Vote("H") {
			t.Fatal("honest vote refused")
		}
		restarted := lock.Restart()
		if restarted.Vote("abort") {
			t.Fatal("restart lost honest lock")
		}
	}
}
func TestD4_LeaderCPlus2Crash(t *testing.T) {
	f := fixture(t)
	progress := D4OldProgress{Order: 10, Start: 13, Live: true}
	// Leader 12 crashes before aggregating QC(11); old timeouts cross A*.
	for _, round := range []uint64{12, 13, 14, 15} {
		if e := progress.Timeout(round); e != nil {
			t.Fatal(e)
		}
	}
	progress.Live = false
	assertIs(t, progress.DeliverProof(), ErrD4Proof)
	if progress.NewMayBootstrap() {
		t.Fatal("new quorum started without old proof")
	}
	progress.Live = true
	if e := progress.CertifyEmpty(15); e != nil {
		t.Fatal(e)
	}
	if e := progress.CertifyEmpty(16); e != nil {
		t.Fatal(e)
	}
	c := progress.Seal
	if c != 15 || progress.Timeouts[len(progress.Timeouts)-1] < progress.Start {
		t.Fatal("later pair did not commit suffix")
	}
	if e := progress.DeliverProof(); e != nil {
		t.Fatal(e)
	}
	progress.Live = false
	if !progress.NewMayBootstrap() {
		t.Fatal("new quorum still needs old signatures after proof")
	}
	p := f.proof(t, c)
	v := mustVerified(t, p, f.old)
	g, e := DeriveEpochGenesis(v, f.body)
	if e != nil {
		t.Fatal(e)
	}
	if g.Start != 13 || v.CommitSealRound <= 13 {
		t.Fatal("late proof moved fixed start")
	}
	b := D4Bootstrap{}
	newTB, _ := D4FixtureTrustBase(8, map[string]uint64{"n1": 1, "n2": 1, "n3": 1, "n4": 1})
	if e = b.Install(v, g, f.snapshot, newTB); e != nil {
		t.Fatal(e)
	}
	if e = b.Vote(13, b.HighestQC); e != nil {
		t.Fatal(e)
	}
	if e := b.Commit(b.HighestQC, D4QC{}); !errors.Is(e, ErrD4CommitAnchor) {
		t.Fatal(e)
	}
}
func TestD4_DeterministicGenesis(t *testing.T) {
	f := fixture(t)
	p10 := f.proof(t, 10)
	p100 := f.proof(t, 100)
	v10 := mustVerified(t, p10, f.old)
	v100 := mustVerified(t, p100, f.old)
	g10, e := DeriveEpochGenesis(v10, f.body)
	if e != nil {
		t.Fatal(e)
	}
	g100, e := DeriveEpochGenesis(v100, f.body)
	if e != nil {
		t.Fatal(e)
	}
	if !bytes.Equal(g10.Bytes(), g100.Bytes()) || !bytes.Equal(g10.ID(), g100.ID()) {
		t.Fatal("proof c changed genesis")
	}
	p100.CommitQC.Signatures = map[string][]byte{}
	D4SignQC(&p100.CommitQC, f.keys, "b", "c", "d")
	v100 = mustVerified(t, p100, f.old)
	g100, e = DeriveEpochGenesis(v100, f.body)
	if e != nil || !bytes.Equal(g10.ID(), g100.ID()) {
		t.Fatal("signer subset changed genesis")
	}
	bad := p10
	bad.Snapshot.Shards = append([]ShardSnapshot(nil), p10.Snapshot.Shards...)
	bad.Snapshot.Shards[0].Root = bytes.Repeat([]byte{0x99}, 32)
	assertIs(t, func() error { _, e := VerifyHandoff(bad, f.old); return e }(), ErrD4Snapshot)
}

func TestD4_DeterministicGenesisInputOrdering(t *testing.T) {
	f := fixture(t)
	extra := ShardSnapshot{Partition: 4, InputRecord: []byte("IR-4"), TechnicalRecord: []byte("TR-4"), LastCR: []byte("last-4")}
	extra.Root = extra.CalculatedRoot()
	f.snapshot.Shards = append(f.snapshot.Shards, extra)
	p1 := f.proof(t, 10)
	v1 := mustVerified(t, p1, f.old)
	g1, e := DeriveEpochGenesis(v1, f.body)
	if e != nil {
		t.Fatal(e)
	}
	f.snapshot.Shards[0], f.snapshot.Shards[1] = f.snapshot.Shards[1], f.snapshot.Shards[0]
	p2 := f.proof(t, 100)
	v2 := mustVerified(t, p2, f.old)
	g2, e := DeriveEpochGenesis(v2, f.body)
	if e != nil || !bytes.Equal(g1.Bytes(), g2.Bytes()) || !bytes.Equal(g1.ID(), g2.ID()) {
		t.Fatal("input order or seal round changed genesis", e)
	}
}
func TestD4_NewBootstrapTimeout(t *testing.T) {
	f := fixture(t)
	p := f.proof(t, 100)
	v := mustVerified(t, p, f.old)
	g, _ := DeriveEpochGenesis(v, f.body)
	b := D4Bootstrap{}
	newTB, newKeys := D4FixtureTrustBase(8, map[string]uint64{"n1": 1, "n2": 1, "n3": 1, "n4": 1})
	if e := b.Install(v, g, f.snapshot, newTB); e != nil {
		t.Fatal(e)
	}
	anchor := b.HighestQC
	if anchor.Round != 12 {
		t.Fatal(anchor)
	}
	tc := D4TimeoutCertificate{Epoch: 8, Round: 13, HighQC: anchor}
	D4SignTC(&tc, newKeys, "n1", "n2", "n3")
	if e := b.ApplyTC(tc); e != nil {
		t.Fatal(e)
	}
	head := D4RecoveryHead{Parent: anchor, Proof: &p, Snapshot: &f.snapshot}
	if e := head.Verify(f.old, newTB, g); e != nil {
		t.Fatal(e)
	}
	tc.HighQC.GenesisID = bytes.Repeat([]byte{0}, 32)
	assertIs(t, tc.Verify(newTB, g), ErrD4Anchor)
	leader, e := D4FallbackLeader(g, []string{"n4", "n2", "n1", "n3"}, 13)
	if e != nil || leader != "n1" {
		t.Fatal("fallback leader not canonical", leader, e)
	}
	if e := b.Vote(13, anchor); e != nil {
		t.Fatal(e)
	}
	restart := b.Restart()
	assertIs(t, restart.Vote(13, anchor), ErrD4Epoch)
	assertIs(t, restart.Commit(anchor, D4QC{}), ErrD4CommitAnchor)
	newQC := D4QC{Vote: D4VoteInfo{Round: 14, Epoch: 8, ParentRound: 13, Timestamp: 1700000001, CurrentRoot: g.Root}}
	D4SignQC(&newQC, newKeys, "n1", "n2", "n3")
	ordinary := D4Parent{Kind: D4OrdinaryParent, Epoch: 8, Round: 14, QC: &newQC}
	if e := restart.Vote(15, ordinary); e != nil {
		t.Fatal(e)
	}
	childQC := D4QC{Vote: D4VoteInfo{Round: 15, Epoch: 8, ParentRound: 14, Timestamp: 1700000002, CurrentRoot: g.Root}, Seal: D4Seal{Commit: D4LedgerCommitInfo{Network: 3, Round: 14, Epoch: 8, Timestamp: 1700000001, Root: g.Root}}}
	D4SignQC(&childQC, newKeys, "n1", "n2", "n3")
	if e := restart.Commit(ordinary, childQC); e != nil {
		t.Fatal(e)
	}
	if !reflect.DeepEqual(restart.Committed, []uint64{14}) {
		t.Fatal(restart.Committed)
	}
	assertIs(t, restart.Vote(16, anchor), ErrD4Anchor)
}

func TestD4_NewEpochLockRejectsOlderCertifiedParent(t *testing.T) {
	f := fixture(t)
	v := mustVerified(t, f.proof(t, 100), f.old)
	g, _ := DeriveEpochGenesis(v, f.body)
	newTB, keys := D4FixtureTrustBase(8, map[string]uint64{"n1": 1, "n2": 1, "n3": 1, "n4": 1})
	b := D4Bootstrap{}
	if e := b.Install(v, g, f.snapshot, newTB); e != nil {
		t.Fatal(e)
	}
	if e := b.Vote(13, b.HighestQC); e != nil {
		t.Fatal(e)
	}
	qc14 := D4QC{Vote: D4VoteInfo{Round: 14, Epoch: 8, ParentRound: 13, Timestamp: 1700000001, CurrentRoot: g.Root}}
	D4SignQC(&qc14, keys, "n1", "n2", "n3")
	if e := b.Vote(15, D4Parent{Kind: D4OrdinaryParent, Epoch: 8, Round: 14, QC: &qc14}); e != nil {
		t.Fatal(e)
	}
	qc13 := D4QC{Vote: D4VoteInfo{Round: 13, Epoch: 8, ParentRound: 12, Timestamp: 1700000000, CurrentRoot: g.Root}}
	D4SignQC(&qc13, keys, "n1", "n2", "n3")
	stale := D4Parent{Kind: D4OrdinaryParent, Epoch: 8, Round: 13, QC: &qc13}
	assertIs(t, b.CanVote(16, stale), ErrD4Proof)
	restarted := b.Restart()
	assertIs(t, restarted.CanVote(16, stale), ErrD4Proof)
}

func TestD4_TCIntervalRejectsWrongRoundAndEpoch(t *testing.T) {
	f := fixture(t)
	v := mustVerified(t, f.proof(t, 10), f.old)
	g, _ := DeriveEpochGenesis(v, f.body)
	newTB, keys := D4FixtureTrustBase(8, map[string]uint64{"n1": 1, "n2": 1, "n3": 1, "n4": 1})
	anchor := D4Parent{Kind: D4AnchorParent, GenesisID: g.ID(), Epoch: 8, Round: 12}
	for _, name := range []string{"before_start", "wrong_highqc_epoch"} {
		t.Run(name, func(t *testing.T) {
			tc := D4TimeoutCertificate{Epoch: 8, Round: 13, HighQC: anchor}
			if name == "before_start" {
				tc.Round = 12
			} else {
				tc.HighQC.Epoch = 7
			}
			D4SignTC(&tc, keys, "n1", "n2", "n3")
			assertIs(t, tc.Verify(newTB, g), ErrD4Epoch)
		})
	}
}
func TestD4_ConsumerEpochAndRound(t *testing.T) {
	f := fixture(t)
	v := mustVerified(t, f.proof(t, 100), f.old)
	for _, name := range []string{"shard", "ureth", "SealRegistry"} {
		t.Run(name, func(t *testing.T) {
			terminal := D4ShardUC{Shard: 1, Position: D4Position{7, 100}, Root: v.Root, InputRecord: []byte("IR-H"), SignerEpoch: 7, Valid: true}
			c := D4Consumer{OrderedRound: 10, Current: &terminal, History: []D4ShardUC{terminal}}
			old := terminal
			old.Position.Round = 101
			assertIs(t, c.Accept(old), ErrD4Unready)
			if c.TimeoutCount != 0 || c.RevertCount != 0 {
				t.Fatal("unclassified repeat triggered side effect")
			}
			c.Install(v)
			assertIs(t, c.Accept(old), ErrD4TerminalRepeat)
			c.Ready = true
			newUC := D4ShardUC{Shard: 1, Position: D4Position{8, 13}, Root: bytes.Repeat([]byte{0x91}, 32), InputRecord: []byte("IR-H"), ParentIR: []byte("IR-H"), SignerEpoch: 8, Valid: true}
			wrongParent := newUC
			wrongParent.ParentIR = []byte("other")
			assertIs(t, c.Accept(wrongParent), ErrD4Proof)
			if e := c.Accept(newUC); e != nil {
				t.Fatal(e)
			}
			outOfOrder := newUC
			outOfOrder.Position.Round = 12
			assertIs(t, c.Accept(outOfOrder), ErrD4Epoch)
			c = c.Restart()
			assertIs(t, c.Accept(old), ErrD4TerminalRepeat)
			if c.Current.Position != newUC.Position {
				t.Fatal("old UC replaced new")
			}
		})
	}
}

func TestD4_PositionLexicographic(t *testing.T) {
	if !(D4Position{7, 100}).Less(D4Position{8, 13}) || (D4Position{8, 13}).Less(D4Position{7, 100}) || !(D4Position{8, 13}).Less(D4Position{8, 14}) {
		t.Fatal("epoch-qualified root order was lost")
	}
}
func TestD4_ProofNegatives(t *testing.T) {
	f := fixture(t)
	cases := map[string]struct {
		mut  func(*HandoffProof)
		want error
	}{"record": {func(p *HandoffProof) { p.Record.Attempt++ }, ErrD4Record}, "ordered_round": {func(p *HandoffProof) { p.Record.OrderedRound++ }, ErrD4Record}, "body": {func(p *HandoffProof) { p.Record.NextBodyID[0] ^= 1 }, ErrD4Record}, "network": {func(p *HandoffProof) { p.Record.Network++ }, ErrD4Record}, "path_key": {func(p *HandoffProof) { p.ControlPath.Partition = 1 }, ErrD4Control}, "path_item_key": {func(p *HandoffProof) { p.ControlPath.HashSteps[0].Key = D4ControlPartition }, ErrD4Control}, "missing_leaf": {func(p *HandoffProof) { p.ControlPath = nil }, ErrD4Control}, "under_quorum": {func(p *HandoffProof) { delete(p.CommitQC.Signatures, "c") }, ErrD4Quorum}, "wrong_epoch": {func(p *HandoffProof) { p.CommitQC.Vote.Epoch++ }, ErrD4Proof}, "wrong_parent": {func(p *HandoffProof) { p.CommitQC.Vote.ParentRound-- }, ErrD4Proof}, "bad_timestamp": {func(p *HandoffProof) { p.CommitQC.Vote.Timestamp = 0 }, ErrD4Proof}, "noncommitting": {func(p *HandoffProof) { p.CommitQC.Seal.Commit.Round = 0 }, ErrD4Proof}, "genesis_exemption": {func(p *HandoffProof) { p.CommitQC.Signatures = nil }, ErrD4Quorum}, "forged_seal": {func(p *HandoffProof) { p.CommitQC.Seal.Commit.Root[0] ^= 1 }, ErrD4Proof}}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			p := f.proof(t, 10)
			tc.mut(&p)
			_, e := VerifyHandoff(p, f.old)
			assertIs(t, e, tc.want)
		})
	}
	p := f.proof(t, 10)
	root, _ := f.snapshot.Root()
	qcC := D4QC{Vote: D4VoteInfo{Round: 10, Epoch: 7, ParentRound: 9, Timestamp: 1699999999, CurrentRoot: root}}
	D4SignQC(&qcC, f.keys, "a", "b", "c")
	p.OptionalQC = &qcC
	_ = mustVerified(t, p, f.old)
	qcC.Signatures["a"][0] ^= 1
	_, e := VerifyHandoff(p, f.old)
	assertIs(t, e, ErrD4Proof)
	badTB := f.old
	badTB.Members = append(append([]D4Member(nil), f.old.Members...), f.old.Members[0])
	_, e = VerifyHandoff(f.proof(t, 10), badTB)
	assertIs(t, e, ErrD4Proof)
}

func TestD4_ProofRootBindingSignedWrongRoots(t *testing.T) {
	f := fixture(t)
	for _, name := range []string{"both_roots", "seal_root_only"} {
		t.Run(name, func(t *testing.T) {
			p := f.proof(t, 10)
			wrong := bytes.Repeat([]byte{0xee}, 32)
			p.CommitQC.Seal.Commit.Root = wrong
			if name == "both_roots" {
				p.CommitQC.Vote.CurrentRoot = bytes.Clone(wrong)
			}
			D4SignQC(&p.CommitQC, f.keys, "a", "b", "c")
			if e := p.CommitQC.Verify(f.old); e != nil {
				t.Fatal("wrong-root QC must still be validly signed", e)
			}
			_, e := VerifyHandoff(p, f.old)
			assertIs(t, e, ErrD4Proof)
		})
	}
}

func TestD4_FinalizeRefusesMissingAndForgedProof(t *testing.T) {
	f := fixture(t)
	h := &Handoff{Phase: PhaseCommitted, Record: f.record}
	assertIs(t, h.Finalize(HandoffProof{}, f.old), ErrD4Proof)
	forged := f.proof(t, 10)
	forged.CommitQC.Signatures["a"][0] ^= 1
	assertIs(t, h.Finalize(forged, f.old), ErrD4Proof)
	if h.Verified != nil {
		t.Fatal("forged finality installed")
	}
	if e := h.Finalize(f.proof(t, 10), f.old); e != nil {
		t.Fatal(e)
	}
	g, e := DeriveEpochGenesis(*h.Verified, f.body)
	if e != nil {
		t.Fatal(e)
	}
	if e := h.Activate(g, f.snapshot); e != nil || h.Phase != PhaseActivated {
		t.Fatal("verified checkpoint did not activate", e)
	}
}
func TestD4_MintedLateSuffixUC(t *testing.T) {
	f := fixture(t)
	v := mustVerified(t, f.proof(t, 10), f.old)
	for _, consumer := range []string{"shard", "ureth", "SealRegistry"} {
		t.Run(consumer, func(t *testing.T) {
			ordinary := D4Consumer{OrderedRound: 10, Current: &D4ShardUC{Shard: 1, Position: D4Position{7, 7}, InputRecord: []byte("IR-H")}}
			if e := ordinary.Accept(D4ShardUC{Shard: 1, Position: D4Position{7, 8}, Root: v.Root, InputRecord: []byte("IR-H"), SignerEpoch: 7, Valid: true}); e != nil || ordinary.TimeoutCount != 1 || ordinary.RevertCount != 1 {
				t.Fatal("ordinary old repeat did not exercise timeout/revert path", e)
			}
			c := D4Consumer{OrderedRound: 10, Current: &D4ShardUC{Shard: 1, Position: D4Position{7, 9}, InputRecord: []byte("IR-H")}}
			for _, round := range []uint64{10, 100, 1000} {
				uc := D4ShardUC{Shard: 1, Position: D4Position{7, round}, Root: v.Root, InputRecord: []byte("IR-H"), SignerEpoch: 7, Valid: true}
				assertIs(t, c.Accept(uc), ErrD4Unready)
				if c.TimeoutCount != 0 || c.RevertCount != 0 {
					t.Fatal("pre-install terminal repeat caused timeout or revert")
				}
			}
			c.Install(v)
			for _, round := range []uint64{10, 100, 1000} {
				uc := D4ShardUC{Shard: 1, Position: D4Position{7, round}, Root: v.Root, InputRecord: []byte("IR-H"), SignerEpoch: 7, Valid: true}
				assertIs(t, c.Accept(uc), ErrD4TerminalRepeat)
			}
			c.Ready = true
			c = c.Restart()
			if e := c.Accept(D4ShardUC{Shard: 1, Position: D4Position{8, 13}, Root: bytes.Repeat([]byte{0x91}, 32), InputRecord: []byte("IR-H"), ParentIR: []byte("IR-H"), SignerEpoch: 8, Valid: true}); e != nil {
				t.Fatal(e)
			}
			if c.TimeoutCount != 0 || c.RevertCount != 0 {
				t.Fatal("late suffix caused timeout or revert")
			}
		})
	}
}
func TestD4_DifferentCFixedStart(t *testing.T) {
	f := fixture(t)
	var id []byte
	for _, c := range []uint64{10, 100, 1000} {
		v := mustVerified(t, f.proof(t, c), f.old)
		g, e := DeriveEpochGenesis(v, f.body)
		if e != nil {
			t.Fatal(e)
		}
		if g.Start != 13 {
			t.Fatal("proof-dependent floor")
		}
		if id == nil {
			id = g.ID()
		} else if !bytes.Equal(id, g.ID()) {
			t.Fatal("genesis split")
		}
	}
	newTB, _ := D4FixtureTrustBase(8, map[string]uint64{"n1": 1, "n2": 1, "n3": 1, "n4": 1})
	for _, c := range []uint64{10, 100} {
		v := mustVerified(t, f.proof(t, c), f.old)
		g, _ := DeriveEpochGenesis(v, f.body)
		b := D4Bootstrap{}
		if e := b.Install(v, g, f.snapshot, newTB); e != nil {
			t.Fatal(e)
		}
		if e := b.Vote(13, b.HighestQC); e != nil || b.LastVoted != 13 {
			t.Fatal("split new validators chased old c", e)
		}
	}
}

func TestD4_OldSuffixProofCannotAuthorizeOrdinaryInterval(t *testing.T) {
	f := fixture(t)
	p := f.proof(t, 100)
	_ = mustVerified(t, p, f.old)
	assertIs(t, D4VerifyOrdinaryQC(p.CommitQC, f.old, 1, 13), ErrD4Epoch)
}
func TestD4_NextEpochCarryOver(t *testing.T) {
	s := D4DeferredShard{IR: []byte("ir"), TR: []byte("tr"), LastCR: []byte("last"), PendingConfig: []byte("next"), ActiveConfig: []byte("old"), FeeStats: []byte("fee"), IREpoch: 7, TREpoch: 8}
	before := s
	if e := s.NewEpochBlock(); e != nil {
		t.Fatal(e)
	}
	if s.IREpoch != 8 || string(s.ActiveConfig) != "next" || s.Changed || string(s.IR) != "ir" || string(s.TR) != "tr" || string(s.LastCR) != "last" || !bytes.Equal(s.FeeStats, append(before.FeeStats, 1)) {
		t.Fatal("nextEpoch carry-over mismatch")
	}
	again := s
	s.NewEpochBlock()
	if !reflect.DeepEqual(s, again) {
		t.Fatal("replay double-applied")
	}
	s.PayloadCertification([]byte("ir2"))
	if !s.Changed {
		t.Fatal("subsequent certification not changed")
	}
}
func TestD4_PayloadBearingRecoveredSuffix(t *testing.T) {
	f := fixture(t)
	parent := &D4BranchState{Control: &f.snapshot.Control, Shards: f.snapshot.Shards}
	_, e := RecoverOldSuffix(parent, D4Proposal{Epoch: 7, Round: 11, PayloadKind: "evm_tx"})
	assertIs(t, e, ErrD4Suffix)
}
func TestD4_MissingForgedControl(t *testing.T) {
	f := fixture(t)
	p := f.proof(t, 10)
	p.Control.RecordBytes = []byte("forged")
	_, e := VerifyHandoff(p, f.old)
	assertIs(t, e, ErrD4Record)
	p = f.proof(t, 10)
	p.Snapshot.Control = ControlState{}
	_, e = VerifyHandoff(p, f.old)
	assertIs(t, e, ErrD4Snapshot)
}
func TestD4_AnchorCommitRefused(t *testing.T) {
	f := fixture(t)
	v := mustVerified(t, f.proof(t, 10), f.old)
	g, _ := DeriveEpochGenesis(v, f.body)
	b := D4Bootstrap{}
	newTB, _ := D4FixtureTrustBase(8, map[string]uint64{"n1": 1, "n2": 1, "n3": 1, "n4": 1})
	b.Install(v, g, f.snapshot, newTB)
	assertIs(t, b.Commit(b.HighestQC, D4QC{}), ErrD4CommitAnchor)
}

func TestD4_AnchorVoteSealNoncommitting(t *testing.T) {
	f := fixture(t)
	v := mustVerified(t, f.proof(t, 10), f.old)
	g, _ := DeriveEpochGenesis(v, f.body)
	newTB, keys := D4FixtureTrustBase(8, map[string]uint64{"n1": 1, "n2": 1, "n3": 1, "n4": 1})
	b := D4Bootstrap{}
	if e := b.Install(v, g, f.snapshot, newTB); e != nil {
		t.Fatal(e)
	}
	anchor := b.HighestQC
	qc, e := b.BuildVoteQC(13, anchor, g.Root, 1700000001)
	if e != nil {
		t.Fatal(e)
	}
	if qc.Seal.Commit.Round != 0 || len(qc.Seal.Commit.Root) != 0 {
		t.Fatal("vote at A* claims an anchor commit")
	}
	D4SignQC(&qc, keys, "n1", "n2", "n3")
	if e := qc.Verify(newTB); e != nil {
		t.Fatal(e)
	}
	assertIs(t, b.Commit(anchor, qc), ErrD4CommitAnchor)
}

// Formula/illustrative: epoch flags stand in for historical UC signatures.
func TestD4_MixedHistoricalLastCR_Illustrative(t *testing.T) {
	ucs := []D4HistoricalUC{{Epoch: 6, Shard: 1, ValidForEpoch: 6}, {Epoch: 7, Shard: 2, ValidForEpoch: 7}}
	if e := VerifyHistoricalLastCR(ucs, map[uint64]bool{6: true, 7: true, 8: true}, 8); e != nil {
		t.Fatal(e)
	}
	assertIs(t, VerifyHistoricalLastCR(ucs, map[uint64]bool{8: true}, 8), ErrD4Proof)
}

// Formula/illustrative: durations are model event times, not runtime latency.
func TestD4_PauseMeasurement_Illustrative(t *testing.T) {
	normal := D4PauseMeasurement{time.Second, 2 * time.Second, 3 * time.Second, 4 * time.Second, 5 * time.Second, 6 * time.Second}
	crash := D4PauseMeasurement{time.Second, 4 * time.Second, 5 * time.Second, 7 * time.Second, 8 * time.Second, 9 * time.Second}
	for _, m := range []D4PauseMeasurement{normal, crash} {
		if !m.Valid() || m.Pause() <= 0 {
			t.Fatal(m)
		}
	}
}

// Formula/illustrative: replicas are constructed to probe the history checker.
func TestD4_CommittedHistoryInvariant_Illustrative(t *testing.T) {
	f := fixture(t)
	state := D4BranchState{Control: &f.snapshot.Control, Shards: f.snapshot.Shards}
	root, _ := f.snapshot.Root()
	a := D4Committed{Position: D4Position{7, 10}, Root: root, State: state, RecordID: f.record.ID()}
	replicas := []D4Replica{{ID: "a", Committed: []D4Committed{a}}, {ID: "b", Committed: []D4Committed{a}}}
	if e := ExploreCommittedHistories(replicas); e != nil {
		t.Fatal(e)
	}
	bad := a
	bad.Root = bytes.Repeat([]byte{0xee}, 32)
	replicas[1].Committed[0] = bad
	if e := ExploreCommittedHistories(replicas); e == nil {
		t.Fatal("different committed histories accepted")
	}
}

func TestD4_ExplorerGuardInvariants(t *testing.T) {
	f := fixture(t)
	v := mustVerified(t, f.proof(t, 100), f.old)
	g, e := DeriveEpochGenesis(v, f.body)
	if e != nil {
		t.Fatal(e)
	}
	newTB, _ := D4FixtureTrustBase(8, map[string]uint64{"n1": 1, "n2": 1, "n3": 1, "n4": 1})
	parent := D4BranchState{Control: &f.snapshot.Control, Shards: f.snapshot.Shards}
	if e := ExploreD4GuardInvariants(parent, v, g, newTB); e != nil {
		t.Fatal(e)
	}
}
func TestD4_VectorsMatchGolden(t *testing.T) {
	data, e := os.ReadFile("testdata/d4-vectors.json")
	if e != nil {
		t.Fatal(e)
	}
	var v D4VectorSet
	if e = json.Unmarshal(data, &v); e != nil {
		t.Fatal(e)
	}
	if v.Version != 2 || !reflect.DeepEqual(v.TraceCoverage, D4TraceNames()) || v.Crypto.Profile != 2 || v.Crypto.Scope != "model-crypto-only (Ed25519); runtime secp256k1 vectors are separate" || v.Crypto.ControlPartition != "ffffffff" {
		t.Fatal("v2 vector coverage mismatch")
	}
	for _, s := range []string{v.Crypto.RecordID, v.Crypto.ControlDigest, v.Crypto.Root, v.Crypto.VoteInfoHash, v.Crypto.GenesisID} {
		b, e := hex.DecodeString(s)
		if e != nil || len(b) != 32 {
			t.Fatalf("bad vector digest %q", s)
		}
	}
	if len(v.Crypto.Signatures) != 3 || len(v.Crypto.Path) == 0 {
		t.Fatal("missing real proof bytes")
	}
	f := fixture(t)
	p := f.proof(t, 10)
	verified := mustVerified(t, p, f.old)
	g, err := DeriveEpochGenesis(verified, f.body)
	if err != nil {
		t.Fatal(err)
	}
	checks := map[string][]byte{
		"record_cbor": p.Record.Bytes(), "record_id": p.Record.ID(),
		"control_cbor": p.Control.Bytes(), "control_digest": p.Control.Digest(),
		"shard_root": p.Snapshot.Shards[0].Root, "root": verified.Root,
		"vote_info_cbor": p.CommitQC.Vote.Bytes(), "vote_info_hash": p.CommitQC.Vote.Hash(),
		"ledger_commit_info_cbor": p.CommitQC.Seal.Commit.Bytes(p.CommitQC.Seal.PreviousHash), "seal_cbor": p.CommitQC.Seal.Bytes(),
		"genesis_cbor": g.Bytes(), "genesis_id": g.ID(),
		"pre_freeze_summary":     D4PreFreezeSummary(3, f.record.PredecessorBodyID, 1, 9, bytes.Repeat([]byte{0x88}, 32), bytes.Repeat([]byte{0x99}, 32)),
		"candidate_context_hash": D4CandidateContextHash(3, f.record.PredecessorBodyID, 1, bytes.Repeat([]byte{0xaa}, 32), 12),
	}
	encoded, _ := json.Marshal(v.Crypto)
	fields := map[string]json.RawMessage{}
	if err := json.Unmarshal(encoded, &fields); err != nil {
		t.Fatal(err)
	}
	for name, want := range checks {
		var got string
		if err := json.Unmarshal(fields[name], &got); err != nil {
			t.Fatal(err)
		}
		if got != hex.EncodeToString(want) {
			t.Fatalf("independent %s differs", name)
		}
	}
	for id, sig := range v.Crypto.Signatures {
		if sig != hex.EncodeToString(p.CommitQC.Signatures[id]) {
			t.Fatalf("signature %s differs", id)
		}
	}
	if len(v.Crypto.Path) != 2 || len(p.ControlPath.HashSteps) != 2 {
		t.Fatal("control path must have two independent steps")
	}
	for i, key := range []string{"00000003", "00000002"} {
		if v.Crypto.Path[i].Key != key || v.Crypto.Path[i].Hash != hex.EncodeToString(p.ControlPath.HashSteps[i].Hash) {
			t.Fatal("independent control path differs at step", i)
		}
	}
}

func TestD4_QCBytesMatchRootTypes(t *testing.T) {
	f := fixture(t)
	p := f.proof(t, 10)
	round := &drctypes.RoundInfo{Version: 1, RoundNumber: p.CommitQC.Vote.Round, Epoch: p.CommitQC.Vote.Epoch, Timestamp: p.CommitQC.Vote.Timestamp, ParentRoundNumber: p.CommitQC.Vote.ParentRound, CurrentRootHash: p.CommitQC.Vote.CurrentRoot}
	roundBytes, e := round.MarshalCBOR()
	if e != nil || !bytes.Equal(roundBytes, p.CommitQC.Vote.Bytes()) {
		t.Fatal("model VoteInfo differs from root RoundInfo CBOR", e)
	}
	roundHash, e := round.Hash(crypto.SHA256)
	if e != nil || !bytes.Equal(roundHash, p.CommitQC.Vote.Hash()) {
		t.Fatal("model VoteInfo hash differs", e)
	}
	l := p.CommitQC.Seal.Commit
	seal := &base.UnicitySeal{Version: 1, NetworkID: base.NetworkID(l.Network), RootChainRoundNumber: l.Round, Epoch: l.Epoch, Timestamp: l.Timestamp, PreviousHash: p.CommitQC.Seal.PreviousHash, Hash: l.Root}
	sealBytes, e := seal.SigBytes()
	if e != nil || !bytes.Equal(sealBytes, p.CommitQC.Seal.Bytes()) {
		t.Fatal("model seal signed bytes differ from UnicitySeal", e)
	}
}
func TestD4_ReservedControlNotShard(t *testing.T) {
	f := fixture(t)
	f.snapshot.Shards = append(f.snapshot.Shards, ShardSnapshot{Partition: D4ControlPartition, Root: bytes.Repeat([]byte{1}, 32)})
	_, e := f.snapshot.Root()
	assertIs(t, e, ErrD4Snapshot)
	_ = base.PartitionID(1)
}
