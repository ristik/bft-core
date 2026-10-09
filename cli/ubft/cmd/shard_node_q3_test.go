package cmd

import (
	"bytes"
	"context"
	"crypto"
	"crypto/sha256"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/engineapi"
	"github.com/unicitynetwork/bft-core/evmassign"
	"github.com/unicitynetwork/bft-core/evmroot"
	"github.com/unicitynetwork/bft-core/handoff"
	"github.com/unicitynetwork/bft-core/handoffdelivery"
	"github.com/unicitynetwork/bft-core/internal/testutils/q3fixture"
	"github.com/unicitynetwork/bft-core/internal/testutils/q3process"
	"github.com/unicitynetwork/bft-core/network/protocol/abdrc"
	"github.com/unicitynetwork/bft-core/q3format"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/votesig"
	"github.com/unicitynetwork/bft-go-base/types"
)

func TestTheShardSinkDelegatesInstallRestoreAndHoldsToTheNodesOwnInstall(t *testing.T) {
	f := q3fixture.New(t, q3fixture.Options{})
	held := map[uint64]bool{}
	var applied []uint64
	errNoCheckpoint := errors.New("no checkpoint")
	sink := &shardQ3Sink{
		verify: func(_ context.Context, e q3format.Entry, _ handoff.OldCommitProof, head *abdrc.CommittedBlock, _ []byte) error {
			if head == nil {
				return errNoCheckpoint
			}
			applied = append(applied, e.Epoch())
			held[e.Epoch()] = true
			return nil
		},
		holds: func(epoch uint64) bool { return held[epoch] },
	}
	// an entry only the history mints; the fixture's history yields it
	h, err := q3format.NewHistory(f.Old)
	require.NoError(t, err)
	h, err = h.VerifyEnvelope(f.Envelope)
	require.NoError(t, err)
	entry, err := h.ForEpoch(f.Claim.Epoch)
	require.NoError(t, err)

	require.ErrorIs(t, sink.HoldsVerifiedEpoch(entry), ErrQ3ShardEpoch, "nothing is held before the install")
	anchor, err := sink.InstallVerifiedEpoch(entry, f.Proof, f.Snapshot, nil)
	require.NoError(t, err)
	_, g, _ := entry.Handoff()
	require.Equal(t, g.ID(), anchor.GenesisID)
	require.Equal(t, g.Start-1, anchor.Slot)
	require.NoError(t, sink.HoldsVerifiedEpoch(entry))

	held = map[uint64]bool{} // a restart loses the state
	require.ErrorIs(t, sink.HoldsVerifiedEpoch(entry), ErrQ3ShardEpoch)
	require.NoError(t, sink.RestoreVerifiedEpoch(entry, f.Proof, f.Snapshot, nil))
	require.NoError(t, sink.HoldsVerifiedEpoch(entry))
	require.Equal(t, []uint64{f.Claim.Epoch, f.Claim.Epoch}, applied)

	_, err = sink.InstallVerifiedEpoch(entry, f.Proof, nil, nil)
	require.ErrorIs(t, err, errNoCheckpoint, "an install the node refuses reports no anchor")
}

func TestTheNextConfigurationIsTheCandidatesActivatedAssignmentOrTheUnchangedOne(t *testing.T) {
	active := make([]byte, 32)
	active[0] = 7
	got, err := q3NextConf(active, handoff.OldCommitProof{}, nil)
	require.NoError(t, err)
	require.Equal(t, active, got)
	got[0] = 9
	require.Equal(t, byte(7), active[0], "a copy, never the caller's slice")

	f := q3fixture.New(t, q3fixture.Options{Assignment: true})
	next, err := q3NextConf(active, f.Proof, f.Candidate)
	require.NoError(t, err)
	_, activated, err := evmassign.ActivatedFromPreimage(f.Candidate, f.Proof.Record.ActivationRound)
	require.NoError(t, err)
	want, err := activated.Hash(crypto.SHA256)
	require.NoError(t, err)
	require.Equal(t, want, next)
	require.NotEqual(t, active, next)

	_, err = q3NextConf(active, f.Proof, []byte("not a candidate"))
	require.ErrorIs(t, err, evmassign.ErrCandidate)
}

// installerFixture is a shard installer over a real activation (the fixture's old committee, checkpoint and candidate) whose node-side
// steps are recorded fakes.
type installerFixture struct {
	f       *q3fixture.Fixture
	entry   q3format.Entry
	head    *abdrc.CommittedBlock
	in      *shardQ3Installer
	calls   []string
	failAt  string
	raw     []byte
	epochs  []uint64
	failure error
}

func newInstallerFixture(t *testing.T, o q3fixture.Options) *installerFixture {
	t.Helper()
	f := q3fixture.New(t, o)
	h, err := q3format.NewHistory(f.Old)
	require.NoError(t, err)
	h, err = h.VerifyEnvelope(f.Envelope)
	require.NoError(t, err)
	entry, err := h.ForEpoch(f.Claim.Epoch)
	require.NoError(t, err)

	// the closing certificate of the shard, as the root's checkpoint carries it for the frozen parent
	head := *f.Snapshot
	head.ShardInfo = append([]abdrc.ShardInfo(nil), f.Snapshot.ShardInfo...)
	ir := *head.ShardInfo[0].IR
	head.ShardInfo[0].UC = &types.UnicityCertificate{InputRecord: &ir}

	conf, err := f.ShardConf.Hash(crypto.SHA256)
	require.NoError(t, err)
	x := &installerFixture{f: f, entry: entry, head: &head}
	step := func(name string, err ...error) error {
		x.calls = append(x.calls, name)
		if x.failAt == name {
			return x.failure
		}
		return nil
	}
	x.in = &shardQ3Installer{Partition: q3fixture.PartitionID, Shard: types.ShardID{}, AnchorEpoch: 1, AnchorConf: conf,
		Trust: func(_ context.Context, epoch uint64) (*types.RootTrustBaseV1, error) {
			require.EqualValues(t, 1, epoch)
			return f.Old, nil
		},
		Signing: func(epoch uint64) (votesig.Config, error) { return votesig.Config{Scheme: votesig.SchemeLegacy}, nil },
		Terminal: func(_ context.Context, v handoffdelivery.Verified) error {
			require.NotNil(t, v.Shard.UC)
			return step("terminal")
		},
		Transition: func(_ handoffdelivery.Bundle, _ handoffdelivery.Verified, epoch uint64) error {
			require.Equal(t, f.Claim.Epoch, epoch)
			return step("transition")
		},
		InstallAssignment: func(view handoffdelivery.Bundle, s handoff.AssignmentStep) error {
			require.Equal(t, o.Assignment, s.Assignment)
			require.Equal(t, f.Candidate, view.Candidate)
			return step("assignment")
		},
		NoteJoiner:           func(handoffdelivery.Bundle, handoff.AssignmentStep) error { return step("joiner") },
		InstallEVMTransition: func(raw []byte) error { x.raw = raw; return step("evm-transition") },
		Activate:             func(epoch uint64) error { x.epochs = append(x.epochs, epoch); return step("activate") },
		Log:                  func(uint64) { x.calls = append(x.calls, "log") },
	}
	return x
}

func (x *installerFixture) apply(candidate []byte) error {
	return x.in.Apply(context.Background(), x.entry, x.f.Proof, x.head, candidate)
}

var installerOrder = []string{"terminal", "transition", "assignment", "joiner", "evm-transition", "activate", "log"}

func TestTheShardInstallerAppliesAVerifiedActivationInOrderAndActivatesLast(t *testing.T) {
	for name, o := range map[string]q3fixture.Options{"root-only": {}, "coupled": {Assignment: true}} {
		x := newInstallerFixture(t, o)
		require.NoError(t, x.apply(x.f.Candidate), name)
		require.Equal(t, installerOrder, x.calls, name)
		tr, err := handoff.DecodeEVMTransition(x.raw)
		require.NoError(t, err, name)
		require.Equal(t, x.f.Claim.Epoch, tr.NewRootEpoch, name)
		require.EqualValues(t, 1, tr.OldRootEpoch, name)
		require.Equal(t, []uint64{x.f.Claim.Epoch}, x.epochs, name)
	}
}

func TestEachNodeSideStepThatFailsStopsTheInstallBeforeTheEpochIsActive(t *testing.T) {
	boom := errors.New("node refused")
	for i, failing := range installerOrder[:6] { // every step up to and including activate
		x := newInstallerFixture(t, q3fixture.Options{Assignment: true})
		x.failAt, x.failure = failing, boom
		err := x.apply(x.f.Candidate)
		require.ErrorIs(t, err, boom, failing)
		require.Equal(t, installerOrder[:i+1], x.calls, "%s: nothing after the failed step runs", failing)
		if failing != "activate" {
			require.Empty(t, x.epochs, "%s: the epoch is not active", failing)
		}
	}
}

func TestTheShardInstallerRefusesWhatTheOldCommitteesCommitDoesNotAuthenticate(t *testing.T) {
	noneCalled := func(t *testing.T, x *installerFixture) { require.Empty(t, x.calls, "no node-side step runs") }

	x := newInstallerFixture(t, q3fixture.Options{Assignment: true})
	x.in.AnchorEpoch = 5 // the configuration of the epoch this activation replaces is not known
	require.ErrorIs(t, x.apply(x.f.Candidate), ErrQ3ShardEpoch)
	noneCalled(t, x)

	x = newInstallerFixture(t, q3fixture.Options{Assignment: true})
	other := q3fixture.New(t, q3fixture.Options{Chain: x.f, Weights: []uint64{5, 2, 1, 1}})
	require.NotEqual(t, x.f.Proof.Record.ID(), other.Proof.Record.ID())
	require.ErrorIs(t, x.in.Apply(context.Background(), x.entry, other.Proof, x.head, x.f.Candidate), ErrQ3ShardEpoch, "a proof of another record than the one that activated the epoch")
	noneCalled(t, x)

	x = newInstallerFixture(t, q3fixture.Options{Assignment: true})
	x.in.AnchorConf = bytes.Repeat([]byte{9}, 32) // a checkpoint of another shard configuration than the one followed
	require.ErrorIs(t, x.apply(x.f.Candidate), handoffdelivery.ErrBundle)
	noneCalled(t, x)

	x = newInstallerFixture(t, q3fixture.Options{Assignment: true})
	x.head.ShardInfo[0].UC = nil // no closing certificate
	require.ErrorIs(t, x.apply(x.f.Candidate), ErrHandoffTerminalCertificate)
	noneCalled(t, x)

	x = newInstallerFixture(t, q3fixture.Options{Assignment: true})
	unknownEpoch := errors.New("epoch unknown")
	x.in.Trust = func(context.Context, uint64) (*types.RootTrustBaseV1, error) { return nil, unknownEpoch }
	require.ErrorIs(t, x.apply(x.f.Candidate), unknownEpoch)
	noneCalled(t, x)

	x = newInstallerFixture(t, q3fixture.Options{Assignment: true})
	noScheme := errors.New("no scheme")
	x.in.Signing = func(uint64) (votesig.Config, error) { return votesig.Config{}, noScheme }
	require.ErrorIs(t, x.apply(x.f.Candidate), noScheme)
	noneCalled(t, x)
}

// A restart applies every finished activation again: the same epoch twice is the same install, and an epoch re-applied with another
// configuration is refused rather than overwriting what was installed.
func TestTheShardInstallerIsIdempotentAndRefusesAConflictingReapply(t *testing.T) {
	x := newInstallerFixture(t, q3fixture.Options{Assignment: true})
	require.NoError(t, x.apply(x.f.Candidate))
	require.NoError(t, x.apply(x.f.Candidate), "the same activation applied again")
	require.Equal(t, append(append([]string{}, installerOrder...), installerOrder...), x.calls)

	before := len(x.calls)
	require.ErrorIs(t, x.apply(nil), ErrQ3Candidate, "the same epoch with the assignment dropped")
	require.Len(t, x.calls, before, "and nothing is installed")
}

// The delivered candidate is authenticated against the verified entry before anything is installed from it: each substitution below keeps the
// old committee's commit, the checkpoint and the predecessor valid, differs from the genuine candidate in one thing, and is refused with its own
// sentinel and no node-side step.
func TestTheShardInstallerRefusesACandidateThatIsNotTheOneTheBodyBinds(t *testing.T) {
	refused := func(name string, candidate func(x *installerFixture) []byte) {
		t.Helper()
		x := newInstallerFixture(t, q3fixture.Options{Assignment: true})
		err := x.apply(candidate(x))
		require.ErrorIs(t, err, ErrQ3Candidate, name)
		require.Empty(t, x.calls, "%s: nothing is installed", name)
		require.Empty(t, x.epochs, name)
	}
	refused("an assignment with other weights and valid proofs of possession", func(x *installerFixture) []byte {
		other := q3fixture.New(t, q3fixture.Options{Chain: x.f, Assignment: true, EVMWeights: []uint64{5, 2, 1, 1}, CandidateRootWeights: []uint64{5, 2, 1, 1}})
		require.NotEqual(t, x.f.Candidate, other.Candidate)
		return other.Candidate
	})
	refused("the assignment dropped from a coupled handoff", func(*installerFixture) []byte { return nil })
	refused("a preimage with one byte changed", func(x *installerFixture) []byte {
		c := bytes.Clone(x.f.Candidate)
		c[len(c)-1] ^= 1
		return c
	})
	// a candidate whose own digest, assignment and coupling are consistent (so the change record binds it) but whose committee is not the body's
	x := newInstallerFixture(t, q3fixture.Options{Assignment: true, EVMWeights: []uint64{5, 2, 1, 1}, CandidateRootWeights: []uint64{5, 2, 1, 1}})
	err := x.apply(x.f.Candidate)
	require.ErrorIs(t, err, ErrQ3Candidate)
	require.ErrorContains(t, err, "is not the body's")
	require.Empty(t, x.calls)
	// a candidate for a root-only entry: an assignment the body never bound
	root := newInstallerFixture(t, q3fixture.Options{})
	coupled := q3fixture.New(t, q3fixture.Options{Chain: root.f, Assignment: true})
	require.ErrorIs(t, root.apply(coupled.Candidate), ErrQ3Candidate)
	require.Empty(t, root.calls)
}

type fakeAdmitter struct {
	err   error
	calls int
}

func (f *fakeAdmitter) AdmitHead(context.Context) error { f.calls++; return f.err }

func TestTheNodeRefusesToStartOnAnExecutionHeadItCouldNotAdmit(t *testing.T) {
	ok := &fakeAdmitter{}
	require.NoError(t, admitRestartedHead(context.Background(), ok))
	require.Equal(t, 1, ok.calls)

	cause := errors.New("the retained input is not this node's derivation")
	err := admitRestartedHead(context.Background(), &fakeAdmitter{err: cause})
	require.ErrorIs(t, err, cause)
	require.ErrorContains(t, err, "restart admission of the execution client's head")
}

func TestThePairConfigPinsTheHistoryAndNamesTheVerifiedActivations(t *testing.T) {
	f := q3fixture.New(t, q3fixture.Options{})
	p := q3process.New(t, f)
	rt := p.Start()
	require.NoError(t, rt.Recover(context.Background()))
	genesis := [32]byte{0x52, 31: 0x52}
	cfg := q3PairConfig(rt, 5, genesis)
	require.EqualValues(t, 5, cfg.Pins.NetworkID)
	require.Equal(t, rt.History().Genesis(), cfg.Pins.RootGenesisID, "the history's genesis, never one a client reports")
	require.Equal(t, genesis, cfg.ExecutionGenesis)
	_, ok := cfg.ActivationID(f.Claim.Epoch)
	require.False(t, ok, "no activation before it is installed")

	require.NoError(t, rt.Activate(context.Background(), p.Bundle()))
	id, ok := cfg.ActivationID(f.Claim.Epoch)
	require.True(t, ok)
	require.Equal(t, f.Claim.CommitID, id, "the activation's commit identity")
	_, ok = cfg.ActivationID(1)
	require.False(t, ok, "the genesis epoch has no activation commit")
}

// The node's construction: a lane shard node turns the binding on in its real adapter from its own verified runtime and gets the adapter's
// restart admission back; anything that cannot carry the binding, or has no checked origin to anchor it, is refused.
func TestTheLaneNodeWiresThePairIntoItsAdapterAndRefusesWhatCannotCarryIt(t *testing.T) {
	f := q3fixture.New(t, q3fixture.Options{})
	rt := q3process.New(t, f).Start()
	full, path, _ := preparedGenesisFixtureAt(t, 1337, 3)
	origin, _, err := loadGenesisOrigin(full, path, "", 3)
	require.NoError(t, err)

	adapter := engineapi.NewAdapter(engineapi.Config{EngineURL: "http://127.0.0.1:1", EthURL: "http://127.0.0.1:1"}, nil)
	require.False(t, adapter.PairEnabled(), "off until the node wires it")
	admit, err := wireQ3Pair(adapter, rt, 3, origin.Valid(), [32]byte(origin.BlockHash()))
	require.NoError(t, err)
	require.True(t, adapter.PairEnabled())
	require.Same(t, adapter, admit, "the restart admission is the adapter's own")

	other := engineapi.NewAdapter(engineapi.Config{EngineURL: "http://127.0.0.1:1", EthURL: "http://127.0.0.1:1"}, nil)
	_, err = wireQ3Pair(other, rt, 3, false, [32]byte{})
	require.ErrorIs(t, err, ErrQ3Pair, "no checked origin")
	require.False(t, other.PairEnabled(), "and nothing is enabled")
	_, err = wireQ3Pair(struct{}{}, rt, 3, origin.Valid(), [32]byte(origin.BlockHash()))
	require.ErrorIs(t, err, ErrQ3Pair, "an executor that cannot carry the binding")
}

// A staged successor assignment's members are announced to the node's archive authorization, so a joiner can catch up before its own
// readiness; a refused stage announces nothing, and a root-only change (no preimage) names no EVM node.
func TestStagingAnnouncesTheSuccessorAssignmentsMembers(t *testing.T) {
	f := q3fixture.New(t, q3fixture.Options{Assignment: true})
	c, err := evmassign.DecodeCandidate(f.Candidate)
	require.NoError(t, err)
	var want []string
	for _, id := range c.Identities {
		want = append(want, id.EVMNodeID)
	}
	require.NotEmpty(t, want)

	var got [][]string
	st := &shardQ3Staging{onStaged: func(ids []string) error { got = append(got, ids); return nil }}
	require.NoError(t, st.announceStaged(shardQ3StageRequest{Preimage: f.Candidate}))
	require.Equal(t, [][]string{want}, got)

	require.NoError(t, st.announceStaged(shardQ3StageRequest{}))
	require.Len(t, got, 1, "a root-only change names no EVM node")

	require.ErrorIs(t, st.announceStaged(shardQ3StageRequest{Preimage: f.Candidate[:len(f.Candidate)-1]}), ErrQ3StageBody, "an undecodable preimage")
	require.Len(t, got, 1)

	// a refused stage (a digest that is not 32 bytes) never reaches the announcement
	refusing := &shardQ3Staging{cfg: func() (q3format.ProtocolConfig, error) { return q3format.ProtocolConfig{}, nil }, onStaged: func([]string) error { got = append(got, nil); return nil }}
	require.ErrorIs(t, refusing.Stage(shardQ3StageRequest{Candidate: []byte{1}, Preimage: f.Candidate}), ErrQ3StageDigest)
	require.Len(t, got, 1)

	// the hook's refusal refuses the stage's announcement
	boom := errors.New("boom")
	failing := &shardQ3Staging{onStaged: func([]string) error { return boom }}
	require.ErrorIs(t, failing.announceStaged(shardQ3StageRequest{Preimage: f.Candidate}), boom)
}

// The shard node's staging is wired to the active peers' stage in production: a stage that announces nothing would leave a joiner that is
// behind unable to catch up (the archive refuses it until its assignment is installed).
func TestShardNodeRunWiresStagingToTheActivePeers(t *testing.T) {
	file, err := parser.ParseFile(token.NewFileSet(), "shard_node_run.go", nil, 0)
	require.NoError(t, err)
	var wired string
	ast.Inspect(file, func(n ast.Node) bool {
		lit, ok := n.(*ast.CompositeLit)
		if !ok {
			return true
		}
		if id, ok := lit.Type.(*ast.Ident); !ok || id.Name != "shardQ3Staging" {
			return true
		}
		for _, e := range lit.Elts {
			kv, ok := e.(*ast.KeyValueExpr)
			if !ok || kv.Key.(*ast.Ident).Name != "onStaged" {
				continue
			}
			sel, ok := kv.Value.(*ast.SelectorExpr)
			require.True(t, ok)
			wired = sel.X.(*ast.Ident).Name + "." + sel.Sel.Name
		}
		return true
	})
	require.Equal(t, "activePeers.Stage", wired)
}

// stageFixture is a staging node whose checkStaged runs in full (a tip and a self are set) and a request that passes it: the coupled
// candidate of the Q3 fixture, a body that is the tip's successor with the change record the digest and attempt determine, naming self.
type stageFixture struct {
	st      *shardQ3Staging
	good    shardQ3StageRequest
	body    q3format.BodyV3
	tipID   [32]byte
	tip     [3]uint64
	members []string
	called  *[][]string
}

func newStageFixture(t *testing.T) stageFixture {
	t.Helper()
	f := q3fixture.New(t, q3fixture.Options{Assignment: true})
	c, err := evmassign.DecodeCandidate(f.Candidate)
	require.NoError(t, err)
	var members []string
	for _, id := range c.Identities {
		members = append(members, id.EVMNodeID)
	}
	require.GreaterOrEqual(t, len(members), 2)
	digest := sha256.Sum256(f.Candidate)
	tipID := [32]byte{7}
	tipEpoch, tipVersion := uint64(4), uint64(1)
	body := f.Body
	body.Epoch = tipEpoch + 1
	prior, err := q3format.Prior{Network: body.Network, Epoch: tipEpoch, BodyVersion: tipVersion, Identity: tipID[:]}.Hash()
	require.NoError(t, err)
	body.PredecessorHash = prior
	body.ChangeRecordHash = evmroot.D4CandidateContextHash(body.Network, tipID[:], 1, digest[:], body.EarliestActivation)
	var called [][]string
	st := &shardQ3Staging{
		cfg:      func() (q3format.ProtocolConfig, error) { return body.Config, nil },
		tip:      func() (uint64, uint64, [32]byte, error) { return tipEpoch, tipVersion, tipID, nil },
		self:     members[0],
		onStaged: func(ids []string) error { called = append(called, ids); return nil },
	}
	return stageFixture{st: st, body: body, tipID: tipID, tip: [3]uint64{tipEpoch, tipVersion}, members: members, called: &called,
		good: shardQ3StageRequest{Body: body.Encode(), Candidate: digest[:], Preimage: f.Candidate, Attempt: 1}}
}

// Through Stage with the checks running in full, each refusal differs from the accepted stage in one thing, carries its sentinel, and never
// reaches the announcement (a refused candidate grants no archive or journal access: both authorize through ActivePeers, which only the
// announcement writes). The control is the accepted stage: it announces its successor members and is recorded.
func TestARefusedStageNeverAnnouncesItsMembers(t *testing.T) {
	x := newStageFixture(t)
	refused := func(name string, req shardQ3StageRequest, want error) {
		t.Helper()
		before := len(*x.called)
		err := x.st.Stage(req)
		require.ErrorIs(t, err, want, name)
		require.Len(t, *x.called, before, "%s: a refused stage announced its members", name)
		status, serr := x.st.status()
		require.NoError(t, serr)
		require.Nil(t, status.Staged, "%s: nothing is staged", name)
	}

	wrongPreimage := x.good
	wrongPreimage.Preimage = append(bytes.Clone(x.good.Preimage), 0)
	refused("preimage is not the candidate", wrongPreimage, ErrQ3StageDigest)

	notSuccessor := x.body
	notSuccessor.PredecessorHash = bytes.Repeat([]byte{0xee}, len(x.body.PredecessorHash))
	req := x.good
	req.Body = notSuccessor.Encode()
	refused("body is not the tip's successor", req, ErrQ3StageChain)

	badRecord := x.body
	badRecord.ChangeRecordHash = bytes.Repeat([]byte{0xdd}, len(x.body.ChangeRecordHash))
	req = x.good
	req.Body = badRecord.Encode()
	refused("change record mismatch", req, ErrQ3StageBody)

	otherCalled := 0
	other := &shardQ3Staging{cfg: x.st.cfg, tip: x.st.tip, self: "not-a-member-of-the-successor", onStaged: func([]string) error { otherCalled++; return nil }}
	require.ErrorIs(t, other.Stage(x.good), ErrQ3StageBody, "the successor assignment does not name this node")
	require.Zero(t, otherCalled)

	attempt := x.good
	attempt.Attempt = 2 // the change record binds the attempt
	refused("a different attempt than the change record binds", attempt, ErrQ3StageBody)

	// the control: the unchanged request is accepted, announces exactly the successor's members once, and is recorded
	require.NoError(t, x.st.Stage(x.good))
	require.Equal(t, [][]string{x.members}, *x.called)
	status, err := x.st.status()
	require.NoError(t, err)
	require.NotNil(t, status.Staged)
}

// A failing announcement fails the stage with its error and records nothing: a stage whose grant could not be applied is not a staged
// candidate.
func TestAFailingAnnouncementFailsTheStageAndLeavesItUnstaged(t *testing.T) {
	x := newStageFixture(t)
	boom := errors.New("boom")
	x.st.onStaged = func([]string) error { return boom }
	require.ErrorIs(t, x.st.Stage(x.good), boom)
	status, err := x.st.status()
	require.NoError(t, err)
	require.Nil(t, status.Staged, "a stage whose announcement failed is not staged")
}
