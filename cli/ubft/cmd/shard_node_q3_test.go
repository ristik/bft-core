package cmd

import (
	"bytes"
	"context"
	"crypto"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/evmassign"
	"github.com/unicitynetwork/bft-core/handoff"
	"github.com/unicitynetwork/bft-core/handoffdelivery"
	"github.com/unicitynetwork/bft-core/internal/testutils/q3fixture"
	"github.com/unicitynetwork/bft-core/network/protocol/abdrc"
	"github.com/unicitynetwork/bft-core/q3format"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/votesig"
	"github.com/unicitynetwork/bft-go-base/types"
)

func TestTheShardSinkDelegatesInstallRestoreAndHoldsToTheNodesOwnInstall(t *testing.T) {
	f := q3fixture.New(t, q3fixture.Options{})
	held := map[uint64]bool{}
	var applied []uint64
	sink := &shardQ3Sink{
		verify: func(_ context.Context, e q3format.Entry, _ handoff.OldCommitProof, head *abdrc.CommittedBlock, _ []byte) error {
			if head == nil {
				return errors.New("no checkpoint")
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
	require.Error(t, sink.HoldsVerifiedEpoch(entry))
	require.NoError(t, sink.RestoreVerifiedEpoch(entry, f.Proof, f.Snapshot, nil))
	require.NoError(t, sink.HoldsVerifiedEpoch(entry))
	require.Equal(t, []uint64{f.Claim.Epoch, f.Claim.Epoch}, applied)

	_, err = sink.InstallVerifiedEpoch(entry, f.Proof, nil, nil)
	require.Error(t, err, "an install the node refuses reports no anchor")
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
	require.Error(t, err)
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
	x.in.Trust = func(context.Context, uint64) (*types.RootTrustBaseV1, error) { return nil, errors.New("epoch unknown") }
	require.Error(t, x.apply(x.f.Candidate))
	noneCalled(t, x)

	x = newInstallerFixture(t, q3fixture.Options{Assignment: true})
	x.in.Signing = func(uint64) (votesig.Config, error) { return votesig.Config{}, errors.New("no scheme") }
	require.Error(t, x.apply(x.f.Candidate))
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
	require.ErrorIs(t, x.apply(nil), ErrQ3ShardEpoch, "the same epoch with a configuration that does not change the assignment")
	require.Len(t, x.calls, before, "and nothing is installed")
}
