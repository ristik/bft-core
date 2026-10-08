package handoffdelivery

import (
	"bytes"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/evmassign"
	"github.com/unicitynetwork/bft-core/internal/testutils/handoffbundle"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/votesig"
	"github.com/unicitynetwork/bft-go-base/types"
)

type fakeHistory struct {
	old      *types.RootTrustBaseV1
	confHash []byte
	ids      []evmassign.Identity
	assign   [32]byte
	tbErr    error
	asgErr   error
	rounds   []uint64
	epochs   []uint64
}

func (h *fakeHistory) TrustBase(epoch uint64) (*types.RootTrustBaseV1, votesig.Config, error) {
	h.epochs = append(h.epochs, epoch)
	return h.old, votesig.Config{Scheme: votesig.SchemeLegacy}, h.tbErr
}
func (h *fakeHistory) Assignment(round uint64) ([]byte, []evmassign.Identity, [32]byte, error) {
	h.rounds = append(h.rounds, round)
	return h.confHash, h.ids, h.assign, h.asgErr
}

func closureFixture(t *testing.T) (handoffbundle.Fixture, Bundle, *fakeHistory, ClosureVerifier) {
	f := handoffbundle.New(t)
	b := Bundle{Proof: f.Proof, Body: f.Body, Snapshot: f.Snapshot}
	h := &fakeHistory{old: f.Old, confHash: f.ConfHash, ids: []evmassign.Identity{{Weight: 1}}, assign: [32]byte{0xa5}}
	return f, b, h, ClosureVerifier{Partition: f.Partition, Shard: f.Shard, History: h}
}

func TestClosureVerifierEstablishesTheFactsOfAVerifiedTerminalBundle(t *testing.T) {
	f, b, h, v := closureFixture(t)
	raw, err := EncodeBundle(b)
	require.NoError(t, err)
	ev, err := v.Verify(raw, f.Proof.Record.Epoch)
	require.NoError(t, err)
	want, err := SemanticIdentity(b)
	require.NoError(t, err)
	require.Equal(t, want, ev.BundleID)
	require.Equal(t, f.Proof.Record.Epoch, ev.ClosedEpoch)
	require.Equal(t, f.Proof.Record.OrderedRound, ev.HRound)
	require.Equal(t, [32]byte{0xa5}, ev.AssignmentID)
	require.Equal(t, h.ids, ev.Closed)
	require.Equal(t, [32]byte(b.Snapshot.CommitQc.LedgerCommitInfo.Hash), ev.TerminalRoot, "the root the commit certificate seals")
	require.Equal(t, [32]byte(f.Proof.Record.ID()), ev.HRecordID, "the committed record's identifier")
	require.Equal(t, []uint64{f.Proof.Record.Epoch}, h.epochs, "the trust base asked for is the closed epoch's")
	require.Equal(t, []uint64{f.Proof.Record.OrderedRound}, h.rounds, "the configuration is the one installed when H was ordered")
}

func TestClosureVerifierRefusals(t *testing.T) {
	boom := errors.New("history unavailable")
	cases := map[string]func(t *testing.T, f handoffbundle.Fixture, b *Bundle, h *fakeHistory, epoch *uint64) (raw []byte){
		"a different closed epoch": func(t *testing.T, f handoffbundle.Fixture, b *Bundle, h *fakeHistory, e *uint64) []byte {
			*e++
			return nil
		},
		"no trust base for the epoch": func(t *testing.T, f handoffbundle.Fixture, b *Bundle, h *fakeHistory, e *uint64) []byte {
			h.tbErr = boom
			return nil
		},
		"no assignment at that round": func(t *testing.T, f handoffbundle.Fixture, b *Bundle, h *fakeHistory, e *uint64) []byte {
			h.asgErr = boom
			return nil
		},
		"another shard configuration": func(t *testing.T, f handoffbundle.Fixture, b *Bundle, h *fakeHistory, e *uint64) []byte {
			h.confHash = bytes.Repeat([]byte{7}, 32)
			return nil
		},
		"another committee's signatures": func(t *testing.T, f handoffbundle.Fixture, b *Bundle, h *fakeHistory, e *uint64) []byte {
			other := handoffbundle.New(t)
			h.old = other.Old
			return nil
		},
		"a proof without signatures": func(t *testing.T, f handoffbundle.Fixture, b *Bundle, h *fakeHistory, e *uint64) []byte {
			b.Proof.CommitQC.Signatures = nil
			return nil
		},
		"a snapshot that is not the committed one": func(t *testing.T, f handoffbundle.Fixture, b *Bundle, h *fakeHistory, e *uint64) []byte {
			b.Snapshot.CommitQc.LedgerCommitInfo.Hash[0] ^= 1
			return nil
		},
		"bytes that are not a bundle": func(t *testing.T, f handoffbundle.Fixture, b *Bundle, h *fakeHistory, e *uint64) []byte {
			return []byte{1, 2, 3}
		},
		"non-canonical bundle bytes": func(t *testing.T, f handoffbundle.Fixture, b *Bundle, h *fakeHistory, e *uint64) []byte {
			raw, err := EncodeBundle(*b)
			require.NoError(t, err)
			return append(raw, 0)
		},
	}
	for name, mut := range cases {
		t.Run(name, func(t *testing.T) {
			f, b, h, v := closureFixture(t)
			epoch := f.Proof.Record.Epoch
			raw := mut(t, f, &b, h, &epoch)
			if raw == nil {
				var err error
				raw, err = EncodeBundle(b)
				require.NoError(t, err)
			}
			_, err := v.Verify(raw, epoch)
			require.ErrorIs(t, err, ErrClosure)
			if name == "no trust base for the epoch" || name == "no assignment at that round" {
				require.ErrorIs(t, err, boom)
			}
		})
	}
}
