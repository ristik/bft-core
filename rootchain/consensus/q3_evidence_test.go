package consensus

import (
	"context"
	"crypto/sha256"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/evmroot"
	"github.com/unicitynetwork/bft-core/internal/testutils/q3fixture"
	"github.com/unicitynetwork/bft-core/internal/testutils/q3process"
	"github.com/unicitynetwork/bft-core/network/protocol/abdrc"
	"github.com/unicitynetwork/bft-core/q3format"
	basetypes "github.com/unicitynetwork/bft-go-base/types"
)

// fixtureSource retains what the block store retains after it admitted the Freeze and committed the handoff.
type fixtureSource struct {
	head       *abdrc.CommittedBlock
	path       *basetypes.UnicityTreeCertificate
	record     evmroot.OrderedHandoffRecord
	body       []byte
	receipts   []byte
	candidate  []byte
	checkpoint error
}

func (s fixtureSource) HandoffCheckpoint() (*abdrc.CommittedBlock, *basetypes.UnicityTreeCertificate, evmroot.OrderedHandoffRecord, error) {
	return s.head, s.path, s.record, s.checkpoint
}
func (s fixtureSource) HandoffBody([]byte) ([]byte, error)      { return s.body, nil }
func (s fixtureSource) HandoffReceipts([]byte) ([]byte, error)  { return s.receipts, nil }
func (s fixtureSource) HandoffCandidate([]byte) ([]byte, error) { return s.candidate, nil }

func sourceOf(t *testing.T, f *q3fixture.Fixture) fixtureSource {
	t.Helper()
	receipts, err := q3format.EncodeReceipts(f.Receipts)
	require.NoError(t, err)
	return fixtureSource{head: f.Snapshot, path: f.Proof.ControlPath, record: f.Proof.Record, body: f.Body.Encode(), receipts: receipts, candidate: f.Candidate}
}

// The evidence a validator assembles from its own committed tip is exactly the link the verified history authenticates: it installs through
// the journal, root-only and coupled alike. Each refusal differs from the control in one thing.
func TestTheActivationEvidenceOfACommittedHandoffIsTheLinkTheHistoryAuthenticates(t *testing.T) {
	for name, opts := range map[string]q3fixture.Options{"root-only": {}, "coupled": {Assignment: true}} {
		f := q3fixture.New(t, opts)
		link, head, candidate, err := q3ActivationEvidence(sourceOf(t, f), f.Claim.Epoch)
		require.NoError(t, err, name)
		require.Equal(t, f.Evidence, link.Evidence, name)
		require.Equal(t, f.ProofBytes, link.Proof, name+": the commit proof is the retained record, control state, path and QC")
		require.Equal(t, f.Receipts, link.Receipts, name)
		require.Equal(t, f.Body.Encode(), link.Body.Encode(), name)
		require.Equal(t, f.Candidate, candidate, name)
		require.Same(t, f.Snapshot, head, name)
		if opts.Assignment {
			sum := sha256.Sum256(f.Candidate)
			require.Equal(t, sum[:], link.Evidence.CandidateDigest, name+": the digest of the preimage")
		} else {
			require.Empty(t, candidate)
		}

		if !opts.Assignment { // the process fakes install a root-only activation
			p := q3process.New(t, f)
			rt := p.Start()
			bundle, err := rt.BundleFor(link, head, candidate)
			require.NoError(t, err, name)
			require.NoError(t, rt.Recover(context.Background()))
			require.NoError(t, rt.Activate(context.Background(), bundle), name)
			require.NoError(t, rt.Admit(f.Claim.Epoch), name)
		}
	}
}

func TestTheActivationEvidenceRefusesWhatIsNotTheCommittedV3Handoff(t *testing.T) {
	f := q3fixture.New(t, q3fixture.Options{})
	good := sourceOf(t, f)
	refused := func(name string, mutate func(*fixtureSource), epoch uint64) {
		t.Helper()
		s := good
		mutate(&s)
		_, _, _, err := q3ActivationEvidence(s, epoch)
		require.ErrorIs(t, err, ErrNoQ3Evidence, name)
	}
	refused("another successor epoch than the checkpoint's", func(*fixtureSource) {}, f.Claim.Epoch+1)
	refused("no committed checkpoint", func(s *fixtureSource) { s.checkpoint = errors.New("none") }, f.Claim.Epoch)
	refused("a checkpoint without its control state", func(s *fixtureSource) {
		head := *s.head
		head.Control = nil
		s.head = &head
	}, f.Claim.Epoch)
	refused("no retained body", func(s *fixtureSource) { s.body = nil }, f.Claim.Epoch)
	refused("a body that is not canonical V3", func(s *fixtureSource) { s.body = []byte("v2 body") }, f.Claim.Epoch)
	refused("a body that is not the committed one", func(s *fixtureSource) {
		other := f.Body
		other.EarliestActivation++
		s.body = other.Encode()
	}, f.Claim.Epoch)
	refused("no retained readiness receipts", func(s *fixtureSource) { s.receipts = nil }, f.Claim.Epoch)
	refused("receipts that are not a canonical set", func(s *fixtureSource) { s.receipts = []byte{0x80} }, f.Claim.Epoch)

	_, _, _, err := q3ActivationEvidence(good, f.Claim.Epoch)
	require.NoError(t, err, "the control")

	// a manager that is not wired to a verified Q3 history has no evidence to give
	plain := newPlanFixture(t)
	_, _, _, err = plain.cm.Q3ActivationEvidence(2)
	require.ErrorIs(t, err, ErrNoQ3Evidence)
	wired := newPlanFixtureOpts(t, true)
	_, _, _, err = wired.cm.Q3ActivationEvidence(1)
	require.ErrorIs(t, err, ErrNoQ3Evidence, "epoch 1 is not a successor")
	_, _, _, err = wired.cm.Q3ActivationEvidence(2)
	require.ErrorIs(t, err, ErrNoQ3Evidence, "no committed handoff yet")
}
