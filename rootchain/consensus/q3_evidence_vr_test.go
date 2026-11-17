package consensus

import (
	"crypto"
	"crypto/sha256"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/activationproof"
	"github.com/unicitynetwork/bft-core/evmassign"
	"github.com/unicitynetwork/bft-core/internal/testutils/q3fixture"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/storage"
	"github.com/unicitynetwork/bft-core/vradmit"
	"github.com/unicitynetwork/bft-core/vrschema"
)

// A VR handoff, H to bootstrap to acknowledgement (VT-05b, #1177's not-done list): the successor body binds SHA-256 of the candidate v6,
// so the activation evidence a root assembles from its own committed tip carries the v6 bytes (never the v5 view the root retains for its
// install paths), the verified history admits the activation over them (H, then the bootstrap of the successor epoch), the shard's
// activation proof authenticates the same bytes and derives the same next configuration, and the technical record the shard's
// acknowledgement must reach is the one the committed H names.
func TestVRActivationEvidenceCarriesTheCandidateV6(t *testing.T) {
	f := q3fixture.New(t, q3fixture.Options{Assignment: true, V6: true})
	v6, err := vrschema.DecodeCandidateV6(f.Candidate)
	require.NoError(t, err, "the committed candidate is a canonical v6")
	view, err := vradmit.V5Of(v6).Encode()
	require.NoError(t, err)

	// H: the evidence from the committed tip is the link the history verifies (the bootstrap of epoch 2)
	link, _, candidate, err := q3ActivationEvidence(sourceOf(t, f), f.Claim.Epoch)
	require.NoError(t, err)
	require.Equal(t, f.Candidate, candidate, "the v6 bytes, not the retained v5 view")
	sum := sha256.Sum256(f.Candidate)
	require.Equal(t, sum[:], link.Evidence.CandidateDigest)
	h, err := f.NewHistory(t).WithV3(link)
	require.NoError(t, err, "the history admits the activation over the candidate v6 and the receipts that bind its digest")
	entry := h.Tip()
	require.Equal(t, f.Claim.Epoch, entry.Epoch())

	// the shard side: the activation proof authenticates the same bytes and derives the same next configuration as the v5 view
	require.NoError(t, activationproof.AuthenticateCandidate(entry, f.Proof.Record, f.Candidate))
	require.Error(t, activationproof.AuthenticateCandidate(entry, f.Proof.Record, view), "the v5 view is not what the body binds")
	_, fromV6, err := evmassign.ActivatedFromPreimage(f.Candidate, f.Proof.Record.ActivationRound)
	require.NoError(t, err)
	_, fromView, err := evmassign.ActivatedFromPreimage(view, f.Proof.Record.ActivationRound)
	require.NoError(t, err)
	a, err := evmassign.PDRHash(fromV6)
	require.NoError(t, err)
	b, err := evmassign.PDRHash(fromView)
	require.NoError(t, err)
	require.Equal(t, b, a, "the v6 bytes and their view activate the identical configuration")

	// the acknowledgement: the successor technical record derived from the v6 bytes is the one the committed H names
	state, err := storage.NewShardInfo(f.ShardConf, crypto.SHA256)
	require.NoError(t, err)
	state.IR.BlockHash = f.FrozenParent
	state.IR.Hash = make([]byte, 32)
	for i := range state.IR.Hash {
		state.IR.Hash[i] = 0x37
	}
	state.RootHash = state.IR.Hash
	tr, err := storage.AssignmentSuccessorTRHash(state, f.Candidate, f.Proof.Record.ActivationRound, crypto.SHA256)
	require.NoError(t, err)
	require.Equal(t, []byte(f.Proof.Record.SuccessorTRHash), tr)

	// the defect #1177 recorded: evidence assembled from the retained v5 view is refused by the history
	stale := sourceOf(t, f)
	stale.candidate = view
	staleLink, _, _, err := q3ActivationEvidence(stale, f.Claim.Epoch)
	require.NoError(t, err)
	_, err = f.NewHistory(t).WithV3(staleLink)
	require.Error(t, err, "a link over the v5 view does not bind the committed digest")

	// the committed decoder reads both generations; the strict v5 decoder still refuses the v6 bytes
	_, err = evmassign.DecodeCandidate(f.Candidate)
	require.Error(t, err)
	got, err := evmassign.DecodeCommittedCandidate(f.Candidate)
	require.NoError(t, err)
	require.Equal(t, vradmit.V5Of(v6).Identities, got.Identities)
}
