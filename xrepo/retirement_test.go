package xrepo

import (
	"bytes"
	"encoding/binary"
	"math/big"
	"os"
	"testing"

	ethcrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-go-base/crypto"
	bftypes "github.com/unicitynetwork/bft-go-base/types"

	"github.com/unicitynetwork/bft-core/evmassign"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/types"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/votesig"
	"github.com/unicitynetwork/bft-core/rootrecords"
)

// goRetirementPath is produced HERE (XREPO_UPDATE=1 go test ./xrepo) and replayed by the contracts (XRepoRetirement.t.sol) through
// the SealRegistry into custody, to maturity and claim.
const goRetirementPath = "testdata/go-retirement.json"

// The contracts' test deployment (P85Base.sol): the root network and the root-chain genesis G its Evidence manifest pins, and the
// root keys of the publication fixture's identities, which are the test scalars rootPk(i) = 0x2000+i. The contracts check the first
// two against their manifest; the keys are checked here against the publication fixture.
const (
	contractsRootNetwork = 5
	contractsRootKeyBase = 0x2000
)

var contractsRootGenesis = [32]byte(ethcrypto.Keccak256([]byte("p85-test-root-genesis")))

type retirementJSON struct {
	ID                 uint64   `json:"id"`
	Generation         uint64   `json:"generation"`
	ExposureIDs        []string `json:"exposureIds"` // creation order: the genesis assignment's, then the primary's
	RefDigest          string   `json:"refDigest"`
	MaxLiabilityAnchor uint64   `json:"maxLiabilityAnchor"`
	Lot                uint64   `json:"lot"`
	Held               bool     `json:"held"` // the evidence below holds its lot
}

type voteJSON struct {
	Parent    uint64 `json:"parent"`
	Exec      string `json:"exec"`
	Timestamp uint64 `json:"timestamp"`
	Preimage  string `json:"preimage"` // PV
	Digest    string `json:"digest"`   // sha256(PV)
	Signature string `json:"signature"`
}

type evidenceJSON struct {
	Note        string   `json:"note"`
	RootNetwork uint64   `json:"rootNetwork"`
	RootGenesis string   `json:"rootGenesis"`
	ID          uint64   `json:"id"`
	Key         string   `json:"key"` // compressed secp256k1 root key of the identity
	VotingEpoch uint64   `json:"votingEpoch"`
	VotingRound uint64   `json:"votingRound"`
	ExposureID  string   `json:"exposureId"` // the primary assignment's exposure of the identity: the historical attribution
	A           voteJSON `json:"a"`
	B           voteJSON `json:"b"`
}

type retirementRecordJSON struct {
	recordJSON
	ClosedEpoch uint64 `json:"closedEpoch"` // the registry import's closed epoch of a Closure (0 otherwise)
}

type goRetirement struct {
	Format              string                 `json:"format"`
	Note                string                 `json:"note"`
	ResultID            string                 `json:"resultId"`
	GenesisAssignmentID string                 `json:"genesisAssignmentId"`
	PrimaryAssignmentID string                 `json:"primaryAssignmentId"`
	Records             []retirementRecordJSON `json:"records"`
	Retirements         []retirementJSON       `json:"retirements"`
	Evidence            evidenceJSON           `json:"evidence"`
}

func rootSigner(t *testing.T, i int) (*crypto.InMemorySecp256K1Signer, []byte) {
	t.Helper()
	priv := new(big.Int).SetUint64(uint64(contractsRootKeyBase + i)).FillBytes(make([]byte, 32))
	s, err := crypto.NewInMemorySecp256K1SignerFromKey(priv)
	require.NoError(t, err)
	v, err := s.Verifier()
	require.NoError(t, err)
	pub, err := v.MarshalPublicKey()
	require.NoError(t, err)
	return s, pub
}

// equivocation is two conflicting non-committing scheme 2 votes of one key in one voting epoch and round (different executed state),
// built by the root's own statement derivation and signed by the root's signer.
func equivocation(t *testing.T, signer *crypto.InMemorySecp256K1Signer, epoch, round, ts uint64) (voteJSON, voteJSON) {
	t.Helper()
	cfg := votesig.Config{Scheme: votesig.SchemeDomainBound, Network: contractsRootNetwork, Genesis: contractsRootGenesis}
	vote := func(tag string) voteJSON {
		exec := label("xrepo/evidence/exec/" + tag)
		info := &types.RoundInfo{Version: 1, RoundNumber: round, Epoch: epoch, ParentRoundNumber: round - 1, CurrentRootHash: exec[:], Timestamp: ts}
		vh, err := cfg.VoteInfoHash(votesig.VoteInfo{Epoch: epoch, Round: round, Parent: round - 1, Exec: exec, Timestamp: ts})
		require.NoError(t, err)
		pv, _, committing, err := types.DomainBoundStatement(cfg, info, &bftypes.UnicitySeal{PreviousHash: vh[:]}, false)
		require.NoError(t, err)
		require.False(t, committing)
		sig, err := signer.SignBytes(pv)
		require.NoError(t, err)
		v, err := signer.Verifier()
		require.NoError(t, err)
		require.NoError(t, v.VerifyBytes(sig, pv), "the root's verifier accepts the statement")
		d := votesig.Digest(pv)
		return voteJSON{Parent: round - 1, Exec: hx(exec[:]), Timestamp: ts, Preimage: hx(pv), Digest: hx(d[:]), Signature: hx(sig)}
	}
	return vote("A"), vote("B")
}

func u64word(v uint64) []byte {
	b := make([]byte, 32)
	binary.BigEndian.PutUint64(b[24:], v)
	return b
}

func buildRetirement(t *testing.T) goRetirement {
	t.Helper()
	s, p := compute(t)
	_, d := loadPublication(t)

	// ---- the ack history (Closure of G, Ack of J, Closure of J), then the Retirements of identities 1 and 2 ----
	b := &builder{t: t, state: rootrecords.NewState(1, genesisFirst)}
	b.commit(h1, 2, jFirst, "xrepo/body/J")
	b.block(2, jFirst)
	cG := b.close(1, s.closure(s.genesis, s.gExp, s.gKey, h1, "G"), jFirst, t0)
	a := b.ack(jFirst+2, t0+5, s.result, s.primary, 2)
	require.Equal(t, rootrecords.KindAck, a.Kind)
	b.commit(h2, 3, next2First, "xrepo/body/next")
	b.block(3, next2First)
	cJ := b.close(2, s.closure(s.primary, s.jExp, s.jKey, h2, "J"), next2First, t0+10)
	closedEpochs := []uint64{1, 0, 2}

	// custody's liability anchor of a closed assignment is max(its end progress offset + (H - first round), the closure's progress)
	jOffset := uint64(h1-genesisFirst) + 1
	anchor := max(uint64(h1-genesisFirst), cG.Progress)
	anchor = max(anchor, jOffset+(h2-jFirst), cJ.Progress)

	var rets []retirementJSON
	retireRound := uint64(next2First + 20)
	for i, ident := range p.Identities[:2] {
		require.Equal(t, ident.ID, p.IncumbentIdentities[i].ID, "the identity holds the same lot in G and J")
		// the reference digest: custody's exposure chain of the generation, every exposure it was ever given, in creation order
		eg := evmassign.ExposureID(d, s.genesis, ident.ID)
		ej := evmassign.ExposureID(d, s.primary, ident.ID)
		ref := evmassign.ExposureChainStep(evmassign.ExposureChainStep([32]byte{}, eg), ej)
		st, rec, err := b.state.Retire(ident.ID, ident.Generation, ref, anchor, retireRound+uint64(i), t0+20+uint64(i))
		require.NoError(t, err)
		require.NotNil(t, rec)
		require.Equal(t, rootrecords.KindRetirement, rec.Kind)
		require.Equal(t, bytes.Join([][]byte{u64word(ident.ID), u64word(ident.Generation), ref[:]}, nil), rec.Data, "the Retirement carries the digest verbatim")
		b.state, b.recs = st, append(b.recs, *rec)
		closedEpochs = append(closedEpochs, 0)
		require.Len(t, ident.LotIDs, 1)
		rets = append(rets, retirementJSON{ID: ident.ID, Generation: ident.Generation, ExposureIDs: []string{hx(eg[:]), hx(ej[:])}, RefDigest: hx(ref[:]),
			MaxLiabilityAnchor: anchor, Lot: ident.LotIDs[0], Held: i == 0})
	}
	// a repeat with the same digest is no new record; another digest is a conflict
	_, again, err := b.state.Retire(p.Identities[0].ID, p.Identities[0].Generation, h32(t, rets[0].RefDigest), anchor, retireRound+5, t0+30)
	require.NoError(t, err)
	require.Nil(t, again)
	_, _, err = b.state.Retire(p.Identities[0].ID, p.Identities[0].Generation, label("xrepo/another-digest"), anchor, retireRound+5, t0+30)
	require.ErrorIs(t, err, rootrecords.ErrRetirementConflict)

	recs := b.json()
	out := make([]retirementRecordJSON, len(recs))
	for i, r := range recs {
		out[i] = retirementRecordJSON{recordJSON: r, ClosedEpoch: closedEpochs[i]}
	}

	// ---- identity 1's root key equivocates in J's epoch; the evidence is submitted after the generation retired ----
	signer, pub := rootSigner(t, 0)
	require.Equal(t, unhex(t, p.Identities[0].RootKey), pub, "the publication's root key of identity 1 is the contracts' rootPk(0)")
	round := uint64(jFirst + 20)
	require.Less(t, round, uint64(h2), "a round J signed in before its H")
	va, vb := equivocation(t, signer, 2, round, t0+7)
	ej := evmassign.ExposureID(d, s.primary, p.Identities[0].ID)

	return goRetirement{
		Format: "UNICITY_XREPO_GO_RETIREMENT/v1",
		Note: "Produced by bft-core (XREPO_UPDATE=1 go test ./xrepo) from the contracts' publication fixture. The records are what the root's projection " +
			"emits; the Retirement reference digests are the evmassign model of custody's exposure-chain storage word (a root reads it from custody's storage proof); the evidence pair is signed by the root's " +
			"statement derivation and signer. The contracts import the records through the SealRegistry and apply them verbatim. Do not edit by hand.",
		ResultID: p.ResultID, GenesisAssignmentID: hx(s.genesis[:]), PrimaryAssignmentID: hx(s.primary[:]),
		Records: out, Retirements: rets,
		Evidence: evidenceJSON{
			Note:        "Two non-committing scheme 2 votes of identity 1's root key in J's root epoch and one round with different executed states: an equivocation by a key whose generation retires before the evidence is submitted.",
			RootNetwork: contractsRootNetwork, RootGenesis: hx(contractsRootGenesis[:]), ID: p.Identities[0].ID, Key: hx(pub),
			VotingEpoch: 2, VotingRound: round, ExposureID: hx(ej[:]), A: va, B: vb,
		},
	}
}

// The Retirement records and the evidence pair the root produces for the fixture are the committed file the contracts replay.
func TestTheRootsRetirementAndEvidenceAreTheCommittedVectors(t *testing.T) {
	got := encode(t, buildRetirement(t))
	if os.Getenv("XREPO_UPDATE") == "1" {
		require.NoError(t, os.WriteFile(goRetirementPath, got, 0o644))
	}
	want, err := os.ReadFile(goRetirementPath)
	require.NoError(t, err)
	require.Equal(t, string(want), string(got), "the retirement vectors changed: regenerate with XREPO_UPDATE=1 and replay them in unicity-pos-contracts")
}
