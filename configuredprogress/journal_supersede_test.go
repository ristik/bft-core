package configuredprogress

import (
	"bytes"
	"context"
	"crypto/sha256"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	gethtypes "github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/archive"
	"github.com/unicitynetwork/bft-core/frontier"
	"github.com/unicitynetwork/bft-core/network/protocol/certification"
	"github.com/unicitynetwork/bft-core/rootinput"
	"github.com/unicitynetwork/bft-go-base/types"
)

// bft-core#1019: many more consecutive failed rounds at one height than the journal's candidate and observation bounds. Every failed round
// journals one more uncertified proposal for h = frontier+1 and one more repeat certificate of block h-1. The journal must keep admitting
// proposals and certificates, a certifiable proposal must then be admitted and certified, and the frontier must advance over it, across a restart.
func TestJournalSurvivesFailedRoundsBeyondBoundsAtOneHeight(t *testing.T) {
	path := t.TempDir() + "/journal.db"
	limits := JournalLimits{Candidates: 3, Observations: 5, Bytes: 16 << 20}
	s, f, c, policy, item, _ := frontierTestSetupWithLimits(t, path, limits)
	ctx := context.Background()
	admit := func(o rootinput.VerifiedObservationV2) {
		t.Helper()
		p, _, err := s.PrepareObservation(ctx, c, o)
		require.NoError(t, err)
		_, _, err = s.CommitObservation(p)
		require.NoError(t, err)
	}
	// The frontier covers height 1; the shard is stuck at height 2.
	require.NoError(t, s.AdvanceFrontier(ctx, c, limits, []frontier.Coverage{item}))
	require.NoError(t, s.PruneFrontier(ctx, c, limits))
	var anchorUC types.UnicityCertificate
	require.NoError(t, types.Cbor.Unmarshal(item.Material.ResultingUC, &anchorUC))
	anchorTR := new(certification.TechnicalRecord)
	require.NoError(t, types.Cbor.Unmarshal(item.Material.ResultingTR, anchorTR))
	auth, err := rootinput.AuthenticateObservationV2(ctx, c.Observation, &anchorUC, anchorTR)
	require.NoError(t, err)
	parentHash, parentState := item.Anchor.Subject.BlockHash, item.Anchor.StateRoot

	const failed = 3 * 5 // well beyond both bounds
	round, rootRound := uint64(2), anchorUC.GetRootRoundNumber()+1
	var firstFailed JournalCandidate
	for i := 0; i < failed; i++ {
		// The round's proposal is journaled (alternately by the leader and by a follower) and never certified.
		dead := JournalCandidate{Round: round, Number: 2, ParentNumber: 1, Hash: bytes.Repeat([]byte{byte(0x40 + i)}, 32), StateRoot: bytes.Repeat([]byte{byte(0x80 + i)}, 32),
			ParentHash: parentHash[:], ParentState: parentState[:], Raw: []byte{byte(i), 1, 2}, BlockSize: 3, LocallyBuilt: i%2 == 0,
			AuthorizingUC: auth.Certificate(), AuthorizingTR: auth.TechnicalRecord()}
		require.NoError(t, s.PutJournalCandidate(ctx, c, limits, dead), "failed round %d: the proposal must be admitted", i)
		if i == 0 {
			firstFailed = dead
		}
		// The root times out: a repeat certificate of block 1 that moves the shard to the next round.
		auth = f.observation(anchorUC.InputRecord, round+1, rootRound)
		p, outcome, err := s.PrepareObservation(ctx, c, auth)
		require.NoError(t, err)
		require.Equal(t, ObservationRepeated, outcome)
		_, _, err = s.CommitObservation(p)
		require.NoError(t, err, "failed round %d: the repeat certificate must be admitted", i)
		image, err := s.LoadJournal(ctx, c, limits)
		require.NoError(t, err)
		require.LessOrEqual(t, len(image.Candidates), limits.Candidates)
		require.LessOrEqual(t, len(image.Observations), limits.Observations)
		round++
		rootRound++
	}

	// A different local proposal for an evicted proposal's authorization is still refused (equivocation avoidance survives the eviction).
	again := firstFailed
	again.Hash, again.Raw, again.LocallyBuilt = bytes.Repeat([]byte{0xee}, 32), []byte{0xee}, true
	err = s.PutJournalCandidate(ctx, c, limits, again)
	require.ErrorIs(t, err, ErrLocalProposalConflict)
	require.ErrorIs(t, err, ErrConflict)

	// Restart in the stall: the journal reopens and verifies.
	require.NoError(t, s.Close())
	s, err = OpenConfiguredV2(path, Settings{Retain: 3})
	require.NoError(t, err)
	defer func() { require.NoError(t, s.Close()) }()
	require.NoError(t, s.EnableJournal(ctx, c, limits))
	require.NoError(t, s.EnableFrontier(ctx, c, limits, policy))
	_, err = s.LoadJournal(ctx, c, limits)
	require.NoError(t, err)

	// The certifiable proposal of this round is admitted, certified and covered by the frontier.
	state := common.Hash{31: 0x42}
	header := &gethtypes.Header{ParentHash: common.Hash(parentHash), Root: state, Number: big.NewInt(2), Difficulty: new(big.Int), BaseFee: big.NewInt(1)}
	headerRaw, err := rlp.EncodeToBytes(header)
	require.NoError(t, err)
	hash := header.Hash()
	good := JournalCandidate{Round: round, Number: 2, ParentNumber: 1, Hash: hash.Bytes(), StateRoot: state.Bytes(), ParentHash: parentHash[:], ParentState: parentState[:],
		Raw: []byte{7, 7, 7}, BlockSize: 3, LocallyBuilt: true, AuthorizingUC: auth.Certificate(), AuthorizingTR: auth.TechnicalRecord()}
	require.NoError(t, s.PutJournalCandidate(ctx, c, limits, good))
	result := f.observation(&types.InputRecord{Version: 1, RoundNumber: round, PreviousHash: parentState[:], Hash: state.Bytes(), BlockHash: hash.Bytes(), SummaryValue: []byte{}, Timestamp: 1_700_000_000 + round}, round+1, rootRound)
	admit(result)
	image, err := s.LoadJournal(ctx, c, limits)
	require.NoError(t, err)
	certified := false
	for _, e := range image.Candidates {
		if bytes.Equal(e.Candidate.Hash, hash.Bytes()) {
			certified = e.Certified
		}
	}
	require.True(t, certified, "the certifiable proposal is certified")

	uc0, _ := types.Cbor.Marshal(auth.Certificate())
	tr0, _ := types.Cbor.Marshal(auth.TechnicalRecord())
	uc1, _ := types.Cbor.Marshal(result.Certificate())
	tr1, _ := types.Cbor.Marshal(result.TechnicalRecord())
	bodyRaw, _ := rlp.EncodeToBytes(&gethtypes.Body{})
	rec := &archive.Record{Header: headerRaw, Body: bodyRaw, CanonicalRootInput: []byte{1}, OriginalUC: uc0, OriginalTR: tr0, ResultingUC: uc1, ResultingTR: tr1, Companion: []byte{1}}
	q := archive.Request{Context: item.Anchor.Subject.Context, BlockHash: [32]byte(hash)}
	req, err := archive.EncodeRequest(q)
	require.NoError(t, err)
	digest, err := archive.ManifestDigest(q, rec)
	require.NoError(t, err)
	ack := sha256.Sum256(req)
	next := frontier.Record{Sequence: 2, Round: result.Certificate().GetRootRoundNumber(), Height: 2, StateRoot: [32]byte(state), Subject: q,
		Acks: [2]frontier.Acknowledgment{{Replica: "first", RequestDigest: ack, ManifestDigest: digest}, {Replica: "second", RequestDigest: ack, ManifestDigest: digest}}}
	require.NoError(t, s.AdvanceFrontier(ctx, c, limits, []frontier.Coverage{{Anchor: next, Material: rec}}))
	require.NoError(t, s.PruneFrontier(ctx, c, limits))
	image, err = s.LoadJournal(ctx, c, limits)
	require.NoError(t, err)
	require.EqualValues(t, 2, image.Frontier.Anchor.Height, "the frontier advanced past the stuck height")
}
