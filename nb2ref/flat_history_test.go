package nb2ref

import (
	"math/big"
	"slices"
	"testing"

	"github.com/stretchr/testify/require"
)

type flatHistorySegment struct {
	ids   [][32]byte // arrival order, as stored in the vault
	root  [32]byte
	proof []byte
}

type flatHistory struct {
	segments []flatHistorySegment
	heads    [][32]byte // heads[c] follows all segments before c
}

func newFlatHistory(t *testing.T, domain, eta [32]byte, k, count uint64) flatHistory {
	t.Helper()
	return buildFlatHistory(t, domain, eta, k, count, false)
}

func buildFlatHistory(t *testing.T, domain, eta [32]byte, k, count uint64, concentrate bool) flatHistory {
	t.Helper()
	h := flatHistory{heads: [][32]byte{expectedGenesisHead(domain, k)}}
	seen := map[[32]byte]bool{eta: true}
	for index := range count {
		var seg flatHistorySegment
		for slot := range k {
			id := expectedKeccak([]byte("flat-gap/neighbor"), flatU64(index), flatU64(slot))
			if concentrate {
				id[0] = id[0]&0x0f | eta[0]&0xf0
			}
			require.False(t, seen[id], "eta or paid ID reused at segment %d, slot %d", index, slot)
			seen[id] = true
			seg.ids = append(seg.ids, id)
		}
		ordered := slices.Clone(seg.ids)
		slices.SortFunc(ordered, func(a, b [32]byte) int { return slices.Compare(a[:], b[:]) })
		tree, ok := BuildGapTree(ordered)
		require.True(t, ok)
		seg.root = expectedGapRoot(seg.ids)
		require.Equal(t, seg.root, tree.Root())
		seg.proof, ok = tree.Prove(eta)
		require.True(t, ok)
		h.segments = append(h.segments, seg)
		h.heads = append(h.heads, expectedArchiveStep(domain, index, h.heads[index], seg.root))
	}
	return h
}

func (h flatHistory) proofs(start uint64, count int) [][]byte {
	out := make([][]byte, 0, count)
	for _, seg := range h.segments[start : start+uint64(count)] {
		out = append(out, seg.proof)
	}
	return out
}

// Check the 1024 boundary against the common indexing mistake of repeatedly
// reading the first proof. The expected archive head uses distinct segment roots.
func (h flatHistory) assertProofCursor(t *testing.T, domain, eta [32]byte, k, start uint64, count int) {
	t.Helper()
	repeated := make([][]byte, count)
	for i := range repeated {
		repeated[i] = h.segments[start].proof
	}
	head, err := FoldHistory(domain, k, eta, start, h.heads[start], repeated)
	require.NoError(t, err)
	require.NotEqual(t, h.heads[start+uint64(count)], head)
}

// reach constructs a published prestate with successful §6 payments from
// genesis. As in the custody model, background burns enter as certified
// ordinary verdicts. A separate deposit funds them at one unit per payment.
// The fixture retains the target deposit and observes subsequent test-call
// logs; historical background logs are outside the observation window.
func (h flatHistory) reach(t *testing.T, vault *FlatVault, target *Verdict, c, population uint64) flatCustodyFixture {
	t.Helper()
	k := vault.model.Cfg.K
	n, oldC, pop, q, _, _ := vault.State()
	require.Equal(t, uint64(1), n)
	require.Zero(t, oldC)
	require.Zero(t, pop)
	require.Equal(t, target.Amount, q)
	require.Less(t, population, k)
	targetDeposit := vault.Logs()
	require.Len(t, targetDeposit, 1)
	background := Recipient20("flat-history-background")
	require.NotEqual(t, target.Recipient, background)
	funding := c*k + population
	require.Positive(t, funding)
	require.NoError(t, vault.Deposit(new(big.Int).SetUint64(funding),
		FirstOwner(Key("flat-history-funder")), expectedKeccak([]byte("flat-history/rho"))))
	for index := uint64(0); index <= c; index++ {
		count := k
		if index == c {
			count = population
		}
		for _, id := range h.segments[index].ids[:count] {
			require.NotEqual(t, target.Eta, id)
			verdict := syntheticVerdict(vault.model.D, id, index, 1, background)
			_, err := vault.model.Redeem(id, index, nil, VerifierCall{Return: verdict}, RecipientAccepts)
			require.NoError(t, err, "background payment at segment %d", index)
			vault.recordPayout()
		}
	}
	// Compare all published state to the independently folded history.
	n, gotC, gotPop, q, head, prev := vault.State()
	require.Equal(t, uint64(2), n)
	require.Equal(t, c, gotC)
	require.Equal(t, population, gotPop)
	require.Equal(t, target.Amount, q)
	require.Equal(t, h.heads[c], head)
	current, previous := vault.LiveIDs()
	require.True(t, slices.Equal(h.segments[c].ids[:population], current))
	if c > 0 {
		require.Equal(t, h.heads[c-1], prev)
		require.Equal(t, h.segments[c-1].ids, previous)
	}
	assertDistinctLiveIDs(t, current, previous)
	require.Equal(t, target.Amount, vault.Balance(vault.model.Cfg.Vault))
	require.Zero(t, vault.Balance(target.Recipient).Sign())
	require.Equal(t, funding, vault.Balance(background).Uint64())
	vault.model.Events = targetDeposit
	return flatCustodyState(vault, target.Recipient)
}

func assertDistinctLiveIDs(t *testing.T, current, previous [][32]byte) {
	t.Helper()
	seen := make(map[[32]byte]bool, len(current)+len(previous))
	for _, buffer := range [][][32]byte{current, previous} {
		for _, id := range buffer {
			require.False(t, seen[id], "duplicate live paid ID %x", id)
			seen[id] = true
		}
	}
}
