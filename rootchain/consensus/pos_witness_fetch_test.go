package consensus

import (
	"context"
	"crypto/sha256"
	"errors"
	"log/slog"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-go-base/types"

	"github.com/unicitynetwork/bft-core/rootchain/consensus/storage"
	drctypes "github.com/unicitynetwork/bft-core/rootchain/consensus/types"
	rctypes "github.com/unicitynetwork/bft-core/rootchain/consensus/types"
)

type heldWitnesses struct{ m map[[32]byte][]byte }

func (h *heldWitnesses) HasWitness(hash [32]byte) bool { _, ok := h.m[hash]; return ok }
func (h *heldWitnesses) StoreWitness(data []byte) error {
	if len(data) == 0 {
		return storage.ErrWitnessStore
	}
	h.m[sha256.Sum256(data)] = data
	return nil
}

func testPeer(t *testing.T) peer.ID {
	t.Helper()
	priv, _, err := crypto.GenerateEd25519Key(nil)
	require.NoError(t, err)
	id, err := peer.IDFromPrivateKey(priv)
	require.NoError(t, err)
	return id
}

func witnessFixture(t *testing.T) (x *ConsensusManager, self, author, other peer.ID) {
	t.Helper()
	self, author, other = testPeer(t), testPeer(t), testPeer(t)
	tb := &types.RootTrustBaseV1{RootNodes: []*types.NodeInfo{{NodeID: self.String()}, {NodeID: other.String()}, {NodeID: author.String()}}}
	x = &ConsensusManager{id: self, log: slog.Default()}
	x.trustBase.Store(tb)
	return x, self, author, other
}

// validControl is a well-formed Retirement ordered by b.
func validControl(b *drctypes.BlockData, witness [32]byte) rctypes.PosControl {
	return rctypes.PosControl{Op: rctypes.OpRetirement, OrderingEpoch: b.Epoch, OrderingRound: b.Round, Retire: &rctypes.RetireContext{},
		Data: make([]byte, 96), WitnessHash: witness}
}

func blockWith(author peer.ID, hashes ...[32]byte) *drctypes.BlockData {
	b := &drctypes.BlockData{Author: author.String(), Epoch: 3, Round: 9, Payload: &drctypes.Payload{}}
	for _, h := range hashes {
		b.Payload.PosControls = append(b.Payload.PosControls, validControl(b, h))
	}
	return b
}

func TestFetchWitnessesAsksTheAuthorFirstAndNeverItself(t *testing.T) {
	x, self, author, other := witnessFixture(t)
	data := []byte("a witness")
	hash := sha256.Sum256(data)
	var asked [][]peer.ID
	x.witnesses = func(_ context.Context, h [32]byte, peers []peer.ID, _ int) ([]byte, error) {
		require.Equal(t, hash, h)
		asked = append(asked, peers)
		return data, nil
	}
	store := &heldWitnesses{m: map[[32]byte][]byte{}}
	require.NoError(t, x.fetchWitnesses(context.Background(), store, blockWith(author, hash)))
	require.Equal(t, [][]peer.ID{{author, other}}, asked)
	require.NotContains(t, asked[0], self)
	require.Equal(t, data, store.m[hash], "the fetched witness is retained for the executor")
}

func TestFetchWitnessesSkipsWhatIsHeldAndAsksOncePerBlock(t *testing.T) {
	x, _, author, _ := witnessFixture(t)
	held, missing := []byte("held"), []byte("missing")
	hh, hm := sha256.Sum256(held), sha256.Sum256(missing)
	calls := 0
	x.witnesses = func(_ context.Context, h [32]byte, _ []peer.ID, _ int) ([]byte, error) {
		calls++
		require.Equal(t, hm, h, "only the missing witness is fetched")
		return missing, nil
	}
	store := &heldWitnesses{m: map[[32]byte][]byte{hh: held}}
	require.NoError(t, x.fetchWitnesses(context.Background(), store, blockWith(author, hh, hm, hh)))
	require.Equal(t, 1, calls)
	// a block that needs nothing fetches nothing
	calls = 0
	require.NoError(t, x.fetchWitnesses(context.Background(), store, blockWith(author, hh)))
	require.NoError(t, x.fetchWitnesses(context.Background(), store, blockWith(author)))
	require.Zero(t, calls)
}

func TestFetchWitnessesRefusesAnUnavailableWitnessAsUnavailableNotInvalid(t *testing.T) {
	x, _, author, _ := witnessFixture(t)
	hash := sha256.Sum256([]byte("withheld"))
	x.witnesses = func(context.Context, [32]byte, []peer.ID, int) ([]byte, error) {
		return nil, errors.New("nobody has it")
	}
	store := &heldWitnesses{m: map[[32]byte][]byte{}}
	err := x.fetchWitnesses(context.Background(), store, blockWith(author, hash))
	require.ErrorIs(t, err, storage.ErrWitnessUnavailable)
	require.Empty(t, store.m)
}

func TestWithoutAFetcherTheStoreIsTheOnlySource(t *testing.T) {
	x, _, author, _ := witnessFixture(t)
	store := &heldWitnesses{m: map[[32]byte][]byte{}}
	require.NoError(t, x.fetchWitnesses(context.Background(), store, blockWith(author, sha256.Sum256([]byte("x")))),
		"the executor, not this step, answers for a witness nobody supplies")
	require.Empty(t, store.m)
	require.NoError(t, x.fetchWitnesses(context.Background(), store, nil))
}

func TestFetchWitnessesRefusesBytesThatAreNotTheCommittedWitness(t *testing.T) {
	x, _, author, _ := witnessFixture(t)
	hash := sha256.Sum256([]byte("wanted"))
	x.witnesses = func(context.Context, [32]byte, []peer.ID, int) ([]byte, error) { return []byte("other"), nil }
	store := &heldWitnesses{m: map[[32]byte][]byte{}}
	err := x.fetchWitnesses(context.Background(), store, blockWith(author, hash))
	require.ErrorIs(t, err, storage.ErrWitnessUnavailable)
	require.Empty(t, store.m, "nothing is retained under any key")
}

func TestFetchWitnessesRefusesAControlThatCannotBeValidBeforeFetchingAnything(t *testing.T) {
	x, _, author, _ := witnessFixture(t)
	hash := sha256.Sum256([]byte("w"))
	fetched := false
	x.witnesses = func(context.Context, [32]byte, []peer.ID, int) ([]byte, error) { fetched = true; return nil, nil }
	store := &heldWitnesses{m: map[[32]byte][]byte{}}
	for name, mutate := range map[string]func(c *rctypes.PosControl){
		"another ordering round": func(c *rctypes.PosControl) { c.OrderingRound++ },
		"another ordering epoch": func(c *rctypes.PosControl) { c.OrderingEpoch++ },
		"a malformed payload":    func(c *rctypes.PosControl) { c.Data = c.Data[:95] },
		"no context":             func(c *rctypes.PosControl) { c.Retire = nil },
	} {
		b := blockWith(author, hash)
		mutate(&b.Payload.PosControls[0])
		require.Error(t, x.fetchWitnesses(context.Background(), store, b), name)
	}
	require.False(t, fetched, "nothing is fetched for a control that cannot be valid")
	require.Empty(t, store.m)
}

func TestFetchWitnessesIsBoundedByOneDeadlineForTheWholeBlock(t *testing.T) {
	x, _, author, _ := witnessFixture(t)
	x.params = &Parameters{LocalTimeout: 200 * time.Millisecond} // budget: 100ms
	x.witnesses = func(ctx context.Context, _ [32]byte, _ []peer.ID, _ int) ([]byte, error) {
		<-ctx.Done() // a peer that accepts and trickles
		return nil, ctx.Err()
	}
	hashes := [][32]byte{sha256.Sum256([]byte("a")), sha256.Sum256([]byte("b")), sha256.Sum256([]byte("c"))}
	start := time.Now()
	err := x.fetchWitnesses(context.Background(), &heldWitnesses{m: map[[32]byte][]byte{}}, blockWith(author, hashes...))
	require.ErrorIs(t, err, storage.ErrWitnessUnavailable)
	require.Less(t, time.Since(start), time.Second, "three controls share one budget instead of waiting out each")
}

func TestAVotersPullIsBoundedByTheOpOfTheControl(t *testing.T) {
	x, _, author, _ := witnessFixture(t)
	data := []byte("a witness")
	hash := sha256.Sum256(data)
	var got int
	x.witnesses = func(_ context.Context, _ [32]byte, _ []peer.ID, maxBytes int) ([]byte, error) {
		got = maxBytes
		return data, nil
	}
	require.NoError(t, x.fetchWitnesses(context.Background(), &heldWitnesses{m: map[[32]byte][]byte{}}, blockWith(author, hash)))
	require.Equal(t, storage.MaxEVMWitnessBytes, got, "a Retirement's witness may not be longer than the executor accepts")
}
