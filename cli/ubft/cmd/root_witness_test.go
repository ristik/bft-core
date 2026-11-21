package cmd

import (
	"context"
	"crypto/sha256"
	"sync/atomic"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/peerstore"
	"github.com/stretchr/testify/require"

	"github.com/unicitynetwork/bft-core/network"
	"github.com/unicitynetwork/bft-core/rootchain/poswitness"
)

type witnessTestRoot struct {
	installed peer.ID
	joiner    peer.ID
	staged    atomic.Bool
	witness   []byte
}

func (r *witnessTestRoot) Validators() peer.IDSlice { return peer.IDSlice{r.installed} }
func (r *witnessTestRoot) IsStagedRoot(id string) bool {
	return id == r.joiner.String() && r.staged.Load()
}
func (r *witnessTestRoot) Witness([32]byte) ([]byte, error) { return r.witness, nil }

func TestWitnessServerServesStagedSuccessorRoots(t *testing.T) {
	incumbent := committeeTestPeer(t, nil)
	current := committeeTestPeer(t, nil)
	joiner := committeeTestPeer(t, nil)
	stranger := committeeTestPeer(t, nil)
	root := &witnessTestRoot{installed: current.ID(), joiner: joiner.ID(), witness: []byte("retained control witness")}
	t.Cleanup(serveWitnesses(incumbent, root))

	hash := sha256.Sum256(root.witness)
	fetch := func(client *network.Peer) ([]byte, error) {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return poswitness.Fetch(ctx, poswitness.FromLibp2p(client), []peer.ID{incumbent.ID()}, hash, poswitness.MaxWitnessBytes)
	}
	for _, client := range []*network.Peer{current, joiner, stranger} {
		client.Network().Peerstore().AddAddrs(incumbent.ID(), incumbent.MultiAddresses(), peerstore.PermanentAddrTTL)
	}

	got, err := fetch(current)
	require.NoError(t, err)
	require.Equal(t, root.witness, got)

	_, err = fetch(joiner)
	require.ErrorIs(t, err, poswitness.ErrUnavailable)

	root.staged.Store(true)
	got, err = fetch(joiner)
	require.NoError(t, err, "a staged successor must be able to follow before installation")
	require.Equal(t, root.witness, got)
	_, err = fetch(stranger)
	require.ErrorIs(t, err, poswitness.ErrUnavailable)

	root.staged.Store(false)
	_, err = fetch(joiner)
	require.ErrorIs(t, err, poswitness.ErrUnavailable, "clearing the stage revokes witness access")
}
