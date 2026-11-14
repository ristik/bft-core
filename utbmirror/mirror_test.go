package utbmirror

import (
	"context"
	"errors"
	"testing"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/peerstore"
	"github.com/stretchr/testify/require"

	testpeer "github.com/unicitynetwork/bft-core/internal/testutils/peer"
	"github.com/unicitynetwork/bft-core/network"
	"github.com/unicitynetwork/bft-core/utbstore"
)

// fakeStore models utbstore's rule: an entry is appended only as the authenticated successor of the tip (here: bytes "e<epoch>" and not
// marked forged), a replay of a held entry is not new.
type fakeStore struct{ entries [][]byte }

func entry(epoch uint64) []byte { return []byte{'e', byte(epoch)} }

func (s *fakeStore) Tip() utbstore.Tip { return utbstore.Tip{Epoch: uint64(len(s.entries))} }
func (s *fakeStore) Append(b []byte) (bool, error) {
	tip := uint64(len(s.entries))
	if len(b) != 2 || b[0] != 'e' {
		return false, errors.New("does not authenticate")
	}
	switch e := uint64(b[1]); {
	case e <= tip:
		return false, nil
	case e != tip+1:
		return false, utbstore.ErrGap
	}
	s.entries = append(s.entries, b)
	return true, nil
}
func (s *fakeStore) Range(from, _ uint64, maxEntries, _ int) ([][]byte, uint64, bool, error) {
	if from == 0 {
		from = 1
	}
	var out [][]byte
	for e := from; e <= uint64(len(s.entries)) && len(out) < maxEntries; e++ {
		out = append(out, s.entries[e-1])
	}
	if len(out) == 0 {
		return nil, 0, false, utbstore.ErrNotFound
	}
	return out, 0, false, nil
}

func mirrorPeer(t *testing.T, client *network.Peer, store Store) peer.ID {
	t.Helper()
	p := testpeer.CreatePeer(t, testpeer.CreatePeerConfiguration(t))
	p.RegisterProtocolHandler(Protocol, NewServer(store).Handler)
	client.Network().Peerstore().AddAddrs(p.ID(), p.MultiAddresses(), peerstore.PermanentAddrTTL)
	return p.ID()
}

func TestFollowerExtendsItsChainFromMirrorsOnly(t *testing.T) {
	full := &fakeStore{}
	for e := uint64(1); e <= 5; e++ {
		_, err := full.Append(entry(e))
		require.NoError(t, err)
	}
	client := testpeer.CreatePeer(t, testpeer.CreatePeerConfiguration(t))
	// a lying mirror serves a forged entry after the tip; an honest one serves the chain
	liar := mirrorPeer(t, client, &fakeStore{entries: [][]byte{entry(1), {'x', 2}}})
	honest := mirrorPeer(t, client, full)
	down := testpeer.CreatePeer(t, testpeer.CreatePeerConfiguration(t)).ID()
	mine := &fakeStore{entries: [][]byte{entry(1)}}
	f := &Follower{Store: mine, Host: client, Mirrors: func() []peer.ID { return []peer.ID{down, liar, honest} }}
	require.Equal(t, 4, f.Sync(context.Background()))
	require.EqualValues(t, 5, mine.Tip().Epoch)
	require.Zero(t, f.Sync(context.Background()), "nothing newer")
}
