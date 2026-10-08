package cmd

import (
	"errors"
	"testing"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/stretchr/testify/require"
)

func TestFetchFromRootPeers(t *testing.T) {
	a, b, c := peer.ID("peer-a"), peer.ID("peer-b"), peer.ID("peer-c")
	peers := []peer.AddrInfo{{ID: a}, {ID: b}, {ID: c}}
	errA, errB, errC := errors.New("not found"), errors.New("protocols not supported"), errors.New("stream reset")

	t.Run("the first peer that answers wins and later peers are not asked", func(t *testing.T) {
		var asked []peer.ID
		got, err := fetchFromRootPeers(peers, func(id peer.ID) (string, error) {
			asked = append(asked, id)
			if id == a {
				return "", errA
			}
			return "bundle from " + string(id), nil
		})
		require.NoError(t, err)
		require.Equal(t, "bundle from peer-b", got)
		require.Equal(t, []peer.ID{a, b}, asked)
	})

	t.Run("when none answers every peer's id and cause is reported and stays matchable", func(t *testing.T) {
		causes := map[peer.ID]error{a: errA, b: errB, c: errC}
		_, err := fetchFromRootPeers(peers, func(id peer.ID) (string, error) { return "", causes[id] })
		require.Error(t, err)
		for id, cause := range causes {
			require.ErrorIs(t, err, cause)
			require.ErrorContains(t, err, "peer "+id.String()+": "+cause.Error())
		}
	})

	t.Run("no peers is its own refusal", func(t *testing.T) {
		_, err := fetchFromRootPeers(nil, func(peer.ID) (string, error) { t.Fatal("asked a peer that does not exist"); return "", nil })
		require.ErrorIs(t, err, errNoInstallPeers)
	})
}
