package configuredadmission

import (
	"testing"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/stretchr/testify/require"
)

type movingPeers struct{ set []peer.ID }

func (m *movingPeers) Peers() []peer.ID { return m.set }

// The journal suffix providers are asked from the active assignment at the time they are needed, not from the list fixed at startup.
func TestJournalSuffixProvidersFollowTheSource(t *testing.T) {
	genesis := []peer.ID{"B", "C"}
	r := &ExecutionRecovery{Providers: genesis}
	require.Equal(t, genesis, r.providerList(), "a deployment with a fixed list is unchanged")

	src := &movingPeers{set: []peer.ID{"B", "C"}}
	r.ProviderSource = src
	require.Equal(t, []peer.ID{"B", "C"}, r.providerList())
	src.set = []peer.ID{"E", "F", "G"}
	require.Equal(t, []peer.ID{"E", "F", "G"}, r.providerList(), "after a rotation the successors are asked")
	src.set = nil
	require.Empty(t, r.providerList(), "the source wins even when it is empty: the fixed list is not a fallback to a retired set")
}
