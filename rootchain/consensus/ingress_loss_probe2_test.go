package consensus

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-go-base/types"

	"github.com/unicitynetwork/bft-core/internal/testutils/q3fixture"
)

func TestProbeSoleHolderRestart(t *testing.T) {
	for _, restart := range []bool{false, true} {
		name := "holder kept"
		if restart {
			name = "holder restarted"
		}
		t.Run(name, func(t *testing.T) {
			c := newPhaseLockLive(t, 2*time.Second)
			c.start(c.all()...)
			c.warm(8, c.all()...)
			m := func(n string) *ConsensusManager { return c.nodes[c.idx(n)].r.manager }
			seal := func() uint64 {
				si := m("H").blockStore.ShardInfo(q3fixture.PartitionID, types.ShardID{})
				if si == nil || si.LastCR == nil {
					return 0
				}
				return si.LastCR.UC.UnicitySeal.RootChainRoundNumber
			}
			hash0 := bytes.Repeat([]byte{0x90}, 32)
			require.Eventually(t, func() bool {
				if c.certifiedHash("H", hash0) {
					return true
				}
				if p := phaseLockProof(t, c, c.nodes[0].r, hash0); p != nil {
					_ = m("H").RequestCertification(context.Background(), *p)
				}
				return false
			}, 2*time.Minute, 200*time.Millisecond)
			s0 := seal()
			c.stop("a")
			c.stop("b")
			c.stop("c")
			hash1 := bytes.Repeat([]byte{0x91}, 32)
			p := phaseLockProof(t, c, c.nodes[0].r, hash1)
			require.NotNil(t, p)
			require.NoError(t, m("H").RequestCertification(context.Background(), *p))
			t.Logf("the request is held by H alone (a, b, c are down); H restarted: %v", restart)
			if restart {
				c.restart("H")
			}
			t0 := time.Now()
			r0 := c.state("H").Round
			c.start("a", "b", "c")
			require.Eventually(t, func() bool { return seal() > s0 }, 5*time.Minute, 100*time.Millisecond)
			t.Logf("first new certificate for the shard after %s / %d rounds; it is the submitted request: %v", time.Since(t0).Round(100*time.Millisecond), c.state("H").Round-r0, c.certifiedHash("H", hash1))
		})
	}
}
