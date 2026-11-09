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

// #976 probe: what happens when the shard's request is lost at every root (never retained anywhere).
func TestProbeIngressLossRecoversThroughTheT2Repeat(t *testing.T) {
	c := newPhaseLockLive(t, 2*time.Second)
	c.start(c.all()...)
	c.warm(8, c.all()...)
	m := func(name string) *ConsensusManager { return c.nodes[c.idx(name)].r.manager }
	seal := func() (uint64, []byte) {
		si := m("H").blockStore.ShardInfo(q3fixture.PartitionID, types.ShardID{})
		if si == nil || si.LastCR == nil {
			return 0, nil
		}
		return si.LastCR.UC.UnicitySeal.RootChainRoundNumber, si.LastCR.UC.InputRecord.Hash
	}
	// first certificate for the shard so there is a pending state
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
	s0, h0 := seal()
	r0 := c.state("H").Round
	t0 := time.Now()
	t.Logf("certified at seal %d (root round %d); now the next request is lost at every root: nothing is submitted", s0, r0)
	require.Eventually(t, func() bool { s, _ := seal(); return s > s0 }, 5*time.Minute, 100*time.Millisecond)
	s1, h1 := seal()
	t.Logf("a new certificate for the shard at seal %d after %s and %d root rounds; same input record hash as before: %v", s1, time.Since(t0).Round(100*time.Millisecond), c.state("H").Round-r0, bytes.Equal(h0, h1))
	hash1 := bytes.Repeat([]byte{0x91}, 32)
	t1 := time.Now()
	r1 := c.state("H").Round
	require.Eventually(t, func() bool {
		if c.certifiedHash("H", hash1) {
			return true
		}
		if p := phaseLockProof(t, c, c.nodes[0].r, hash1); p != nil {
			_ = m("H").RequestCertification(context.Background(), *p)
		}
		return false
	}, 2*time.Minute, 200*time.Millisecond)
	t.Logf("the fresh request, sent after the repeat, certified after %s and %d root rounds", time.Since(t1).Round(100*time.Millisecond), c.state("H").Round-r1)
}
