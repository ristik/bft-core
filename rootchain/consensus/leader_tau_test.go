package consensus

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"slices"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-go-base/types"

	"github.com/unicitynetwork/bft-core/internal/testutils/q3fixture"
	"github.com/unicitynetwork/bft-core/network/protocol/abdrc"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/leader"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/storage"
)

// onLoopResolver runs a test's one action on the manager's loop: judgeRetained resolves a certify view there, every round, for every retained entry.
type onLoopResolver struct {
	ViewResolver
	action atomic.Pointer[func()]
}

func (r *onLoopResolver) ResolveView(partition types.PartitionID, shard types.ShardID, round uint64, purpose storage.RequestPurpose) (*storage.RequestRoundView, error) {
	if purpose == storage.PurposeCertify {
		if f := r.action.Swap(nil); f != nil {
			(*f)()
		}
	}
	return r.ViewResolver.ResolveView(partition, shard, round, purpose)
}

// #886 gate 9, tau: the time of one unknown-leader round on real managers with durable stores, with every node holding no retained request, then one, then several
// that its next-leader forwarding verifies on the manager loop. Measurement only, for 468 + 822*tau + R: the mean decides that total. It asserts the shape of the
// sample, no number: no sampled round lies in a recovery run, whose known leader with proposals dropped takes the full timer, and every node still holds its entries
// after each row. T does not enter an unknown round. The fixture has one shard, so the extra entries of a row are the shard's request under other keys, and an unknown
// round sends none of them. Each is four signed requests with no configured consistency proof (no proof_type, so NoOpVerifier, and no ZkProof): the rows time no proof
// verification, which judgeRetained would also run every round per entry on a proof-verifying shard. Four roots share one machine, so a round here also pays for the other
// three. Set TMPDIR to the disk being measured. Set BFT_GATE9_TAU=1, and BFT_TAU_ROUNDS for more than 120 rounds a row.
func TestTauOfAnUnknownLeaderRound(t *testing.T) {
	if os.Getenv("BFT_GATE9_TAU") == "" {
		t.Skip("set BFT_GATE9_TAU=1: a measurement, not a regression test")
	}
	rounds := uint64(120)
	if v := os.Getenv("BFT_TAU_ROUNDS"); v != "" {
		var err error
		rounds, err = strconv.ParseUint(v, 10, 64)
		require.NoError(t, err)
	}
	c := newPhaseLockLive(t, 2*time.Second)
	var drop atomic.Bool
	base := c.net.filter
	c.net.filter = func(from, to peer.ID, msg any) bool {
		if drop.Load() {
			switch msg.(type) {
			case *abdrc.ProposalMsg, *abdrc.VoteMsg:
				return true
			}
		}
		return base(from, to, msg)
	}
	resolvers := make([]*onLoopResolver, len(c.nodes))
	for i, n := range c.nodes {
		resolvers[i] = &onLoopResolver{ViewResolver: n.r.manager.viewResolver}
		n.r.manager.SetViewResolver(resolvers[i])
	}
	c.start(c.all()...)
	c.warm(3, c.all()...)
	drop.Store(true)
	head := func() uint64 {
		round, _, _ := c.nodes[0].r.manager.blockStore.LeaderHead()
		return round
	}
	lag := uint64(4*len(c.nodes) + 4)
	require.Eventually(t, func() bool { return c.state("H").Round > head()+lag+1 }, 3*time.Minute, 20*time.Millisecond, "the covered rounds time out")

	selector, ok := c.nodes[0].r.manager.leaderSelector.(*leader.EpochReputation)
	require.True(t, ok)
	inRun := func(round uint64) bool {
		for k := uint64(0); k < leader.RecoveryRun; k++ {
			if round >= k && selector.RecoveryRunStart(round-k) {
				return true
			}
		}
		return false
	}
	// A clean stretch of at most this many rounds fits between two runs: 256 rounds apart, four slots each.
	const longest = 240
	measure := func(label string) {
		var perRound []time.Duration
		var total time.Duration
		done := uint64(0)
		for done < rounds {
			chunk := min(rounds-done, longest)
			clean := func(from uint64) bool {
				for r := from; r < from+chunk+2; r++ {
					if inRun(r) {
						return false
					}
				}
				return true
			}
			require.Eventually(t, func() bool { return clean(c.state("H").Round) }, 2*time.Minute, 200*time.Microsecond, "a clean stretch comes round")
			from := c.state("H").Round
			last, at := from, time.Now()
			for last < from+chunk {
				if r := c.state("H").Round; r != last {
					now := time.Now()
					for k := last; k < r; k++ {
						require.False(t, inRun(k), "round %d of a sample is in a recovery run", k)
					}
					perRound = append(perRound, now.Sub(at)/time.Duration(r-last))
					total += now.Sub(at)
					last, at = r, now
				}
				time.Sleep(200 * time.Microsecond)
			}
			done += last - from
		}
		slices.Sort(perRound)
		q := func(f float64) time.Duration {
			return perRound[int(float64(len(perRound))*f)].Round(10 * time.Microsecond)
		}
		over := 0
		for _, d := range perRound {
			if d > 60100*time.Microsecond { // the design's sufficient tau for the 75 s rescue
				over++
			}
		}
		t.Logf("%s: %d rounds, mean %s, median %s, p95 %s, p99 %s, p99.9 %s, max %s, %d samples, %d over 60.1 ms", label, done, (total / time.Duration(done)).Round(10*time.Microsecond),
			q(.5), q(.95), q(.99), q(.999), perRound[len(perRound)-1], len(perRound), over)
	}
	// onLoop counts every node's retained entries on its own loop, first topping them up to the given number if top is set, and fails on any other count: a dropped entry
	// would flatter a row.
	onLoop := func(top bool, entries int) {
		key := types.PartitionShardID{PartitionID: q3fixture.PartitionID, ShardID: types.ShardID{}.Key()}
		for i, n := range c.nodes {
			m := n.r.manager
			held := make(chan int, 1)
			f := func() {
				if entry := m.retained[key]; top && entry != nil {
					for extra := len(m.retained); extra < entries; extra++ {
						m.retained[types.PartitionShardID{PartitionID: q3fixture.PartitionID + types.PartitionID(extra), ShardID: key.ShardID}] = &retainedRequest{msg: entry.msg}
					}
				}
				held <- len(m.retained)
			}
			resolvers[i].action.Store(&f)
			select {
			case got := <-held:
				require.Equal(t, entries, got, n.name)
			case <-time.After(time.Minute):
				require.Fail(t, "the manager's loop judged nothing", n.name)
			}
		}
	}
	measure("no request held")
	hash := bytes.Repeat([]byte{0x81}, 32)
	for _, n := range c.nodes {
		proof := phaseLockProof(t, c, n.r, hash)
		require.NotNil(t, proof, n.name)
		require.NoError(t, n.r.manager.RequestCertification(context.Background(), *proof))
	}
	for _, entries := range []int{1, 4, 16} {
		onLoop(true, entries)
		measure(fmt.Sprintf("%d retained entries at every node", entries))
		onLoop(false, entries)
	}
	require.False(t, c.certifiedHash("H", hash), "the rounds stayed unknown")
}
