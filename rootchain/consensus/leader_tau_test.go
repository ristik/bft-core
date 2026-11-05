package consensus

import (
	"bytes"
	"context"
	"os"
	"slices"
	"sync/atomic"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/stretchr/testify/require"

	"github.com/unicitynetwork/bft-core/network/protocol/abdrc"
)

// #886 gate 9, tau: the time of one unknown-leader round on real managers with durable stores, with every node holding no request, then with every node holding
// a retained one that its next-leader forwarding verifies on the manager loop. Measurement only, for 468 + 822*tau + R: it asserts no number. T does not enter an
// unknown round. Four roots share one machine, so a round here also pays for the other three. Set TMPDIR to the disk being measured. Set BFT_GATE9_TAU=1.
func TestTauOfAnUnknownLeaderRound(t *testing.T) {
	if os.Getenv("BFT_GATE9_TAU") == "" {
		t.Skip("set BFT_GATE9_TAU=1: a measurement, not a regression test")
	}
	const stretch = 120
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
	c.start(c.all()...)
	c.warm(3, c.all()...)
	drop.Store(true)
	head := func() uint64 {
		round, _, _ := c.nodes[0].r.manager.blockStore.LeaderHead()
		return round
	}
	lag := uint64(4*len(c.nodes) + 4)
	require.Eventually(t, func() bool { return c.state("H").Round > head()+lag+1 }, 3*time.Minute, 20*time.Millisecond, "the covered rounds time out")

	measure := func(label string) {
		var perRound []time.Duration
		from := c.state("H").Round
		last, at := from, time.Now()
		for last < from+stretch {
			if r := c.state("H").Round; r != last {
				now := time.Now()
				perRound = append(perRound, now.Sub(at)/time.Duration(r-last))
				last, at = r, now
			}
			time.Sleep(200 * time.Microsecond)
		}
		slices.Sort(perRound)
		t.Logf("%s: %d rounds, median %s, p95 %s, max %s, %d samples", label, stretch, perRound[len(perRound)/2], perRound[len(perRound)*95/100], perRound[len(perRound)-1], len(perRound))
	}
	measure("no request held")
	hash := bytes.Repeat([]byte{0x81}, 32)
	for _, n := range c.nodes {
		proof := phaseLockProof(t, c, n.r, hash)
		require.NotNil(t, proof, n.name)
		require.NoError(t, n.r.manager.RequestCertification(context.Background(), *proof))
	}
	measure("a retained request at every node")
	require.False(t, c.certifiedHash("H", hash), "the rounds stayed unknown")
}
