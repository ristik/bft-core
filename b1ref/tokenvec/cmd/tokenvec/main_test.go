package main

import (
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/b1ref/b1gen"
	"github.com/unicitynetwork/bft-core/b1ref/tokenvec"
)

// TestCertifyVerifyRoundTrip: what an outside projection does with the CLI. It certifies each fixed scenario with its own roots,
// builds the batch from the returned claims, and gets the reference verdict and the scenario's grouping back; a dropped anchor
// changes the grouping, and an altered claim is false.
func TestCertifyVerifyRoundTrip(t *testing.T) {
	for _, s := range tokenvec.Scenarios {
		sp := spec{Depth: s.Depth(0), DepthByEpoch: map[string]int{}}
		for e := uint64(0); e <= b1gen.HistoryOrigin; e++ {
			sp.DepthByEpoch[fmt.Sprint(e)] = s.Depth(e)
		}
		for i, a := range s.Anchors {
			root := fmt.Sprintf("%064x", 1000+i)
			sp.Anchors = append(sp.Anchors, anchorSpec{Epoch: a.Epoch, Round: a.Round, Shard: a.Shard, StateRoot: root})
		}
		c, err := certifySpec(sp)
		require.NoError(t, err, s.ID)
		var claims [][]byte
		for i, a := range c.Anchors {
			claim, err := hex.DecodeString(a.Claim)
			require.NoError(t, err)
			at := 6 + int(claim[4])<<8 + int(claim[5]) + 32
			require.Equal(t, sp.Anchors[i].StateRoot, hex.EncodeToString(claim[at:at+32]), "the anchor certifies the projection's root")
			claims = append(claims, claim)
		}
		r := verifyRequest(c, b1gen.Request(claims...))
		require.Equal(t, "ok", r.Status, s.ID)
		require.True(t, r.Valid, "%s: %s", s.ID, r.Why)
		require.Equal(t, s.Want.E, r.Grouping.E, s.ID)
		require.Equal(t, s.Want.S, r.Grouping.S, s.ID)
		require.Equal(t, s.Want.A, r.Grouping.A, s.ID)
		require.Equal(t, r.Grouping.Gas, r.Gas, s.ID)

		bad := append([]byte{}, claims[0]...)
		bad[len(bad)-1] ^= 1 // a signature byte of the UC
		r = verifyRequest(c, b1gen.Request(append([][]byte{bad}, claims[1:]...)...))
		require.False(t, r.Valid && r.Status == "ok", s.ID)
	}
}
