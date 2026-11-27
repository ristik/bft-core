package cmd

import (
	"fmt"
	"math/big"
	"testing"

	ethcommon "github.com/ethereum/go-ethereum/common"
	ethcrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/stretchr/testify/require"

	"github.com/unicitynetwork/bft-core/vrclient"
	"github.com/unicitynetwork/bft-core/vrclient/vrfake"
)

// #1316: the election-participation gate of `pos-publish --participate`.
func TestPosParticipationGate(t *testing.T) {
	owner := ethcommon.Address{0x0a}
	bonded := custodyPosition{Owner: owner, Generation: 1, OpenLots: 1, LotCount: 1}
	retiring := bonded
	retiring.RetirementRequested = true
	matured := bonded
	matured.OpenLots = 0
	for name, c := range map[string]struct {
		st   posParticipationState
		want string // a substring of the reason; empty: the identity takes part
	}{
		"a bonded member":                   {st: posParticipationState{ID: 5, Position: bonded}},
		"retirement requested":              {st: posParticipationState{ID: 5, Position: retiring}, want: "requested retirement"},
		"retirement requested and excluded": {st: posParticipationState{ID: 5, Position: retiring, Excluded: true}, want: "requested retirement"},
		"excluded by evidence":              {st: posParticipationState{ID: 5, Position: bonded, Excluded: true}, want: "excluded by evidence"},
		"the bond matured":                  {st: posParticipationState{ID: 5, Position: matured}, want: "no open lots"},
		"unknown to custody":                {st: posParticipationState{ID: 5}, want: "custody knows no identity 5"},
	} {
		t.Run(name, func(t *testing.T) {
			got := planPosParticipation(c.st)
			if c.want == "" {
				require.Empty(t, got.Reason)
				return
			}
			require.Contains(t, got.Reason, c.want)
		})
	}
}

// A retired or excluded identity's `pos-publish --participate` sends nothing, not even for an open result that froze it, and exits 0 (the
// container's participation loop keeps polling); a bonded member passes the gate.
func TestPosPublishParticipateSendsNothingForALeavingIdentity(t *testing.T) {
	rid := [32]byte{0x77}
	setup := func(t *testing.T, edit func(*vrfake.Position)) (*vrfake.Chain, string, []string) {
		chain, url := fakeNetwork(t)
		home := initHome(t, url)
		v, keys := loadHome(t, home)
		operator := ethcrypto.PubkeyToAddress(keys.Operator.PublicKey)
		chain.Fund(operator, big.NewInt(1e18))
		reg, _, _, err := registration(v, keys, 0)
		require.NoError(t, err)
		id := chain.AddMember(operator, reg)
		chain.With(func(c *vrfake.Chain) {
			c.Tag = vrclient.ModuleTagPoS
			c.Custody = ethcommon.Address{0xc1}
			c.Election = ethcommon.Address{0xe1}
			c.Evidence = ethcommon.Address{0xe2}
			c.Pos = vrfake.NewPos()
			p := &vrfake.Position{RootKeyHash: [32]byte(ethcrypto.Keccak256(reg.RootKey)), Generation: 1, OpenLots: 1}
			edit(p)
			c.Pos.Positions[id] = p
			c.Pos.OpenResult = rid
			c.Pos.Frozen = []vrclient.FrozenMember{{Id: id, Generation: 1, Weight: 1, Raw: 1}}
		})
		return chain, home, []string{"pos-publish", "--participate", "--result", ethcommon.Hash(rid).Hex(), "--proof-member", fmt.Sprint(id)}
	}
	for name, c := range map[string]struct {
		edit func(*vrfake.Position)
		want string
	}{
		"retirement requested": {func(p *vrfake.Position) { p.RetirementRequested = true }, "requested retirement"},
		"excluded by evidence": {func(p *vrfake.Position) { p.Excluded = true }, "excluded by evidence"},
		"matured":              {func(p *vrfake.Position) { p.OpenLots = 0 }, "no open lots"},
	} {
		t.Run(name, func(t *testing.T) {
			chain, home, args := setup(t, c.edit)
			out, err := runValidator(t, home, args...)
			require.NoError(t, err, out)
			require.Contains(t, out, "no election transactions: identity")
			require.Contains(t, out, c.want)
			require.Zero(t, chain.Sends(), out)
		})
	}
	t.Run("a bonded member passes the gate", func(t *testing.T) {
		chain, home, args := setup(t, func(*vrfake.Position) {})
		out, err := runValidator(t, home, args...)
		require.ErrorContains(t, err, "popHash", "past the gate it reads its proof slot (the fake does not model it): %s", out)
		require.NotContains(t, out, "no election transactions", "the gate lets a bonded member submit its proof")
		require.Zero(t, chain.Sends(), "nothing is sent")
	})
}
