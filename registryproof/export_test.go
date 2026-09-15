package registryproof

import (
	"testing"

	"github.com/ethereum/go-ethereum/common"
)

// FixtureBlock is one block of the §9 fixture chain, for tests outside the package.
type FixtureBlock struct {
	Hash     common.Hash
	Evidence Evidence
}

// FixtureChain exposes the §9 fixture chain to snapshot_boundary_test.go, which runs as an external
// package so that it can only use what callers of registryproof can use.
func FixtureChain(t testing.TB) (ctx Context, genesis, b1, b2 FixtureBlock) {
	c := newChain(t)
	return c.context(), FixtureBlock{c.genesis.hash, c.genesis.ev}, FixtureBlock{c.b1.hash, c.b1.ev}, FixtureBlock{c.b2.hash, c.b2.ev}
}

// GenesisState is the fixture's genesis state commitment.
func GenesisState() []byte { return named("S0").Bytes() }
