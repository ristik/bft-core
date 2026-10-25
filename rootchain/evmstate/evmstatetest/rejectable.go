package evmstatetest

import (
	"context"
	"encoding/json"
	"os"
	"testing"

	ethcrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/stretchr/testify/require"

	"github.com/unicitynetwork/bft-core/rootchain/consensus/storage"
	"github.com/unicitynetwork/bft-core/rootchain/evmstate"
)

// Rejectable is the fixture's result in a real state with the three accounts a RejectResult proves: Election and custody as the contracts
// left them, and the registry both name, at a given canonical progress. ElectionAttempt is the election's own attempt counter, which no
// root attempt is compared with (contracts#73).
type Rejectable struct {
	Pins            evmstate.Pins
	StateRoot       [32]byte
	ResultID        [32]byte
	Witness         []byte
	Facts           storage.RejectFacts
	ElectionAttempt uint64
}

// LoadRejectable builds the state of the fixture at path in scenario "reserved", "reservedLost" (marked lost before any publication),
// "published" or "lost" (published, then marked lost), with
// the registry at progress, and the witness BuildRejectWitness gathers from it.
func LoadRejectable(t testing.TB, path, scenario string, progress uint64) *Rejectable {
	t.Helper()
	raw, err := os.ReadFile(path)
	require.NoError(t, err)
	var fx fixture
	require.NoError(t, json.Unmarshal(raw, &fx))

	r := &Rejectable{ResultID: word(t, fx.ResultID), ElectionAttempt: fx.Attempt}
	r.Pins.NetworkWord = word(t, fx.Deployment.NetworkWord)
	copy(r.Pins.Custody[:], unhex(t, fx.Deployment.Custody))
	copy(r.Pins.Election[:], unhex(t, fx.Deployment.Election))
	r.Pins.CustodyCode = [32]byte(ethcrypto.Keccak256Hash([]byte("custody code")))
	r.Pins.ElectionCode = [32]byte(ethcrypto.Keccak256Hash([]byte("election code")))
	r.Pins.RegistryCode = [32]byte(ethcrypto.Keccak256Hash([]byte("registry code")))

	election, custody := map[[32]byte][32]byte{}, map[[32]byte][32]byte{}
	into := func(m map[[32]byte][32]byte, rd reads) {
		require.Len(t, rd.Words, len(rd.Slots))
		for i := range rd.Slots {
			m[word(t, rd.Slots[i])] = word(t, rd.Words[i])
		}
	}
	switch scenario {
	case "reserved":
		into(election, fx.Reserved)
	case "reservedLost":
		into(election, fx.ReservedLost)
	case "published":
		into(election, fx.Published)
	case "lost":
		into(election, fx.Lost)
	default:
		t.Fatalf("no scenario %q", scenario)
	}
	for _, rd := range fx.ElectionReads {
		into(election, rd)
	}
	for _, rd := range fx.CustodyReads {
		into(custody, rd)
	}
	var roots [32]byte
	roots[31] = 4 // ElectionPolicy.roots
	registry := election[roots]
	copy(r.Pins.Registry[:], registry[12:])
	progressKey := [32]byte(ethcrypto.Keccak256Hash([]byte("unicity.seal-registry/records.progress")))
	var p [32]byte
	for i := 0; i < 8; i++ {
		p[31-i] = byte(progress >> (8 * i))
	}
	w := newWorld(t,
		contract{addr: r.Pins.Election, codeHash: r.Pins.ElectionCode, storage: election},
		contract{addr: r.Pins.Custody, codeHash: r.Pins.CustodyCode, storage: custody},
		contract{addr: r.Pins.Registry, codeHash: r.Pins.RegistryCode, storage: map[[32]byte][32]byte{progressKey: p}})
	r.StateRoot = w.root
	r.Witness, r.Facts, err = evmstate.BuildRejectWitness(context.Background(), w, r.Pins, r.ResultID)
	require.NoError(t, err)
	verified, err := evmstate.Authority{Pins: r.Pins}.VerifyReject(r.Witness, r.StateRoot, r.ResultID)
	require.NoError(t, err)
	require.Equal(t, verified, r.Facts)
	return r
}
