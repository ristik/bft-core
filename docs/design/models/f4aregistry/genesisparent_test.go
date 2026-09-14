package f4aregistry

import (
	"bytes"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
)

/*
Genesis as the initial certified parent (§7.3).

The certified parent of an authorized round is the last certified block that changed state. Before any
post-genesis block has been certified, that is the authenticated EVM genesis block, for EVERY authorized
round, not only round 1: a root timeout advances the technical-record round without certifying a block
(ShardInfo.nextRound with a nil request), so the first payload can be authorized for round 2 or later
while genesis is still its parent.

Eligibility is established from authenticated evidence, never from the round number and never from a
state-root comparison alone:

  - the bound certificate's input record is genesis history: it names no block (h_b null), its state
    and previous state are the pinned genesis commitment, and its round is below the authorized round.
    That covers the genesis installation record, repeats of it after timeouts, and quiet records that
    extend it;
  - the parent header is the pinned EVM genesis block, by hash and number;
  - the registry proven at that parent (§7.3) has executed no round.
*/

var (
	errGenesisInstallation   = errors.New("authorized round 0 is genesis installation, not a payload")
	errNotGenesisHistory     = errors.New("the bound certificate does not show genesis history")
	errParentNotGenesisBlock = errors.New("the parent header is not the pinned EVM genesis block")
	errRegistryNotAtGenesis  = errors.New("the registry at the parent has executed a round")
)

// inputRecord is the part of a certified input record this rule reads. BlockHash nil means null.
type inputRecord struct {
	Round     uint64
	PrevHash  []byte
	Hash      []byte
	BlockHash []byte
}

type parentEvidence struct {
	AuthorizedRound uint64
	BoundIR         inputRecord // from the authenticated, block-bound certificate
	ParentHash      []byte      // recomputed from the parent header (§7.3 step 1)
	ParentNumber    uint64
	// From the registry proof at the parent (§7.3 steps 2 to 5).
	RegistryRoundAuthorized uint64
	RegistryCertifiedRound  uint64
}

type genesisParentPins struct {
	GenesisState   []byte // the pinned genesis state commitment carried by the genesis input record
	EVMGenesisHash []byte // evmGenesisHash
}

func genesisParentEligible(e parentEvidence, p genesisParentPins) error {
	if e.AuthorizedRound == 0 {
		return errGenesisInstallation
	}
	ir := e.BoundIR
	if ir.BlockHash != nil || ir.Round >= e.AuthorizedRound ||
		!bytes.Equal(ir.Hash, p.GenesisState) || !bytes.Equal(ir.PrevHash, p.GenesisState) {
		return errNotGenesisHistory
	}
	if !bytes.Equal(e.ParentHash, p.EVMGenesisHash) || e.ParentNumber != 0 {
		return errParentNotGenesisBlock
	}
	if e.RegistryRoundAuthorized != 0 || e.RegistryCertifiedRound != 0 {
		return errRegistryNotAtGenesis
	}
	return nil
}

// roundOneRule is the rule the first revision stated ("evmGenesisHash for n = 1"). It is kept only to
// show the stranding it causes.
func roundOneRule(e parentEvidence) bool { return e.AuthorizedRound == 1 }

var (
	s0 = bytes.Repeat([]byte{0x50}, 32) // genesis state commitment
	s1 = bytes.Repeat([]byte{0x51}, 32)
	b1 = bytes.Repeat([]byte{0xb1}, 32)
	g0 = bytes.Repeat([]byte{0x60}, 32) // evmGenesisHash

	parentPins = genesisParentPins{GenesisState: s0, EVMGenesisHash: g0}
)

func atGenesis(n uint64, ir inputRecord) parentEvidence {
	return parentEvidence{AuthorizedRound: n, BoundIR: ir, ParentHash: g0, ParentNumber: 0}
}

func TestGenesisParentDoesNotDependOnRoundOne(t *testing.T) {
	installed := inputRecord{Round: 0, PrevHash: s0, Hash: s0}
	quietAtGenesis := inputRecord{Round: 1, PrevHash: s0, Hash: s0}

	for name, e := range map[string]parentEvidence{
		"installed genesis, first payload authorized for round 1":                  atGenesis(1, installed),
		"one initial timeout: repeat of the genesis record, first payload round 2": atGenesis(2, installed),
		"three initial timeouts: first payload round 4":                            atGenesis(4, installed),
		"quiet certified round 1 still at genesis state, first payload round 2":    atGenesis(2, quietAtGenesis),
	} {
		t.Run(name, func(t *testing.T) {
			require.NoError(t, genesisParentEligible(e, parentPins))
			if e.AuthorizedRound != 1 {
				require.False(t, roundOneRule(e), "a round-1 rule would leave this payload with no permitted parent")
			}
		})
	}
}

func TestGenesisParentRefusals(t *testing.T) {
	installed := inputRecord{Round: 0, PrevHash: s0, Hash: s0}

	premise := atGenesis(2, installed)
	require.NoError(t, genesisParentEligible(premise, parentPins), "premise: the unmodified evidence is eligible")

	for name, c := range map[string]struct {
		e    parentEvidence
		want error
	}{
		"authorized round 0 is installation": {atGenesis(0, installed), errGenesisInstallation},
		"the certificate names a post-genesis block": {
			atGenesis(2, inputRecord{Round: 1, PrevHash: s0, Hash: s1, BlockHash: b1}), errNotGenesisHistory},
		// Only the block-hash condition refuses this record: its states are both the genesis commitment.
		// sealRegistry/v1 cannot produce it, because every successful block changes registry storage,
		// but E2 is stated on the record, and the supporting property is not a check.
		"a record naming a block at the genesis state": {
			atGenesis(2, inputRecord{Round: 1, PrevHash: s0, Hash: s0, BlockHash: b1}), errNotGenesisHistory},
		"a quiet record after a successful block": {
			atGenesis(3, inputRecord{Round: 2, PrevHash: s1, Hash: s1}), errNotGenesisHistory},
		"a record whose previous state is not genesis": {
			atGenesis(3, inputRecord{Round: 2, PrevHash: s1, Hash: s0}), errNotGenesisHistory},
		"the certified round is not below the authorized round": {
			atGenesis(2, inputRecord{Round: 2, PrevHash: s0, Hash: s0}), errNotGenesisHistory},
		"the parent header is another block": {
			func() parentEvidence { e := premise; e.ParentHash = b1; return e }(), errParentNotGenesisBlock},
		"the parent header number is not zero": {
			func() parentEvidence { e := premise; e.ParentNumber = 1; return e }(), errParentNotGenesisBlock},
		"state equality alone: the registry at the parent has executed a round": {
			func() parentEvidence { e := premise; e.RegistryRoundAuthorized = 1; return e }(), errRegistryNotAtGenesis},
		"the registry at the parent names a certified round": {
			func() parentEvidence { e := premise; e.RegistryCertifiedRound = 1; return e }(), errRegistryNotAtGenesis},
	} {
		t.Run(name, func(t *testing.T) {
			require.ErrorIs(t, genesisParentEligible(c.e, parentPins), c.want)
		})
	}
}
