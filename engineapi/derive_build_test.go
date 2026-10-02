package engineapi

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"reflect"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/unicitynetwork/bft-core/rootinput"
	"github.com/unicitynetwork/bft-go-base/types"
)

func TestBlockSizeIsUnchangedByTheCompanion(t *testing.T) {
	payload := samplePayload()
	without, err := EncodeBlock(payload)
	require.NoError(t, err)
	with, err := EncodeBlockWithSealCompanion(payload, sampleCompanion())
	require.NoError(t, err)

	require.Equal(t, without.BlockSize, with.BlockSize,
		"the companion is envelope-only and must not enter BlockSize")
	require.Greater(t, len(with.Raw), len(without.Raw), "but it must be in the envelope")
}

func TestAdapterV2DoesNotWarnAboutTheLegacyCursor(t *testing.T) {
	f := newDerivationFixture(t)

	var unactivated bytes.Buffer
	_ = NewAdapter(Config{EngineURL: "http://127.0.0.1:1", EthURL: "http://127.0.0.1:1", Secret: Secret{}, Verifier: f.verifier(CursorNotActivated())},
		slog.New(slog.NewTextHandler(&unactivated, nil)))
	require.Empty(t, unactivated.String(), "v2 reads the cursor from the verified parent snapshot")

	// An activated cursor is not a warning.
	var committed bytes.Buffer
	_ = NewAdapter(Config{EngineURL: "http://127.0.0.1:1", EthURL: "http://127.0.0.1:1", Secret: Secret{}, Verifier: f.verifier(CommittedCursor(50))},
		slog.New(slog.NewTextHandler(&committed, nil)))
	require.Empty(t, committed.String(), "an activated cursor logs nothing")

	// An adapter with no derivation context (the doctor's) does not log a cursor decision at all.
	var doctor bytes.Buffer
	_ = NewAdapter(Config{EngineURL: "http://127.0.0.1:1", EthURL: "http://127.0.0.1:1", Secret: Secret{}},
		slog.New(slog.NewTextHandler(&doctor, nil)))
	require.Empty(t, doctor.String(), "no verifier context, nothing to say about a cursor")
}

// TestPayloadAttributesHaveNoExtraDataAndTheCommitmentIsCheckable is the rootinput
// wiring-contract §5/§10-5 case, relocated here because it asserts on this package's types and
// engineapi now imports rootinput (which would make importing engineapi from a rootinput test a
// cycle).
func TestPayloadAttributesHaveNoExtraDataAndTheCommitmentIsCheckable(t *testing.T) {
	f := newDerivationFixture(t)
	uc, tr := f.cert(t, 4, 5, 50)
	res, err := rootinput.Derive(context.Background(), rootinput.Context{
		NetworkID: fixtureNetworkID, PartitionID: fixturePartitionID, ShardID: types.ShardID{},
		ShardConfHash: f.confHash, TrustBases: fixtureTrustBases{tb: f.tb},
		Round: 5, ParentHash: f.parent, LastAppliedRootRound: 0,
	}, uc, tr)
	require.NoError(t, err)

	// The import-side check, as a pure comparison: a payload carrying the commitment passes, one
	// carrying anything else does not.
	payload := ExecutionPayloadV3{ExtraData: res.Commitment[:]}
	require.True(t, bytes.Equal(payload.ExtraData, res.Commitment[:]))

	other := ExecutionPayloadV3{ExtraData: bytes.Repeat([]byte{0x00}, 32)}
	require.False(t, bytes.Equal(other.ExtraData, res.Commitment[:]), "a mismatching commitment is detectable")

	// A payload built through the stock attributes carries NOTHING to compare: PayloadAttributesV3
	// has no extraData field, so a builder using the standard Engine API cannot ask for the
	// commitment to be written. Enforcing the check without the provision mechanism would halt the
	// builder rather than protect it, which is why the build path routes through the seal sibling.
	empty := ExecutionPayloadV3{}
	require.Empty(t, empty.ExtraData)
	require.False(t, bytes.Equal(empty.ExtraData, res.Commitment[:]))

	// If a later Engine API revision adds the field, this assertion is what should fail.
	var names []string
	rt := reflect.TypeOf(PayloadAttributesV3{})
	for i := 0; i < rt.NumField(); i++ {
		names = append(names, rt.Field(i).Name)
	}
	require.NotContains(t, names, "ExtraData",
		"PayloadAttributesV3 must still have no extraData field, or §5's dependency has changed")
}

// TestAdapter_RequireSealCapabilitiesTurnsTheStartupCheckOn pins that the adapter exposes the
// requirement the node's executor wiring turns on: a stock client must fail startup once the build
// path uses the seal siblings.
func TestAdapter_RequireSealCapabilitiesTurnsTheStartupCheckOn(t *testing.T) {
	engine := newMockReth(t, Secret{})
	engine.on("engine_exchangeCapabilities", func(json.RawMessage) (any, *rpcError) {
		return requiredCapabilities, nil // a stock client, no seal siblings
	})
	a, closeFn := newTestAdapter(t, engine, newMockReth(t, Secret{}))
	defer closeFn()

	require.NoError(t, a.CheckCapabilities(context.Background()), "not required until the executor opts in")

	a.RequireSealCapabilities()
	err := a.CheckCapabilities(context.Background())
	require.Error(t, err)
	for _, m := range sealCapabilities {
		require.Contains(t, err.Error(), m, "every absent seal sibling is named")
	}
}
