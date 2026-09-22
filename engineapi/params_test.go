package engineapi

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/unicitynetwork/bft-core/evmroot"
)

// mustHex is a test helper for building fixed-length byte slices from a hex
// literal without inline error handling cluttering every case below.
func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	require.NoError(t, err)
	return b
}

// rootInputAt builds the minimal evmroot.RootInput DeriveAttributes reads. Only
// the authorized round and the two certified fields on the origin matter to the
// derivation, so this is not a valid root input — it is the exact input surface
// of the function under test.
func rootInputAt(rootRound, shardRound, referenceTime uint64) evmroot.RootInput {
	return evmroot.RootInput{
		Round:  shardRound,
		Origin: evmroot.RootOrigin{RootRound: rootRound, ReferenceTime: referenceTime},
	}
}

// Golden vectors below were computed independently of this package with a
// standalone script that builds the v1 CBOR preimage by hand and hashes it
// (hashlib.sha256), not by calling evmroot. Each case names the (rootRound,
// shardRound) pair that produced it. The (104, 57) case is the pair
// evmroot/testdata/vectors.json commits, so it ties this file to the accepted
// v1 vectors rather than to this package's own output.
func TestDeriveAttributes_GoldenVectors(t *testing.T) {
	cases := []struct {
		name           string
		ri             evmroot.RootInput
		parent         ParentHeader
		wantTimestamp  uint64
		wantPrevRandao string
		wantBeaconRoot string
	}{
		{
			// (rootRound=104, shardRound=1); reference time 1000 wins over parent+1 (501).
			name:           "rootRound 104, shardRound 1, parent behind reference time",
			ri:             rootInputAt(104, 1, 1000),
			parent:         ParentHeader{Timestamp: 500},
			wantTimestamp:  1000,
			wantPrevRandao: "22e2e9d19080a0ed1feb7cbc9f7780faafb9d0f0a6c1d04da5aa882e38a84fff",
			wantBeaconRoot: "a89d36d6ee2592894eabcec7d750a30d743016547578193c63b1f8088e64b926",
		},
		{
			// (rootRound=104, shardRound=2); parent+1 (1001) beats reference time 1000, so the
			// timestamp is strictly increasing and two rounds cannot share one.
			name:           "rootRound 104, shardRound 2, parent at reference time",
			ri:             rootInputAt(104, 2, 1000),
			parent:         ParentHeader{Timestamp: 1000},
			wantTimestamp:  1001,
			wantPrevRandao: "1bb1e2b35615fd9d7ca4506c4697e65378d6a48a65fd25804047592df4c8f384",
			wantBeaconRoot: "ad7e4fcd5687fecb2f7a0c86179e063683e4f4a0c3cedc62099f7be090a4f808",
		},
		{
			// (rootRound=7, shardRound=1000); reference time 1 wins over parent+1 (1) — equal, so
			// reference time is returned, not parent+1.
			name:           "rootRound 7, shardRound 1000",
			ri:             rootInputAt(7, 1000, 1),
			parent:         ParentHeader{Timestamp: 0},
			wantTimestamp:  1,
			wantPrevRandao: "40e506783e2bfa40e62bfe81cb5d0344785676a8d0793343e624a0b54986992a",
			wantBeaconRoot: "0fb2a5539d4f3f8e1191fb87d1ec4c0b743f0ec2dc0f1e63a88f391324782bf0",
		},
		{
			// (rootRound=104, shardRound=57) — the pair evmroot/testdata/vectors.json pins.
			name:           "rootRound 104, shardRound 57 matches the accepted v1 vector",
			ri:             rootInputAt(104, 57, 123),
			parent:         ParentHeader{Timestamp: 0},
			wantTimestamp:  123,
			wantPrevRandao: "7719babfab66a24b53975094217cffd2bfc110cae783578adc6ff6e93c96fa74",
			wantBeaconRoot: "dadb817429f689121e212f42176afe8fa0bc3ee551455aed871324e20760cdf0",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := DeriveAttributes(c.ri, c.parent)
			require.Equal(t, c.wantTimestamp, uint64(got.Timestamp))
			require.Equal(t, mustHex(t, c.wantPrevRandao), got.PrevRandao[:])
			require.Equal(t, mustHex(t, c.wantBeaconRoot), got.ParentBeaconBlockRoot[:])
			require.Equal(t, data20{}, got.SuggestedFeeRecipient, "zero address for the PoC")
			require.Empty(t, got.Withdrawals)
			require.NotNil(t, got.Withdrawals, "must be an empty slice, not nil — Engine API JSON wants [] not null")
		})
	}
}

// TestDeriveAttributes_DifferentRootRoundChangesValues is the substance of the
// v0-to-v1 switch: v1 keys prevRandao and parentBeaconBlockRoot off the
// certified root round, so the same shard round under a different root round
// must not derive the same parameters.
func TestDeriveAttributes_DifferentRootRoundChangesValues(t *testing.T) {
	parent := ParentHeader{Timestamp: 0}
	at104 := DeriveAttributes(rootInputAt(104, 1, 1), parent)
	at105 := DeriveAttributes(rootInputAt(105, 1, 1), parent)

	require.NotEqual(t, at104.PrevRandao, at105.PrevRandao,
		"prevRandao must depend on the certified root round")
	require.NotEqual(t, at104.ParentBeaconBlockRoot, at105.ParentBeaconBlockRoot,
		"parentBeaconBlockRoot must depend on the certified root round")
}

// TestDeriveAttributes_DifferentShardRoundChangesValues is the other half:
// the value is a function of the pair, so the same root round under a
// different shard round also differs.
func TestDeriveAttributes_DifferentShardRoundChangesValues(t *testing.T) {
	parent := ParentHeader{Timestamp: 0}
	at1 := DeriveAttributes(rootInputAt(104, 1, 1), parent)
	at3 := DeriveAttributes(rootInputAt(104, 3, 1), parent)

	require.NotEqual(t, at1.PrevRandao, at3.PrevRandao,
		"prevRandao must depend on the authorized shard round")
	require.NotEqual(t, at1.ParentBeaconBlockRoot, at3.ParentBeaconBlockRoot,
		"parentBeaconBlockRoot must depend on the authorized shard round")
}

// TestDeriveAttributes_TimestampPlusOneWhenReferenceTimeEqualsParent pins the
// +1 path: at sub-second shard cadence the certified reference time can repeat,
// and EVM headers require strictly increasing timestamps.
func TestDeriveAttributes_TimestampPlusOneWhenReferenceTimeEqualsParent(t *testing.T) {
	const t0 = 1_700_000_000
	got := DeriveAttributes(rootInputAt(104, 1, t0), ParentHeader{Timestamp: t0})
	require.EqualValues(t, t0+1, uint64(got.Timestamp),
		"reference time equal to the parent timestamp must yield parent+1, not a repeat")
}

func TestDeriveAttributes_TwoIndependentCallsAgree(t *testing.T) {
	ri := rootInputAt(42, 42, 123456)
	parent := ParentHeader{Timestamp: 123450}

	a := DeriveAttributes(ri, parent)
	b := DeriveAttributes(ri, parent)
	require.Equal(t, a, b, "same inputs must produce byte-identical attributes — this is the property multi-validator quorum depends on")
}

func TestVerify_AcceptsCorrectAttributes(t *testing.T) {
	ri := rootInputAt(5, 5, 100)
	parent := ParentHeader{Timestamp: 90}
	attrs := DeriveAttributes(ri, parent)
	require.NoError(t, Verify(ri, parent, attrs))
}

func TestVerify_RejectsTamperedTimestamp(t *testing.T) {
	ri := rootInputAt(5, 5, 100)
	parent := ParentHeader{Timestamp: 90}
	attrs := DeriveAttributes(ri, parent)

	attrs.Timestamp = attrs.Timestamp + 1000 // a leader claiming a different clock
	err := Verify(ri, parent, attrs)
	require.Error(t, err)
	require.Contains(t, err.Error(), "timestamp")
}

func TestVerify_RejectsTamperedFeeRecipient(t *testing.T) {
	ri := rootInputAt(5, 5, 100)
	parent := ParentHeader{Timestamp: 90}
	attrs := DeriveAttributes(ri, parent)

	attrs.SuggestedFeeRecipient = data20{0x01} // a leader trying to redirect fees
	err := Verify(ri, parent, attrs)
	require.Error(t, err)
	require.Contains(t, err.Error(), "suggestedFeeRecipient")
}

func TestVerify_RejectsNonEmptyWithdrawals(t *testing.T) {
	ri := rootInputAt(5, 5, 100)
	parent := ParentHeader{Timestamp: 90}
	attrs := DeriveAttributes(ri, parent)

	attrs.Withdrawals = []WithdrawalV1{{Index: 1}}
	err := Verify(ri, parent, attrs)
	require.Error(t, err)
	require.Contains(t, err.Error(), "withdrawals")
}
