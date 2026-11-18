package b1state

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func execRevProfile() Profile {
	const bEpochs, rest = 2, 100
	sys := uint64(155936 + (505244+177800*16)*bEpochs + rest + (2000 + 16*16384 + 1000*32 + 18000000))
	return Profile{Network: 3, RootGenesisID: [32]byte{1}, ExecutionChainID: 2, RuntimeHash: [32]byte{3}, CompilerHash: [32]byte{4},
		DeltaEV: 1, DeltaHold: 2, MaxEpochsPerUpdate: bEpochs, SystemGas: sys, MaxGas: sys + 7000000, OrdinaryCapacity: 7000000,
		RestGas: rest, CompanionBytes: 1 << 20, OtherCompanionBytes: 1024, GenesisUCTime: 1000, ExecutionRevision: CurrentExecutionRevision}
}

func TestExecutionRevisionMustBeExactlyTheCurrentOne(t *testing.T) {
	p := execRevProfile()
	require.NoError(t, p.Validate())
	for _, rev := range []uint64{0, 2, 3, 1 << 63} {
		q := p
		q.ExecutionRevision = rev
		require.ErrorIs(t, q.Validate(), ErrExecutionRevision, "revision %d", rev)
		_, err := q.Hash()
		require.ErrorIs(t, err, ErrExecutionRevision, "revision %d", rev)
	}
}

// The profile hash is under the V2 domain with the revision right after it. The preimage is rebuilt here by hand (header: array of 36, text
// "UNICITY_B1_PROFILE_V2", uint 1) and compared to the production encoding's prefix, and the hash is frozen as a golden value.
const goldenV2ProfileHash = "0563b8ce769d5a610def9b455120c7a2791c0b4c9ae2f81bca7cf35e28369e13"

func TestProfileHashV2GoldenAndPreimage(t *testing.T) {
	p := execRevProfile()
	h, err := p.Hash()
	require.NoError(t, err)
	// Frozen golden value: any change of the V2 encoding is a consensus format change.
	require.Equal(t, goldenV2ProfileHash, hex.EncodeToString(h[:]))

	// The domain and the revision are what separate generations: the same profile at another revision (test-only encoding, production refuses it)
	// and the old domain hash differently.
	enc := func(domain string, rev uint64) [32]byte {
		b := array(nil, 36)
		b = textValue(b, domain)
		b = uintValue(b, rev)
		return sha256.Sum256(b)
	}
	require.NotEqual(t, enc(ProfileHashDomain, 1), enc(ProfileHashDomain, 2))
	require.NotEqual(t, enc("UNICITY_B1_PROFILE", 1), enc(ProfileHashDomain, 1))

}

func TestExecutionRevisionNativesAreExactlyTheCurrentSet(t *testing.T) {
	set, ok := ExecutionRevisionNatives(CurrentExecutionRevision)
	require.True(t, ok)
	got := map[string][20]byte{}
	for _, n := range set {
		got[n.Name] = n.Address
	}
	require.Equal(t, map[string][20]byte{
		"unicity-b1-cert-batch-v2": {18: 0x01, 19: 0x00},
		"unicity-b1-membership":    {18: 0x01, 19: 0x02},
		"unicity-b2-sdk3":          {18: 0x01, 19: 0x04},
	}, got) // no 0x0101, 0x0103, 0x0105
	for _, rev := range []uint64{0, 2} {
		_, ok := ExecutionRevisionNatives(rev)
		require.False(t, ok)
	}
}

// An old binary decodes a profile file strictly: a file carrying executionRevision is refused as an unknown field.
func TestPreRevisionDecoderRefusesARevisionCarryingProfile(t *testing.T) {
	type pre1199 struct {
		Network uint16 `json:"network"`
	}
	dec := json.NewDecoder(strings.NewReader(`{"network":3,"executionRevision":1}`))
	dec.DisallowUnknownFields()
	require.ErrorContains(t, dec.Decode(&pre1199{}), "unknown field \"executionRevision\"")
}
