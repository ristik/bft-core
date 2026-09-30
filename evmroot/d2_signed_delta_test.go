package evmroot

import (
	"encoding/hex"
	"math"
	"testing"
)

func TestD2_ForcedDigestSignedValueDeltaVectors(t *testing.T) {
	vectors := []struct {
		name      string
		value     int64
		encoded   string
		digestHex string
	}{
		{"zero", 0, "0000000000000000", "7c9860d43e777ad1805d537daae29924c5c10ba7a19709749ab2cb9047f80f36"},
		{"minus_one", -1, "ffffffffffffffff", "f33d315d4cd55e9c20331ea7609574c72726c1ee721a9087cfed0d13ef9adbeb"},
		{"min_int64", math.MinInt64, "8000000000000000", "bff35c08e86f42fa3134196d686bf4be58c0057494cebd73a3def3fd0a401499"},
		{"max_int64", math.MaxInt64, "7fffffffffffffff", "4dd0b61a781cb6c4e1e2800f6f02b68ddf824022efe79ccc6d48739163d3b739"},
	}
	for _, vector := range vectors {
		t.Run(vector.name, func(t *testing.T) {
			wantBytes, err := hex.DecodeString(vector.encoded)
			if err != nil {
				t.Fatal(err)
			}
			if got := signedDeltaBytes(vector.value); string(got) != string(wantBytes) {
				t.Fatalf("signed delta bytes = %x, want %x", got, wantBytes)
			}

			gotDigest := forcedDigest(7, ForcedEntry{Sender: "alice", ValueDelta: vector.value, Reason: "invalid"})
			if got := hex.EncodeToString(gotDigest); got != vector.digestHex {
				t.Fatalf("forced digest = %s, want %s", got, vector.digestHex)
			}
		})
	}
}
