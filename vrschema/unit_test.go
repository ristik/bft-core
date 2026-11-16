package vrschema

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNamespaceConstants(t *testing.T) {
	require.Equal(t, "0xb2905100cfe7c1af5dee2b1b6726fdfd755820e0f51ef675ed653be4f1102d00", Hexw(LiabilityNS))
	require.Equal(t, "0x183a6125c38840424c4a85fa12bab2ab606c4b6d0e7cc73c0c06ba5300eab500", Hexw(Erc7201("example.main")))
	require.Equal(t, byte(0), VRNamespace[31])
}

func TestLevelArithmeticIsBoundedAndMonotone(t *testing.T) {
	views := []uint64{0, 1, 2, 3, 15, 16, 17, 63, 64, 1 << 32, ^uint64(0) - 1, ^uint64(0)}
	for l := uint8(0); l <= LMax; l++ {
		for n := uint32(1); n <= MaxCommittee; n++ {
			prevInc, prevDec := uint8(0), uint8(0)
			for i, v := range views {
				inc, dec := IncLevel(l, v, n), DecLevel(l, v, n)
				require.LessOrEqual(t, inc, uint8(LMax))
				require.LessOrEqual(t, dec, uint8(LMax-1))
				if l < LMax {
					require.Greater(t, inc, l)
				}
				if i > 0 {
					require.GreaterOrEqual(t, inc, prevInc)
					require.GreaterOrEqual(t, dec, prevDec)
				}
				prevInc, prevDec = inc, dec
				secs, never := ViewTimeoutSeconds(l, v, n)
				if !never {
					require.LessOrEqual(t, secs, SatSeconds)
					require.GreaterOrEqual(t, secs, uint64(T0Seconds))
				}
			}
		}
	}
	require.Equal(t, uint8(9), IncLevel(1, ^uint64(0), 1))
	require.Equal(t, uint8(8), DecLevel(9, ^uint64(0), 1))
	require.Equal(t, uint8(3), DecLevel(2, 8, 4))
	_, never := ViewTimeoutSeconds(1, ^uint64(0), 1)
	require.True(t, never)
}

func TestABIRoundTripAndStrictness(t *testing.T) {
	for kind, types := range ChangePayloadTypes {
		vals := make([]any, len(types))
		for i, ty := range types {
			switch ty {
			case "address":
				vals[i] = [20]byte{1, 19: 2}
			case "bytes32":
				vals[i] = w("x")
			case "bytes":
				vals[i] = []byte("abc")
			case "string":
				vals[i] = "label"
			default:
				vals[i] = uint64(7)
			}
		}
		enc, err := EncodeChange(kind, vals...)
		require.NoError(t, err)
		back, err := DecodeChangePayload(kind, enc)
		require.NoError(t, err)
		require.Equal(t, vals, back)
		for cut := 32; cut <= len(enc); cut += 32 {
			if cut == len(enc) {
				continue
			}
			_, err := DecodeChangePayload(kind, enc[:cut])
			require.Error(t, err, "kind %d truncated to %d", kind, cut)
		}
	}
}

func TestPackedWordRefusesReservedBytes(t *testing.T) {
	for _, pw := range []PackedWord{OutputWord0, OutputWord2, OutputWord10, ChangeWord0, ChangeWord3, StatusWord, LiabilityWord0, ActivationWord2, HolderWord0} {
		used := make([]bool, 32)
		for _, f := range pw {
			for i := 32 - f.Offset - f.Size; i < 32-f.Offset; i++ {
				require.False(t, used[i], "overlapping fields")
				used[i] = true
			}
		}
		for i, u := range used {
			if u {
				continue
			}
			var w Word
			w[i] = 1
			_, err := pw.Unpack(w)
			require.ErrorIs(t, err, ErrReserved)
		}
	}
}

func TestOutputModelReleasesOnce(t *testing.T) {
	m := NewVRModel(fxModule)
	m.Progress, m.UCTime = DelayRounds, DelaySeconds
	id, _ := m.Queue(KindCommitteeLimits, 96)
	m.Progress, m.UCTime = 2*DelayRounds, 2*DelaySeconds
	require.NoError(t, m.Execute(id, fxModule, true))
	r := w("r")
	require.NoError(t, m.Reserve(r, fxModule, false, []uint64{id}, 0))
	_, err := m.Publish(r)
	require.NoError(t, err)
	m.Import(LogRecord{Kind: RecOutputRejected, ResultID: r}, LogRecord{Kind: RecSessionClosed, ResultID: r}, LogRecord{Kind: RecSessionClosed, ResultID: r})
	require.Equal(t, 3, m.Apply(10))
	require.Equal(t, 1, m.Changes[id].Released)
	require.Equal(t, ChScheduled, m.Changes[id].State)
	require.Equal(t, HealthHealthy, m.Health)
	m.Import(LogRecord{Kind: RecBoundary, ResultID: r})
	m.Apply(1)
	require.Equal(t, HealthInconsistent, m.Health)
}
