package rootrecords

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/vrschema"
	"github.com/unicitynetwork/bft-go-base/types"
)

func TestKindsAreTheSchemaKinds(t *testing.T) {
	for k, want := range map[Kind]uint8{KindSessionClosed: vrschema.RecSessionClosed, KindAck: vrschema.RecAck, KindRecoveryAck: vrschema.RecRecoveryAck,
		KindClosure: vrschema.RecClosure, KindRetirement: vrschema.RecRetirement, KindBoundary: vrschema.RecBoundary,
		KindOutputRejected: vrschema.RecOutputRejected, KindHolderRetirement: vrschema.RecHolderRetirement} {
		require.EqualValues(t, want, k)
		require.Equal(t, len(vrschema.RecordWordTypes[want]), payloadWords[k], "kind %d", k)
	}
	require.Len(t, payloadWords, len(vrschema.RecordWordTypes))
}

// The frozen record.decode and record.width vectors (bft-core testvectors/validator-registry/encoding.json): the payload check every
// projection and every importer runs gives each of them its verdict.
func TestFrozenRecordVectors(t *testing.T) {
	raw, err := os.ReadFile("../testvectors/validator-registry/encoding.json")
	require.NoError(t, err)
	var f struct {
		Vectors []struct {
			Name   string          `json:"name"`
			Op     string          `json:"op"`
			Input  json.RawMessage `json:"input"`
			Expect json.RawMessage `json:"expect"`
		} `json:"vectors"`
	}
	require.NoError(t, json.Unmarshal(raw, &f))
	var decode, width int
	for _, v := range f.Vectors {
		switch v.Op {
		case "record.decode":
			var in struct {
				Data string `json:"data"`
				Kind uint8  `json:"kind"`
			}
			var ex struct {
				OK    bool `json:"ok"`
				Width int  `json:"width"`
			}
			require.NoError(t, json.Unmarshal(v.Input, &in))
			require.NoError(t, json.Unmarshal(v.Expect, &ex))
			data, err := hex.DecodeString(strings.TrimPrefix(in.Data, "0x"))
			require.NoError(t, err)
			err = checkPayload(Kind(in.Kind), data)
			if ex.OK {
				require.NoError(t, err, v.Name)
				require.Equal(t, ex.Width, len(data), v.Name)
			} else {
				require.Error(t, err, v.Name)
			}
			decode++
		case "record.width":
			var in struct {
				Kind  uint8    `json:"kind"`
				Types []string `json:"types"`
			}
			var ex struct {
				Width int `json:"width"`
			}
			require.NoError(t, json.Unmarshal(v.Input, &in))
			require.NoError(t, json.Unmarshal(v.Expect, &ex))
			require.Equal(t, ex.Width, 32*payloadWords[Kind(in.Kind)], v.Name)
			width++
		}
	}
	require.Equal(t, 25, decode)
	require.Equal(t, 8, width)
}

// primaryAcked is a state with one committed primary handoff from epoch 1 (H at round 100) to epoch 2 (first round 101).
func primaryPending(t *testing.T) State {
	s := NewState(1, 1)
	return mustCommit(t, s, 100, 2, 101, true)
}

func TestAckBoundaryPrimary(t *testing.T) {
	s := primaryPending(t)
	s = mustBlock(t, s, 2, 101)
	next, recs, err := s.AckBoundary(110, 1_000, id32(0xa1), id32(0xb1), 7, 0b101)
	require.NoError(t, err)
	require.Len(t, recs, 2)
	require.Equal(t, KindAck, recs[0].Kind)
	require.Equal(t, KindBoundary, recs[1].Kind)
	require.Equal(t, recs[0].ID, recs[1].Predecessor)
	require.Equal(t, Anchor{recs[0].Progress, recs[0].UCTime}, Anchor{recs[1].Progress, recs[1].UCTime})
	b, err := vrschema.DecodeBoundary(recs[1].Data)
	require.NoError(t, err)
	require.Equal(t, vrschema.Boundary{ResultID: id32(0xa1), ChangesEpoch: 2, InstalledRootEpoch: 2, InstalledShardEpoch: 7, ActivationRound: 101,
		RejectedBitmap: 0b101}, b)
	require.EqualValues(t, 2, next.Count)
	require.True(t, next.IsResolved(id32(0xa1)))
	require.NoError(t, Verify(recs))
	// the result resolves once: a repeated acknowledgement projects nothing
	_, _, err = next.AckBoundary(111, 1_000, id32(0xa1), id32(0xb1), 7, 0)
	require.ErrorIs(t, err, ErrNoPending)
}

func TestAckBoundaryRecovery(t *testing.T) {
	s := primaryPending(t)
	s = mustBlock(t, s, 2, 101)
	s = mustCommit(t, s, 130, 3, 131, true)
	s = mustBlock(t, s, 3, 131)
	_, recs, err := s.AckBoundary(140, 1_000, id32(0xa1), id32(0xb2), 9, 0)
	require.NoError(t, err)
	require.Equal(t, []Kind{KindRecoveryAck, KindBoundary}, kinds(recs))
	b, err := vrschema.DecodeBoundary(recs[1].Data)
	require.NoError(t, err)
	require.Equal(t, vrschema.Boundary{ResultID: id32(0xa1), ChangesEpoch: 2, InstalledRootEpoch: 3, InstalledShardEpoch: 9, ActivationRound: 131,
		Recovered: true}, b)

	// a K that is not one root epoch after J has no boundary: nothing is projected
	s2 := primaryPending(t)
	s2 = mustBlock(t, s2, 2, 101)
	s2 = mustCommit(t, s2, 130, 4, 131, true)
	s2 = mustBlock(t, s2, 4, 131)
	before := s2.Digest()
	_, _, err = s2.AckBoundary(140, 1_000, id32(0xa1), id32(0xb2), 9, 0)
	require.ErrorIs(t, err, ErrBoundary)
	require.Equal(t, before, s2.Digest())
}

func TestRejectOutputProjectsThePairOnce(t *testing.T) {
	s := NewState(1, 1)
	next, recs, err := s.RejectOutput(id32(0xc1), vrschema.RejExpired, 0, 0b11, 50, 1_000)
	require.NoError(t, err)
	require.Equal(t, []Kind{KindOutputRejected, KindSessionClosed}, kinds(recs))
	require.Equal(t, id32(0xc1), [32]byte(recs[1].Data))
	o, err := vrschema.DecodeOutputRejected(recs[0].Data)
	require.NoError(t, err)
	require.Equal(t, vrschema.OutputRejected{ResultID: id32(0xc1), Reason: vrschema.RejExpired, ReadyBitmap: 0b11}, o)
	require.NoError(t, Verify(recs))
	// the frozen pair is vrschema's projection of the same data
	pair, err := vrschema.ProjectRejectResult(recs[0].Data)
	require.NoError(t, err)
	require.Equal(t, recs[0].Data, pair[0][1])
	require.Equal(t, recs[1].Data, pair[1][1])

	_, _, err = next.RejectOutput(id32(0xc1), vrschema.RejInvalidated, 0, 0, 51, 1_000)
	require.ErrorIs(t, err, ErrResultResolved)
	_, _, err = next.SessionClosed(id32(0xc1), 51, 1_000)
	require.ErrorIs(t, err, ErrResultResolved)

	for name, c := range map[string]struct {
		reason uint8
		member uint64
		ready  uint16
		id     [32]byte
	}{
		"reason 0": {0, 0, 0, id32(1)}, "reason 4": {4, 0, 0, id32(1)}, "member outside Invalid": {vrschema.RejExpired, 3, 0, id32(1)},
		"bitmap outside Expired": {vrschema.RejInvalid, 0, 1, id32(1)}, "zero result": {vrschema.RejInvalidated, 0, 0, [32]byte{}},
	} {
		before := s.Digest()
		_, _, err := s.RejectOutput(c.id, c.reason, c.member, c.ready, 50, 1_000)
		require.ErrorIs(t, err, ErrPayload, name)
		require.Equal(t, before, s.Digest(), name)
	}
	// an Invalid rejection names its member
	_, recs, err = s.RejectOutput(id32(0xc2), vrschema.RejInvalid, 4, 0, 50, 1_000)
	require.NoError(t, err)
	o, err = vrschema.DecodeOutputRejected(recs[0].Data)
	require.NoError(t, err)
	require.EqualValues(t, 4, o.MemberID)
}

func TestHolderRetireIsOncePerHolderKey(t *testing.T) {
	s := NewState(1, 1)
	require.Equal(t, uint64(1), versionOf(t, s), "a state without holder markers stays version 1")
	s1, rec, err := s.HolderRetire(0, 5, 1, id32(7), 40, 50, 1_000)
	require.NoError(t, err)
	require.NotNil(t, rec)
	require.Equal(t, KindHolderRetirement, rec.Kind)
	h, err := vrschema.DecodeHolderRetirement(rec.Data)
	require.NoError(t, err)
	require.Equal(t, vrschema.HolderRetirement{Holder: 0, ID: 5, Generation: 1, RefDigest: id32(7)}, h)
	ref, ok := s1.IsHolderRetired(0, 5, 1)
	require.True(t, ok)
	require.Equal(t, id32(7), ref)
	require.Equal(t, uint64(2), versionOf(t, s1))

	// a repeat is no record and no change; a conflicting digest is refused
	again, rec, err := s1.HolderRetire(0, 5, 1, id32(7), 40, 60, 1_000)
	require.NoError(t, err)
	require.Nil(t, rec)
	require.Equal(t, s1.Digest(), again.Digest())
	_, _, err = s1.HolderRetire(0, 5, 1, id32(8), 40, 60, 1_000)
	require.ErrorIs(t, err, ErrRetirementConflict)
	// the same identity generation at another holder is another key
	s2, rec, err := s1.HolderRetire(1, 5, 1, id32(8), 40, 60, 1_000)
	require.NoError(t, err)
	require.NotNil(t, rec)
	// and the pre-VR marker of the same (id, generation) is independent
	s3, rec5, err := s2.Retire(5, 1, id32(9), 40, 61, 1_000)
	require.NoError(t, err)
	require.NotNil(t, rec5)
	// early and out-of-range refusals
	_, _, err = s3.HolderRetire(2, 5, 1, id32(7), 1_000, 62, 1_000)
	require.ErrorIs(t, err, ErrRetireEarly)
	_, _, err = s3.HolderRetire(vrschema.MaxHolders, 5, 1, id32(7), 0, 62, 1_000)
	require.ErrorIs(t, err, ErrPayload)
	// order: inserted below an existing key
	s4, _, err := s3.HolderRetire(0, 2, 9, id32(1), 0, 62, 1_000)
	require.NoError(t, err)
	require.Equal(t, []HolderRetired{{0, 2, 9, id32(1)}, {0, 5, 1, id32(7)}, {1, 5, 1, id32(8)}}, s4.HolderRetired)

	got, err := DecodeState(s4.Bytes())
	require.NoError(t, err)
	require.Equal(t, s4.Digest(), got.Digest())
	require.Equal(t, s4.HolderRetired, got.HolderRetired)
}

func versionOf(t *testing.T, s State) uint64 {
	t.Helper()
	var f []any
	require.NoError(t, types.Cbor.Unmarshal(s.Bytes(), &f))
	return f[1].(uint64)
}

func TestStateVersionTwoRefusals(t *testing.T) {
	s, _, err := NewState(1, 1).HolderRetire(0, 5, 1, id32(7), 0, 50, 1_000)
	require.NoError(t, err)
	var f []any
	require.NoError(t, types.Cbor.Unmarshal(s.Bytes(), &f))
	enc := func(f []any) []byte {
		b, err := types.Cbor.Marshal(f)
		require.NoError(t, err)
		return b
	}
	clone := func() []any { return append([]any(nil), f...) }

	g := clone()
	g[19] = []any{}
	_, err = DecodeState(enc(g))
	require.ErrorIs(t, err, ErrState, "version 2 with no marker is not canonical")

	g = clone()
	g[1] = uint64(1)
	_, err = DecodeState(enc(g))
	require.ErrorIs(t, err, ErrState, "twenty fields under version 1")

	g = clone()
	g[19] = []any{[]any{uint64(8), uint64(5), uint64(1), make([]byte, 32)}}
	_, err = DecodeState(enc(g))
	require.ErrorIs(t, err, ErrState, "holder 8")

	g = clone()
	g[19] = []any{[]any{uint64(0), uint64(5), uint64(1), make([]byte, 32)}, []any{uint64(0), uint64(5), uint64(1), make([]byte, 32)}}
	_, err = DecodeState(enc(g))
	require.ErrorIs(t, err, ErrState, "duplicate marker")

	v1 := clone()[:19]
	v1[1] = uint64(2)
	_, err = DecodeState(enc(v1))
	require.ErrorIs(t, err, ErrState, "nineteen fields under version 2")
}

func TestVerifyRefusesNonCanonicalNewKinds(t *testing.T) {
	var l Log
	bad := BoundaryPayload(id32(1), 5, 5, 0, 0, false, 0)
	bad[5*32+31] = 2 // recovered = 2
	_, err := l.Append(KindBoundary, bad, Anchor{1, 1})
	require.ErrorIs(t, err, ErrPayload)
	_, err = l.Append(Kind(9), make([]byte, 32), Anchor{1, 1})
	require.ErrorIs(t, err, ErrKind)
}

// vrschemaVerdict is the frozen reference's verdict on a payload: its width and word check, and for kinds 6 to 8 its strict decoder.
func vrschemaVerdict(kind Kind, data []byte) bool {
	if err := vrschema.CheckRecordPayload(uint8(kind), data); err != nil {
		return false
	}
	var err error
	switch kind {
	case KindBoundary:
		_, err = vrschema.DecodeBoundary(data)
	case KindOutputRejected:
		_, err = vrschema.DecodeOutputRejected(data)
	case KindHolderRetirement:
		_, err = vrschema.DecodeHolderRetirement(data)
	}
	return err == nil
}

// The payload rules restated in records.go are vrschema's: every word of every kind set to each boundary value, alone and in pairs.
func TestPayloadRulesAreVrschemas(t *testing.T) {
	values := [][32]byte{{}, wordOf(1), wordOf(2), wordOf(3), wordOf(4), wordOf(7), wordOf(8), wordOf(0xffff), wordOf(0x1_0000), wordOf(^uint64(0)), id32(0xab)}
	high := [32]byte{}
	high[0] = 1
	values = append(values, high)
	n := 0
	for kind, ws := range payloadWords {
		base := make([]byte, 32*ws)
		for i := 0; i < ws; i++ {
			for _, a := range values {
				for j := i; j < ws; j++ {
					for _, b := range values {
						d := append([]byte(nil), base...)
						copy(d[32*i:], a[:])
						copy(d[32*j:], b[:])
						got := checkPayload(kind, d) == nil
						require.Equal(t, vrschemaVerdict(kind, d), got, "kind %d words %d=%x %d=%x", kind, i, a, j, b)
						n++
					}
				}
			}
		}
		// and the projection's own encodings
		switch kind {
		case KindBoundary:
			require.Equal(t, vrschema.Boundary{ResultID: id32(1), ChangesEpoch: 5, InstalledRootEpoch: 6, InstalledShardEpoch: 8, ActivationRound: 9,
				Recovered: true, RejectedBitmap: 3}.Encode(), BoundaryPayload(id32(1), 5, 6, 8, 9, true, 3))
		case KindOutputRejected:
			require.Equal(t, vrschema.OutputRejected{ResultID: id32(1), Reason: 3, MemberID: 4}.Encode(), OutputRejectedPayload(id32(1), 3, 4, 0))
		case KindHolderRetirement:
			require.Equal(t, vrschema.HolderRetirement{Holder: 7, ID: 1, Generation: 2, RefDigest: id32(9)}.Encode(), HolderRetirementPayload(7, 1, 2, id32(9)))
		}
	}
	require.Greater(t, n, 10_000)
	require.EqualValues(t, vrschema.MaxHolders, MaxHolders)
	require.Equal(t, []uint8{vrschema.RejExpired, vrschema.RejInvalidated, vrschema.RejInvalid}, []uint8{RejectExpired, RejectInvalidated, RejectInvalid})
	for k, bits := range payloadWordBits {
		require.Len(t, bits, payloadWords[k])
	}
}

func wordOf(v uint64) (w [32]byte) {
	copy(w[:], word(v))
	return
}
