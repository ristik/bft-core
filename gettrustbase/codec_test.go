package gettrustbase

import (
	"bytes"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-go-base/types"
)

func TestRequestRoundTripAndStrictDecode(t *testing.T) {
	id := bytes.Repeat([]byte{7}, 32)
	req := &Request{Version: 1, Network: testNetwork, FromEpoch: 0, ToEpoch: u64(0), SnapshotEnd: u64(9), SnapshotEntryID: id, MaxEntries: 4, MaxBytes: 1000}
	b, err := req.Encode()
	require.NoError(t, err)
	got, err := DecodeRequest(b)
	require.NoError(t, err)
	require.Equal(t, req.FromEpoch, got.FromEpoch)
	require.Equal(t, uint64(0), *got.ToEpoch, "zero is a value, not an omission")

	// null (omitted) and zero are different
	nul := &Request{Version: 1, Network: testNetwork, FromEpoch: 1, MaxEntries: 1, MaxBytes: 1}
	nb, err := nul.Encode()
	require.NoError(t, err)
	g, err := DecodeRequest(nb)
	require.NoError(t, err)
	require.Nil(t, g.ToEpoch)
	require.Nil(t, g.SnapshotEnd)
	require.NotEqual(t, b, nb)

	for name, bad := range map[string][]byte{
		"trailing byte": append(bytes.Clone(b), 0),
		"wrong tag":     retag(t, b, types.TrustBaseResponseTag),
		"truncated":     b[:len(b)-1],
		"oversize":      append(bytes.Clone(b), make([]byte, MaxRequestBytes)...),
	} {
		_, err := DecodeRequest(bad)
		require.Error(t, err, name)
	}
	v2 := *req
	v2.Version = 2
	vb, _ := v2.Encode()
	_, err = DecodeRequest(vb)
	require.ErrorIs(t, err, ErrEncoding)
	half := *req
	half.SnapshotEntryID = nil
	hb, _ := half.Encode()
	_, err = DecodeRequest(hb)
	require.ErrorIs(t, err, ErrEncoding, "a snapshot end without its id")
	short := *req
	short.SnapshotEntryID = id[:5]
	sb, _ := short.Encode()
	_, err = DecodeRequest(sb)
	require.ErrorIs(t, err, ErrEncoding)
}

func retag(t *testing.T, b []byte, tag types.CborTag) []byte {
	var rt cbor.RawTag
	require.NoError(t, cbor.Unmarshal(b, &rt))
	out, err := types.Cbor.Marshal(cbor.RawTag{Number: tag, Content: rt.Content})
	require.NoError(t, err)
	return out
}

func TestResponseDecodeRejectsEveryStructuralViolation(t *testing.T) {
	es := chain(t, nodes(t, 4), 5)
	rs := raw(t, es)
	good := func() *types.TrustBaseResponse {
		id := idOf(t, es[3])
		return &types.TrustBaseResponse{Version: 1, Network: testNetwork, Status: types.TrustBaseStatusOK, FromEpoch: 2, EffectiveEnd: 4, EndEntryID: id[:],
			Entries: []cbor.RawMessage{rs[1], rs[2], rs[3]}}
	}
	enc := func(r *types.TrustBaseResponse) []byte {
		b, err := r.Encode()
		require.NoError(t, err)
		return b
	}
	_, decoded, err := types.DecodeTrustBaseResponse(enc(good()), types.TrustBasePageLimits)
	require.NoError(t, err)
	require.Len(t, decoded, 3)

	mut := map[string]func(*types.TrustBaseResponse){
		"first entry is not from":      func(r *types.TrustBaseResponse) { r.FromEpoch = 3 },
		"gap":                          func(r *types.TrustBaseResponse) { r.Entries = []cbor.RawMessage{rs[1], rs[3]} },
		"duplicate":                    func(r *types.TrustBaseResponse) { r.Entries = []cbor.RawMessage{rs[1], rs[1], rs[2]} },
		"descending":                   func(r *types.TrustBaseResponse) { r.Entries = []cbor.RawMessage{rs[3], rs[2], rs[1]} },
		"ends before end without next": func(r *types.TrustBaseResponse) { r.EffectiveEnd = 5 },
		"beyond the effective end":     func(r *types.TrustBaseResponse) { r.EffectiveEnd = 3 },
		"wrong cursor":                 func(r *types.TrustBaseResponse) { r.EffectiveEnd = 6; r.NextEpoch = u64(6) },
		"cursor past end":              func(r *types.TrustBaseResponse) { r.NextEpoch = u64(5) },
		"wrong end id":                 func(r *types.TrustBaseResponse) { r.EndEntryID = bytes.Repeat([]byte{1}, 32) },
		"no end id":                    func(r *types.TrustBaseResponse) { r.EndEntryID = nil },
		"short end id":                 func(r *types.TrustBaseResponse) { r.EndEntryID = r.EndEntryID[:3] },
		"other network":                func(r *types.TrustBaseResponse) { r.Network = 6 },
		"OK without entries":           func(r *types.TrustBaseResponse) { r.Entries = nil },
		"unknown status":               func(r *types.TrustBaseResponse) { r.Status = 99; r.Entries = nil },
		"version":                      func(r *types.TrustBaseResponse) { r.Version = 2 },
		"garbage entry":                func(r *types.TrustBaseResponse) { r.Entries = []cbor.RawMessage{{0x01}} },
		"error status with entries":    func(r *types.TrustBaseResponse) { r.Status = types.TrustBaseStatusBusy },
		"error status with cursor": func(r *types.TrustBaseResponse) {
			r.Status = types.TrustBaseStatusBusy
			r.Entries = nil
			r.NextEpoch = u64(3)
		},
		"too many entries for the page": func(r *types.TrustBaseResponse) { r.Entries = []cbor.RawMessage{rs[1], rs[2], rs[3]} },
	}
	for name, m := range mut {
		r := good()
		m(r)
		lim := types.TrustBasePageLimits
		if name == "too many entries for the page" {
			lim.MaxEntries = 2
		}
		_, _, err := types.DecodeTrustBaseResponse(enc(r), lim)
		require.Error(t, err, name)
	}
	// each link rule alone: consecutive epochs with a broken link, and a linked run that skips an epoch
	relinked := func(i int, edit func(*types.RootTrustBaseV2)) *types.TrustBaseResponse {
		cp := *es[i]
		edit(&cp)
		b, err := cp.MarshalCBOR()
		require.NoError(t, err)
		r := good()
		r.Entries = []cbor.RawMessage{rs[1], b, rs[3]}
		return r
	}
	_, _, err = types.DecodeTrustBaseResponse(enc(relinked(2, func(e *types.RootTrustBaseV2) { e.PreviousEntryID = bytes.Repeat([]byte{4}, 32) })), types.TrustBasePageLimits)
	require.ErrorIs(t, err, types.ErrTrustBaseResponse, "broken link, consecutive epochs")
	skip := relinked(2, func(e *types.RootTrustBaseV2) { e.Epoch += 5 })
	skip.Entries, skip.EffectiveEnd, skip.NextEpoch = skip.Entries[:2], 20, u64(9) // the run ends at the skipping entry, so only its epoch can refuse it
	_, _, err = types.DecodeTrustBaseResponse(enc(skip), types.TrustBasePageLimits)
	require.ErrorIs(t, err, types.ErrTrustBaseResponse, "skipped epoch, intact link")

	b := enc(good())
	for name, bad := range map[string][]byte{"trailing": append(bytes.Clone(b), 0), "wrong tag": retag(t, b, RequestTag), "truncated": b[:len(b)-2]} {
		_, _, err := types.DecodeTrustBaseResponse(bad, types.TrustBasePageLimits)
		require.Error(t, err, name)
	}
	_, _, err = types.DecodeTrustBaseResponse(b, types.TrustBaseLimits{MaxBytes: len(b) - 1, MaxEntries: 64})
	require.ErrorIs(t, err, types.ErrTrustBaseResponseEncoding, "byte budget is checked before decoding")
	// a non-OK response with no entries is fine and carries no hole
	ok, _, err := types.DecodeTrustBaseResponse(enc(&types.TrustBaseResponse{Version: 1, Network: testNetwork, Status: types.TrustBaseStatusNotYetAvailable, Entries: []cbor.RawMessage{}}), types.TrustBasePageLimits)
	require.NoError(t, err)
	require.Equal(t, types.TrustBaseStatusNotYetAvailable, ok.Status)
}
