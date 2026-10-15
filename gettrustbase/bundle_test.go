package gettrustbase

import (
	"bytes"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-go-base/types"

	"github.com/unicitynetwork/bft-core/keyvaluedb/memorydb"
	"github.com/unicitynetwork/bft-core/utbstore"
)

var big = BundleLimits{MaxBytes: 1 << 30, MaxEntries: 1 << 20}

func TestACompleteBundleBeyondThePageCapsExportsAndReloadsByteForByte(t *testing.T) {
	es := chain(t, nodes(t, 4), 200) // 201 entries: far beyond a 64-entry page
	st := store(t, es, 200)
	file, err := ExportStore(st)
	require.NoError(t, err)
	require.Greater(t, len(file), 64*len(raw(t, es)[1])/2)

	// the same object as a page: it is not decodable under the page caps, only under the bundle budget
	_, _, err = DecodeResponse(file, PageLimits)
	require.Error(t, err)
	b, err := DecodeBundle(file, BundleLimits{MaxBytes: len(file), MaxEntries: 201})
	require.NoError(t, err)
	require.Len(t, b.Entries, 201)
	require.Equal(t, st.Tip().EntryID, idOf(t, b.Tip()))
	again, err := EncodeBundle(b.Raw)
	require.NoError(t, err)
	require.Equal(t, file, again, "exact export/reload bytes")
	// the budget is checked before decoding
	_, err = DecodeBundle(file, BundleLimits{MaxBytes: len(file) - 1, MaxEntries: 201})
	require.ErrorIs(t, err, ErrEncoding)
	_, err = DecodeBundle(file, BundleLimits{MaxBytes: len(file), MaxEntries: 200})
	require.Error(t, err)

	// a single-page history is the same format
	small := store(t, es, 3)
	one, err := ExportStore(small)
	require.NoError(t, err)
	r, _, err := DecodeResponse(one, PageLimits)
	require.NoError(t, err)
	require.Equal(t, StatusOK, r.Status)
}

func TestABundleThatIsNotCompleteIsRefused(t *testing.T) {
	es := chain(t, nodes(t, 4), 6)
	rs := raw(t, es)
	enc := func(r *Response) []byte {
		b, err := r.Encode()
		require.NoError(t, err)
		return b
	}
	mk := func(from, to int, ents ...[]byte) *Response {
		id := idOf(t, es[to])
		r := &Response{Version: 1, Network: testNetwork, Status: StatusOK, FromEpoch: uint64(from + 1), EffectiveEnd: uint64(to + 1), EndEntryID: id[:]}
		for _, e := range ents {
			r.Entries = append(r.Entries, e)
		}
		return r
	}
	_, err := DecodeBundle(enc(mk(0, 6, rs...)), big)
	require.NoError(t, err)
	cases := map[string][]byte{
		"missing prefix (a partial range ending at the tip)": enc(mk(2, 6, rs[2:]...)),
		"missing middle":    enc(mk(0, 6, append(append([][]byte{}, rs[:3]...), rs[4:]...)...)),
		"duplicate epoch":   enc(mk(0, 6, append(append([][]byte{}, rs[:3]...), rs[2:]...)...)),
		"short of its end":  enc(mk(0, 6, rs[:6]...)),
		"wrong end id":      enc(func() *Response { r := mk(0, 6, rs...); r.EndEntryID = bytes.Repeat([]byte{9}, 32); return r }()),
		"continuation set":  enc(func() *Response { r := mk(0, 5, rs[:6]...); r.NextEpoch = u64(7); r.EffectiveEnd = 7; return r }()),
		"error status":      enc(&Response{Version: 1, Network: testNetwork, Status: StatusNotYetAvailable, Entries: []cbor.RawMessage{}}),
		"trailing bytes":    append(enc(mk(0, 6, rs...)), 0),
		"no entries at all": enc(&Response{Version: 1, Network: testNetwork, Status: StatusOK, Entries: []cbor.RawMessage{}, EndEntryID: bytes.Repeat([]byte{1}, 32)}),
	}
	for name, c := range cases {
		_, err := DecodeBundle(c, big)
		require.Error(t, err, name)
	}
	_, err = EncodeBundle(append(append([][]byte{}, rs[:2]...), rs[3:]...))
	require.Error(t, err, "export fails on a gap rather than shortening history")
	_, err = EncodeBundle(nil)
	require.Error(t, err)
}

func TestInstallBundle(t *testing.T) {
	ns := nodes(t, 4)
	es := chain(t, ns, 12)
	rs := raw(t, es)
	file := func(upto int) *Bundle {
		b, err := EncodeBundle(rs[:upto+1])
		require.NoError(t, err)
		d, err := DecodeBundle(b, big)
		require.NoError(t, err)
		return d
	}

	t.Run("trusted fresh bootstrap installs the whole shipped history", func(t *testing.T) {
		st := store(t, es, 0)
		n, err := InstallBundle(st, file(12))
		require.NoError(t, err)
		require.Equal(t, 12, n)
		require.Equal(t, uint64(13), st.Tip().Epoch)
	})
	t.Run("an older bundle neither truncates history nor rolls the tip back", func(t *testing.T) {
		st := store(t, es, 12)
		n, err := InstallBundle(st, file(5))
		require.NoError(t, err)
		require.Zero(t, n)
		require.Equal(t, uint64(13), st.Tip().Epoch)
		for e := uint64(1); e <= 13; e++ {
			held, _ := st.Get(e)
			require.Equal(t, rs[e-1], held)
		}
	})
	t.Run("a newer bundle verifies its suffix from the latest held entry", func(t *testing.T) {
		st := store(t, es, 4)
		n, err := InstallBundle(st, file(12))
		require.NoError(t, err)
		require.Equal(t, 8, n)
		require.Equal(t, st.Tip().EntryID, idOf(t, es[12]))
	})
	t.Run("an overlapping record that conflicts is refused and held history is unchanged", func(t *testing.T) {
		other := chain(t, ns[1:], 12) // same shape, different committee: a different history with the same epochs
		ob, err := EncodeBundle(raw(t, other))
		require.NoError(t, err)
		od, err := DecodeBundle(ob, big)
		require.NoError(t, err)
		st := store(t, es, 4)
		before := st.Tip()
		_, err = InstallBundle(st, od)
		require.ErrorIs(t, err, ErrBundleInstall)
		require.Equal(t, before, st.Tip())
	})
	t.Run("a bad signature in the unknown suffix stops the install at the last good entry", func(t *testing.T) {
		bad := chain(t, ns, 12)
		bad[8].Signatures = nil
		for _, s := range ns[:2] { // two of four: below the strict quorum
			require.NoError(t, bad[8].Sign(s.id, s.signer))
		}
		st := store(t, es, 4)
		_, err := InstallBundle(st, forcedBundle(t, bad))
		require.ErrorIs(t, err, ErrBundleInstall)
		require.Equal(t, uint64(8), st.Tip().Epoch, "authenticated prefix kept, nothing beyond the refused entry")
	})
	t.Run("a different genesis is refused", func(t *testing.T) {
		other := chain(t, nodes(t, 5), 3)
		ob, err := EncodeBundle(raw(t, other))
		require.NoError(t, err)
		od, _ := DecodeBundle(ob, big)
		st := store(t, es, 0)
		_, err = InstallBundle(st, od)
		require.ErrorIs(t, err, ErrBundleInstall)
		require.Equal(t, uint64(1), st.Tip().Epoch)
	})
}

// forcedBundle packs entries without the exporter's structural prechecks passing through the store.
func forcedBundle(t *testing.T, es []*types.RootTrustBaseV2) *Bundle {
	b := &Bundle{Network: testNetwork, Entries: es, Raw: raw(t, es)}
	return b
}

func TestVerifyBundleOffline(t *testing.T) {
	ns := nodes(t, 4)
	es := chain(t, ns, 10)
	pin := idOf(t, es[0])
	mk := func(es []*types.RootTrustBaseV2) *Bundle {
		b, err := EncodeBundle(raw(t, es))
		require.NoError(t, err)
		d, err := DecodeBundle(b, big)
		require.NoError(t, err)
		return d
	}
	require.NoError(t, VerifyBundle(mk(es), pin))

	require.ErrorIs(t, VerifyBundle(mk(es), [32]byte{1}), ErrBundleChain, "wrong pin")

	short := chain(t, ns, 10)
	short[5].Signatures = nil
	for _, s := range ns[:2] {
		require.NoError(t, short[5].Sign(s.id, s.signer))
	}
	err := VerifyBundle(forcedBundle(t, short), pin)
	require.ErrorIs(t, err, ErrBundleChain)
	require.Contains(t, err.Error(), "epoch 6")

	// an extra unknown signer fails the entry even though the valid ones reach quorum
	extra := chain(t, ns, 10)
	extra[7].Signatures["stranger"] = bytes.Repeat([]byte{1}, 65)
	require.ErrorIs(t, VerifyBundle(forcedBundle(t, extra), pin), ErrBundleChain)

	// a broken hash link
	linked := chain(t, ns, 10)
	linked[4].PreviousEntryID = bytes.Repeat([]byte{4}, 32)
	require.ErrorIs(t, VerifyBundle(forcedBundle(t, linked), pin), ErrBundleChain)

	// a different chain on the same pin
	require.ErrorIs(t, VerifyBundle(mk(chain(t, nodes(t, 5), 3)), pin), ErrBundleChain)
}

var _ = utbstore.ErrConflict
var _ = memorydb.New
