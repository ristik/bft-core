package cmd

import (
	"bytes"
	"encoding/json"
	"github.com/unicitynetwork/bft-go-base/types"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/stretchr/testify/require"
	abcrypto "github.com/unicitynetwork/bft-go-base/crypto"

	"github.com/unicitynetwork/bft-core/utb"
)

func TestUTBExportVerifyImportRoundTrip(t *testing.T) {
	dir := t.TempDir()
	type member struct {
		id     string
		key    []byte
		signer abcrypto.Signer
	}
	var ms []member
	for i := 0; i < 4; i++ {
		s, err := abcrypto.NewInMemorySecp256K1SignerFromKey(bytes.Repeat([]byte{byte(i + 1)}, 32))
		require.NoError(t, err)
		v, _ := s.Verifier()
		pk, _ := v.MarshalPublicKey()
		pub, err := crypto.UnmarshalSecp256k1PublicKey(pk)
		require.NoError(t, err)
		id, err := peer.IDFromPublicKey(pub)
		require.NoError(t, err)
		ms = append(ms, member{id.String(), pk, s})
	}
	facts := func(epoch, start uint64) utb.SuccessorFacts {
		var um []utb.Member
		for _, m := range ms {
			um = append(um, utb.Member{NodeID: m.id, Key: m.key, Weight: 1})
		}
		return utb.SuccessorFacts{Network: 5, Epoch: epoch, EpochStart: start, Members: um, Threshold: 3,
			StateHash: bytes.Repeat([]byte{1}, 32), ChangeRecordHash: bytes.Repeat([]byte{2}, 32)}
	}
	g, err := utb.BuildUnsigned(nil, facts(1, 1))
	require.NoError(t, err)
	graw, _ := g.MarshalCBOR()
	gid, _ := g.EntryID()
	genesisPath := filepath.Join(dir, "genesis.cbor")
	require.NoError(t, os.WriteFile(genesisPath, graw, 0o644))
	pin := "0x" + string(bytesHex(gid[:]))

	base := &baseFlags{HomeDir: dir}
	srcDB := filepath.Join(dir, "src.db")
	src := &rootNodeRunFlags{baseFlags: base, HandoffProfile: true, UTBGenesisFile: genesisPath, UTBGenesisID: pin, UTBEntriesDBFile: srcDB}
	store, closeStore, err := src.openUTBStore(nil)
	require.NoError(t, err)
	prev := g
	for e := uint64(2); e <= 8; e++ {
		next, err := utb.BuildUnsigned(prev, facts(e, e*100))
		require.NoError(t, err)
		for _, m := range ms[:3] {
			require.NoError(t, next.Sign(m.id, m.signer))
		}
		raw, _ := next.MarshalCBOR()
		_, err = store.Append(raw)
		require.NoError(t, err)
		prev = next
	}
	closeStore()

	run := func(c interface {
		SetArgs([]string)
		Execute() error
	}, args ...string) error {
		c.SetArgs(args)
		return c.Execute()
	}
	bundle := filepath.Join(dir, "bundle.cbor")
	require.NoError(t, run(trustBaseUTBExportCmd(base), "--utb-genesis", genesisPath, "--utb-genesis-id", pin, "--utb-entries-db", srcDB, "--out", bundle))

	require.NoError(t, run(trustBaseUTBVerifyCmd(), "--bundle", bundle, "--utb-genesis-id", pin))
	// #1297: --keys-out writes every epoch's root signing keys of the verified history
	keysOut := filepath.Join(dir, "keys.json")
	require.NoError(t, run(trustBaseUTBVerifyCmd(), "--bundle", bundle, "--utb-genesis-id", pin, "--keys-out", keysOut))
	var keys struct {
		Format, GenesisID string
		Epochs            []struct {
			Epoch uint64
			Keys  []string
		}
	}
	keysRaw, err := os.ReadFile(keysOut)
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal(keysRaw, &keys))
	require.Equal(t, "unicity-utb-root-keys/1", keys.Format)
	require.Equal(t, pin, keys.GenesisID)
	require.Len(t, keys.Epochs, 8)
	for i, e := range keys.Epochs {
		require.EqualValues(t, i+1, e.Epoch)
		var want []string
		for _, m := range ms {
			want = append(want, "0x"+string(bytesHex(m.key)))
		}
		require.ElementsMatch(t, want, e.Keys)
	}
	// --url reads a served history page by page (three entries a page here) and verifies the assembled bundle
	served, err := readBundle(bundle)
	require.NoError(t, err)
	tipID, err := served.Tip().EntryID()
	require.NoError(t, err)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		from, err := strconv.ParseUint(r.URL.Query().Get("from"), 10, 64)
		if err != nil || from < 1 || from > uint64(len(served.Raw)) || r.Header.Get("X-Forwarded-For") != "203.0.113.10" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		end := min(from+2, uint64(len(served.Raw)))
		page := &types.TrustBaseResponse{Version: types.TrustBaseResponseVersion, Network: served.Network, Status: types.TrustBaseStatusOK, FromEpoch: from,
			EffectiveEnd: uint64(len(served.Raw)), EndEntryID: tipID[:]}
		for _, e := range served.Raw[from-1 : end] {
			page.Entries = append(page.Entries, e)
		}
		if end < uint64(len(served.Raw)) {
			next := end + 1
			page.NextEpoch = &next
		}
		out, err := page.Encode()
		require.NoError(t, err)
		_, _ = w.Write(out)
	}))
	defer srv.Close()
	fetched, fetchedKeys := filepath.Join(dir, "fetched.cbor"), filepath.Join(dir, "fetched-keys.json")
	require.NoError(t, run(trustBaseUTBVerifyCmd(), "--url", srv.URL, "--forwarded-for", "203.0.113.10", "--utb-genesis-id", pin, "--save-bundle", fetched, "--keys-out", fetchedKeys))
	require.Equal(t, data0(t, bundle), data0(t, fetched), "the assembled bundle is the exported one")
	gotKeys, err := os.ReadFile(fetchedKeys)
	require.NoError(t, err)
	require.Equal(t, keysRaw, gotKeys)
	require.Error(t, run(trustBaseUTBVerifyCmd(), "--url", srv.URL, "--utb-genesis-id", pin), "the gateway refuses a client without the proxy header")
	require.Error(t, run(trustBaseUTBVerifyCmd(), "--bundle", bundle, "--url", srv.URL, "--utb-genesis-id", pin), "one source")
	require.Error(t, run(trustBaseUTBVerifyCmd(), "--bundle", bundle, "--utb-genesis-id", "0x"+string(bytesHex(make([]byte, 32))), "--keys-out", filepath.Join(dir, "no.json")))
	_, err = os.Stat(filepath.Join(dir, "no.json"))
	require.True(t, os.IsNotExist(err), "an unverified history writes no keys")
	require.Error(t, run(trustBaseUTBVerifyCmd(), "--bundle", bundle, "--utb-genesis-id", "0x"+string(bytesHex(make([]byte, 32)))), "another pin")
	data, err := os.ReadFile(bundle)
	require.NoError(t, err)
	tampered := filepath.Join(dir, "tampered.cbor")
	bad := bytes.Clone(data)
	bad[len(bad)/2] ^= 1
	require.NoError(t, os.WriteFile(tampered, bad, 0o644))
	require.Error(t, run(trustBaseUTBVerifyCmd(), "--bundle", tampered, "--utb-genesis-id", pin))
	require.NoError(t, os.WriteFile(tampered, append(bytes.Clone(data), 0), 0o644))
	require.Error(t, run(trustBaseUTBVerifyCmd(), "--bundle", tampered, "--utb-genesis-id", pin), "trailing bytes")

	// a fresh store takes the shipped history; a second import is idempotent; the export of the result is the same file
	dstDB := filepath.Join(dir, "dst.db")
	require.NoError(t, run(trustBaseUTBImportCmd(base), "--utb-genesis", genesisPath, "--utb-genesis-id", pin, "--utb-entries-db", dstDB, "--bundle", bundle))
	require.NoError(t, run(trustBaseUTBImportCmd(base), "--utb-genesis", genesisPath, "--utb-genesis-id", pin, "--utb-entries-db", dstDB, "--bundle", bundle))
	again := filepath.Join(dir, "again.cbor")
	require.NoError(t, run(trustBaseUTBExportCmd(base), "--utb-genesis", genesisPath, "--utb-genesis-id", pin, "--utb-entries-db", dstDB, "--out", again))
	got, err := os.ReadFile(again)
	require.NoError(t, err)
	require.Equal(t, data, got)
}

func data0(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	require.NoError(t, err)
	return b
}
