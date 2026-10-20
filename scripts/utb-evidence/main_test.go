package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/unicitynetwork/bft-core/bridgeprofile"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-go-base/types"

	"github.com/unicitynetwork/bft-core/gettrustbase"
	testcertificates "github.com/unicitynetwork/bft-core/internal/testutils/certificates"
	"github.com/unicitynetwork/bft-core/internal/testutils/utbchain"
	"github.com/unicitynetwork/bft-core/network/protocol/certification"
	"github.com/unicitynetwork/bft-core/utbstore"
)

// aggregator serves a store's history the way the patched aggregator does: GET ?from=E[&snapshotEnd=E&snapshotEntryId=0x..], the PR6 response.
func aggregator(t *testing.T, store *utbstore.Store, maxEntries uint32) *httptest.Server {
	srv, err := gettrustbase.NewServer(store, gettrustbase.Config{})
	require.NoError(t, err)
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		from, err := strconv.ParseUint(r.URL.Query().Get("from"), 10, 64)
		if err != nil {
			http.Error(w, "from", http.StatusBadRequest)
			return
		}
		req := &gettrustbase.Request{Version: gettrustbase.Version, Network: 5, FromEpoch: from, MaxEntries: maxEntries, MaxBytes: 1 << 20}
		if s := r.URL.Query().Get("snapshotEnd"); s != "" {
			end, _ := strconv.ParseUint(s, 10, 64)
			id, _ := hex.DecodeString(r.URL.Query().Get("snapshotEntryId")[2:])
			req.SnapshotEnd, req.SnapshotEntryID = &end, id
		}
		body, err := srv.Respond(req).Encode()
		require.NoError(t, err)
		_, _ = w.Write(body)
	}))
}

func TestFetchVerifyExtractAndTheReferenceClient(t *testing.T) {
	dir := t.TempDir()
	chain := utbchain.New(t, 4)
	store := chain.Store(t, 1)
	srv := aggregator(t, store, 2) // two entries a page: the cursor is followed
	defer srv.Close()
	pin, _ := chain.Genesis.EntryID()
	pinS := "0x" + hex.EncodeToString(pin[:])
	genesisRaw, _ := chain.Genesis.MarshalCBOR()
	genesisFile := filepath.Join(dir, "genesis.cbor")
	require.NoError(t, os.WriteFile(genesisFile, genesisRaw, 0o644))

	// the client holds the genesis only; the aggregator is at epoch 1
	clientStore := filepath.Join(dir, "client.db")
	require.NoError(t, cmdClient([]string{"--url", srv.URL, "--store", clientStore, "--genesis", genesisFile, "--pin", pinS}))

	// the aggregator learns epoch 2 (the ordinary handoff), the client syncs the one entry
	_, err := store.Append(chain.Entries[0])
	require.NoError(t, err)
	require.NoError(t, cmdClient([]string{"--url", srv.URL, "--store", clientStore, "--genesis", genesisFile, "--pin", pinS}))

	// it misses epochs 3 and 4 (the client is offline), then fetches the two-entry gap in one request and reloads from its own store
	for _, e := range chain.Entries[1:] {
		_, err := store.Append(e)
		require.NoError(t, err)
	}
	require.NoError(t, cmdClient([]string{"--url", srv.URL, "--store", clientStore, "--genesis", genesisFile, "--pin", pinS}))
	require.NoError(t, cmdClient([]string{"--url", srv.URL, "--store", clientStore, "--genesis", genesisFile, "--pin", pinS}), "an up-to-date client appends nothing")

	// the complete history, verified from the pin, one record at a time
	bundleFile := filepath.Join(dir, "final.cbor")
	require.NoError(t, cmdFetch([]string{"--url", srv.URL, "--out", bundleFile}))
	require.NoError(t, cmdVerify([]string{"--bundle", bundleFile, "--pin", pinS}))
	wrong := "0x" + hex.EncodeToString(make([]byte, 32))
	require.Error(t, cmdVerify([]string{"--bundle", bundleFile, "--pin", wrong}), "another pin")

	out := filepath.Join(dir, "e3.cbor")
	require.NoError(t, cmdExtract([]string{"--bundle", bundleFile, "--epoch", "3", "--out", out}))
	got, _ := os.ReadFile(out)
	require.Equal(t, chain.Entries[1], got)
	require.Error(t, cmdExtract([]string{"--bundle", bundleFile, "--epoch", "9", "--out", out}))
}

func TestFetchRefusesATamperedHistory(t *testing.T) {
	dir := t.TempDir()
	chain := utbchain.New(t, 3)
	pin, _ := chain.Genesis.EntryID()
	raw := [][]byte{}
	g, _ := chain.Genesis.MarshalCBOR()
	bad := bytes.Clone(chain.Entries[0])
	bad[len(bad)-9] ^= 1 // inside a signature
	raw = append(raw, g, bad)
	bundle, err := gettrustbase.EncodeBundle(raw)
	if err != nil {
		t.Skip("the codec already refuses this tamper:", err)
	}
	f := filepath.Join(dir, "b.cbor")
	require.NoError(t, os.WriteFile(f, bundle, 0o644))
	require.Error(t, cmdVerify([]string{"--bundle", f, "--pin", "0x" + hex.EncodeToString(pin[:])}))
}

func TestUCRespCheckRequiresTheExactAttachment(t *testing.T) {
	dir := t.TempDir()
	chain := utbchain.New(t, 3)
	base := &certification.CertificationResponse{Partition: 1,
		UC: types.UnicityCertificate{Version: 1, UnicityTreeCertificate: &types.UnicityTreeCertificate{Version: 1, Partition: 1}}}
	require.NoError(t, base.SetTechnicalRecord(certification.TechnicalRecord{Round: 5, Epoch: 2, Leader: "1", StatHash: []byte{1}, FeeHash: []byte{2}}))
	msg, err := types.Cbor.Marshal(certification.NewCertificationResponseV3(base, chain.Entries[:1]))
	require.NoError(t, err)
	file, entry, other := filepath.Join(dir, "m.cbor"), filepath.Join(dir, "e2.cbor"), filepath.Join(dir, "e3.cbor")
	require.NoError(t, os.WriteFile(file, msg, 0o644))
	require.NoError(t, os.WriteFile(entry, chain.Entries[0], 0o644))
	require.NoError(t, os.WriteFile(other, chain.Entries[1], 0o644))
	require.NoError(t, cmdUCResp([]string{"--file", file, "--entry", entry}))
	require.Error(t, cmdUCResp([]string{"--file", file, "--entry", other}), "another entry")
	legacy, _ := types.Cbor.Marshal(base)
	require.NoError(t, os.WriteFile(file, legacy, 0o644))
	require.Error(t, cmdUCResp([]string{"--file", file, "--entry", entry}), "a legacy response is not a version 2 response")
	require.NoError(t, os.WriteFile(file, []byte("x\n"), 0o644))
	require.Error(t, cmdUCResp([]string{"--file", file, "--entry", entry}), "a placeholder")
}

// A saved token holds the certificates the aggregator returned when its transitions were certified. Each verifies under the committee of ITS OWN epoch, strictly, and
// inside that epoch's activation interval.
func TestUCVerifyChecksEachCertificateUnderItsOwnEpoch(t *testing.T) {
	dir := t.TempDir()
	chain := utbchain.New(t, 3) // epoch e starts at round 100*e (the genesis at 1)
	store := chain.Store(t, 3)
	g, _ := chain.Genesis.MarshalCBOR()
	raw := [][]byte{g}
	raw = append(raw, chain.Entries...)
	bundle, err := gettrustbase.EncodeBundle(raw)
	require.NoError(t, err)
	bundleFile := filepath.Join(dir, "b.cbor")
	require.NoError(t, os.WriteFile(bundleFile, bundle, 0o644))
	_ = store

	pdr := &types.PartitionDescriptionRecord{Version: 1, NetworkID: 5, PartitionID: 9, PartitionTypeID: 9, T2Timeout: 2500000000}
	conf, err := json.Marshal(pdr)
	require.NoError(t, err)
	confFile := filepath.Join(dir, "conf.json")
	require.NoError(t, os.WriteFile(confFile, conf, 0o644))

	uc := func(epoch, round uint64, signers int) []byte {
		cert := testcertificates.CreateUnicityCertificate(t, chain.Members[0].Signer, &types.InputRecord{Version: 1, RoundNumber: 7, Hash: bytes.Repeat([]byte{1}, 32),
			BlockHash: bytes.Repeat([]byte{2}, 32), SummaryValue: []byte{0}, Timestamp: 1, Epoch: 0}, pdr, round, bytes.Repeat([]byte{3}, 32), bytes.Repeat([]byte{4}, 32))
		cert.UnicitySeal.Epoch = epoch
		cert.UnicitySeal.Signatures = nil
		for _, m := range chain.Members[:signers] {
			require.NoError(t, cert.UnicitySeal.Sign(m.ID, m.Signer))
		}
		enc, err := types.Cbor.Marshal(cert)
		require.NoError(t, err)
		return enc
	}
	token := func(ucs ...[]byte) string {
		var arr []any
		for _, u := range ucs {
			arr = append(arr, cbor.RawMessage(u))
		}
		enc, err := cbor.Marshal([]any{uint64(2), arr})
		require.NoError(t, err)
		f := filepath.Join(dir, fmt.Sprintf("token-%d.cbor", len(enc)))
		require.NoError(t, os.WriteFile(f, enc, 0o644))
		return f
	}
	run := func(tok string) error {
		return cmdUCVerify([]string{"--token", tok, "--bundle", bundleFile, "--shard-conf", confFile})
	}
	require.NoError(t, run(token(uc(1, 50, 3), uc(2, 250, 3))), "the pre-handoff certificate under the genesis committee, the post-handoff one under epoch 2's")
	require.Error(t, run(token(uc(1, 250, 3))), "a retired committee signing after its successor started")
	require.Error(t, run(token(uc(2, 150, 3))), "a round before the epoch started")
	require.Error(t, run(token(uc(1, 50, 2))), "below the threshold")
	require.Error(t, run(token(uc(5, 50, 3))), "an epoch the history does not hold")
	empty, _ := cbor.Marshal([]any{uint64(2), []any{}})
	ef := filepath.Join(dir, "empty.cbor")
	require.NoError(t, os.WriteFile(ef, empty, 0o644))
	require.Error(t, run(ef), "a token with no certificate proves nothing")
}

// Several shards of one aggregator partition (the two-shard lane): a token holds certificates of both, each verifies under its own shard's configuration, and a
// certificate of a configuration which was not given is refused, whichever order the configurations are listed in. Real two-shard certificates from the bridge
// profile's aggregator world (one shard tree per certificate).
func TestUCVerifyTwoShardsOfOnePartition(t *testing.T) {
	dir := t.TempDir()
	auth, err := bridgeprofile.NewAuthority("root-1")
	require.NoError(t, err)
	tb, err := auth.Genesis(bridgeprofile.DevNetwork, 1, 1)
	require.NoError(t, err)
	gen, err := types.Cbor.Marshal(tb)
	require.NoError(t, err)
	bundle, err := gettrustbase.EncodeBundle([][]byte{gen})
	require.NoError(t, err)
	bundleFile := filepath.Join(dir, "b.cbor")
	require.NoError(t, os.WriteFile(bundleFile, bundle, 0o644))

	left, right := types.ShardID{}.Split()
	pdrL := bridgeprofile.FixtureShardPDR(bridgeprofile.DevNetwork, bridgeprofile.DevAggPart, left, bridgeprofile.DevChainID, "agg-0")
	pdrR := bridgeprofile.FixtureShardPDR(bridgeprofile.DevNetwork, bridgeprofile.DevAggPart, right, bridgeprofile.DevChainID, "agg-1")
	pdrOther := bridgeprofile.FixtureShardPDR(bridgeprofile.DevNetwork, bridgeprofile.DevAggPart, right, bridgeprofile.DevChainID, "agg-other") // not the one certified under
	conf := func(name string, pdr *types.PartitionDescriptionRecord) string {
		enc, err := json.Marshal(pdr)
		require.NoError(t, err)
		f := filepath.Join(dir, name)
		require.NoError(t, os.WriteFile(f, enc, 0o644))
		return f
	}
	confL, confR, confOther := conf("l.json", pdrL), conf("r.json", pdrR), conf("o.json", pdrOther)

	world := &bridgeprofile.AggregatorWorld{PDRs: []*types.PartitionDescriptionRecord{pdrL, pdrR}, Auth: auth, TB: tb}
	var sl, sr [32]byte
	sl[0], sr[0] = 0x00, 0x80 // the top bit picks the shard
	sl[1], sr[1] = 1, 1
	cert, err := world.Certify([]bridgeprofile.Leaf{{SID: sl, Value: sl}, {SID: sr, Value: sr}}, nil, 1_000, 5)
	require.NoError(t, err)
	require.Len(t, cert.Anchors, 2)
	token := func(name string, ucs ...[]byte) string {
		var arr []any
		for _, u := range ucs {
			arr = append(arr, cbor.RawMessage(u))
		}
		enc, err := cbor.Marshal([]any{uint64(2), arr})
		require.NoError(t, err)
		f := filepath.Join(dir, name)
		require.NoError(t, os.WriteFile(f, enc, 0o644))
		return f
	}
	run := func(tok string, confs ...string) error {
		return cmdUCVerify([]string{"--token", tok, "--bundle", bundleFile, "--shard-conf", strings.Join(confs, ",")})
	}
	both := token("both.cbor", cert.Anchors[0].UC, cert.Anchors[1].UC)
	require.NoError(t, run(both, confL, confR), "a token holding a certificate of each shard verifies against both configurations")
	require.NoError(t, run(both, confR, confL), "in either order")
	require.Error(t, run(both, confL), "the right shard's certificate does not verify under the left shard's configuration alone")
	require.Error(t, run(both, confL, confOther), "nor under a configuration it was not made under")
	require.NoError(t, run(token("left.cbor", cert.Anchors[0].UC), confL, confR))
}
