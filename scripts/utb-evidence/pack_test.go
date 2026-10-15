package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-go-base/types"
	"github.com/unicitynetwork/bft-go-base/util"

	"github.com/unicitynetwork/bft-core/gettrustbase"
	testcertificates "github.com/unicitynetwork/bft-core/internal/testutils/certificates"
	"github.com/unicitynetwork/bft-core/internal/testutils/utbchain"
	"github.com/unicitynetwork/bft-core/network/protocol/certification"
)

func goBuild(t *testing.T, dir, pkg, out string) string {
	t.Helper()
	cmd := exec.Command("go", "build", "-o", out, pkg)
	cmd.Dir = dir
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("go build %s: %v\n%s", pkg, err, b)
	}
	return out
}

func run(t *testing.T, bin string, args ...string) string {
	t.Helper()
	cmd := exec.Command(bin, args...)
	b, err := cmd.CombinedOutput()
	require.NoError(t, err, "%s %v: %s", bin, args, b)
	return string(b)
}

// buildPack writes a complete, real evidence pack: a signed chain of three epochs, a served-and-fetched history, a captured response, a token holding a certificate,
// and the verifier outputs the tool prints. The checker must accept it, and refuse every variation of it that has the right names and the wrong bytes.
func buildPack(t *testing.T, ubft, tool string) string {
	dir := t.TempDir()
	chain := utbchain.New(t, 3)
	pack := filepath.Join(dir, "pack")
	for _, d := range []string{"manifest/aggregator", "bundle", "entries", "ucresp", "verifier", "catchup", "handoff", "proofs", "history"} {
		require.NoError(t, os.MkdirAll(filepath.Join(pack, d), 0o755))
	}
	put := func(name string, data []byte) {
		require.NoError(t, os.WriteFile(filepath.Join(pack, name), data, 0o644))
	}

	// the deployment's genesis trust base: the V1 trust base whose entry is the chain's genesis
	var nodes []*types.NodeInfo
	for _, m := range chain.Members {
		nodes = append(nodes, &types.NodeInfo{NodeID: m.ID, SigKey: m.Key, Stake: 1})
	}
	tb, err := types.NewTrustBase(5, nodes, types.WithEpoch(1), types.WithEpochStart(1), types.WithQuorumThreshold(3))
	require.NoError(t, err)
	tb.StateHash, tb.ChangeRecordHash = bytes.Repeat([]byte{0x22}, 32), bytes.Repeat([]byte{0x33}, 32)
	require.NoError(t, util.WriteJsonFile(filepath.Join(pack, "manifest", "trust-base.json"), tb))
	out := run(t, ubft, "trust-base", "utb-manifest", "--trust-base", filepath.Join(pack, "manifest", "trust-base.json"), "--out-dir", filepath.Join(pack, "manifest"), "--relative-paths")
	require.Contains(t, out, "utb genesis id")
	pin, _ := chain.Genesis.EntryID()
	var m utbManifestJSON
	raw, _ := os.ReadFile(filepath.Join(pack, "manifest", "utb-manifest.json"))
	require.NoError(t, json.Unmarshal(raw, &m))
	require.Equal(t, "0x"+hex.EncodeToString(pin[:]), m.Derived.UTBGenesisEntryID, "premise: the chain's genesis is the trust base's")
	pdr := &types.PartitionDescriptionRecord{Version: 1, NetworkID: 5, PartitionID: 9, PartitionTypeID: 9, T2Timeout: 2500000000}
	conf, _ := json.Marshal(pdr)
	put("manifest/shard-conf.json", conf)
	put("manifest/build.txt", []byte("build\n"))
	for _, f := range []string{"base.txt", "patch.diff", "sha256.txt"} {
		put("manifest/aggregator/"+f, []byte("x\n"))
	}

	// the histories
	g, _ := chain.Genesis.MarshalCBOR()
	initial, err := gettrustbase.EncodeBundle([][]byte{g})
	require.NoError(t, err)
	final, err := gettrustbase.EncodeBundle(append([][]byte{g}, chain.Entries...))
	require.NoError(t, err)
	put("bundle/initial.cbor", initial)
	put("bundle/final.cbor", final)
	put("entries/ordinary-handoff.cbor", chain.Entries[0])
	put("entries/recovery.cbor", chain.Entries[1])
	pinS := "0x" + hex.EncodeToString(pin[:])
	verified := run(t, tool, "verify", "--bundle", filepath.Join(pack, "bundle", "final.cbor"), "--pin", pinS)
	for name, epoch := range map[string]string{"ordinary": "epoch 2 ", "recovery": "epoch 3 "} {
		var line string
		for _, l := range strings.Split(verified, "\n") {
			if strings.HasPrefix(l, epoch) {
				line = l
			}
		}
		require.NotEmpty(t, line)
		put("verifier/"+name+".txt", []byte(line+"\n"))
	}

	// the captured response
	base := &certification.CertificationResponse{Partition: 9,
		UC: types.UnicityCertificate{Version: 1, UnicityTreeCertificate: &types.UnicityTreeCertificate{Version: 1, Partition: 9}}}
	require.NoError(t, base.SetTechnicalRecord(certification.TechnicalRecord{Round: 5, Epoch: 2, Leader: "1", StatHash: []byte{1}, FeeHash: []byte{2}}))
	msg, err := types.Cbor.Marshal(certification.NewCertificationResponseV2(base, chain.Entries[:1]))
	require.NoError(t, err)
	put("ucresp/piggyback-sample.cbor", msg)

	// the original token: one certificate of epoch 1, and its recorded digest and verification
	cert := testcertificates.CreateUnicityCertificate(t, chain.Members[0].Signer, &types.InputRecord{Version: 1, RoundNumber: 7, Hash: bytes.Repeat([]byte{1}, 32),
		BlockHash: bytes.Repeat([]byte{2}, 32), SummaryValue: []byte{0}, Timestamp: 1}, pdr, 50, bytes.Repeat([]byte{3}, 32), bytes.Repeat([]byte{4}, 32))
	cert.UnicitySeal.Signatures = nil
	for _, mm := range chain.Members[:3] {
		require.NoError(t, cert.UnicitySeal.Sign(mm.ID, mm.Signer))
	}
	enc, err := types.Cbor.Marshal(cert)
	require.NoError(t, err)
	tok, err := cbor.Marshal([]any{uint64(2), []any{cbor.RawMessage(enc)}})
	require.NoError(t, err)
	put("proofs/token.cbor", tok)
	sum := sha256.Sum256(tok)
	put("proofs/original-proof.sha256", []byte(hex.EncodeToString(sum[:])+"\n"))
	hist := run(t, tool, "uc-verify", "--token", filepath.Join(pack, "proofs", "token.cbor"), "--bundle", filepath.Join(pack, "bundle", "final.cbor"), "--shard-conf", filepath.Join(pack, "manifest", "shard-conf.json"))
	put("proofs/historical-verify.log", []byte(strings.TrimSuffix(hist, "\n")))
	put("proofs/bridge-receipt.json", []byte(`{"redeem":{"gasUsed":"12345"},"claim":{"gasUsed":"6789"}}`))

	fsum := sha256.Sum256(final)
	put("history/client-reload.log", []byte(fmt.Sprintf("client: tip before 1, appended [2 3], tip now 3 entryId 0x00\nfinal bundle sha256 %x\n", fsum)))
	put("catchup/client-gap-two-entries.log", []byte("client: tip before 1, appended [2 3], tip now 3 entryId 0x00\n"))
	put("catchup/aggregator-peer-repair.log", []byte("peer repair\n"))
	put("catchup/restart.log", []byte("restart\n"))
	put("handoff/ordinary-ack.log", []byte("piggyback\n"))
	put("handoff/recovery-closure.log", []byte("J closed at (1,2) = its closure\n"))
	return pack
}

type utbManifestJSON struct {
	Derived struct {
		UTBGenesisEntryID string `json:"utbGenesisEntryId"`
	} `json:"derived"`
}

func check(t *testing.T, ubft, tool, pack string) (string, error) {
	cmd := exec.Command("bash", "-c", "source scripts/lib/utb-lib.sh; utb_check_evidence \"$1\"", "bash", pack)
	cmd.Dir = repoRoot(t)
	cmd.Env = append(os.Environ(), "UBFT="+ubft, "UTB_EVIDENCE="+tool)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func repoRoot(t *testing.T) string {
	wd, err := os.Getwd()
	require.NoError(t, err)
	return filepath.Dir(filepath.Dir(wd))
}

func copyDir(t *testing.T, src string) string {
	dst := filepath.Join(t.TempDir(), "pack")
	require.NoError(t, exec.Command("cp", "-R", src, dst).Run())
	return dst
}

func TestEvidencePackIsCheckedByTheToolsAndEveryBadByteIsRefused(t *testing.T) {
	root := repoRoot(t)
	ubft := os.Getenv("UBFT_BIN")
	if ubft == "" {
		ubft = goBuild(t, filepath.Join(root, "cli", "ubft"), ".", filepath.Join(t.TempDir(), "ubft"))
	}
	tool := goBuild(t, root, "./scripts/utb-evidence", filepath.Join(t.TempDir(), "utb-evidence"))
	good := buildPack(t, ubft, tool)

	out, err := check(t, ubft, tool, good)
	require.NoError(t, err, out)

	chain := utbchain.New(t, 3) // the same fixed keys: the same records
	for name, tc := range map[string]struct {
		mutate func(pack string)
		want   string
	}{
		"a placeholder in the final bundle": {func(p string) { write(t, p, "bundle/final.cbor", []byte("x\n")) }, "does not verify"},
		"a signature byte flipped in the final bundle": {func(p string) {
			b := read(t, p, "bundle/final.cbor")
			b[len(b)-40] ^= 1
			write(t, p, "bundle/final.cbor", b)
		}, "does not verify"},
		"the ordinary entry replaced by another epoch's": {func(p string) { write(t, p, "entries/ordinary-handoff.cbor", chain.Entries[1]) }, "not the history's record for epoch 2"},
		"an entry that is not a record at all":           {func(p string) { write(t, p, "entries/recovery.cbor", []byte("x\n")) }, "not the history's record for epoch 3"},
		"a verifier output edited":                       {func(p string) { write(t, p, "verifier/recovery.txt", []byte("epoch 3 ok threshold 3\n")) }, "not the verifier's line"},
		"the initial history equal to the final":         {func(p string) { write(t, p, "bundle/initial.cbor", read(t, p, "bundle/final.cbor")) }, "did not advance"},
		"a placeholder initial history":                  {func(p string) { write(t, p, "bundle/initial.cbor", []byte("x\n")) }, "initial.cbor does not verify"},
		"a response attaching another entry":             {func(p string) { write(t, p, "entries/ordinary-handoff.cbor", read(t, p, "entries/recovery.cbor")) }, "not the history's record"},
		"a placeholder UCResp sample":                    {func(p string) { write(t, p, "ucresp/piggyback-sample.cbor", []byte("x\n")) }, "UCResp sample"},
		"a legacy response as the sample":                {func(p string) { write(t, p, "ucresp/piggyback-sample.cbor", legacyResponse(t)) }, "UCResp sample"},
		"a refetched token":                              {func(p string) { write(t, p, "proofs/token.cbor", []byte("x\n")) }, "not the original proof"},
		"a historical log that is not the tool's output": {func(p string) { write(t, p, "proofs/historical-verify.log", []byte("verified\n")) }, "not the verifier's output"},
		"a client reload without the final digest":       {func(p string) { write(t, p, "history/client-reload.log", []byte("tip now 3\n")) }, "client-reload.log"},
		"a client that fetched one entry at a time":      {func(p string) { write(t, p, "catchup/client-gap-two-entries.log", []byte("client: appended [3]\n")) }, "epochs 2 and 3 fetched in one sync"},
		"a failed redemption": {func(p string) {
			write(t, p, "proofs/bridge-receipt.json", []byte(`{"redeem":{"gasUsed":"0"},"claim":{"gasUsed":"1"}}`))
		}, "successful redemption"},
		"a trust base other than the manifest's": {func(p string) {
			write(t, p, "manifest/trust-base.json", append(read(t, p, "manifest/trust-base.json"), ' '))
		}, "manifest does not check out"},
		"an empty file":  {func(p string) { write(t, p, "catchup/restart.log", nil) }, "missing or empty"},
		"a missing file": {func(p string) { require.NoError(t, os.Remove(filepath.Join(p, "handoff/ordinary-ack.log"))) }, "missing or empty"},
	} {
		t.Run(name, func(t *testing.T) {
			pack := copyDir(t, good)
			tc.mutate(pack)
			out, err := check(t, ubft, tool, pack)
			require.Error(t, err, "the checker accepted it")
			require.Contains(t, out, tc.want)
		})
	}

	t.Run("the pack is self-contained: it checks out after it is moved and without any live deployment", func(t *testing.T) {
		moved := filepath.Join(t.TempDir(), "elsewhere")
		require.NoError(t, exec.Command("cp", "-R", good, moved).Run())
		out, err := check(t, ubft, tool, moved)
		require.NoError(t, err, out)
	})
	t.Run("a pack of placeholders", func(t *testing.T) {
		pack := t.TempDir()
		for _, f := range requiredFiles(t, root) {
			require.NoError(t, os.MkdirAll(filepath.Dir(filepath.Join(pack, f)), 0o755))
			require.NoError(t, os.WriteFile(filepath.Join(pack, f), []byte("x\n"), 0o644))
		}
		out, err := check(t, ubft, tool, pack)
		require.Error(t, err)
		require.NotContains(t, out, "ok", out)
	})
}

func requiredFiles(t *testing.T, root string) []string {
	cmd := exec.Command("bash", "-c", "source scripts/lib/utb-lib.sh; utb_evidence_required")
	cmd.Dir = root
	b, err := cmd.Output()
	require.NoError(t, err)
	return strings.Fields(string(b))
}

func read(t *testing.T, pack, name string) []byte {
	b, err := os.ReadFile(filepath.Join(pack, name))
	require.NoError(t, err)
	return b
}

func write(t *testing.T, pack, name string, data []byte) {
	require.NoError(t, os.WriteFile(filepath.Join(pack, name), data, 0o644))
}

func legacyResponse(t *testing.T) []byte {
	base := &certification.CertificationResponse{Partition: 9,
		UC: types.UnicityCertificate{Version: 1, UnicityTreeCertificate: &types.UnicityTreeCertificate{Version: 1, Partition: 9}}}
	require.NoError(t, base.SetTechnicalRecord(certification.TechnicalRecord{Round: 5, Epoch: 2, Leader: "1", StatHash: []byte{1}, FeeHash: []byte{2}}))
	b, err := types.Cbor.Marshal(base)
	require.NoError(t, err)
	return b
}
