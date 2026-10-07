package bridgeprofile

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

const candidatePin = "testdata/corpus-candidate.digest"

var updateCorpus = os.Getenv("UPDATE_CORPUS_PIN") != ""

func TestCorpusIsDeterministicAndPinned(t *testing.T) {
	a, err := BuildCorpus()
	require.NoError(t, err)
	b, err := BuildCorpus()
	require.NoError(t, err)
	require.Equal(t, len(a.Files), len(b.Files))
	for p, x := range a.Files {
		require.True(t, bytes.Equal(x, b.Files[p]), "%s differs between two generations", p)
	}
	if updateCorpus {
		require.NoError(t, os.MkdirAll("testdata", 0o755))
		require.NoError(t, os.WriteFile(candidatePin, []byte(a.Digest()+"\n"), 0o644))
	}
	want, err := os.ReadFile(candidatePin)
	require.NoError(t, err, "UPDATE_CORPUS_PIN=1 go test ./bridgeprofile -run TestCorpusIsDeterministicAndPinned")
	require.Equal(t, strings.TrimSpace(string(want)), a.Digest(),
		"the candidate corpus changed; review the diff of the generated tree and update the pin")
	// The tree is exactly what native-bridge-plugins' tools/vectors.py seals: the nine
	// family directories plus the semantic profile and the pinned SDK trust document.
	for p := range a.Files {
		dir, _, _ := strings.Cut(p, "/")
		require.Contains(t, families, dir, p)
		require.NotContains(t, []string{"VERSION", "provenance.json", "SHA256SUMS", "MANIFEST.sha256", "PROVENANCE.json"}, p)
	}
	require.Equal(t, semanticProfile, a.Files["config/semantic-profile.json"])
}

// TestCorpusReplay re-executes every case from the bytes in the generated
// files alone (fixtures parsed from the JSON, nothing from the builders) and
// compares with the stored expectation.
func TestCorpusReplay(t *testing.T) {
	c, err := BuildCorpus()
	require.NoError(t, err)
	var fs FixtureSet
	require.NoError(t, json.Unmarshal(c.Files["config/fixtures.json"], &fs))
	seen := map[string]bool{}
	total := 0
	for _, fam := range families {
		var cf CaseFile
		require.NoError(t, json.Unmarshal(c.Files[fam+"/cases.json"], &cf))
		require.Equal(t, fam, cf.Family)
		require.Equal(t, NativeBridgeProtoVersion, cf.Proto)
		require.NotEmpty(t, cf.Cases, fam)
		for _, cs := range cf.Cases {
			require.False(t, seen[cs.ID], "duplicate id %s", cs.ID)
			seen[cs.ID] = true
			total++
			require.Equal(t, cs.Expected, Replay(&fs, cs), cs.ID)
		}
	}
	require.GreaterOrEqual(t, total, 250)
	// Every prior case ID survives as mapped regression coverage.
	for _, id := range priorCaseIDs {
		if r, ok := priorCaseRename[id]; ok {
			id = r
		}
		require.True(t, seen[id], "prior case %s has no counterpart", id)
	}
}

// TestCorpusCoversTheDesign pins the required case classes of design section 7
// by ID and outcome, so a dropped class fails loudly.
func TestCorpusCoversTheDesign(t *testing.T) {
	c, err := BuildCorpus()
	require.NoError(t, err)
	want := map[string]string{ // id -> reason ("" = ok)
		"network-0-cfg": "ErrIntRange", "network-0-mint": "ErrIntRange", "network-0-prepare": "ErrIntRange",
		"network-1-cfg": "", "network-1-mint": "", "network-1-prepare": "",
		"network-65535-cfg": "", "network-65535-mint": "", "network-65535-prepare": "",
		"network-65536-cfg": "ErrIntRange", "network-65536-kernel-0": "ErrIntRange", "network-65536-kernel-1": "ErrIntRange",
		"network-0-mint-wire": "ErrIntRange", "network-65536-mint-wire": "ErrIntRange",
		"deadline-null-valid": "", "deadline-explicit-before": "", "deadline-explicit-equal": "ErrDeadlineExpired",
		"deadline-explicit-after": "ErrDeadlineExpired", "deadline-cd-differs": "ErrDeadlineMismatch",
		"wire-cd-deadline-zero": "ErrDeadline", "wire-pre30-mint": "ErrShape", "wire-pre30-transfer": "ErrShape",
		"wire-pre30-cd": "ErrShape", "token-proof-pre30-no-time": "ErrShape", "mint-pre30-pointer-reason": "ErrMintJustif",
		"mint-pre30-bare-payload": "ErrMintData", "compose-false-opening": "ErrIROpening", "compose-ir-time-before-latest-t": "ErrIRTime",
		"compose-refresh-later-anchor": "", "compose-refresh-rewritten-t": "ErrLeafProof", "compose-txhash-as-leaf-value": "ErrLeafProof",
		"unlock-regression-01": "", "unlock-regression-00": "ErrUnlockKey", "backing-valid": "",
		"backing-trust-base-digest": "ErrTrustBaseDigest", "backing-next-epoch-trust-base": "ErrTrustBaseDigest",
		"backing-non-unit-weight": "ErrTrustConfig", "backing-threshold": "ErrTrustConfig", "backing-epoch-mismatch": "ErrEpochMismatch",
		"backing-epoch-start-after": "ErrEpochMismatch", "backing-other-network": "ErrEpochMismatch",
		"mint-j-mutated-after-certification": "ErrCDMismatch", "justification-missing-proof": "ErrLockProofShape",
		"justification-bound-header-over": "ErrLockProofTooLarge", "justification-over-64k": "ErrJustificationTooLarge",
		"mint-two-assets": "ErrMintData", "return-partial-amount": "ErrReturnAmount",
		"kernel-return-valid": "", "token-third-slot": "ErrShape", "backing-header-not-bound": "ErrLockHeader",
		"backing-quorum-n3-signers3": "", "backing-quorum-n3-signers2": "ErrLockUC",
		"backing-quorum-n4-signers3": "", "backing-quorum-n4-signers2": "ErrLockUC",
		"backing-quorum-n7-signers5": "", "backing-quorum-n7-signers4": "ErrLockUC",
	}
	for _, mutation := range certificateMutations() {
		want["token-certificate-"+mutation.name] = "ErrCertScan"
		want["backing-certificate-"+mutation.name] = "ErrCertScan"
	}
	want["trust-network-0"] = "ErrTrustConfig"
	want["trust-network-65536"] = "ErrTrustConfig"
	want["token-combined-path-2048"] = ""
	want["token-combined-path-2049"] = "ErrTooManyPaths"
	got := map[string]Expect{}
	for _, fam := range families {
		for _, cs := range c.Cases[fam] {
			got[cs.ID] = cs.Expected
		}
	}
	for id, reason := range want {
		e, ok := got[id]
		require.True(t, ok, id)
		if reason == "" {
			require.Equal(t, "ok", e.Status, id)
		} else {
			require.Equal(t, reason, e.Reason, id)
		}
	}
	for _, network := range []string{"1", "65535"} {
		for _, op := range []string{"mint", "prepare"} {
			id := "network-" + network + "-" + op
			out, err := hex.DecodeString(got[id].Output)
			require.NoError(t, err, id)
			valid, _, err := DecodeResult(out)
			require.NoError(t, err, id)
			require.True(t, valid, id)
		}
	}
	// A successful kernel output is 448+128*m bytes.
	for _, cs := range c.Cases["wire"] {
		if cs.ID == "kernel-return-valid" {
			out, _ := hex.DecodeString(cs.Expected.Output)
			var m int
			var fs FixtureSet
			require.NoError(t, json.Unmarshal(c.Files["config/fixtures.json"], &fs))
			in, _ := hex.DecodeString(cs.Input)
			_ = in
			_, res, err := DecodeResult(out)
			require.NoError(t, err)
			m = len(res.Leaves)
			require.Equal(t, 448+128*m, len(out))
		}
	}
}
