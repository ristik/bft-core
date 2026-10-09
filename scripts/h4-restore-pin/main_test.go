package main

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"

	gethtypes "github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/unicitynetwork/bft-core/evmroot"
	"github.com/unicitynetwork/bft-core/handoffdelivery"
	"github.com/unicitynetwork/bft-go-base/types"
	"github.com/unicitynetwork/bft-go-base/util"
)

func TestArchiveRecordDirectorySupportsV1AndV2(t *testing.T) {
	hash := strings.Repeat("ab", 32)
	for name, want := range map[string]bool{
		hash:                             true,
		"v2-" + hash:                     true,
		"v2-" + strings.Repeat("g0", 32): false,
		"v3-" + hash:                     false,
		"v2-" + hash[:62]:                false,
		"prefix-" + hash:                 false,
	} {
		if got := archiveRecordDirectory(name); got != want {
			t.Errorf("archiveRecordDirectory(%q) = %v, want %v", name, got, want)
		}
	}
}

func TestPreferPinUsesLatestEpochThenRoundAndPrefersV2(t *testing.T) {
	cases := []struct {
		name                           string
		candidateV2                    bool
		candidateEpoch, candidateRound uint64
		bestV2                         bool
		bestEpoch, bestRound           uint64
		want                           bool
	}{
		{"later epoch beats larger prior epoch round", true, 3, 1, true, 2, 99, true},
		{"later round wins within epoch", true, 3, 10, true, 3, 9, true},
		{"older position loses", true, 2, 99, true, 3, 1, false},
		{"v2 beats v1", true, 1, 1, false, 8, 99, true},
		{"v1 cannot replace v2", false, 8, 99, true, 1, 1, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := preferPin(tc.candidateV2, tc.candidateEpoch, tc.candidateRound, tc.bestV2, tc.bestEpoch, tc.bestRound); got != tc.want {
				t.Fatalf("preferPin() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestArchiveTrustBodyIDReadsTheTipEpochBundle(t *testing.T) {
	dir := t.TempDir()
	bundle := handoffdelivery.Bundle{Body: evmroot.TrustBaseBodyV2{Epoch: 3, Version: evmroot.TrustBaseVersion}}
	raw, err := handoffdelivery.EncodeBundle(bundle)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(raw)
	path := filepath.Join(dir, fmt.Sprintf("bundle-%016x-test", bundle.Body.Epoch))
	if err := os.WriteFile(path, append(digest[:], raw...), 0600); err != nil {
		t.Fatal(err)
	}
	got, err := archiveTrustBodyID(dir, 3, &types.RootTrustBaseV1{Epoch: 1})
	if err != nil {
		t.Fatal(err)
	}
	want := bundle.Body.Identity()
	if got != [32]byte(want) {
		t.Fatalf("body id = %x, want %x", got, want)
	}
}

func TestNamedBodyIDIsTakenOnlyForItsEpochAndOnlyWhenWellFormed(t *testing.T) {
	id := strings.Repeat("ab", 32)
	got, ok := namedBodyID("1=00"+id[2:]+", 2="+id, 2)
	if !ok || hex.EncodeToString(got[:]) != id {
		t.Fatalf("epoch 2 must be taken: %x %v", got, ok)
	}
	for name, spec := range map[string]string{
		"another epoch": "3=" + id, "no spec": "", "short": "2=abab", "not hex": "2=" + strings.Repeat("zz", 32), "no separator": "2" + id,
	} {
		if _, ok := namedBodyID(spec, 2); ok {
			t.Fatalf("%s must not name a body identity", name)
		}
	}
	if _, ok := namedBodyID("2=0x"+id, 2); !ok {
		t.Fatal("a 0x prefix is accepted")
	}
}

// pinFixture is an archive with one certified record at root epoch `rootEpoch` and a genesis (epoch 1) trust base; it returns the paths.
func pinFixture(t *testing.T, rootEpoch uint64) (archive, trustBase, prefix string) {
	t.Helper()
	root := t.TempDir()
	archive = filepath.Join(root, "archive")
	record := filepath.Join(archive, strings.Repeat("ab", 32))
	if err := os.MkdirAll(record, 0o700); err != nil {
		t.Fatal(err)
	}
	uc := types.UnicityCertificate{
		InputRecord: &types.InputRecord{RoundNumber: 5, BlockHash: make([]byte, 32)},
		UnicitySeal: &types.UnicitySeal{Epoch: rootEpoch, RootChainRoundNumber: 9},
	}
	ucRaw, err := types.Cbor.Marshal(uc)
	if err != nil {
		t.Fatal(err)
	}
	headerRaw, err := rlp.EncodeToBytes(&gethtypes.Header{Number: big.NewInt(4)})
	if err != nil {
		t.Fatal(err)
	}
	for name, raw := range map[string][]byte{"resulting-uc": ucRaw, "resulting-tr": {1}, "header": headerRaw} {
		if err := os.WriteFile(filepath.Join(record, hex.EncodeToString([]byte(name))+".chunk"), raw, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	trustBase = filepath.Join(root, "trust-base.json")
	if err := util.WriteJsonFile(trustBase, &types.RootTrustBaseV1{Epoch: 1}); err != nil {
		t.Fatal(err)
	}
	return archive, trustBase, filepath.Join(root, "pin")
}

// Missing input is a named error, not a panic: each refusal is its own sentinel, so a caller can tell them apart.
func TestRunRefusesMissingInputWithNamedErrors(t *testing.T) {
	noEnv := func(string) string { return "" }
	var out strings.Builder

	if err := run([]string{"only-one"}, noEnv, &out); !errors.Is(err, errUsage) {
		t.Fatalf("wrong argument count: %v", err)
	}
	if err := run([]string{filepath.Join(t.TempDir(), "absent"), "tb.json", "pin"}, noEnv, &out); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("absent archive: %v", err)
	}
	empty := t.TempDir()
	if err := run([]string{empty, "tb.json", filepath.Join(empty, "pin")}, noEnv, &out); !errors.Is(err, errNoCertifiedPin) {
		t.Fatalf("archive with no certified record: %v", err)
	}

	// the case that panicked: the newest record is at root epoch 2, a Q3 activation the archive holds no bundle for
	archive, trustBase, prefix := pinFixture(t, 2)
	err := run([]string{archive, trustBase, prefix}, noEnv, &out)
	if !errors.Is(err, errNoTrustBodyID) {
		t.Fatalf("missing body identity: %v", err)
	}
	if !strings.Contains(err.Error(), "epoch 2") {
		t.Fatalf("the refusal does not name the epoch: %v", err)
	}
	if _, statErr := os.Stat(prefix + ".uc.cbor"); statErr == nil {
		t.Fatal("a refused run wrote a pin")
	}
	// naming another epoch's identity does not help; naming this epoch's does, and the pin is written
	other := func(string) string { return "3=" + strings.Repeat("ab", 32) }
	if err := run([]string{archive, trustBase, prefix}, other, &out); !errors.Is(err, errNoTrustBodyID) {
		t.Fatalf("an identity named for another epoch: %v", err)
	}
	named := func(string) string { return "2=" + strings.Repeat("ab", 32) }
	if err := run([]string{archive, trustBase, prefix}, named, &out); err != nil {
		t.Fatalf("named identity: %v", err)
	}
	if !strings.Contains(out.String(), "bodyID=0x"+strings.Repeat("ab", 32)) {
		t.Fatalf("pin line: %q", out.String())
	}
	if _, statErr := os.Stat(prefix + ".uc.cbor"); statErr != nil {
		t.Fatalf("the pin was not written: %v", statErr)
	}
}
