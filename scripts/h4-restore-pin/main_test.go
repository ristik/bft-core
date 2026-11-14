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
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/unicitynetwork/bft-core/archive"
	"github.com/unicitynetwork/bft-core/archive/archivetest"
	"github.com/unicitynetwork/bft-core/evmroot"
	"github.com/unicitynetwork/bft-core/handoffdelivery"
	"github.com/unicitynetwork/bft-go-base/types"
	"github.com/unicitynetwork/bft-go-base/util"
)

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
	// The bundle directory of the current archive layout, and the archive directory itself for an archive written before bft-core#1018.
	for _, sub := range []string{"bundles", ""} {
		t.Run("in "+sub+"/", func(t *testing.T) {
			dir := t.TempDir()
			bundle := handoffdelivery.Bundle{Body: evmroot.TrustBaseBodyV2{Epoch: 3, Version: evmroot.TrustBaseVersion}}
			raw, err := handoffdelivery.EncodeBundle(bundle)
			if err != nil {
				t.Fatal(err)
			}
			digest := sha256.Sum256(raw)
			if err := os.MkdirAll(filepath.Join(dir, sub), 0700); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(dir, sub, fmt.Sprintf("bundle-%016x-test", bundle.Body.Epoch))
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
		})
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

// pinFixture is an archive with one certified record at root epoch `rootEpoch`, packed or in the directory layout of an earlier binary
// (bft-core#1049), and a genesis (epoch 1) trust base; it returns the paths.
func pinFixture(t *testing.T, rootEpoch uint64, directoryLayout bool) (archiveDir, trustBase, prefix string) {
	t.Helper()
	root := t.TempDir()
	archiveDir = filepath.Join(root, "archive")
	headerRaw, err := rlp.EncodeToBytes(&gethtypes.Header{Number: big.NewInt(4), Difficulty: new(big.Int)})
	if err != nil {
		t.Fatal(err)
	}
	q := archive.Request{Context: archive.Context{NetworkID: 1, PartitionID: 2, ExecutionIdentity: []byte("config")}}
	q.Context.FullShardConfHash[0], q.Context.RegistryAddress[0], q.Context.RegistryCodeHash[0] = 1, 2, 3
	q.Context.GenesisCommitment[0], q.Context.EVMGenesisHash[0] = 4, 5
	copy(q.BlockHash[:], crypto.Keccak256(headerRaw))
	uc := types.UnicityCertificate{
		InputRecord: &types.InputRecord{RoundNumber: 5, BlockHash: q.BlockHash[:]},
		UnicitySeal: &types.UnicitySeal{Epoch: rootEpoch, RootChainRoundNumber: 9},
	}
	ucRaw, err := types.Cbor.Marshal(uc)
	if err != nil {
		t.Fatal(err)
	}
	rec := &archive.Record{Header: headerRaw, Body: []byte{0xc0}, CanonicalRootInput: []byte{1}, OriginalUC: []byte{2}, OriginalTR: []byte{3}, ResultingUC: ucRaw, ResultingTR: []byte{1}, Companion: []byte{6}}
	if err := os.MkdirAll(archiveDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if directoryLayout {
		if _, err := archivetest.WriteDirectoryLayout(archiveDir, q, rec, false); err != nil {
			t.Fatal(err)
		}
	} else {
		store, err := archive.Open(archiveDir)
		if err != nil {
			t.Fatal(err)
		}
		if err := store.Put(q, rec); err != nil {
			t.Fatal(err)
		}
	}
	trustBase = filepath.Join(root, "trust-base.json")
	if err := util.WriteJsonFile(trustBase, &types.RootTrustBaseV1{Epoch: 1}); err != nil {
		t.Fatal(err)
	}
	return archiveDir, trustBase, filepath.Join(root, "pin")
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

	for _, directoryLayout := range []bool{false, true} {
		t.Run(map[bool]string{false: "packed", true: "directory layout"}[directoryLayout], func(t *testing.T) {
			var out strings.Builder
			// the case that panicked: the newest record is at root epoch 2, a Q3 activation the archive holds no bundle for
			archive, trustBase, prefix := pinFixture(t, 2, directoryLayout)
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
		})
	}
}
