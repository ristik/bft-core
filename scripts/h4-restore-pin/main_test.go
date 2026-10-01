package main

import (
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/unicitynetwork/bft-core/evmroot"
	"github.com/unicitynetwork/bft-core/handoffdelivery"
	"github.com/unicitynetwork/bft-go-base/types"
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
