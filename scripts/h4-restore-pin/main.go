// h4-restore-pin extracts a devnet restore pin from a replica's immutable
// archive. The restore command independently authenticates these bytes.
package main

import (
	"crypto"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	gethtypes "github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/unicitynetwork/bft-core/handoffdelivery"
	"github.com/unicitynetwork/bft-go-base/types"
	"github.com/unicitynetwork/bft-go-base/util"
)

func main() {
	if len(os.Args) != 4 {
		panic("usage: h4-restore-pin ARCHIVE TRUST_BASE OUTPUT_PREFIX")
	}
	archiveDir, trustPath, prefix := os.Args[1], os.Args[2], os.Args[3]
	entries, err := os.ReadDir(archiveDir)
	if err != nil {
		panic(err)
	}
	var bestUC, bestTR, bestHeader []byte
	var bestRound uint64
	var bestEpoch uint64
	var bestRootRound uint64
	var bestV2 bool
	for _, entry := range entries {
		name := entry.Name()
		if !entry.IsDir() || !archiveRecordDirectory(name) {
			continue
		}
		read := func(name string) []byte {
			b, e := os.ReadFile(filepath.Join(archiveDir, entry.Name(), hex.EncodeToString([]byte(name))+".chunk"))
			if e != nil {
				return nil
			}
			return b
		}
		ucRaw, trRaw, headerRaw := read("resulting-uc"), read("resulting-tr"), read("header")
		var uc types.UnicityCertificate
		var header gethtypes.Header
		if types.Cbor.Unmarshal(ucRaw, &uc) != nil || uc.InputRecord == nil || len(uc.InputRecord.BlockHash) != 32 || len(trRaw) == 0 || rlp.DecodeBytes(headerRaw, &header) != nil || header.Number == nil {
			continue
		}
		isV2 := strings.HasPrefix(name, "v2-")
		// Prefer v2 records because they retain the complete proof material.
		// Within a version, compare the full root position: rounds restart at
		// handoff, so round alone cannot identify the newest certified record.
		if preferPin(isV2, uc.GetRootEpoch(), uc.GetRootRoundNumber(), bestV2, bestEpoch, bestRootRound) {
			bestRound, bestEpoch, bestRootRound, bestUC, bestTR, bestHeader, bestV2 = uc.GetRoundNumber(), uc.GetRootEpoch(), uc.GetRootRoundNumber(), ucRaw, trRaw, headerRaw, isV2
		}
	}
	if bestRound == 0 {
		panic("no certified block pin in archive")
	}
	tb, err := util.ReadJsonFile(trustPath, &types.RootTrustBaseV1{})
	if err != nil {
		panic(err)
	}
	bodyID, err := archiveTrustBodyID(archiveDir, bestEpoch, tb)
	if err != nil {
		// A Q3 activation is not archived as a handoff-delivery bundle: the lane names the body identity of the epoch it activated
		// (H4_RESTORE_BODY_IDS="<epoch>=<64 hex>[,<epoch>=<64 hex>...]"). It is an operator anchor, not a trust decision: after catch-up the restored
		// node compares it with the BodyID of the verified current history for the tip UC's root epoch (checkRestoreTrustBodyID in
		// cli/ubft/cmd/shard_node_run.go) and refuses to start with ErrTrustBodyIDMismatch if they differ.
		named, ok := namedBodyID(os.Getenv("H4_RESTORE_BODY_IDS"), bestEpoch)
		if !ok {
			panic(err)
		}
		bodyID = named
	}
	if err := os.WriteFile(prefix+".uc.cbor", bestUC, 0600); err != nil {
		panic(err)
	}
	if err := os.WriteFile(prefix+".tr.cbor", bestTR, 0600); err != nil {
		panic(err)
	}
	var header gethtypes.Header
	if err := rlp.DecodeBytes(bestHeader, &header); err != nil {
		panic(err)
	}
	fmt.Printf("round=%d height=%d blockHash=%s stateRoot=%s receiptsRoot=%s bodyID=0x%x\n",
		bestRound, header.Number.Uint64(), header.Hash(), header.Root, header.ReceiptHash, bodyID)
}

func namedBodyID(spec string, epoch uint64) ([32]byte, bool) {
	for _, item := range strings.Split(spec, ",") {
		key, value, found := strings.Cut(strings.TrimSpace(item), "=")
		if !found || key != fmt.Sprint(epoch) {
			continue
		}
		raw, err := hex.DecodeString(strings.TrimPrefix(value, "0x"))
		if err != nil || len(raw) != sha256.Size {
			return [32]byte{}, false
		}
		return [32]byte(raw), true
	}
	return [32]byte{}, false
}

func preferPin(candidateV2 bool, candidateEpoch, candidateRound uint64, bestV2 bool, bestEpoch, bestRound uint64) bool {
	if candidateV2 != bestV2 {
		return candidateV2
	}
	return candidateEpoch > bestEpoch || candidateEpoch == bestEpoch && candidateRound > bestRound
}

func archiveTrustBodyID(archiveDir string, epoch uint64, anchor *types.RootTrustBaseV1) ([32]byte, error) {
	if epoch == anchor.Epoch {
		var out [32]byte
		raw, err := anchor.Hash(crypto.SHA256)
		copy(out[:], raw)
		return out, err
	}
	entries, err := os.ReadDir(archiveDir)
	if err != nil {
		return [32]byte{}, err
	}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasPrefix(entry.Name(), "bundle-") {
			continue
		}
		raw, readErr := os.ReadFile(filepath.Join(archiveDir, entry.Name()))
		if readErr != nil || len(raw) < sha256.Size+1 {
			continue
		}
		want := sha256.Sum256(raw[sha256.Size:])
		if !strings.HasPrefix(entry.Name(), fmt.Sprintf("bundle-%016x-", epoch)) || string(want[:]) != string(raw[:sha256.Size]) {
			continue
		}
		bundle, decodeErr := handoffdelivery.DecodeBundle(raw[sha256.Size:])
		if decodeErr != nil || bundle.Body.Epoch != epoch {
			continue
		}
		return [32]byte(bundle.Body.Identity()), nil
	}
	return [32]byte{}, fmt.Errorf("no archived verified-trust body identity for epoch %d", epoch)
}

func archiveRecordDirectory(name string) bool {
	if len(name) == 64 {
		_, err := hex.DecodeString(name)
		return err == nil
	}
	if len(name) == 67 && name[:3] == "v2-" {
		_, err := hex.DecodeString(name[3:])
		return err == nil
	}
	return false
}
