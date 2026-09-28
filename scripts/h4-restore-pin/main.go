// h4-restore-pin extracts a devnet restore pin from a replica's immutable
// archive. The restore command independently authenticates these bytes.
package main

import (
	"crypto"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"

	gethtypes "github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/rlp"
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
	for _, entry := range entries {
		if !entry.IsDir() || len(entry.Name()) != 64 {
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
		if uc.InputRecord.RoundNumber > bestRound {
			bestRound, bestUC, bestTR, bestHeader = uc.InputRecord.RoundNumber, ucRaw, trRaw, headerRaw
		}
	}
	if bestRound == 0 {
		panic("no certified block pin in archive")
	}
	tb, err := util.ReadJsonFile(trustPath, &types.RootTrustBaseV1{})
	if err != nil {
		panic(err)
	}
	bodyID, err := tb.Hash(crypto.SHA256)
	if err != nil {
		panic(err)
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
