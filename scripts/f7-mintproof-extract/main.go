// Command f7-mintproof-extract extracts proof bundles from immutable archive v2 records.
// It does not call an execution client; the request is recovered from the archive manifest.
package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	gethtypes "github.com/ethereum/go-ethereum/core/types"
	"github.com/unicitynetwork/bft-core/archive"
	"github.com/unicitynetwork/bft-core/archivewiring"
	"github.com/unicitynetwork/bft-core/mintproof"
)

func main() { os.Exit(run(os.Args[1:])) }

func run(args []string) int {
	if len(args) == 0 || args[0] != "extract" {
		fmt.Fprintln(os.Stderr, "usage: f7-mintproof-extract extract --archive DIR --block-hash HASH --out FILE [--tx-index N --log-index N --emitter ADDRESS --topic HASH | --absence]")
		return 2
	}
	flags := flag.NewFlagSet("extract", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	archiveDir := flags.String("archive", "", "local immutable archive v2 directory")
	blockHashText := flags.String("block-hash", "", "exact certified EVM block hash")
	out := flags.String("out", "", "output CBOR bundle path")
	txIndex := flags.Uint64("tx-index", 0, "transaction index from the receipt")
	logIndex := flags.Uint64("log-index", 0, "block-global log index from the receipt")
	emitterText := flags.String("emitter", "", "expected lock contract address")
	topicText := flags.String("topic", "", "expected event topic")
	absence := flags.Bool("absence", false, "extract the complete receipt list for an absence proof")
	if err := flags.Parse(args[1:]); err != nil {
		return 2
	}
	if *archiveDir == "" || *out == "" || !validHash(*blockHashText) || flags.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "archive, exact block hash and output path are required")
		return 2
	}
	blockHash := common.HexToHash(*blockHashText)
	request, err := requestForBlock(*archiveDir, blockHash)
	if err != nil {
		return fail(err)
	}
	store, err := archive.Open(*archiveDir)
	if err != nil {
		return fail(err)
	}
	var bundle mintproof.MintReasonBundleV1
	if *absence {
		bundle, err = mintproof.Extract(store, mintproof.ExtractRequest{Archive: request, Absence: true})
	} else {
		if !common.IsHexAddress(*emitterText) || !validHash(*topicText) {
			return fail(errors.New("positive extraction requires --emitter and --topic"))
		}
		record, getErr := store.GetReceiptComplete(request)
		if getErr != nil {
			return fail(getErr)
		}
		receipts, decodeErr := archivewiring.DecodeReceiptList(record)
		if decodeErr != nil {
			return fail(decodeErr)
		}
		if *txIndex >= uint64(len(receipts)) {
			return fail(fmt.Errorf("transaction index %d is outside %d archived receipts", *txIndex, len(receipts)))
		}
		var precedingLogs uint64
		var target *gethtypes.Log
		var localLogIndex uint64
		for i, encoded := range receipts {
			var receipt gethtypes.Receipt
			if err = receipt.UnmarshalBinary(encoded); err != nil {
				return fail(fmt.Errorf("decode receipt %d: %w", i, err))
			}
			if uint64(i) < *txIndex {
				precedingLogs += uint64(len(receipt.Logs))
				continue
			}
			if uint64(i) > *txIndex {
				break
			}
			if *logIndex < precedingLogs || *logIndex-precedingLogs >= uint64(len(receipt.Logs)) {
				return fail(fmt.Errorf("block-global log index %d does not belong to transaction %d", *logIndex, *txIndex))
			}
			localLogIndex = *logIndex - precedingLogs
			target = receipt.Logs[localLogIndex]
		}
		if target == nil || target.Address != common.HexToAddress(*emitterText) || len(target.Topics) == 0 || target.Topics[0] != common.HexToHash(*topicText) {
			return fail(errors.New("selected archived log does not match expected emitter and topic"))
		}
		bundle, err = mintproof.Extract(store, mintproof.ExtractRequest{Archive: request, TxIndex: *txIndex, LogIndex: localLogIndex})
	}
	if err != nil {
		return fail(err)
	}
	raw, err := bundle.MarshalCBOR()
	if err != nil {
		return fail(err)
	}
	if err = os.WriteFile(*out, raw, 0o600); err != nil {
		return fail(err)
	}
	fmt.Printf("extracted blockHash=%s txIndex=%d globalLogIndex=%d absence=%t bytes=%d\n", blockHash, *txIndex, *logIndex, *absence, len(raw))
	return 0
}

func requestForBlock(dir string, blockHash common.Hash) (archive.Request, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return archive.Request{}, err
	}
	var matches []archive.Request
	for _, entry := range entries {
		if !entry.IsDir() || !strings.HasPrefix(entry.Name(), "v2-") {
			continue
		}
		manifest, readErr := os.ReadFile(filepath.Join(dir, entry.Name(), "manifest"))
		if readErr != nil || len(manifest) < 12 || !bytes.Equal(manifest[:8], []byte("ARCHIVE2")) {
			continue
		}
		requestLen := binary.BigEndian.Uint32(manifest[8:12])
		if requestLen == 0 || uint64(requestLen)+12 > uint64(len(manifest)) {
			continue
		}
		request, decodeErr := archive.DecodeRequest(manifest[12 : 12+requestLen])
		if decodeErr == nil && request.BlockHash == [32]byte(blockHash) {
			matches = append(matches, request)
		}
	}
	if len(matches) != 1 {
		return archive.Request{}, fmt.Errorf("expected one receipt-complete archive request for %s, found %d", blockHash, len(matches))
	}
	return matches[0], nil
}

func fail(err error) int {
	fmt.Fprintln(os.Stderr, "f7-mintproof-extract: FAIL:", err)
	return 1
}

func validHash(text string) bool {
	b, err := hexutil.Decode(text)
	return err == nil && len(b) == common.HashLength
}
