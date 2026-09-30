// Command f7-mintproof-verify is the intentionally offline verifier process.
// Its only file inputs are a MintReasonBundleV1 and the authentic root trust base
// for that bundle's epoch; expected log predicates are fixed by this demo.
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"

	"github.com/ethereum/go-ethereum/common"
	gethtypes "github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/unicitynetwork/bft-core/mintproof"
	"github.com/unicitynetwork/bft-go-base/types"
)

const (
	demoNetworkID     = 3
	demoPartitionID   = 8
	demoShardID       = 0x80
	demoSender        = "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266"
	lockDeployNonce   = 3
	lockedEventName   = "Locked(uint256)"
	unlockedEventName = "Unlocked(uint256)"
)

func main() { os.Exit(run(os.Args[1:])) }

func run(args []string) int {
	flags := flag.NewFlagSet("f7-mintproof-verify", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	bundlePath := flags.String("bundle", "", "MintReasonBundleV1 CBOR file")
	trustBasePath := flags.String("trust-base", "", "epoch RootTrustBaseV1 JSON file")
	mode := flags.String("mode", "", "fixed demo predicate: locked or absent")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if *bundlePath == "" || *trustBasePath == "" || (*mode != "locked" && *mode != "absent") || flags.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "usage: f7-mintproof-verify --bundle FILE --trust-base FILE --mode locked|absent")
		return 2
	}
	bundleRaw, err := os.ReadFile(*bundlePath)
	if err != nil {
		return fail(err)
	}
	trustRaw, err := os.ReadFile(*trustBasePath)
	if err != nil {
		return fail(err)
	}
	trustBase := new(types.RootTrustBaseV1)
	if err = json.Unmarshal(trustRaw, trustBase); err != nil {
		return fail(fmt.Errorf("decode epoch trust base: %w", err))
	}
	bundle, err := mintproof.DecodeBundle(bundleRaw, mintproof.DefaultLimits())
	if err != nil {
		return fail(err)
	}
	if bundle.Evidence.Absence != (*mode == "absent") {
		return fail(errors.New("bundle evidence kind does not match requested verification mode"))
	}
	var header gethtypes.Header
	if err = rlp.DecodeBytes(bundle.HeaderRLP, &header); err != nil || header.Number == nil || !header.Number.IsUint64() {
		return fail(errors.New("bundle has an invalid EVM header"))
	}
	lockAddress := crypto.CreateAddress(common.HexToAddress(demoSender), lockDeployNonce)
	eventSignature := lockedEventName
	if *mode == "absent" {
		eventSignature = unlockedEventName
	}
	eventTopic := crypto.Keccak256Hash([]byte(eventSignature))
	var blockHash [32]byte
	copy(blockHash[:], header.Hash().Bytes())
	expected := mintproof.ExpectedClaim{
		// Network, partition and shard are fixed for this lane and therefore independent of
		// untrusted bundle metadata. The full shard-conf hash varies with each freshly enrolled
		// validator set; it is bound into the signed UC and checked by Verify against the same bundle.
		Network: types.NetworkID(demoNetworkID), Partition: types.PartitionID(demoPartitionID),
		Shard: []byte{demoShardID}, ShardConf: bundle.Context.ShardConf,
		BlockHash: blockHash, BlockNumber: header.Number.Uint64(),
		MatchLog: func(log *gethtypes.Log) bool {
			return log.Address == lockAddress && len(log.Topics) > 0 && log.Topics[0] == eventTopic
		},
	}
	if err = mintproof.Verify(bundleRaw, trustBase, expected, mintproof.DefaultLimits()); err != nil {
		return fail(err)
	}
	_ = json.NewEncoder(os.Stdout).Encode(struct {
		Status       string `json:"status"`
		Mode         string `json:"mode"`
		BlockHash    string `json:"blockHash"`
		BlockNumber  uint64 `json:"blockNumber"`
		RootEpoch    uint64 `json:"trustBaseEpoch"`
		EventEmitter string `json:"expectedEmitter"`
		EventTopic   string `json:"expectedTopic"`
	}{"PASS", *mode, header.Hash().Hex(), header.Number.Uint64(), trustBase.GetEpoch(), lockAddress.Hex(), eventTopic.Hex()})
	return 0
}

func fail(err error) int {
	fmt.Fprintln(os.Stderr, "f7-mintproof-verify: FAIL:", err)
	return 1
}
