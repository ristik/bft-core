package posrelayer

import (
	"fmt"
	"strings"

	"github.com/ethereum/go-ethereum/accounts/abi"
)

// The read surface of the builder: getters of ElectionPolicy and StakeCustody (unicity-pos-contracts), nothing else. The tool is untrusted: what
// it reads only decides what it proposes, and the root re-verifies every word of it against the certified EVM state.

const electionABI = `[
 {"type":"function","name":"openResult","stateMutability":"view","inputs":[],"outputs":[{"type":"bytes32"}]},
 {"type":"function","name":"result","stateMutability":"view","inputs":[{"type":"bytes32"}],"outputs":[{"type":"tuple","components":[
   {"name":"state","type":"uint8"},{"name":"reason","type":"uint8"},{"name":"attempt","type":"uint64"},{"name":"progress","type":"uint64"},
   {"name":"ucTime","type":"uint64"},{"name":"policyID","type":"uint32"},{"name":"origin","type":"bytes32"},{"name":"predecessor","type":"bytes32"},
   {"name":"assignmentID","type":"bytes32"},{"name":"snapshotDigest","type":"bytes32"}]}]},
 {"type":"function","name":"publication","stateMutability":"view","inputs":[{"type":"bytes32"}],"outputs":[{"type":"tuple","components":[
   {"name":"primaryHash","type":"bytes32"},{"name":"kCommit","type":"bytes32"},{"name":"incumbent","type":"bytes32"},
   {"name":"incumbentExposureDigest","type":"bytes32"},{"name":"incumbentKeyDigest","type":"bytes32"},{"name":"policyDigest","type":"bytes32"},
   {"name":"contractsDigest","type":"bytes32"},{"name":"snapshotDigest","type":"bytes32"},{"name":"assignmentID","type":"bytes32"},
   {"name":"popSetDigest","type":"bytes32"},{"name":"published","type":"bool"},{"name":"popCount","type":"uint32"},{"name":"attempt","type":"uint64"},
   {"name":"lost","type":"bool"}]}]},
 {"type":"function","name":"frozenMembers","stateMutability":"view","inputs":[{"type":"bytes32"}],"outputs":[{"type":"tuple[]","components":[
   {"name":"id","type":"uint64"},{"name":"generation","type":"uint64"},{"name":"weight","type":"uint64"},{"name":"raw","type":"uint64"},
   {"name":"bindingHash","type":"bytes32"}]}]},
 {"type":"function","name":"popHash","stateMutability":"view","inputs":[{"type":"bytes32"},{"type":"uint64"}],"outputs":[{"type":"bytes32"}]},
 {"type":"function","name":"delegation","stateMutability":"view","inputs":[{"type":"uint64"},{"type":"uint64"}],"outputs":[
   {"name":"binding","type":"tuple","components":[{"name":"rootNodeID","type":"bytes32"},{"name":"rootKey","type":"bytes"},
     {"name":"evmNodeID","type":"bytes32"},{"name":"evmKey","type":"bytes"},{"name":"operatorPayee","type":"address"}]},
   {"name":"bindingHash","type":"bytes32"},{"name":"nextNonce","type":"uint64"}]}
]`

const custodyABI = `[
 {"type":"function","name":"assignmentExposures","stateMutability":"view","inputs":[{"type":"bytes32"}],"outputs":[{"type":"bytes32[]"}]},
 {"type":"function","name":"exposures","stateMutability":"view","inputs":[{"type":"bytes32"}],"outputs":[
   {"name":"assignmentID","type":"bytes32"},{"name":"id","type":"uint64"},{"name":"generation","type":"uint64"},{"name":"weight","type":"uint64"},
   {"name":"rawWeight","type":"uint64"},{"name":"rootKeyHash","type":"bytes32"},{"name":"evmKeyHash","type":"bytes32"},
   {"name":"operatorPayee","type":"address"},{"name":"referencesReleased","type":"bool"},{"name":"sessionLocks","type":"uint32"}]},
 {"type":"function","name":"exposureLots","stateMutability":"view","inputs":[{"type":"bytes32"}],"outputs":[{"type":"uint256[]"}]}
]`

var election, custody abi.ABI

func init() {
	var err error
	if election, err = abi.JSON(strings.NewReader(electionABI)); err != nil {
		panic(fmt.Sprintf("posrelayer: election ABI: %v", err))
	}
	if custody, err = abi.JSON(strings.NewReader(custodyABI)); err != nil {
		panic(fmt.Sprintf("posrelayer: custody ABI: %v", err))
	}
}
