package b1state

import (
	"errors"
	"fmt"
)

// The execution revision (bft-core#1199, astra-design-1199): the version of the native EVM semantics the shard's execution client must implement,
// committed into the B1 profile and therefore into the profile hash, the registry's B1ProfileHash word, the genesis commitment, the PDR's
// seal_registry_genesis and the full shard-conf hash.
//
// The registry artifact pins (RuntimeHash, CompilerHash) identify the Solidity registry, not the NATIVE precompiles around it. Two matched BFT+ureth
// pairs that differ in the native set (0x0105 present or removed) used to pass every startup check against one shard configuration.
//
// Revision 1 is an immutable specification of the post-#1189 execution semantics: the pinned Cancun envelope; native unicity-b1-cert-batch-v2 at
// 0x0100, unicity-b1-membership at 0x0102 and unicity-b2-sdk3 at 0x0104; no 0x0101, 0x0103 or 0x0105; and the native validation, gas and hook
// semantics of the initial implementation, ureth b8a50547 (existing profile fields keep the deployment-specific parameters). A future
// consensus-affecting change takes a new revision even if names and addresses stay identical. It is not a build SHA: equivalent builds implement
// the same revision. Zero is legacy/absent and always refused.
//
// Revision 2 (bft-core#1294) admits certificates against the imported tip, independent of D1's observation.
// The native name at 0x0100 changes so eth_config distinguishes the verifier rules at startup.
const CurrentExecutionRevision uint64 = 2

// ErrExecutionRevision is returned for an absent (zero, legacy), unknown or future execution revision.
var ErrExecutionRevision = errors.New("b1state: execution revision absent, legacy or not implemented by this binary")

// CheckExecutionRevision requires exactly CurrentExecutionRevision.
func CheckExecutionRevision(r uint64) error {
	switch {
	case r == 0:
		return fmt.Errorf("%w: the profile names no executionRevision (legacy or pre-#1199); this binary requires %d", ErrExecutionRevision, CurrentExecutionRevision)
	case r != CurrentExecutionRevision:
		return fmt.Errorf("%w: revision %d; this binary requires %d", ErrExecutionRevision, r, CurrentExecutionRevision)
	}
	return nil
}

// NativePrecompile is one native precompile (beyond the pinned Cancun set): the name ureth reports in eth_config and its address.
type NativePrecompile struct {
	Name    string
	Address [20]byte
}

// ExecutionRevisionNatives is the one table mapping a revision to its native precompile set; the engine startup check (engineapi) uses it, so the
// set the profile commits and the set enforced locally cannot drift. Operators cannot supply another map. ok is false for any revision but the
// current one.
func ExecutionRevisionNatives(r uint64) (set []NativePrecompile, ok bool) {
	if r != CurrentExecutionRevision {
		return nil, false
	}
	return []NativePrecompile{
		{"unicity-b1-cert-batch-v2-tip", [20]byte{18: 0x01, 19: 0x00}}, // 0x0100: the any-age certificate batch (protocol 4)
		{"unicity-b1-membership", [20]byte{18: 0x01, 19: 0x02}},        // 0x0102: the stateless RSMT membership check
		{"unicity-b2-sdk3", [20]byte{18: 0x01, 19: 0x04}},              // 0x0104: the B2 native token kernel
	}, true
}
