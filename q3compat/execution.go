package q3compat

import (
	"bytes"
	"errors"
	"fmt"
	"slices"

	"github.com/unicitynetwork/bft-core/q3format"
)

var (
	// ErrExecutionVersion is returned for an execution-protocol report of a version this verifier does not read.
	ErrExecutionVersion = errors.New("q3compat: unsupported execution protocol report version")
	// ErrExecutionLayout is returned when the loaded registry layout is not the one the tuple requires (layout 1 is refused).
	ErrExecutionLayout = errors.New("q3compat: execution client has the wrong registry layout loaded")
	// ErrExecutionProtocol is returned when the client does not report the required execution protocol.
	ErrExecutionProtocol = errors.New("q3compat: execution client does not support the required protocol")
	// ErrExecutionCodec is returned when the client lacks the transition or configuration codec of the tuple.
	ErrExecutionCodec = errors.New("q3compat: execution client lacks a required codec")
	// ErrExecutionIdentity is returned when the client's genesis or code hash is not the pinned one.
	ErrExecutionIdentity = errors.New("q3compat: execution client genesis or code is not the pinned one")
)

// ExecutionReportVersion is the version of the report this verifier reads.
const ExecutionReportVersion = 1

// ExecutionReport is the answer of the JWT-endpoint execution-protocol query: the registry layout the client has actually loaded
// (not what it was built to support) and the protocols and codecs it runs. It is a compatibility statement from the paired
// client. It does not authenticate any root epoch, activation or trust history; that remains the proof verifier's work.
type ExecutionReport struct {
	Version         uint64
	Protocols       []string
	RegistryLayout  uint64
	GenesisHash     []byte
	CodeHash        []byte
	ConfigRevisions []uint64 // protocol-tuple revisions the client's configuration codec reads
	TransitionCodec []uint64 // compact-transition codec versions the client reads
}

// ExecutionRequirement is what the operator has pinned locally for the execution client and the transition codec the candidate
// needs. The pins are never taken from the report under test: that would compare a value with itself.
type ExecutionRequirement struct {
	GenesisHash, CodeHash []byte
	TransitionCodec       uint64
}

// Check refuses a report that does not satisfy the tuple and the local pins.
func (w ExecutionRequirement) Check(r ExecutionReport, cfg q3format.ProtocolConfig) error {
	switch {
	case r.Version != ExecutionReportVersion:
		return fmt.Errorf("%w: %d", ErrExecutionVersion, r.Version)
	case r.RegistryLayout != cfg.RegistryLayout:
		return fmt.Errorf("%w: loaded %d, want %d", ErrExecutionLayout, r.RegistryLayout, cfg.RegistryLayout)
	case !slices.Contains(r.Protocols, cfg.RequiredExecutionProtocol):
		return fmt.Errorf("%w: %q", ErrExecutionProtocol, cfg.RequiredExecutionProtocol)
	case !slices.Contains(r.ConfigRevisions, cfg.Revision):
		return fmt.Errorf("%w: configuration revision %d", ErrExecutionCodec, cfg.Revision)
	case !slices.Contains(r.TransitionCodec, w.TransitionCodec):
		return fmt.Errorf("%w: transition codec %d", ErrExecutionCodec, w.TransitionCodec)
	case len(w.GenesisHash) == 0 || len(w.CodeHash) == 0:
		return fmt.Errorf("%w: no pin configured", ErrExecutionIdentity)
	case !bytes.Equal(r.GenesisHash, w.GenesisHash) || !bytes.Equal(r.CodeHash, w.CodeHash):
		return ErrExecutionIdentity
	}
	return nil
}
