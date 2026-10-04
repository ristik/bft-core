package engineapi

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"reflect"
	"strings"

	"github.com/unicitynetwork/bft-core/q3compat"
	"github.com/unicitynetwork/bft-core/q3format"
)

const q3ProtocolMethod = "engine_q3ProtocolV1"

var (
	// ErrQ3ProtocolUnavailable is returned when the client cannot answer the query: a Q3-unaware (for instance layout-1) client
	// has no such method, which prevents its entity's readiness and its successor building and signing.
	ErrQ3ProtocolUnavailable = errors.New("engineapi: execution-protocol query unavailable")
	// ErrQ3ProtocolMalformed is returned for an answer that is not a well-formed version-1 report.
	ErrQ3ProtocolMalformed = errors.New("engineapi: malformed execution-protocol report")
	// ErrQ3ProtocolChanged is returned when the client's report differs from the one pinned, as after a reconnect to another client.
	ErrQ3ProtocolChanged = errors.New("engineapi: execution-protocol report changed since it was pinned")
)

// q3ProtocolWire is returned by the paired Ureth on the JWT Engine endpoint, reporting the registry identity and layout it has
// loaded and the protocols and codecs it supports.
type q3ProtocolWire struct {
	Version          uint64   `json:"version"`
	Protocols        []string `json:"protocols"`
	RegistryLayout   uint64   `json:"registryLayout"`
	GenesisHash      string   `json:"genesisHash"`
	CodeHash         string   `json:"codeHash"`
	ConfigRevisions  []uint64 `json:"configRevisions"`
	TransitionCodecs []uint64 `json:"transitionCodecs"`
}

func decodeHash(s string) ([]byte, error) {
	b, err := hex.DecodeString(strings.TrimPrefix(s, "0x"))
	if err != nil || len(b) != 32 || !strings.HasPrefix(s, "0x") {
		return nil, fmt.Errorf("%w: hash %q", ErrQ3ProtocolMalformed, s)
	}
	return b, nil
}

// Q3ExecutionReport asks the paired client for its execution-protocol report. It is a compatibility statement: it does not
// authenticate any root epoch, activation or trust history, and nothing returned here may stand in for the proof verifier.
func (a *Adapter) Q3ExecutionReport(ctx context.Context) (q3compat.ExecutionReport, error) {
	var w q3ProtocolWire
	if err := a.engine.call(ctx, q3ProtocolMethod, []any{}, &w); err != nil {
		return q3compat.ExecutionReport{}, fmt.Errorf("%w: %v", ErrQ3ProtocolUnavailable, err)
	}
	if w.Version != q3compat.ExecutionReportVersion {
		return q3compat.ExecutionReport{}, fmt.Errorf("%w: %d", q3compat.ErrExecutionVersion, w.Version)
	}
	g, err := decodeHash(w.GenesisHash)
	if err != nil {
		return q3compat.ExecutionReport{}, err
	}
	c, err := decodeHash(w.CodeHash)
	if err != nil {
		return q3compat.ExecutionReport{}, err
	}
	return q3compat.ExecutionReport{Version: w.Version, Protocols: w.Protocols, RegistryLayout: w.RegistryLayout, GenesisHash: g,
		CodeHash: c, ConfigRevisions: w.ConfigRevisions, TransitionCodec: w.TransitionCodecs}, nil
}

// CheckQ3Execution reads the report and checks it against the tuple and the operator's pins, returning the report it checked.
func (a *Adapter) CheckQ3Execution(ctx context.Context, cfg q3format.ProtocolConfig, want q3compat.ExecutionRequirement) (q3compat.ExecutionReport, error) {
	r, err := a.Q3ExecutionReport(ctx)
	if err != nil {
		return q3compat.ExecutionReport{}, err
	}
	return r, want.Check(r, cfg)
}

// PinQ3Execution checks the report and pins it: every later Engine call first reads the report again and refuses unless it is
// the pinned one and still satisfies the requirement, including after a reconnect. Unlike the readiness probe it therefore
// holds for as long as the adapter is used.
func (a *Adapter) PinQ3Execution(ctx context.Context, cfg q3format.ProtocolConfig, want q3compat.ExecutionRequirement) error {
	pinned, err := a.CheckQ3Execution(ctx, cfg, want)
	if err != nil {
		return err
	}
	a.engine.setBeforeQ3(func(ctx context.Context) error {
		now, err := a.CheckQ3Execution(ctx, cfg, want)
		if err != nil {
			return err
		}
		if !reflect.DeepEqual(now, pinned) {
			return ErrQ3ProtocolChanged
		}
		return nil
	})
	return nil
}

// Q3Execution adapts the Adapter to q3compat.Execution for the readiness probe.
func (a *Adapter) Q3Execution() q3compat.Execution { return q3Probe{a} }

type q3Probe struct{ a *Adapter }

func (p q3Probe) Report(ctx context.Context) (q3compat.ExecutionReport, error) {
	return p.a.Q3ExecutionReport(ctx)
}
