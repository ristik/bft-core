package engineapi

// The node's side of the paired-execution restart admission (ureth#52): reading what the execution client retained for its head, and the
// node's own re-derivation of that head from it. The client's claims are only ever compared with the node's derivation, never trusted.

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/unicitynetwork/bft-core/shardnode"
)

type pairHeader struct {
	Number                string            `json:"number"`
	Hash                  string            `json:"hash"`
	ParentHash            string            `json:"parentHash"`
	StateRoot             string            `json:"stateRoot"`
	MixHash               string            `json:"mixHash"`
	Miner                 string            `json:"miner"`
	Timestamp             string            `json:"timestamp"`
	ExtraData             string            `json:"extraData"`
	ParentBeaconBlockRoot string            `json:"parentBeaconBlockRoot"`
	Withdrawals           []json.RawMessage `json:"withdrawals"`
}

func hexBytes(s string, size int) ([]byte, error) {
	raw, err := hex.DecodeString(strings.TrimPrefix(s, "0x"))
	if err != nil || (size >= 0 && len(raw) != size) {
		return nil, fmt.Errorf("engineapi: %q is not a %d-byte hex value", s, size)
	}
	return raw, nil
}

func hexUint(s string) (uint64, error) { return strconv.ParseUint(strings.TrimPrefix(s, "0x"), 16, 64) }

func (c *EthClient) header(ctx context.Context, tag string) (pairHeader, error) {
	var h pairHeader
	var raw json.RawMessage
	if err := c.call(ctx, "eth_getBlockByNumber", []any{tag, false}, &raw); err != nil {
		return h, err
	}
	if isJSONNull(raw) {
		return h, fmt.Errorf("engineapi: the execution client has no block %s", tag)
	}
	return h, json.Unmarshal(raw, &h)
}

type pairCompanionLookup struct {
	Status    string `json:"status"`
	Companion struct {
		RootInput   string   `json:"rootInput"`
		PairBinding string   `json:"pairBinding"`
		Witnesses   []string `json:"witnesses"`
	} `json:"companion"`
}

// ErrPairCompanion is returned when the execution client holds no companion for a block.
var ErrPairCompanion = errors.New("engineapi: the execution client retains no companion for the block")

func (c *EthClient) companion(ctx context.Context, hash string) (rootInput, binding []byte, err error) {
	rootInput, binding, _, err = c.companionWithWitnesses(ctx, hash)
	return rootInput, binding, err
}

func (c *EthClient) companionWithWitnesses(ctx context.Context, hash string) (rootInput, binding []byte, witnesses []data, err error) {
	var l pairCompanionLookup
	if err := c.call(ctx, "unicity_getSealCompanionV1", []any{hash}, &l); err != nil {
		return nil, nil, nil, err
	}
	if l.Status != "found" {
		return nil, nil, nil, fmt.Errorf("%w: %s (%s)", ErrPairCompanion, hash, l.Status)
	}
	if rootInput, err = hexBytes(l.Companion.RootInput, -1); err != nil {
		return nil, nil, nil, err
	}
	if binding, err = hexBytes(l.Companion.PairBinding, -1); err != nil {
		return nil, nil, nil, err
	}
	for _, w := range l.Companion.Witnesses {
		raw, err := hexBytes(w, -1)
		if err != nil {
			return nil, nil, nil, err
		}
		witnesses = append(witnesses, data(raw))
	}
	return rootInput, binding, witnesses, nil
}

func (c *EthClient) headerByHash(ctx context.Context, hash string) (pairHeader, error) {
	var h pairHeader
	var raw json.RawMessage
	if err := c.call(ctx, "eth_getBlockByHash", []any{hash, false}, &raw); err != nil {
		return h, err
	}
	if isJSONNull(raw) {
		return h, fmt.Errorf("engineapi: the execution client has no block %s", hash)
	}
	return h, json.Unmarshal(raw, &h)
}

// EnablePair turns the paired-execution binding on for this adapter, before it runs: every build and import then carries the binding this
// node derives, and the execution client's reported pins must be these. A nil config leaves it off.
func (a *Adapter) EnablePair(cfg *PairConfig) { a.pair = cfg }

// PairEnabled reports whether builds and imports carry the pair binding.
func (a *Adapter) PairEnabled() bool { return a.pair != nil }

// ErrAdmissionVerifier is returned when restart admission is asked of an adapter that holds no verifier context: the head is re-derived from
// this node's own trust, never from the execution client's claims, so without it nothing can be admitted.
var ErrAdmissionVerifier = errors.New("engineapi: restart admission requires the verifier context")

// ErrAdmissionInput is returned when the root input the execution client retained for its head is not the one this node derives from the
// witnesses retained with it.
var ErrAdmissionInput = errors.New("engineapi: the retained root input is not this node's own derivation of the head's authorizing certificate")

// AdmitHead is the node's restart admission of its execution client's canonical head, from the node's own verification and nothing the
// client asserts: the certificate and technical record retained with the head's companion are authenticated again against this node's
// trust (as a historical observation: they may belong to an earlier root epoch), the head's canonical root input is derived from them
// and the parent's registry witness, and the client's retained root input must be exactly that derivation. Only then is the binding of
// that derivation presented to the client (engine_admitParentV1), which re-checks it against everything it retained. A client with no
// block beyond genesis has nothing to admit.
func (a *Adapter) AdmitHead(ctx context.Context) error {
	if a.pair == nil {
		return fmt.Errorf("%w: pair binding is not configured", ErrPairBinding)
	}
	if a.verifier == nil {
		return ErrAdmissionVerifier
	}
	head, err := a.eth.header(ctx, "latest")
	if err != nil {
		return err
	}
	number, err := hexUint(head.Number)
	if err != nil {
		return err
	}
	if number == 0 {
		return nil
	}
	rootInput, _, witnesses, err := a.eth.companionWithWitnesses(ctx, head.Hash)
	if err != nil {
		return err
	}
	uc, tr, err := decodeSealCompanionWitnesses(witnesses)
	if err != nil {
		return err
	}
	parent, err := a.eth.headerByHash(ctx, head.ParentHash)
	if err != nil {
		return err
	}
	parentHash, err := hexBytes(head.ParentHash, 32)
	if err != nil {
		return err
	}
	parentRoot, err := hexBytes(parent.StateRoot, 32)
	if err != nil {
		return err
	}
	headHash, err := hexBytes(head.Hash, 32)
	if err != nil {
		return err
	}
	params := shardnode.RoundParams{Round: tr.Round, Parent: shardnode.BlockRef{Number: number - 1, Hash: parentHash, StateRoot: parentRoot},
		AuthorizingCertificate: uc, AuthorizingTechnicalRecord: tr}
	derived, err := a.deriveV2(a.HistoricalContext(ctx), params, uc, tr)
	if err != nil {
		return fmt.Errorf("engineapi: re-deriving the head's root input: %w", err)
	}
	if !bytes.Equal(derived.Encoded, rootInput) {
		return fmt.Errorf("%w: block %d", ErrAdmissionInput, number)
	}
	var p, h [32]byte
	copy(p[:], parentHash)
	copy(h[:], headHash)
	return a.AdmitRecoveredHead(ctx, derived, p, number-1, h)
}
