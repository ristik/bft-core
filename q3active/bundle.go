package q3active

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/unicitynetwork/bft-core/handoff"
	"github.com/unicitynetwork/bft-core/network/protocol/abdrc"
	"github.com/unicitynetwork/bft-core/q3format"
	"github.com/unicitynetwork/bft-go-base/types"
)

// ErrBundle is returned for a staged bundle that is not one canonical encoding, or that does not carry the activation it is for.
var ErrBundle = errors.New("q3active: invalid activation bundle")

// Bundle is the unit the install journal stages and replays: the proof envelope that authenticates the activation (the lineage
// rooted in the trusted genesis, with the old committee's commit proof of the activating link), the native recovery checkpoint of
// the old epoch that the root installs its anchor from, and the EVM assignment candidate when the handoff carries one. Nothing in
// it is trusted: the envelope is verified by the history, the checkpoint is re-authenticated against that verified entry.
type Bundle struct {
	_         struct{} `cbor:",toarray"`
	Envelope  []byte
	Snapshot  *abdrc.CommittedBlock
	Candidate []byte
}

// EncodeBundle is the canonical staged bundle.
func EncodeBundle(b Bundle) ([]byte, error) {
	if len(b.Envelope) == 0 || b.Snapshot == nil {
		return nil, fmt.Errorf("%w: an envelope and a snapshot are required", ErrBundle)
	}
	raw, err := types.Cbor.Marshal(b)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrBundle, err)
	}
	return raw, nil
}

// DecodeBundle accepts exactly one canonical encoding, with the envelope decoded and its last link naming the activation.
func DecodeBundle(raw []byte) (Bundle, q3format.Envelope, error) {
	var b Bundle
	if len(raw) == 0 || len(raw) > q3format.MaxEnvelopeBytes {
		return b, q3format.Envelope{}, fmt.Errorf("%w: %d bytes", ErrBundle, len(raw))
	}
	if err := types.Cbor.Unmarshal(raw, &b); err != nil {
		return Bundle{}, q3format.Envelope{}, fmt.Errorf("%w: %v", ErrBundle, err)
	}
	if again, err := types.Cbor.Marshal(b); err != nil || !bytes.Equal(again, raw) {
		return Bundle{}, q3format.Envelope{}, fmt.Errorf("%w: not canonical", ErrBundle)
	}
	if len(b.Envelope) == 0 || b.Snapshot == nil {
		return Bundle{}, q3format.Envelope{}, fmt.Errorf("%w: an envelope and a snapshot are required", ErrBundle)
	}
	env, err := q3format.DecodeEnvelope(b.Envelope)
	if err != nil {
		return Bundle{}, q3format.Envelope{}, errors.Join(ErrBundle, err)
	}
	if len(env.Links) == 0 {
		return Bundle{}, q3format.Envelope{}, fmt.Errorf("%w: the envelope has no link", ErrBundle)
	}
	return b, env, nil
}

// activatingProof is the old committee's commit proof of the envelope's last link, decoded. The history has already required its
// bytes to be canonical when it verified the link.
func activatingProof(env q3format.Envelope) (handoff.OldCommitProof, error) {
	var p handoff.OldCommitProof
	if err := types.Cbor.Unmarshal(env.Links[len(env.Links)-1].Proof, &p); err != nil {
		return p, fmt.Errorf("%w: %v", ErrBundle, err)
	}
	return p, nil
}
