package storage

import (
	"bytes"
	"crypto"
	"errors"
	"math"

	"github.com/unicitynetwork/bft-core/evmroot"
	"github.com/unicitynetwork/bft-go-base/types"
	"github.com/unicitynetwork/bft-go-base/types/hex"
)

// FreezeAuthorization is a block-local companion to an ordered freeze record.
// It is outside the record ID, but inside the signed proposal and block hash.
type FreezeAuthorization struct {
	_          struct{} `cbor:",toarray"`
	Version    uint64
	Body       []byte // canonical D3 TrustBaseBodyV2 encoding
	Signatures map[string]hex.Bytes
}

func (a FreezeAuthorization) Bytes() ([]byte, error) { return types.Cbor.Marshal(a) }

// EndorsementBytes uses D4's old-set endorsement domain and fixes all fields
// known at freeze. The signatures do not enter the ordered record ID.
func EndorsementBytes(r evmroot.OrderedHandoffRecord) ([]byte, error) {
	return types.Cbor.Marshal([]any{"UNICITY_D4_ENDORSEMENT", uint64(1), r.Network, r.Epoch,
		r.PredecessorBodyID, r.Attempt, r.NextBodyID, r.FrozenID})
}

type v1HandoffAuthority struct {
	trust       *types.RootTrustBaseV1
	predecessor []byte
	link        []byte
}

// ConfigureHandoffAuthority installs the independently authenticated old v1
// body before profile-2 records can execute. Epoch transitions remain closed
// until the typed anchor implementation can install a verified v2 authority.
func (x *BlockStore) ConfigureHandoffAuthority(tb *types.RootTrustBaseV1) error {
	if x.profile != ProfileHandoff || tb == nil || tb.Epoch != 1 {
		return ErrHandoffRecord
	}
	raw, err := types.Cbor.Marshal(tb)
	if err != nil {
		return err
	}
	var owned types.RootTrustBaseV1
	if err := types.Cbor.Unmarshal(raw, &owned); err != nil {
		return err
	}
	if err := owned.Verify(nil); err != nil {
		return errors.Join(ErrHandoffRecord, err)
	}
	predecessor, err := owned.Hash(crypto.SHA256)
	if err != nil {
		return err
	}
	link, err := evmroot.FirstV2PredecessorHash(evmroot.V1Anchor{Version: 1,
		NetworkID: uint64(owned.NetworkID), Epoch: owned.Epoch, HashIncludingSigs: predecessor})
	if err != nil {
		return err
	}
	x.handoffAuth = &v1HandoffAuthority{trust: &owned, predecessor: predecessor, link: link}
	return nil
}

func (a *v1HandoffAuthority) Predecessor() []byte { return a.predecessor }

func (a *v1HandoffAuthority) VerifyFreeze(r evmroot.OrderedHandoffRecord, companion []byte) error {
	if len(companion) == 0 || len(companion) > 1<<20 || r.Epoch != a.trust.Epoch ||
		r.Network != uint64(a.trust.NetworkID) || len(r.FrozenID) != 32 || bytes.Equal(r.FrozenID, make([]byte, 32)) ||
		!bytes.Equal(r.PredecessorBodyID, a.predecessor) {
		return ErrHandoffRecord
	}
	var proof FreezeAuthorization
	if err := types.Cbor.Unmarshal(companion, &proof); err != nil || proof.Version != 1 || len(proof.Signatures) == 0 {
		return ErrHandoffRecord
	}
	canonical, err := proof.Bytes()
	if err != nil || !bytes.Equal(canonical, companion) {
		return ErrHandoffRecord
	}
	body, err := decodeD3Body(proof.Body)
	if err != nil || r.Epoch == math.MaxUint64 || body.NetworkID != r.Network || body.Epoch != r.Epoch+1 ||
		body.EarliestActivation == 0 || body.EarliestActivation > r.ActivationRound || !bytes.Equal(body.PredecessorHash, a.link) {
		return ErrHandoffRecord
	}
	for _, member := range body.Members {
		if member.Weight != 1 {
			return ErrHandoffRecord
		}
	}
	id := body.Identity()
	if !bytes.Equal(id[:], r.NextBodyID) {
		return ErrHandoffRecord
	}
	message, err := EndorsementBytes(r)
	if err != nil {
		return ErrHandoffRecord
	}
	var weight uint64
	for signer, signature := range proof.Signatures {
		stake, err := a.trust.VerifySignature(message, signature, signer)
		if err != nil || math.MaxUint64-weight < stake {
			return ErrHandoffRecord
		}
		weight += stake
	}
	if err := a.trust.VerifyQuorumSignatures(message, proof.Signatures); err != nil {
		return ErrHandoffRecord
	}
	return nil
}

func decodeD3Body(raw []byte) (evmroot.TrustBaseBodyV2, error) {
	var body evmroot.TrustBaseBodyV2
	if len(raw) == 0 || len(raw) > 1<<20 {
		return body, ErrHandoffRecord
	}
	var fields []any
	if err := types.Cbor.Unmarshal(raw, &fields); err != nil || len(fields) != 9 {
		return body, ErrHandoffRecord
	}
	var ok bool
	if body.Version, ok = fields[0].(uint64); !ok {
		return body, ErrHandoffRecord
	}
	if body.NetworkID, ok = fields[1].(uint64); !ok {
		return body, ErrHandoffRecord
	}
	if body.Epoch, ok = fields[2].(uint64); !ok {
		return body, ErrHandoffRecord
	}
	if body.EarliestActivation, ok = fields[3].(uint64); !ok {
		return body, ErrHandoffRecord
	}
	members, ok := fields[4].([]any)
	if !ok {
		return body, ErrHandoffRecord
	}
	for _, value := range members {
		entry, ok := value.([]any)
		if !ok || len(entry) != 4 {
			return body, ErrHandoffRecord
		}
		staking, sOK := entry[0].(string)
		node, nOK := entry[1].(string)
		key, kOK := entry[2].([]byte)
		weight, wOK := entry[3].(uint64)
		if !sOK || !nOK || !kOK || !wOK {
			return body, ErrHandoffRecord
		}
		body.Members = append(body.Members, evmroot.Member{StakingID: staking, NodeID: node, ConsensusKey: key, Weight: weight})
	}
	if body.RootThreshold, ok = fields[5].(uint64); !ok {
		return body, ErrHandoffRecord
	}
	if body.StateSummary, ok = optionalD3Bytes(fields[6]); !ok {
		return body, ErrHandoffRecord
	}
	if body.ChangeRecordHash, ok = optionalD3Bytes(fields[7]); !ok {
		return body, ErrHandoffRecord
	}
	if body.PredecessorHash, ok = optionalD3Bytes(fields[8]); !ok {
		return body, ErrHandoffRecord
	}
	if err := body.Validate(); err != nil || !bytes.Equal(body.Encode(), raw) {
		return body, ErrHandoffRecord
	}
	return body, nil
}

func optionalD3Bytes(value any) ([]byte, bool) {
	if value == nil {
		return nil, true
	}
	b, ok := value.([]byte)
	return b, ok
}
