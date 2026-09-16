// Package frontiertransport implements the inactive bounded wire exchange for
// root frontier and committed-cut evidence. It performs no gathering, receipt,
// bootstrap, or node registration.
package frontiertransport

import (
	"bytes"
	"errors"

	"github.com/fxamacker/cbor/v2"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/internal/frontiercodec"
	"github.com/unicitynetwork/bft-go-base/types"
)

const (
	FrontierProtocolID = "/ab/root-bootstrap/frontier/1.0.0"
	CutProtocolID      = "/ab/root-bootstrap/cut/1.0.0"
	MaxRequestBytes    = 4 << 10
	MaxResponseBytes   = frontiercodec.MaxReply
)

var (
	ErrWire        = errors.New("frontier transport: invalid wire data")
	ErrBounds      = errors.New("frontier transport: bounds exceeded")
	ErrNotAdmitted = errors.New("frontier transport: not admitted")
	ErrClosed      = errors.New("frontier transport: closed")
	ErrBudget      = errors.New("frontier transport: receive budget exhausted")
)

type FrontierRequest struct {
	_       struct{} `cbor:",toarray"`
	Version uint64
	Context frontiercodec.Context
	Nonce   []byte
}

type CutRequest struct {
	_                  struct{} `cbor:",toarray"`
	Version            uint64
	Context            frontiercodec.Context
	Nonce              []byte
	AcquisitionBinding []byte
	Floor              uint64
}

func EncodeFrontierRequest(r FrontierRequest) ([]byte, error) {
	if err := validateContext(r.Version, r.Context, r.Nonce); err != nil {
		return nil, err
	}
	return marshalBounded(r)
}

func DecodeFrontierRequest(raw []byte) (FrontierRequest, error) {
	var r FrontierRequest
	if err := strictDecode(raw, &r, 3); err != nil || validateContext(r.Version, r.Context, r.Nonce) != nil {
		return FrontierRequest{}, ErrWire
	}
	return ownFrontierRequest(r), nil
}

func EncodeCutRequest(r CutRequest) ([]byte, error) {
	if err := validateContext(r.Version, r.Context, r.Nonce); err != nil || len(r.AcquisitionBinding) != 32 || r.Floor == 0 {
		return nil, ErrWire
	}
	return marshalBounded(r)
}

func DecodeCutRequest(raw []byte) (CutRequest, error) {
	var r CutRequest
	if err := strictDecode(raw, &r, 5); err != nil || validateContext(r.Version, r.Context, r.Nonce) != nil || len(r.AcquisitionBinding) != 32 || r.Floor == 0 {
		return CutRequest{}, ErrWire
	}
	r.Context = ownContext(r.Context)
	r.Nonce = bytes.Clone(r.Nonce)
	r.AcquisitionBinding = bytes.Clone(r.AcquisitionBinding)
	return r, nil
}

func validateContext(version uint64, c frontiercodec.Context, nonce []byte) error {
	if version != frontiercodec.Version || c.NetworkID == 0 || c.PartitionID == 0 || len(c.CanonicalShardBytes) == 0 || len(c.CanonicalShardBytes) > 513 || len(c.FullShardConfHash) != 32 || c.RootEpoch == 0 || len(c.GenesisOriginIdentity) != 32 || len(nonce) != 32 {
		return ErrWire
	}
	encoded, err := types.Cbor.Marshal(c.CanonicalShardBytes)
	if err != nil {
		return ErrWire
	}
	var shard types.ShardID
	if err := types.Cbor.Unmarshal(encoded, &shard); err != nil || shard.Length() > 4096 || !bytes.Equal(shard.Bytes(), c.CanonicalShardBytes) {
		return ErrWire
	}
	return nil
}

func ownFrontierRequest(r FrontierRequest) FrontierRequest {
	r.Context = ownContext(r.Context)
	r.Nonce = bytes.Clone(r.Nonce)
	return r
}

func ownContext(c frontiercodec.Context) frontiercodec.Context {
	c.CanonicalShardBytes = bytes.Clone(c.CanonicalShardBytes)
	c.FullShardConfHash = bytes.Clone(c.FullShardConfHash)
	c.GenesisOriginIdentity = bytes.Clone(c.GenesisOriginIdentity)
	return c
}

func marshalBounded(v any) ([]byte, error) {
	b, err := types.Cbor.Marshal(v)
	if err != nil || len(b) == 0 || len(b) > MaxRequestBytes {
		return nil, ErrBounds
	}
	return b, nil
}

func strictDecode(raw []byte, target any, arrayLen int) error {
	if len(raw) == 0 || len(raw) > MaxRequestBytes {
		return ErrBounds
	}
	dm, err := (cbor.DecOptions{DupMapKey: cbor.DupMapKeyEnforcedAPF, IndefLength: cbor.IndefLengthForbidden, TagsMd: cbor.TagsForbidden, MaxNestedLevels: 16, MaxArrayElements: 32, MaxMapPairs: 16, ExtraReturnErrors: cbor.ExtraDecErrorUnknownField}).DecMode()
	if err != nil {
		return err
	}
	var generic any
	if err := dm.Unmarshal(raw, &generic); err != nil {
		return err
	}
	arr, ok := generic.([]any)
	if !ok || len(arr) != arrayLen {
		return ErrWire
	}
	canonical, err := types.Cbor.Marshal(generic)
	if err != nil || !bytes.Equal(canonical, raw) {
		return ErrWire
	}
	if err := dm.Unmarshal(raw, target); err != nil {
		return err
	}
	reencoded, err := types.Cbor.Marshal(target)
	if err != nil || !bytes.Equal(reencoded, raw) {
		return ErrWire
	}
	return nil
}
