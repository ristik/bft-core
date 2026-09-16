// Package parentwitness defines the inactive parent SealRegistry witness wire boundary.
// It registers no protocol and performs no provider lookup or retry policy.
package parentwitness

import (
	"bytes"
	"errors"
	"fmt"
	"math"

	"github.com/ethereum/go-ethereum/common"
	"github.com/fxamacker/cbor/v2"
	"github.com/unicitynetwork/bft-core/registryproof"
	"github.com/unicitynetwork/bft-go-base/types"
)

const (
	ProtocolID        = "/unicity/shard-parent-registry-witness/1.0.0"
	Version    uint64 = 1

	MaxRequestBytes    = 4 << 10
	MaxResponseBytes   = 272 << 10
	MaxEvidenceBytes   = 256 << 10
	MaxDiagnosticBytes = 200
	MaxShardIDBytes    = 33

	// MaxFoundResponseBytes is the exact largest canonical v1 found response: 256 KiB
	// aggregate evidence spread over 23*65 nodes to maximize length prefixes, a 1,024-byte
	// header, the maximum canonical shard encoding and a 200-byte diagnostic.
	MaxFoundResponseBytes = 265621
)

var (
	ErrWire           = errors.New("parent witness: invalid wire message")
	ErrContext        = errors.New("parent witness: wrong context or subject")
	ErrBounds         = errors.New("parent witness: encoded value exceeds its bound")
	ErrInvalidRequest = errors.New("parent witness: invalid request")
)

type Outcome uint64

const (
	OutcomeFound Outcome = iota
	OutcomeUnavailable
	OutcomeBusy
	OutcomeUnsupportedVersion
	OutcomeWrongContext
	OutcomeInvalidRequest
)

type Context struct {
	NetworkID         types.NetworkID
	PartitionID       types.PartitionID
	ShardID           types.ShardID
	FullShardConfHash common.Hash
	RegistryAddress   common.Address
	RegistryCodeHash  common.Hash
	GenesisCommitment common.Hash
	EVMGenesisHash    common.Hash
	ShardEpoch        uint64
	RootEpoch         uint64
}

type Request struct {
	Context   Context
	BlockHash common.Hash
}

type Response struct {
	Request  Request
	Outcome  Outcome
	Detail   string
	Evidence registryproof.Evidence
}

type contextWire struct {
	_                                                                                                struct{} `cbor:",toarray"`
	NetworkID, PartitionID                                                                           uint64
	ShardID, FullShardConfHash, RegistryAddress, RegistryCodeHash, GenesisCommitment, EVMGenesisHash []byte
	ShardEpoch, RootEpoch                                                                            uint64
}

type requestWire struct {
	_         struct{} `cbor:",toarray"`
	Version   uint64
	Context   contextWire
	BlockHash []byte
}

type evidenceWire struct {
	_             struct{} `cbor:",toarray"`
	Header        []byte
	AccountProof  [][]byte
	StorageProofs [][][]byte
}

type responseWire struct {
	_         struct{} `cbor:",toarray"`
	Version   uint64
	Context   contextWire
	BlockHash []byte
	Outcome   uint64
	Detail    string
	Evidence  *evidenceWire
}

var decoder cbor.DecMode

func init() {
	var err error
	decoder, err = cbor.DecOptions{MaxNestedLevels: 16, MaxArrayElements: 2048, MaxMapPairs: 16, IndefLength: cbor.IndefLengthForbidden, TagsMd: cbor.TagsForbidden}.DecMode()
	if err != nil {
		panic(err)
	}
}

func contextToWire(c Context) contextWire {
	return contextWire{NetworkID: uint64(c.NetworkID), PartitionID: uint64(c.PartitionID), ShardID: bytes.Clone(c.ShardID.Bytes()), FullShardConfHash: c.FullShardConfHash.Bytes(), RegistryAddress: c.RegistryAddress.Bytes(), RegistryCodeHash: c.RegistryCodeHash.Bytes(), GenesisCommitment: c.GenesisCommitment.Bytes(), EVMGenesisHash: c.EVMGenesisHash.Bytes(), ShardEpoch: c.ShardEpoch, RootEpoch: c.RootEpoch}
}

func contextFromWire(w contextWire) (Context, error) {
	if w.NetworkID > math.MaxUint16 || w.PartitionID > math.MaxUint32 {
		return Context{}, fmt.Errorf("%w: network/partition width", ErrWire)
	}
	if len(w.FullShardConfHash) != 32 || len(w.RegistryAddress) != 20 || len(w.RegistryCodeHash) != 32 || len(w.GenesisCommitment) != 32 || len(w.EVMGenesisHash) != 32 {
		return Context{}, fmt.Errorf("%w: fixed context field length", ErrWire)
	}
	shard, err := shardFromBytes(w.ShardID)
	if err != nil {
		return Context{}, fmt.Errorf("%w: shard encoding: %v", ErrWire, err)
	}
	if !bytes.Equal(shard.Bytes(), w.ShardID) {
		return Context{}, fmt.Errorf("%w: shard encoding", ErrWire)
	}
	return Context{NetworkID: types.NetworkID(w.NetworkID), PartitionID: types.PartitionID(w.PartitionID), ShardID: shard, FullShardConfHash: common.BytesToHash(w.FullShardConfHash), RegistryAddress: common.BytesToAddress(w.RegistryAddress), RegistryCodeHash: common.BytesToHash(w.RegistryCodeHash), GenesisCommitment: common.BytesToHash(w.GenesisCommitment), EVMGenesisHash: common.BytesToHash(w.EVMGenesisHash), ShardEpoch: w.ShardEpoch, RootEpoch: w.RootEpoch}, nil
}

func shardFromBytes(b []byte) (types.ShardID, error) {
	raw, err := types.Cbor.Marshal(bytes.Clone(b))
	if err != nil {
		return types.ShardID{}, err
	}
	var shard types.ShardID
	if err := types.Cbor.Unmarshal(raw, &shard); err != nil {
		return types.ShardID{}, err
	}
	return shard, nil
}

func (c Context) proofContext() registryproof.Context {
	return registryproof.Context{RegistryAddress: c.RegistryAddress, RegistryCodeHash: c.RegistryCodeHash, GenesisCommitment: c.GenesisCommitment, FullShardConfHash: c.FullShardConfHash, ShardEpoch: c.ShardEpoch, RootEpoch: c.RootEpoch, EVMGenesisHash: c.EVMGenesisHash}
}

func validateRequest(r Request) error {
	if r.BlockHash == (common.Hash{}) {
		return fmt.Errorf("%w: zero block hash", ErrInvalidRequest)
	}
	if uint64(r.Context.NetworkID) == 0 || uint64(r.Context.PartitionID) == 0 {
		return fmt.Errorf("%w: zero network/partition", ErrInvalidRequest)
	}
	if n := len(r.Context.ShardID.Bytes()); n == 0 || n > MaxShardIDBytes {
		return fmt.Errorf("%w: shard encoding is %d bytes", ErrInvalidRequest, n)
	}
	if r.Context.RegistryAddress != registryproof.RegistryAddress {
		return fmt.Errorf("%w: registry address", ErrInvalidRequest)
	}
	for name, h := range map[string]common.Hash{"full configuration": r.Context.FullShardConfHash, "registry code": r.Context.RegistryCodeHash, "genesis commitment": r.Context.GenesisCommitment, "EVM genesis": r.Context.EVMGenesisHash} {
		if h == (common.Hash{}) {
			return fmt.Errorf("%w: zero %s hash", ErrInvalidRequest, name)
		}
	}
	return nil
}

func marshalCanonical(v any) ([]byte, error) { return types.Cbor.Marshal(v) }

func decodeCanonical(raw []byte, max int, v any) error {
	if len(raw) == 0 || len(raw) > max {
		return fmt.Errorf("%w: %d bytes, bound 1..%d", ErrBounds, len(raw), max)
	}
	if err := validateCBORBounds(raw); err != nil {
		return err
	}
	if err := decoder.Unmarshal(raw, v); err != nil {
		return fmt.Errorf("%w: %v", ErrWire, err)
	}
	again, err := marshalCanonical(v)
	if err != nil {
		return err
	}
	if !bytes.Equal(raw, again) {
		return fmt.Errorf("%w: non-canonical CBOR", ErrWire)
	}
	return nil
}

func EncodeRequest(r Request) ([]byte, error) {
	if err := validateRequest(r); err != nil {
		return nil, err
	}
	raw, err := marshalCanonical(requestWire{Version: Version, Context: contextToWire(r.Context), BlockHash: r.BlockHash.Bytes()})
	if err != nil {
		return nil, err
	}
	if len(raw) > MaxRequestBytes {
		return nil, ErrBounds
	}
	return raw, nil
}

func DecodeRequest(raw []byte) (Request, error) {
	var w requestWire
	if err := decodeCanonical(raw, MaxRequestBytes, &w); err != nil {
		return Request{}, err
	}
	if w.Version != Version {
		return Request{}, fmt.Errorf("%w: unsupported version %d", ErrWire, w.Version)
	}
	c, err := contextFromWire(w.Context)
	if err != nil {
		return Request{}, err
	}
	if len(w.BlockHash) != 32 {
		return Request{}, fmt.Errorf("%w: block hash length", ErrWire)
	}
	r := Request{Context: c, BlockHash: common.BytesToHash(w.BlockHash)}
	if err := validateRequest(r); err != nil {
		return Request{}, err
	}
	return r, nil
}

func EncodeResponse(r Response) ([]byte, error) {
	if err := validateRequest(r.Request); err != nil {
		return nil, err
	}
	if r.Outcome > OutcomeInvalidRequest {
		return nil, fmt.Errorf("%w: unknown outcome", ErrWire)
	}
	if len(r.Detail) > MaxDiagnosticBytes {
		return nil, fmt.Errorf("%w: diagnostic is %d bytes", ErrBounds, len(r.Detail))
	}
	var ev *evidenceWire
	if r.Outcome == OutcomeFound {
		owned, err := ownEvidence(r.Evidence)
		if err != nil {
			return nil, err
		}
		ev = &evidenceWire{Header: owned.Header, AccountProof: owned.AccountProof, StorageProofs: owned.StorageProofs}
	} else if evidencePresent(r.Evidence) {
		return nil, fmt.Errorf("%w: refusal carries evidence", ErrWire)
	}
	w := responseWire{Version: Version, Context: contextToWire(r.Request.Context), BlockHash: r.Request.BlockHash.Bytes(), Outcome: uint64(r.Outcome), Detail: r.Detail, Evidence: ev}
	raw, err := marshalCanonical(w)
	if err != nil {
		return nil, err
	}
	if len(raw) > MaxResponseBytes {
		return nil, fmt.Errorf("%w: response is %d bytes", ErrBounds, len(raw))
	}
	return raw, nil
}

func decodeResponse(raw []byte) (Response, error) {
	var w responseWire
	if err := decodeCanonical(raw, MaxResponseBytes, &w); err != nil {
		return Response{}, err
	}
	if w.Version != Version || w.Outcome > uint64(OutcomeInvalidRequest) {
		return Response{}, fmt.Errorf("%w: version/outcome", ErrWire)
	}
	c, err := contextFromWire(w.Context)
	if err != nil {
		return Response{}, err
	}
	if len(w.BlockHash) != 32 || len(w.Detail) > MaxDiagnosticBytes {
		return Response{}, fmt.Errorf("%w: response field bound", ErrWire)
	}
	r := Response{Request: Request{Context: c, BlockHash: common.BytesToHash(w.BlockHash)}, Outcome: Outcome(w.Outcome), Detail: w.Detail}
	if err := validateRequest(r.Request); err != nil {
		return Response{}, err
	}
	if r.Outcome == OutcomeFound {
		if w.Evidence == nil {
			return Response{}, fmt.Errorf("%w: found without evidence", ErrWire)
		}
		r.Evidence, err = ownEvidence(registryproof.Evidence{Header: w.Evidence.Header, AccountProof: w.Evidence.AccountProof, StorageProofs: w.Evidence.StorageProofs})
		if err != nil {
			return Response{}, err
		}
	} else if w.Evidence != nil {
		return Response{}, fmt.Errorf("%w: refusal carries evidence", ErrWire)
	}
	return r, nil
}

func evidencePresent(e registryproof.Evidence) bool {
	return len(e.Header) != 0 || len(e.AccountProof) != 0 || len(e.StorageProofs) != 0
}

func ownEvidence(e registryproof.Evidence) (registryproof.Evidence, error) {
	if len(e.Header) == 0 || len(e.Header) > 1024 || len(e.StorageProofs) != registryproof.FieldCount {
		return registryproof.Evidence{}, fmt.Errorf("%w: evidence shape", ErrBounds)
	}
	total := len(e.Header)
	copyNodes := func(in [][]byte) ([][]byte, error) {
		if len(in) > 65 {
			return nil, ErrBounds
		}
		out := make([][]byte, len(in))
		for i, n := range in {
			if len(n) > 1024 || total+len(n) > MaxEvidenceBytes {
				return nil, ErrBounds
			}
			total += len(n)
			out[i] = bytes.Clone(n)
		}
		return out, nil
	}
	out := registryproof.Evidence{Header: bytes.Clone(e.Header), StorageProofs: make([][][]byte, registryproof.FieldCount)}
	var err error
	if out.AccountProof, err = copyNodes(e.AccountProof); err != nil {
		return registryproof.Evidence{}, err
	}
	for i := range e.StorageProofs {
		if out.StorageProofs[i], err = copyNodes(e.StorageProofs[i]); err != nil {
			return registryproof.Evidence{}, err
		}
	}
	return out, nil
}
