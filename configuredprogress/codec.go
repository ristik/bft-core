// Package configuredprogress is the configured-origin v2 persistence boundary from F6e, used by
// the shard-node admission path. It stores authenticated progress data only; it grants no freshness,
// readiness, execution or signing authority.
package configuredprogress

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"

	"github.com/ethereum/go-ethereum/common"
	"github.com/fxamacker/cbor/v2"
	"github.com/unicitynetwork/bft-core/evmroot"
	"github.com/unicitynetwork/bft-core/registrygenesis"
	"github.com/unicitynetwork/bft-core/registryproof"
	"github.com/unicitynetwork/bft-go-base/types"
)

const (
	FormatVersion       uint64 = 2
	MaxDescriptorBytes         = 4 << 10
	MaxPairBytes               = 1 << 20
	MaxControlBytes            = (2 << 20) + (4 << 10)
	MaxOuterRecordBytes        = (1 << 20) + (4 << 10)
	maxNestedLevels            = 16
)

const (
	kindDescriptor uint64 = iota
	kindControl
	kindRecord
)

var (
	ErrUnavailable = errors.New("configuredprogress: required durable state is unavailable")
	ErrUntrusted   = errors.New("configuredprogress: durable state is damaged or untrusted")
	ErrVersion     = errors.New("configuredprogress: unsupported storage version or kind")
	ErrContext     = errors.New("configuredprogress: durable state is for another configured origin")
	ErrConflict    = errors.New("configuredprogress: authenticated progress conflicts")
	ErrStale       = errors.New("configuredprogress: prepared state changed")
	ErrBounds      = errors.New("configuredprogress: encoded value exceeds its bound")
	ErrSettings    = errors.New("configuredprogress: invalid settings")
)

var outerDec, innerDec cbor.DecMode

func init() {
	var err error
	outerDec, err = cbor.DecOptions{
		MaxNestedLevels:  maxNestedLevels,
		MaxArrayElements: 65536,
		MaxMapPairs:      65536,
		IndefLength:      cbor.IndefLengthForbidden,
		TagsMd:           cbor.TagsForbidden,
	}.DecMode()
	if err != nil {
		panic(err)
	}
	innerDec, err = cbor.DecOptions{MaxNestedLevels: maxNestedLevels, MaxArrayElements: 65536, MaxMapPairs: 65536, IndefLength: cbor.IndefLengthForbidden}.DecMode()
	if err != nil {
		panic(err)
	}
}

type envelopeWire struct {
	_               struct{} `cbor:",toarray"`
	Version, Kind   uint64
	Payload, Digest []byte
}
type descriptorContextWire struct {
	_                                                                       struct{} `cbor:",toarray"`
	NetworkID, PartitionID                                                  uint64
	ShardID, FullConf, RegistryAddress, RegistryCodeHash, GenesisCommitment []byte
	ShardEpoch, RootEpoch                                                   uint64
}
type descriptorWire struct {
	_                                       struct{} `cbor:",toarray"`
	Version                                 uint64
	OriginIdentity, ExecutionConfigIdentity []byte
	Context                                 descriptorContextWire
	B0, S0                                  []byte
	RootInputVersion, RegistryLayoutVersion uint64
}
type pairWire struct {
	_      struct{} `cbor:",toarray"`
	UC, TR []byte
}
type controlWire struct {
	_                struct{} `cbor:",toarray"`
	Version          uint64
	DescriptorDigest []byte
	Revision         uint64
	First, Observed  *pairWire
	HeadKey          []byte
}
type recordWire struct {
	_                        struct{} `cbor:",toarray"`
	Version                  uint64
	DescriptorDigest, Legacy []byte
}

func marshal(v any) ([]byte, error) { return types.Cbor.Marshal(v) }

func encodeEnvelope(kind uint64, payload []byte, limit int) ([]byte, error) {
	s := sha256.Sum256(payload)
	b, err := marshal(envelopeWire{Version: FormatVersion, Kind: kind, Payload: payload, Digest: s[:]})
	if err != nil {
		return nil, err
	}
	if len(b) > limit {
		return nil, fmt.Errorf("%w: envelope is %d bytes, limit %d", ErrBounds, len(b), limit)
	}
	return b, nil
}

func decodeEnvelope(raw []byte, want uint64, limit int) ([]byte, error) {
	if len(raw) == 0 || len(raw) > limit {
		return nil, fmt.Errorf("%w: envelope is %d bytes, bound 1..%d", ErrBounds, len(raw), limit)
	}
	var e envelopeWire
	if err := outerDec.Unmarshal(raw, &e); err != nil {
		return nil, fmt.Errorf("%w: envelope: %v", ErrUntrusted, err)
	}
	if e.Version != FormatVersion || e.Kind != want {
		return nil, fmt.Errorf("%w: envelope version/kind %d/%d", ErrVersion, e.Version, e.Kind)
	}
	s := sha256.Sum256(e.Payload)
	if !bytes.Equal(s[:], e.Digest) {
		return nil, fmt.Errorf("%w: envelope digest", ErrUntrusted)
	}
	canonical, err := encodeEnvelope(e.Kind, e.Payload, limit)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(raw, canonical) {
		return nil, fmt.Errorf("%w: non-canonical envelope", ErrUntrusted)
	}
	return bytes.Clone(e.Payload), nil
}

func decodePayload(payload []byte, v any) error {
	if err := outerDec.Unmarshal(payload, v); err != nil {
		return fmt.Errorf("%w: payload: %v", ErrUntrusted, err)
	}
	again, err := marshal(v)
	if err != nil {
		return err
	}
	if !bytes.Equal(payload, again) {
		return fmt.Errorf("%w: non-canonical payload", ErrUntrusted)
	}
	return nil
}

func descriptorFor(o registrygenesis.GenesisOrigin) (descriptorWire, error) {
	if !o.Valid() {
		return descriptorWire{}, fmt.Errorf("%w: invalid GenesisOrigin", ErrContext)
	}
	r := o.Record()
	pc := o.ProofContext()
	return descriptorWire{Version: FormatVersion, OriginIdentity: o.Identity().Bytes(), ExecutionConfigIdentity: o.ExecutionConfigIdentity().Bytes(), Context: descriptorContextWire{NetworkID: r.NetworkID, PartitionID: r.PartitionID, ShardID: bytes.Clone(r.ShardID), FullConf: o.FullShardConfHash().Bytes(), RegistryAddress: pc.RegistryAddress.Bytes(), RegistryCodeHash: pc.RegistryCodeHash.Bytes(), GenesisCommitment: pc.GenesisCommitment.Bytes(), ShardEpoch: pc.ShardEpoch, RootEpoch: pc.RootEpoch}, B0: o.BlockHash().Bytes(), S0: o.StateRoot().Bytes(), RootInputVersion: evmroot.ProfileVersionV2, RegistryLayoutVersion: registryproof.LayoutVersion}, nil
}

func encodeDescriptor(o registrygenesis.GenesisOrigin) ([]byte, [32]byte, error) {
	d, err := descriptorFor(o)
	if err != nil {
		return nil, [32]byte{}, err
	}
	p, err := marshal(d)
	if err != nil {
		return nil, [32]byte{}, err
	}
	sum := sha256.Sum256(p)
	raw, err := encodeEnvelope(kindDescriptor, p, MaxDescriptorBytes)
	return raw, sum, err
}

func verifyDescriptor(raw []byte, o registrygenesis.GenesisOrigin) ([32]byte, error) {
	p, err := decodeEnvelope(raw, kindDescriptor, MaxDescriptorBytes)
	if err != nil {
		return [32]byte{}, err
	}
	var got descriptorWire
	if err = decodePayload(p, &got); err != nil {
		return [32]byte{}, err
	}
	want, err := descriptorFor(o)
	if err != nil {
		return [32]byte{}, err
	}
	wb, _ := marshal(want)
	if !bytes.Equal(p, wb) {
		return [32]byte{}, ErrContext
	}
	return sha256.Sum256(p), nil
}

func checkDigest(b []byte) bool { return len(b) == sha256.Size }
func validRecordKey(k []byte) bool {
	if len(k) != len("record/")+20+1+64 || !bytes.HasPrefix(k, []byte("record/")) || k[len("record/")+20] != '/' {
		return false
	}
	for _, c := range k[len("record/") : len("record/")+20] {
		if c < '0' || c > '9' {
			return false
		}
	}
	for _, c := range k[len("record/")+21:] {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}
func recordKey(round uint64, h common.Hash) []byte {
	return []byte(fmt.Sprintf("record/%020d/%064x", round, h[:]))
}
