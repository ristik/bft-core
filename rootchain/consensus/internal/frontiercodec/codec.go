package frontiercodec

import (
	"crypto/sha256"
	"errors"

	"github.com/unicitynetwork/bft-core/network/protocol/certification"
	"github.com/unicitynetwork/bft-go-base/types"
)

const (
	AcquisitionDomain = "root-bootstrap-admission/acquisition"
	SigningDomain     = "root-bootstrap-admission/frontier"
	PairDomain        = "root-bootstrap-admission/pair"
	Version           = uint64(1)
	MaxAuthor         = 256
	MaxSignature      = 256
	MaxPart           = 256 << 10
	MaxReply          = 1 << 20
)

type AcquisitionTuple struct {
	_                struct{} `cbor:",toarray"`
	Domain           string
	Version          uint64
	Context          Context
	Nonce            []byte
	TrustFingerprint []byte
}

type Context struct {
	_                     struct{} `cbor:",toarray"`
	NetworkID             types.NetworkID
	PartitionID           types.PartitionID
	CanonicalShardBytes   []byte
	FullShardConfHash     []byte
	RootEpoch             uint64
	GenesisOriginIdentity []byte
}

type Pair struct {
	_  struct{} `cbor:",toarray"`
	UC *types.UnicityCertificate
	TR *certification.TechnicalRecord
}

type PairIdentityTuple struct {
	_            struct{} `cbor:",toarray"`
	Domain       string
	Version      uint64
	InputRecord  []byte
	SealSigBytes []byte
	Technical    []byte
	Context      Context
}

type SigningPreimage struct {
	_        struct{} `cbor:",toarray"`
	Domain   string
	Version  uint64
	Context  Context
	Nonce    []byte
	Author   string
	PairID   []byte
	QCDigest []byte
}

type Reply struct {
	_         struct{} `cbor:",toarray"`
	Version   uint64
	Author    string
	Pair      []byte
	QC        []byte
	Signature []byte
}

// AcquisitionBinding identifies the request context and nonce under which
// evidence was authenticated. It grants no authority by itself.
func AcquisitionBinding(context Context, nonce, trustFingerprint []byte) ([32]byte, error) {
	if len(nonce) != sha256.Size || len(trustFingerprint) != sha256.Size {
		return [32]byte{}, errors.New("invalid acquisition binding input")
	}
	b, err := types.Cbor.Marshal(AcquisitionTuple{Domain: AcquisitionDomain, Version: Version, Context: context, Nonce: nonce, TrustFingerprint: trustFingerprint})
	if err != nil || len(b) > MaxReply {
		return [32]byte{}, errors.New("acquisition binding encoding exceeds bounds")
	}
	return sha256.Sum256(b), nil
}

func PairIdentity(pair Pair, context Context) ([32]byte, error) {
	if pair.UC == nil || pair.UC.InputRecord == nil || pair.UC.UnicitySeal == nil || pair.TR == nil {
		return [32]byte{}, errors.New("incomplete pair")
	}
	ir, err := pair.UC.InputRecord.Bytes()
	if err != nil {
		return [32]byte{}, err
	}
	seal, err := pair.UC.UnicitySeal.SigBytes()
	if err != nil {
		return [32]byte{}, err
	}
	tr, err := types.Cbor.Marshal(pair.TR)
	if err != nil {
		return [32]byte{}, err
	}
	if len(ir) > MaxPart || len(seal) > MaxPart || len(tr) > MaxPart {
		return [32]byte{}, errors.New("pair identity component exceeds bounds")
	}
	b, err := types.Cbor.Marshal(PairIdentityTuple{Domain: PairDomain, Version: Version, InputRecord: ir, SealSigBytes: seal, Technical: tr, Context: context})
	if err != nil || len(b) > MaxReply {
		return [32]byte{}, errors.New("pair identity encoding exceeds bounds")
	}
	return sha256.Sum256(b), nil
}
