package nb2ref

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"math"

	"github.com/unicitynetwork/bft-core/b1ref"
	"github.com/unicitynetwork/bft-go-base/types"
)

// FlatAuthority contains an authenticated execution registry view and its
// independent consensus pins. The caller must authenticate the view against the
// deployment and its historical origin before supplying it to the oracle.
type FlatAuthority struct {
	Registry b1ref.State
	Pins     b1ref.Pins
}

type flatClaim struct {
	key, value [32]byte
	wire       []byte
}

func (v *FlatVerifier) claim(raw []byte, partition uint32, expectedShard []byte) (flatClaim, *types.UnicityCertificate, error) {
	uc, err := decodeUC(raw)
	if err != nil {
		return flatClaim{}, nil, err
	}
	if uc.UnicitySeal.NetworkID != types.NetworkID(v.cfg.Network) || uint32(uc.UnicityTreeCertificate.Partition) != partition {
		return flatClaim{}, nil, ErrCertStructure
	}
	shard := uc.ShardTreeCertificate.Shard.Bytes()
	if expectedShard != nil && !bytes.Equal(expectedShard, shard) {
		return flatClaim{}, nil, ErrCertStructure
	}
	ir, err := uc.InputRecord.Bytes()
	if err != nil {
		return flatClaim{}, nil, err
	}
	seal, err := types.Cbor.Marshal(uc.UnicitySeal)
	if err != nil {
		return flatClaim{}, nil, err
	}
	sealHash, irHash := HU(seal), HU(ir)
	prefix := cat(flatU32(partition), flatU16(uint16(len(shard))), shard)
	wire := flatBlob(cat(prefix, uc.ShardConfHash, uc.InputRecord.Hash, irHash[:]), raw)
	wireHash := HU(wire)
	return flatClaim{
		key: FlatHash("CLAIM_KEY", sealHash[:], prefix), value: FlatHash("CLAIM_VALUE", wireHash[:]), wire: wire,
	}, uc, nil
}

func flatBatchWire(claims []flatClaim) []byte {
	data := []byte{2, 0, 0, byte(len(claims))}
	for _, c := range claims {
		data = append(data, c.wire...)
	}
	return data
}

func (a FlatAuthority) verify(claims []flatClaim) error {
	for len(claims) > 0 {
		n := min(len(claims), b1ref.MaxClaims)
		for {
			data := flatBatchWire(claims[:n])
			_, err := b1ref.Group(data)
			if err != nil {
				if n > 1 && errors.Is(err, b1ref.ErrBound) {
					n--
					continue
				}
				return err
			}
			verdict, err := b1ref.Cert(data, a.Registry, a.Pins)
			if err != nil {
				return err
			}
			if !verdict.Valid {
				return fmt.Errorf("lineage certificate batch: %w", verdict.Why)
			}
			claims = claims[n:]
			break
		}
	}
	return nil
}

type flatClaimUse func(flatClaim) error

func (v *FlatVerifier) receipt(emitter [20]byte, p *DepositProof, use flatClaimUse) (*ReceiptLog, error) {
	c, uc, err := v.claim(p.UC, v.cfg.EVMPartition, v.cfg.EVMShard)
	if err != nil {
		return nil, err
	}
	if err := use(c); err != nil {
		return nil, err
	}
	return verifyReceiptLog(emitter, p, uc)
}

func (v *FlatVerifier) event(header FlatHeader, kind FlatEventKind, wire []byte) (FlatEvent, error) {
	p, err := DecodeDepositProof(wire)
	if err != nil {
		return FlatEvent{}, errors.Join(ErrFlatPredecessor, err)
	}
	log, err := v.receipt(v.deployment.Recovery, p, func(c flatClaim) error {
		return v.authority.verify([]flatClaim{c})
	})
	if err != nil {
		return FlatEvent{}, errors.Join(ErrFlatPredecessor, err)
	}
	return flatDecodeEvent(log, kind, v.Session(header))
}

func (v *FlatVerifier) certified(source Predicate, state, tx [32]byte, deadline Deadline,
	p *InclusionProof, insert func([32]byte) error, use flatClaimUse,
) ([32]byte, error) {
	cd := p.CD
	if !bytes.Equal(source.Bytes(), cd.Source.Bytes()) || state != cd.SourceHash || tx != cd.TxHash {
		return [32]byte{}, ErrCDMismatch
	}
	if deadline != cd.Deadline {
		return [32]byte{}, ErrDeadlineMismatch
	}
	key, err := ParseKey(source.Params)
	if err != nil || source.Type != PredSignature {
		return [32]byte{}, ErrBurnNotFinal
	}
	if err := VerifyUnlock(key, state, tx, cd.Unlock); err != nil {
		return [32]byte{}, err
	}
	if deadline.Set && p.T >= deadline.At {
		return [32]byte{}, ErrDeadlineExpired
	}
	sid := StateID(source, state)
	if err := insert(sid); err != nil {
		return [32]byte{}, err
	}
	claim, uc, err := v.claim(p.UC, v.cfg.AggregatorPartition, nil)
	if err != nil {
		return [32]byte{}, err
	}
	if err := use(claim); err != nil {
		return [32]byte{}, err
	}
	shard := uc.ShardTreeCertificate.Shard
	if len(uc.InputRecord.Hash) != 32 || !shard.Comparator()(sid[:]) {
		return [32]byte{}, ErrInclusionProof
	}
	if p.T > uc.InputRecord.Timestamp {
		return [32]byte{}, ErrReferenceTime
	}
	leaf := LeafValue(tx, p.T)
	input := cat([]byte{1, 0, 0, 1}, uc.InputRecord.Hash, sid[:], flatU32(32), leaf[:], p.Bitmap[:])
	for _, sibling := range p.Siblings {
		input = append(input, sibling[:]...)
	}
	out, _, err := b1ref.Run(b1ref.OpMember, input, nil, b1ref.Pins{}, math.MaxUint64)
	if err != nil || !bytes.Equal(out, b1ref.MemberOutput(true)) {
		return [32]byte{}, errors.Join(ErrInclusionProof, err)
	}
	return sid, nil
}

type flatPacketClaims struct {
	root  [32]byte
	cache map[[32]byte][32]byte
	batch []flatClaim
}

func (c *flatPacketClaims) apply(claim flatClaim, proof FlatClaimOpening) error {
	if known, ok := c.cache[claim.key]; ok {
		if !proof.Reuse || known != claim.value {
			return ErrFlatStep
		}
		return nil
	}
	if proof.Reuse || (proof.Present && proof.Old != claim.value) {
		return ErrFlatStep
	}
	old := [32]byte{}
	if proof.Present {
		old = flatClaimLeaf(claim.key, proof.Old)
	}
	next := flatClaimLeaf(claim.key, claim.value)
	root, err := flatClaimTree.update(c.root, claim.key, old, next, proof.Path)
	if err != nil {
		return err
	}
	c.root = root
	c.cache[claim.key] = claim.value
	c.batch = append(c.batch, claim)
	return nil
}

func flatRegistryNetwork(registry b1ref.State, expected uint16) error {
	if registry == nil {
		return ErrTrustInput
	}
	network, err := registry.Word(b1ref.FixedSlot("b1.network"))
	if err != nil || !zeroFlat(network[:30]) || binary.BigEndian.Uint16(network[30:]) != expected {
		return errors.Join(ErrTrustInput, err)
	}
	return nil
}
