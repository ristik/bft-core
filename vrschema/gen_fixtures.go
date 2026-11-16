package vrschema

import (
	"fmt"
	"time"

	"github.com/unicitynetwork/bft-core/evmassign"
	"github.com/unicitynetwork/bft-go-base/types"
)

// Deterministic fixture world shared by the generators.
var (
	fxNetwork     = w("unicity.vr.schema.test-network")
	fxChainID     = U64(3)
	fxRootNetwork = uint64(3)
	fxModule      = [20]byte{0xa0, 19: 0x01}
	fxOther       = [20]byte{0xb0, 19: 0x02}
	fxSender      = [20]byte{0xc0, 19: 0x03}
)

func fxNodeID(i int) string { return fmt.Sprintf("vr-test-node-%02d", i) }

func fxRegistration(i int, nonce uint64) Registration {
	var payee [20]byte
	payee[0], payee[19] = 0x9a, byte(i)
	return Registration{RootNodeID: fxNodeID(2 * i), RootKey: pubOf(genKey(2 * i)), EVMNodeID: fxNodeID(2*i + 1), EVMKey: pubOf(genKey(2*i + 1)),
		Payee: payee, Nonce: nonce}
}

func fxMember(id uint64, resultID Word) Member {
	return MemberOf(id, 1, 1, 1, fxRegistration(int(id), 0), PoaExposureDigest(fxNetwork, fxChainID, ValidatorRegistry, resultID, id))
}

func fxMembers(n int, resultID Word) []Member {
	ms := make([]Member, n)
	for i := range ms {
		ms[i] = fxMember(uint64(i+1), resultID)
	}
	return ms
}

// fxPDR is a valid unit-weight PDR whose validators are test keys base..base+n-1.
func fxPDR(partition uint32, typeID uint32, epoch uint64, base, n int) *types.PartitionDescriptionRecord {
	p := &types.PartitionDescriptionRecord{Version: 1, NetworkID: types.NetworkID(fxRootNetwork), PartitionID: types.PartitionID(partition),
		PartitionTypeID: types.PartitionTypeID(typeID), TypeIDLen: 8, UnitIDLen: 256, T2Timeout: 2500 * time.Millisecond, Epoch: epoch,
		PartitionParams: map[string]string{"proof_type": "aggregator_rsmt_v1"}}
	for i := 0; i < n; i++ {
		p.Validators = append(p.Validators, &types.NodeInfo{NodeID: fxNodeID(100 + base + i), SigKey: pubOf(genKey(100 + base + i)), Stake: 1})
	}
	return p
}

func mustCBOR(v any) []byte {
	b, err := types.Cbor.Marshal(v)
	if err != nil {
		panic(err)
	}
	return b
}

// fxChangePoPs signs the VR-context PoPs of a successor PDR for change id.
func fxChangePoPs(changeID uint64, pdr *types.PartitionDescriptionRecord, base int) []byte {
	raw := mustCBOR(pdr)
	var ps []evmassign.PoP
	for i, v := range pdr.Validators {
		msg, err := ChangePoPMessage(fxRootNetwork, ValidatorRegistry, changeID, uint32(pdr.PartitionID), pdr.ShardID.Bytes(), raw, v.NodeID)
		if err != nil {
			panic(err)
		}
		sig, err := signerOf(genKey(100 + base + i)).SignBytes(msg)
		if err != nil {
			panic(err)
		}
		ps = append(ps, evmassign.PoP{NodeID: v.NodeID, Key: v.SigKey, Signature: sig})
	}
	return mustCBOR(ps)
}

func mustChange(kind uint8, vals ...any) []byte {
	b, err := EncodeChange(kind, vals...)
	if err != nil {
		panic(fmt.Sprintf("kind %d: %v", kind, err))
	}
	return b
}

func pdrHash(p *types.PartitionDescriptionRecord) Word {
	h, err := evmassign.PDRHash(p)
	if err != nil {
		panic(err)
	}
	return h
}
