package bridgeprofile

// LockProof is the complete Unicity-certified EVM account/storage lock proof
// embedded in the mint justification:
//
//	LockProof = [1,b(cfg32),b(trustBaseId32),b(evmPDR),b(evmUC),b(headerRLP),
//	             [b(accountNodeRLP)...],[b(storageNodeRLP)...]]
//
// Both node arrays have exact arity; no receipt alternative exists. trustBaseId
// is the SHA-256 of the exact canonical signer-epoch root trust-base artifact
// the caller supplies: it names the authority and never supplies keys.
type LockProof struct {
	Cfg          [32]byte
	TrustBaseID  [32]byte
	PDR          []byte // canonical PartitionDescriptionRecord of the EVM shard configuration
	UC           []byte // canonical native UnicityCertificate
	Header       []byte // EVM header RLP
	AccountNodes [][]byte
	StorageNodes [][]byte
}

// Bytes is the exact canonical LockProof encoding.
func (p *LockProof) Bytes() []byte {
	nodes := func(ns [][]byte) []byte {
		items := make([][]byte, len(ns))
		for i, n := range ns {
			items[i] = CBytes(n)
		}
		return CArr(items...)
	}
	return CArr(CUint(LockProofVersion), CBytes(p.Cfg[:]), CBytes(p.TrustBaseID[:]), CBytes(p.PDR), CBytes(p.UC),
		CBytes(p.Header), nodes(p.AccountNodes), nodes(p.StorageNodes))
}

// decodeLockProof checks the exact arity, literal version and every
// component's bound before copying anything. Nothing here touches crypto.
func decodeLockProof(it *item) (*LockProof, error) {
	if !it.isArray(8) {
		return nil, ErrLockProofShape
	}
	k := it.kids
	if k[0].version(LockProofVersion) != nil {
		return nil, ErrLockProofShape
	}
	var p LockProof
	if fixed(&k[1], p.Cfg[:]) != nil || fixed(&k[2], p.TrustBaseID[:]) != nil {
		return nil, ErrLockProofShape
	}
	blob := func(it *item, max int) ([]byte, error) {
		if !it.isBytes() || len(it.data) == 0 {
			return nil, ErrLockProofShape
		}
		if len(it.data) > max {
			return nil, ErrLockProofTooLarge
		}
		return it.data, nil
	}
	var err error
	if p.PDR, err = blob(&k[3], MaxLockPDRBytes); err != nil {
		return nil, err
	}
	if p.UC, err = blob(&k[4], MaxLockUCBytes); err != nil {
		return nil, err
	}
	if p.Header, err = blob(&k[5], MaxLockHeaderBytes); err != nil {
		return nil, err
	}
	total := 0
	nodes := func(it *item) ([][]byte, error) {
		if it.major != majArray {
			return nil, ErrLockProofShape
		}
		if len(it.kids) == 0 {
			return nil, ErrLockProofShape
		}
		if len(it.kids) > MaxMPTNodes {
			return nil, ErrLockProofTooLarge
		}
		out := make([][]byte, len(it.kids))
		for i := range it.kids {
			n, err := blob(&it.kids[i], MaxMPTNodeBytes)
			if err != nil {
				return nil, err
			}
			if total += len(n); total > MaxMPTBytes {
				return nil, ErrLockProofTooLarge
			}
			out[i] = n
		}
		return out, nil
	}
	if p.AccountNodes, err = nodes(&k[6]); err != nil {
		return nil, err
	}
	if p.StorageNodes, err = nodes(&k[7]); err != nil {
		return nil, err
	}
	return &p, nil
}
