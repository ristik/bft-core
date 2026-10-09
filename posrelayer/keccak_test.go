package posrelayer

import ethcrypto "github.com/ethereum/go-ethereum/crypto"

func evmassignKeccak(b []byte) []byte { return ethcrypto.Keccak256(b) }
