package vrstate

import (
	"context"
	"fmt"

	"github.com/unicitynetwork/bft-core/rootchain/evmstate"
	"github.com/unicitynetwork/bft-core/vrschema"
)

// ReadFees verifies the five VR fee slots against the certified parent state and the genesis-pinned contract.
func ReadFees(ctx context.Context, src evmstate.ProofSource, registry [20]byte, code, stateRoot [32]byte) (vrschema.Fees, error) {
	witness, err := evmstate.BuildAccounts(ctx, src, [][20]byte{registry}, func(accounts []evmstate.SlotReader) error {
		_, err := (Reader{W: accounts[0]}).Fees()
		return err
	})
	if err != nil {
		return vrschema.Fees{}, err
	}
	accounts, err := evmstate.VerifyAccounts(witness, stateRoot, registry)
	if err != nil {
		return vrschema.Fees{}, err
	}
	account := accounts[0]
	if account.CodeHash() != code {
		return vrschema.Fees{}, fmt.Errorf("%w: fee proof registry code hash", ErrState)
	}
	fees, err := (Reader{W: account}).Fees()
	if err != nil {
		return vrschema.Fees{}, err
	}
	return fees, account.Unused()
}
