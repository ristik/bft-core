package posrelayer

import "math/big"

type bigInt = big.Int

func toBig(v any) []*big.Int {
	l, _ := v.([]*big.Int)
	return l
}
