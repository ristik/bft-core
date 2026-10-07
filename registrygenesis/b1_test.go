package registrygenesis_test

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/b1state"
	"github.com/unicitynetwork/bft-core/internal/testutils/b1fixture"
	"github.com/unicitynetwork/bft-core/internal/testutils/certifiedchain"
	"github.com/unicitynetwork/bft-core/registrygenesis"
	"github.com/unicitynetwork/bft-core/registryproof"
	"github.com/unicitynetwork/bft-go-base/types"
)

func TestB1GenesisBindsRootProfileAndAllStorageWords(t *testing.T) {
	f := b1fixture.New(t, 15)
	p := f.Pair.Profile
	words := f.Genesis.B1Words()
	require.Equal(t, common.Hash(b1state.Word(1)), words[common.Hash(b1state.FixedSlot("b1.initialized"))])
	require.Equal(t, common.Hash(b1state.Word(1)), words[common.Hash(b1state.QueueSlot(0))])
	names, err := registryproof.SlotNamesFor(registryproof.FreshB1)
	require.NoError(t, err)
	keys := make([]common.Hash, len(names))
	for i, name := range names {
		keys[i] = common.Hash(b1state.FixedSlot(name))
		require.Contains(t, words, keys[i])
	}
	proven, err := f.Parent.VerifyWords(keys, f.Genesis.B1Proofs(keys))
	require.NoError(t, err)
	for i, key := range keys {
		require.Equal(t, words[key], proven[i])
	}
	require.NotContains(t, words, common.Hash(b1state.FixedSlot("layoutVersion")))
	require.Equal(t, common.Hash(p.RootGenesisID), f.Genesis.Record().RootGenesisID)
	var recordFields []any
	require.NoError(t, types.Cbor.Unmarshal(f.Genesis.RecordCBOR(), &recordFields))
	require.Len(t, recordFields, 13)
	require.Equal(t, p.RootGenesisID[:], recordFields[11])
	profileHash, err := p.Hash()
	require.NoError(t, err)
	require.Equal(t, common.Hash(profileHash), f.Genesis.Record().B1ProfileHash)
	require.Equal(t, profileHash[:], recordFields[12])
	changed := p
	changed.WCert--
	other, err := registrygenesis.GenerateB1(certifiedchain.Config(5), changed, f.History, registrygenesis.EVMParams{GasLimit: changed.MaxGas, BaseFee: registrygenesis.DefaultEVMParams.BaseFee})
	require.NoError(t, err)
	require.NotEqual(t, f.Genesis.GenesisCommitment(), other.GenesisCommitment())
	full, err := f.Genesis.FullConfig()
	require.NoError(t, err)
	for _, tc := range []struct {
		name   string
		mutate func(map[string]json.RawMessage)
	}{
		{"gas", func(d map[string]json.RawMessage) { d["gasLimit"] = json.RawMessage(`"0x1"`) }},
		{"root-key", func(d map[string]json.RawMessage) {
			var alloc map[string]map[string]json.RawMessage
			require.NoError(t, json.Unmarshal(d["alloc"], &alloc))
			for address, a := range alloc {
				var s map[string]string
				require.NoError(t, json.Unmarshal(a["storage"], &s))
				s[common.Hash(b1state.MemberSlot(1, 0, 5)).Hex()] = common.Hash{9}.Hex()
				a["storage"], _ = json.Marshal(s)
				alloc[address] = a
			}
			d["alloc"], _ = json.Marshal(alloc)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var d map[string]json.RawMessage
			require.NoError(t, json.Unmarshal(f.Genesis.GenesisJSON(), &d))
			tc.mutate(d)
			raw, err := json.Marshal(d)
			require.NoError(t, err)
			_, err = registrygenesis.B1Origin(full, p, f.History, raw, nil, registrygenesis.GenesisJSONLimits{})
			if tc.name == "gas" {
				require.ErrorIs(t, err, registrygenesis.ErrEVMParams)
			} else {
				require.ErrorIs(t, err, registrygenesis.ErrReservedAccount)
			}
		})
	}
	_, err = registrygenesis.B1Origin(nil, p, f.History, f.Genesis.GenesisJSON(), nil, registrygenesis.GenesisJSONLimits{})
	require.ErrorIs(t, err, registrygenesis.ErrContextMismatch)
	bad := p
	bad.RootGenesisID[0] ^= 1
	_, err = registrygenesis.GenerateB1(certifiedchain.Config(5), bad, f.History, registrygenesis.EVMParams{GasLimit: bad.MaxGas})
	require.ErrorIs(t, err, registrygenesis.ErrContextMismatch)
	bad = p
	bad.ExecutionChainID++
	_, err = registrygenesis.GenerateB1(certifiedchain.Config(5), bad, f.History, registrygenesis.EVMParams{GasLimit: bad.MaxGas})
	require.ErrorIs(t, err, registrygenesis.ErrChainIDMismatch)
	again, err := registrygenesis.GenerateB1(certifiedchain.Config(5), p, f.History, registrygenesis.EVMParams{GasLimit: p.MaxGas, BaseFee: registrygenesis.DefaultEVMParams.BaseFee})
	require.NoError(t, err)
	require.True(t, bytes.Equal(f.Genesis.GenesisJSON(), again.GenesisJSON()))
	_, err = registrygenesis.PinnedArtifactForLayout(registryproof.FreshB1)
	require.ErrorIs(t, err, registrygenesis.ErrArtifact)
}
