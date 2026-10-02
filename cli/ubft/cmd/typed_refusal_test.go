package cmd

import (
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	abcrypto "github.com/unicitynetwork/bft-go-base/crypto"
	"github.com/unicitynetwork/bft-go-base/types"

	"github.com/unicitynetwork/bft-core/evmroot"
	"github.com/unicitynetwork/bft-core/handoff"
	"github.com/unicitynetwork/bft-core/handoffdelivery"
	"github.com/unicitynetwork/bft-core/network/protocol/abdrc"
	"github.com/unicitynetwork/bft-core/network/protocol/certification"
)

type bodyIDHistory struct {
	id  [32]byte
	err error
}

func (h bodyIDHistory) BodyID(uint64) ([32]byte, error) { return h.id, h.err }

// A wrong --trust-body-id after verified catch-up is an operator pin error with its own type, and a BodyID lookup failure keeps
// its cause; the message text is the one scripts may match.
func TestRestoreTrustBodyIDRefusalIsTyped(t *testing.T) {
	const message = "restore trust BodyID differs from verified current history"
	id := [32]byte{1, 2, 3}
	require.NoError(t, checkRestoreTrustBodyID(id[:], bodyIDHistory{id: id}, 7), "a matching pin is accepted")

	wrong := [32]byte{9}
	err := checkRestoreTrustBodyID(wrong[:], bodyIDHistory{id: id}, 7)
	require.ErrorIs(t, err, ErrTrustBodyIDMismatch)
	require.EqualError(t, err, message+": <nil>")

	errLookup := errors.New("no body for epoch 7")
	err = checkRestoreTrustBodyID(id[:], bodyIDHistory{id: id, err: errLookup}, 7)
	require.ErrorIs(t, err, ErrTrustBodyIDMismatch, "an unreadable BodyID is refused as the same class")
	require.ErrorIs(t, err, errLookup, "the lookup cause stays matchable")
	require.EqualError(t, err, message+": no body for epoch 7")
}

// Each way the verified handoff can fail to carry a terminal shard certificate consistent with the frozen parent is the same typed
// refusal. Every mutation is applied alone to a bundle that is accepted.
func TestHandoffTerminalCertificateRefusalIsTyped(t *testing.T) {
	frozen := []byte{0xf0, 0x0d}
	build := func() (handoffdelivery.Bundle, handoffdelivery.Verified) {
		bundle := handoffdelivery.Bundle{Proof: handoff.OldCommitProof{Control: evmroot.ControlState{FrozenParent: frozen}}}
		verified := handoffdelivery.Verified{Shard: abdrc.ShardInfo{
			UC: &types.UnicityCertificate{InputRecord: &types.InputRecord{BlockHash: frozen, RoundNumber: 12}},
			TR: &certification.TechnicalRecord{},
			IR: &types.InputRecord{BlockHash: frozen, RoundNumber: 12},
		}}
		return bundle, verified
	}
	bundle, verified := build()
	require.NoError(t, checkTerminalCertificate(bundle, verified), "the consistent bundle is accepted")

	for _, tc := range []struct {
		name   string
		mutate func(*handoffdelivery.Bundle, *handoffdelivery.Verified)
	}{
		{"no certificate", func(_ *handoffdelivery.Bundle, v *handoffdelivery.Verified) { v.Shard.UC = nil }},
		{"certificate without an input record", func(_ *handoffdelivery.Bundle, v *handoffdelivery.Verified) { v.Shard.UC.InputRecord = nil }},
		{"no technical record", func(_ *handoffdelivery.Bundle, v *handoffdelivery.Verified) { v.Shard.TR = nil }},
		{"no input record", func(_ *handoffdelivery.Bundle, v *handoffdelivery.Verified) { v.Shard.IR = nil }},
		{"input record not on the frozen parent", func(_ *handoffdelivery.Bundle, v *handoffdelivery.Verified) { v.Shard.IR.BlockHash = []byte{1} }},
		{"frozen parent differs", func(b *handoffdelivery.Bundle, _ *handoffdelivery.Verified) { b.Proof.Control.FrozenParent = []byte{2} }},
		{"certificate on another block", func(_ *handoffdelivery.Bundle, v *handoffdelivery.Verified) {
			v.Shard.UC.InputRecord.BlockHash = []byte{3}
		}},
		{"certificate of another round", func(_ *handoffdelivery.Bundle, v *handoffdelivery.Verified) { v.Shard.UC.InputRecord.RoundNumber = 13 }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			bundle, verified := build()
			tc.mutate(&bundle, &verified)
			err := checkTerminalCertificate(bundle, verified)
			require.ErrorIs(t, err, ErrHandoffTerminalCertificate)
			require.EqualError(t, err, "verified handoff lacks the terminal shard certificate")
		})
	}
}

// A genesis-named node whose configuration names its local key gets the joiner's typed refusal class, with the message it always had.
func TestGenesisNamedNodeWithLocalKeyRefusalIsTyped(t *testing.T) {
	home := t.TempDir()
	keyConf, err := (&keyConfFlags{KeyConfFile: filepath.Join(home, keyConfFileName)}).loadKeyConf(&baseFlags{}, true)
	require.NoError(t, err)
	nodeID, err := keyConf.NodeID()
	require.NoError(t, err)
	localKey, ok := localSigningKey(keyConf)
	require.True(t, ok)
	named := func(key []byte) *types.PartitionDescriptionRecord {
		return &types.PartitionDescriptionRecord{
			Version: 1, NetworkID: 5, PartitionID: 7, PartitionTypeID: 1, TypeIDLen: 8, UnitIDLen: 256,
			T2Timeout: 2500 * time.Millisecond, Validators: []*types.NodeInfo{{NodeID: nodeID.String(), SigKey: key, Stake: 1}},
		}
	}
	flags := &shardNodeSigningFlags{SigningAuthoritySocket: filepath.Join(home, "authority.sock"), SigningAuthorityCredential: filepath.Join(home, "client.cred")}

	_, err = buildCertificationSigning(flags, keyConf, named(localKey), false)
	require.ErrorIs(t, err, ErrGenesisLocalKey)
	require.ErrorIs(t, err, ErrJoinerLocalKey)
	require.EqualError(t, err, "the shard configuration names this node's local signing key from the key configuration, not a signing authority's key; "+
		"generate the configuration from `signing-authority node-info`")

	// Another key is not this refusal: it proceeds to the credential, which is absent here.
	other, err := abcrypto.NewInMemorySecp256K1Signer()
	require.NoError(t, err)
	verifier, err := other.Verifier()
	require.NoError(t, err)
	otherKey, err := verifier.MarshalPublicKey()
	require.NoError(t, err)
	_, err = buildCertificationSigning(flags, keyConf, named(otherKey), false)
	require.Error(t, err)
	require.NotErrorIs(t, err, ErrGenesisLocalKey)
	require.NotErrorIs(t, err, ErrJoinerLocalKey)
}
