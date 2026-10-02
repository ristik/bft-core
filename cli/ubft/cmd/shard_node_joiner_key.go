package cmd

import (
	"bytes"
	"crypto"
	"errors"
	"fmt"

	abcrypto "github.com/unicitynetwork/bft-go-base/crypto"

	"github.com/unicitynetwork/bft-core/handoff"
	"github.com/unicitynetwork/bft-core/handoffdelivery"
)

// ErrJoinerConf is an activated assignment configuration that is not the one installed for its shard epoch.
var ErrJoinerConf = errors.New("the activated assignment configuration is not the installed one")

// bindJoinerKey gives a restoring JOINER's signing authority its expected key, from the verified handoff history: the full shard
// configuration the verified bundle's assignment activates. Nothing is trusted that was not checked: the configuration is rebuilt from
// the bundle's candidate (which the root-certified successor body binds, so the bundle was verified before this is called), its hash
// must equal both the hash the verified step names for the new shard epoch and the hash INSTALLED for that epoch, and its epoch must be
// the step's. A configuration that does not name this node binds nothing (the node is not in that epoch's set); one that does binds the
// key it names for this node. A signer that is not deferred (a node the genesis configuration names) is left exactly as it is.
func bindJoinerKey(signing *certificationSigning, bundle handoffdelivery.Bundle, step handoff.AssignmentStep, installed func(epoch uint64) ([]byte, bool)) error {
	if signing == nil || signing.deferred == nil {
		return nil
	}
	conf, ok, err := handoffdelivery.AssignmentConf(bundle)
	if err != nil {
		return fmt.Errorf("reading the activated assignment: %w", err)
	}
	if !ok {
		return nil
	}
	hash, err := conf.Hash(crypto.SHA256)
	if err != nil {
		return fmt.Errorf("hashing the activated assignment: %w", err)
	}
	have, found := installed(conf.Epoch)
	if conf.Epoch != step.NewShardEpoch || !bytes.Equal(hash, step.NewActiveConfHash[:]) || !found || !bytes.Equal(hash, have) {
		return fmt.Errorf("%w: shard epoch %d", ErrJoinerConf, conf.Epoch)
	}
	for _, v := range conf.Validators {
		if v.NodeID != signing.nodeID {
			continue
		}
		key, err := abcrypto.NewVerifierSecp256k1(v.SigKey)
		if err != nil {
			return fmt.Errorf("the activated configuration's key for this node: %w", err)
		}
		return signing.deferred.BindKey(key)
	}
	return nil
}
