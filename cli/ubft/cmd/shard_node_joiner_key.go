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

// ErrJoinerUnnamed is a node the genesis configuration does not name, with no installed assignment step that does.
var ErrJoinerUnnamed = errors.New("no installed assignment step names this node: the genesis configuration does not, so there is no authority key to verify responses under")

// ErrJoinerLocalKey is an installed configuration that names this node with the key of its LOCAL key configuration, not a signing
// authority's key (the same guard as for a node the genesis configuration names).
var ErrJoinerLocalKey = errors.New("an installed configuration names this node's local signing key from the key configuration, not a signing authority's key")

// finishJoinerKey binds the joiner's expected key ONCE, after the verified installed steps have all been replayed (the persisted ones on
// a start, then the caught-up ones on a restore: the same point at which the archive peer hold is released), from the LATEST installed
// step that names this node. Binding as each step is replayed would bind the oldest key first and make a later rotation impossible.
// With no installed step naming the node it refuses (ErrJoinerUnnamed): the node is a validator of no epoch it knows. A signer that is
// not deferred is untouched.
func finishJoinerKey(signing *certificationSigning) error {
	if signing == nil || signing.deferred == nil {
		return nil
	}
	if signing.joinerKey == nil {
		return ErrJoinerUnnamed
	}
	return signing.deferred.BindKey(signing.joinerKey)
}

// ErrJoinerConf is an activated assignment configuration that is not the one installed for its shard epoch.
var ErrJoinerConf = errors.New("the activated assignment configuration is not the installed one")

// noteJoinerStep records, for a deferred signer, the key a VERIFIED assignment step gives this node, from the verified handoff history: the full shard
// configuration the verified bundle's assignment activates. Nothing is trusted that was not checked: the configuration is rebuilt from
// the bundle's candidate (which the root-certified successor body binds, so the bundle was verified before this is called), its hash
// must equal both the hash the verified step names for the new shard epoch and the hash INSTALLED for that epoch, and its epoch must be
// the step's. A configuration that does not name this node records nothing (the node is not in that epoch's set); one that does records
// the key it names for this node, replacing an earlier epoch's (steps arrive in epoch order, the latest wins), and finishJoinerKey binds
// it once the replay is complete. A signer that is not deferred (a node the genesis configuration names) is left exactly as it is.
func noteJoinerStep(signing *certificationSigning, bundle handoffdelivery.Bundle, step handoff.AssignmentStep, installed func(epoch uint64) ([]byte, bool)) error {
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
		if bytes.Equal(signing.localKey, v.SigKey) {
			return fmt.Errorf("%w: shard epoch %d", ErrJoinerLocalKey, conf.Epoch)
		}
		if signing.joinerKey == nil || conf.Epoch >= signing.joinerEpoch {
			signing.joinerKey, signing.joinerEpoch = key, conf.Epoch
		}
		return nil
	}
	return nil
}
