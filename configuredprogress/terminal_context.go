package configuredprogress

import (
	"bytes"
	"errors"
	"fmt"
)

// ErrTerminalConfConflict refuses a terminal context whose verified configuration for a shard epoch differs from the one the node's
// installed set already holds for that epoch. The verified snapshot is never allowed to silently override an installed configuration.
var ErrTerminalConfConflict = errors.New("configuredprogress: the installed shard configuration for the terminal certificate's epoch differs from the verified snapshot's")

// TerminalContext is the Context under which the terminal shard certificate of a verified handoff is authenticated and recorded. That
// certificate belongs to the epoch the handoff ends, whose configuration is the one the verified snapshot carries, which after the first
// assignment change is not the genesis configuration.
//
// The store is bound to the deployment's genesis origin, so Observation.ShardConfHash stays the genesis pin (Context.check refuses any
// other value as another configured origin). What changes is the per-epoch resolver. The same context also re-verifies the durable state
// the store already holds, whose certificates sit at other shard epochs, so the resolver only adds one entry to the node's installed set:
//   - shardEpoch, the epoch the terminal certificate's technical record names, resolves to epochConf, the verified snapshot's
//     configuration;
//   - every other epoch is answered by the installed set the caller's context already carries (its own installed hash for its own epoch,
//     never another epoch's), so an epoch with nothing installed is still rootinput.ErrConfEpochUnknown.
//
// If the installed set already holds shardEpoch with a different hash the context is refused with ErrTerminalConfConflict: a verified
// snapshot does not override an installed configuration. A caller's context with no installed set resolves only shardEpoch. The caller's
// context is not modified.
func TerminalContext(c Context, epochConf []byte, shardEpoch uint64) (Context, error) {
	conf := bytes.Clone(epochConf)
	installed := c.Observation.ConfForEpoch
	if installed != nil {
		if have, ok := installed(shardEpoch); ok && !bytes.Equal(have, conf) {
			return Context{}, fmt.Errorf("%w: shard epoch %d", ErrTerminalConfConflict, shardEpoch)
		}
	}
	c.Observation.ConfForEpoch = func(epoch uint64) ([]byte, bool) {
		if epoch == shardEpoch {
			return bytes.Clone(conf), true
		}
		if installed == nil {
			return nil, false
		}
		return installed(epoch)
	}
	return c, nil
}
