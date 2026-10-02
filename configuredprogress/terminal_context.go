package configuredprogress

import "bytes"

// TerminalContext is the Context under which the terminal shard certificate of a verified handoff is authenticated and recorded. That
// certificate belongs to the epoch the handoff ends, whose configuration is the one the verified snapshot carries, which after the first
// assignment change is not the genesis configuration.
//
// The store is bound to the deployment's genesis origin, so Observation.ShardConfHash stays the genesis pin (Context.check refuses any
// other value as another configured origin). What changes is the per-epoch configuration: the certificate must commit to exactly
// epochConf for shardEpoch, the epoch its technical record names, and any other epoch is rootinput.ErrConfEpochUnknown, never a fallback to
// another epoch's hash. The caller's context is not modified.
func TerminalContext(c Context, epochConf []byte, shardEpoch uint64) Context {
	conf := bytes.Clone(epochConf)
	c.Observation.ConfForEpoch = func(epoch uint64) ([]byte, bool) {
		if epoch != shardEpoch {
			return nil, false
		}
		return bytes.Clone(conf), true
	}
	return c
}
