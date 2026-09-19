package cmd

import (
	"context"
	"errors"
	"fmt"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/unicitynetwork/bft-go-base/types"

	"github.com/unicitynetwork/bft-core/recordwiring"
	"github.com/unicitynetwork/bft-core/shardnode"
)

const (
	defaultCertifiedRecordRetain      = 64
	recordwiringDefaultAcquireTimeout = recordwiring.DefaultAcquireTimeout
)

/*
startCertifiedRecord is the certified-block record (#14) at startup, reached only when --certified-record-store
is set. It checks the deployment configuration once, opens the store (syncing its directory), reloads and
re-verifies the head record and compares it with the executor, and reports the outcome in health and the log
(W1). It then starts witness capture and publication for every block the round commits (W2).

A configuration that cannot be checked, or a store that cannot be opened, stops startup: the operator asked
for a record store, and running without one would look the same from outside. A reload outcome other than
durable-ready does not stop startup and changes no vote, and neither does any capture outcome; readiness for
a recorded block's child is W3. The returned function stops capture and then closes the store.
*/
func startCertifiedRecord(ctx context.Context, flags *shardNodeRunFlags, shardConf *types.PartitionDescriptionRecord,
	confHash []byte, trustBases shardnode.TrustBaseStore, rootEpoch uint64, executor shardnode.Executor, node *shardnode.Node) (func(), error) {
	if flags.Executor != "engine-api" {
		return nil, fmt.Errorf("--certified-record-store needs --executor engine-api: the record holds SealRegistry witnesses, which only an execution client with the registry produces")
	}
	evm, err := registryEVMParams(flags)
	if err != nil {
		return nil, err
	}
	var expected []byte
	if flags.ExpectedGenesisHash != "" {
		h, err := hexToHash(flags.ExpectedGenesisHash)
		if err != nil {
			return nil, fmt.Errorf("parsing --expected-genesis-hash: %w", err)
		}
		expected = h
	}
	deployment, err := recordwiring.NewDeployment(ctx, recordwiring.DeploymentConfig{
		Shard: shardConf, ShardConfHash: confHash, TrustBases: trustBases, RootEpoch: rootEpoch,
		EVM: evm, ExpectedGenesisHash: expected,
	}, executor)
	if err != nil {
		return nil, fmt.Errorf("checking the certified-record deployment: %w", err)
	}
	store, err := recordwiring.OpenStore(flags.CertifiedRecordStore, flags.CertifiedRecordRetain)
	if err != nil {
		return nil, fmt.Errorf("opening the certified-record store %q: %w", flags.CertifiedRecordStore, err)
	}
	log := flags.observe.Logger()

	res := recordwiring.Reload(ctx, store, deployment, executor)
	detail := ""
	if res.Err != nil {
		detail = res.Err.Error()
	}
	node.SetCertifiedRecordStatus(res.Outcome.String(), detail)
	if res.Outcome == recordwiring.OutcomeDurableReady {
		log.Info("certified record reloaded: durable-ready for the recorded block; readiness for its child is not decided at startup and voting is unchanged",
			"outcome", res.Outcome.String(), "block", res.Record.BlockNumber(), "hash", res.Record.BlockHash().String())
	} else {
		log.Warn("certified record reload did not establish durable readiness; voting is unchanged",
			"outcome", res.Outcome.String(), "err", detail)
	}

	// THE RECORD GATE (#14 W3b-1), behind its own flag. It needs the same durable record the store
	// holds and the certificate/technical-record history the round observes, so it is built here from
	// the checked deployment and attached before the node runs. Without the flag nothing is attached
	// and the node behaves exactly as W3a did: it reloads, reports, captures and publishes, and no vote
	// changes.
	if flags.CertifiedRecordGate {
		observed, err := recordwiring.NewObservations(recordwiring.DefaultObservationLimits)
		if err != nil {
			_ = store.Close()
			return nil, fmt.Errorf("preparing certified-record readiness observations: %w", err)
		}
		readiness, err := recordwiring.NewReadiness(deployment, store, executor, observed)
		if err != nil {
			_ = store.Close()
			return nil, fmt.Errorf("preparing the certified-record readiness gate: %w", err)
		}
		installCertifiedRecordGate(node, recordwiring.NewChildReadiness(readiness), recordwiring.NewCertificateObserver(observed))
		log.Info("certified-record gate enabled: leadership and signatures are withheld until the record proves readiness for the held certificate's child (#14 W3b-1)")
	}

	capturer, err := recordwiring.NewCapturer(recordwiring.CaptureConfig{
		Deployment: deployment, Store: store, Executor: executor, Finality: node.FinalityGate(), Log: log,
		RPC:            recordwiring.HTTPWitnessCaller(flags.EthURL, flags.CertifiedRecordCaptureTimeout),
		AcquireTimeout: flags.CertifiedRecordCaptureTimeout,
	})
	if err != nil {
		_ = store.Close()
		return nil, fmt.Errorf("starting certified-record capture: %w", err)
	}
	node.SetCommitObserver(capturer)
	captureCtx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = capturer.Run(captureCtx)
	}()
	return func() {
		cancel()
		<-done
		_ = store.Close()
	}, nil
}

// validateCertifiedRecordFlags refuses the one configuration in which the record gate would run with
// nothing to read. It is checked at the top of shard-node run so the operator sees their own mistake
// rather than a node that silently cannot prove readiness.
func validateCertifiedRecordFlags(store string, gate bool) error {
	if gate && store == "" {
		return ErrCertifiedRecordGateNeedsStore
	}
	return nil
}

// ErrCertifiedRecordGateNeedsStore is the named refusal for --certified-record-gate without
// --certified-record-store.
var ErrCertifiedRecordGateNeedsStore = errors.New("--certified-record-gate requires --certified-record-store: the readiness gate reads the durable record")

// readinessHookTarget is the pair of Node setters the record gate uses. It exists so the wiring can
// be exercised without constructing a whole node, and so the two setters are always installed
// together: a readiness gate without the observer that feeds it could never become ready.
type readinessHookTarget interface {
	SetChildReadiness(shardnode.ChildReadiness)
	SetCertificateObserver(shardnode.CertificateObserver)
}

func installCertifiedRecordGate(target readinessHookTarget, readiness shardnode.ChildReadiness, observer shardnode.CertificateObserver) {
	target.SetChildReadiness(readiness)
	target.SetCertificateObserver(observer)
}

// registryEVMParams are the EVM genesis parameters the SealRegistry deployment was generated with.
func registryEVMParams(flags *shardNodeRunFlags) (recordwiring.EVMParams, error) {
	evm := recordwiring.DefaultEVMParams
	evm.GasLimit = flags.RegistryEVMGasLimit
	if !common.IsHexAddress(flags.RegistryEVMCoinbase) {
		return evm, fmt.Errorf("--registry-evm-coinbase %q is not an address", flags.RegistryEVMCoinbase)
	}
	evm.Coinbase = common.HexToAddress(flags.RegistryEVMCoinbase)
	extra, err := hexutil.Decode(flags.RegistryEVMExtraData)
	if err != nil {
		return evm, fmt.Errorf("--registry-evm-extra-data: %w", err)
	}
	evm.ExtraData = extra
	return evm, nil
}
