package executortest_test

import (
	"testing"

	"github.com/unicitynetwork/bft-core/shardnode"
	"github.com/unicitynetwork/bft-core/shardnode/executortest"
)

func TestFakeConformance(t *testing.T) {
	executortest.RunConformance(t, func(t *testing.T) shardnode.Executor {
		return executortest.New()
	})
}
