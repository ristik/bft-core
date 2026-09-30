# M2 test hygiene round 2

This PR reduces the runtime of `archivewiring` and removes scheduler-sensitive timing flakes from the root consensus integration tests. It adds no skips and keeps the tested protocol paths and assertions enabled.

## Archive timing

Profiled with `go test -v -json ./archivewiring -count=1`:

| Measurement | Before | After |
| --- | ---: | ---: |
| Package elapsed | 506.112s | 42.041s |
| Wall time | 597.04s | 44.98s |
| `TestFrontierLongRunPastJournalCapsAndReplicaLoss` | 198.50s | 17.16s |

The long-run fixture still advances beyond both journal caps, prunes repeatedly, keeps unresolved observations pending, exercises replica loss, and reopens from storage. It now uses 34 blocks, 16 candidates, and 32 observations instead of 518, 256, and 512. Independent archive tests use `t.Parallel()` with isolated stores.

## Consensus timing flake

The pre-fix `go test -v -json ./rootchain/consensus -count=20` log showed failures in `Test_rootNetworkRunning`, `Test_ConsensusManager_messages/IR_change_request_forwarded_by_peer_included_in_proposal`, and four `Test_recoverState` scenarios. The integration cases started several live manager clusters with `t.Parallel()` and used short wall-clock waits. Under scheduler contention, those waits expired before the protocol progressed. The late-joiner scenario also counted its fourth manager before starting it and had no deferred shutdown if an earlier assertion failed.

The timing-based manager scenarios now run serially. `Test_rootNetworkRunning` allows the configured full round timeout plus startup grace and permits bounded scheduler delay in the average-round assertion. Message-delivery waits use bounded multiples of the round timeout. Both formerly unjoined manager loops are cancelled and joined. In the recovery matrix, the late-joiner count increments only when that manager starts, and deferred cleanup cancels and joins every started manager.

## Validation

- `go test ./... -count=1` passed with the default Go test timeout.
- `go test -v -json ./rootchain/consensus -count=20 -timeout=45m` passed all 20 package repetitions. No `Action:"fail"` entries were recorded.
- `go test -race -p 1 ./rootchain/consensus -run '^(Test_recoverState|Test_ConsensusManager_messages|Test_rootNetworkRunning)$' -count=1 -timeout=15m` passed in 63.122s.
- The post-change `archivewiring` profile passed in 42.041s package time.
