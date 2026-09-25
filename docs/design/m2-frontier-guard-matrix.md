# PR #264 fix 1: disabled-guard evidence

Each row was run separately against `frontier/frontier.go` with a temporary
literal replacement, using `go test ./frontier -run '^<test>$' -count=1`.
A nonzero exit means the named test failed. The source was restored after
every run, and `git diff --check` plus the normal focused test ran afterward.

| Guard at file:line | Exact temporary disabling edit (`old` → `new`) | Failing test |
| --- | --- | --- |
| `frontier/frontier.go:219` plan sequence | `next.Sequence <= current.Sequence` → `false` | `TestAdvanceIsolatedMonotonicAndCoverage/sequence` |
| `frontier/frontier.go:219` plan round | `next.Round <= current.Round` → `false` | `TestAdvanceIsolatedMonotonicAndCoverage/round` |
| `frontier/frontier.go:219` plan height | `next.Height <= current.Height` → `false` | `TestAdvanceIsolatedMonotonicAndCoverage/height` |
| `frontier/frontier.go:223` no coverage | `len(covered) == 0 && next.Height > current.Height` → `false` | `TestAdvanceIsolatedMonotonicAndCoverage/missing-all` |
| `frontier/frontier.go:187` trailing bytes | `if remaining != 0 {` → `if false {` | `TestCodecTrailingAndNoncanonical/trailing` |
| `frontier/frontier.go:194` canonical re-encode | `if !bytes.Equal(payload[len(domain)+1:len(payload)-remaining], again[len(domain)+1:len(again)-32]) {` → `if false {` | `TestCodecTrailingAndNoncanonical/noncanonical` |
| `frontier/frontier.go:91` distinct replicas | `p.Replicas[0] == p.Replicas[1]` → `false` | `TestConfiguredReplicasAndNames/duplicate` |
| `frontier/frontier.go:344` save sequence | `next.Sequence <= old.Sequence` → `false` | `TestStoreIsolatedRegressionsAndUnloadable/sequence` |
| `frontier/frontier.go:344` save round | `next.Round <= old.Round` → `false` | `TestStoreIsolatedRegressionsAndUnloadable/round` |
| `frontier/frontier.go:344` save height | `next.Height <= old.Height` → `false` | `TestStoreIsolatedRegressionsAndUnloadable/height` |
| `frontier/frontier.go:339` decode before replace | `if _, err := Decode(raw, p); err != nil {` → `if _, err := Decode(raw, p); false {` | `TestStoreIsolatedRegressionsAndUnloadable/unloadable` |
| `frontier/frontier.go:91` name over 64 | `len(p.Replicas[0]) > 64` → `false` | `TestConfiguredReplicasAndNames/65` |
| `frontier/frontier.go:91` empty name | `len(p.Replicas[0]) == 0` → `false` | `TestConfiguredReplicasAndNames/zero` |
| `frontier/frontier.go:236` real manifest digest | `digest != r.Acks[0].ManifestDigest || digest != r.Acks[1].ManifestDigest` → `false` | `TestAdvanceIsolatedMonotonicAndCoverage/manifest-binding` |
| `frontier/frontier.go:239` certified anchor | `p.Binding.VerifyCertified(r, item.Material) != nil` → `false` | `TestAdvanceIsolatedMonotonicAndCoverage/certified-binding` |
| `frontier/frontier.go:243` replica read-back | `p.Availability.VerifyAvailable(ack.Replica, r.Subject, digest) != nil` → `false` | `TestAdvanceIsolatedMonotonicAndCoverage/replica-readback` |

All 16 disabled guards produced a failing named test. This is an inert contract
mutation check. Runtime adapters, journal Bolt integration and kill evidence
remain child-PR requirements.
