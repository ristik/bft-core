
### External companion replay and release gate

`TestExternalSealedCorpus` verifies and replays the checked-in offline cache from
an exact native-bridge-plugins commit, then compares every generated data file
with that independently imported snapshot. Refresh it with
`python3 tools/import-bridge-corpus.py CHECKOUT COMMIT SEALED_DIGEST` after the
companion import is committed. The import reads git objects at COMMIT, never
working-tree files, and verifies the complete sealed manifest before replacing
the cache. Normal tests and CI need no network for this replay.

The source commit named by seal provenance generates the corpus. A later
cache/pin-only commit can import the resulting companion snapshot without
resealing or changing that source identity. Both repositories are public;
companion CI regenerates from that source anonymously.

The current snapshot is a sealed candidate from open PR1, not a merged release.
`BRIDGEPROFILE_REQUIRE_MERGED_CORPUS=1 go test ./bridgeprofile -run TestExternalSealedCorpus`
is the explicit release gate and remains closed until the companion snapshot is
merged and its pin status is updated with merge evidence. No PR merge is implied
by successful candidate replay.
