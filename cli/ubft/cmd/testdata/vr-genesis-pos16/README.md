`custody-runtimes.json.gz` contains the deployed StakeCustody and CustodyGenesis
bytecode from `alloc.json` produced by `script/vr-pos-genesis.sh` at
unicity-pos-contracts `69f0e116e24aa7e19262d04c2890f2109dae3f7b` (#1319: the `RecordKind`
enum gains `PoPMissed`, which moves the runtime's enum range check; the writer is unchanged). The two
JSON fields are `custody` and `writer`. Their hashes match the reviewed PoS16
genesis pins. The regression uses the authentic custody runtime because it
contains both the writer hash and unrelated protocol digests.
