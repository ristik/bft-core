`custody-runtimes.json.gz` contains the deployed StakeCustody and CustodyGenesis
bytecode from `alloc.json` produced by `script/vr-pos-genesis.sh` at
unicity-pos-contracts `e2b995b273da2d11f0093118e2e8aa30ed9c2664` (#1297/#1298: the anchor
step and the report-window immutables). The two
JSON fields are `custody` and `writer`. Their hashes match the reviewed PoS16
genesis pins. The regression uses the authentic custody runtime because it
contains both the writer hash and unrelated protocol digests.
