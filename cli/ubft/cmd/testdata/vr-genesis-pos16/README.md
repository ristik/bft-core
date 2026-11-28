`custody-runtimes.json.gz` contains the deployed StakeCustody and CustodyGenesis
bytecode from `../vr-genesis-pos/alloc.json`, produced by `script/vr-pos-genesis.sh`
at unicity-pos-contracts `1df61d193c01483853e360979512123ebdfb4523` (PR #111).
The two JSON fields are `custody` and `writer`. Their hashes match the PoS16
genesis pins. The regression uses the authentic custody runtime because it
contains both the writer hash and unrelated protocol digests.
