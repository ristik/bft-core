`custody-runtimes.json.gz` contains the deployed StakeCustody and CustodyGenesis
bytecode from `alloc.json` produced by `script/vr-pos-genesis.sh` at
unicity-pos-contracts `e36795ba144d56ca7d4cbc4b8a6854779b9a6bf3`. The two
JSON fields are `custody` and `writer`. Their hashes match the reviewed PoS16
genesis pins. The regression uses the authentic custody runtime because it
contains both the writer hash and unrelated protocol digests.
