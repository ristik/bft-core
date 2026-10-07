# TN-OPS local evidence, 2026-10-07

Host: macOS, Intel, 16 GiB physical RAM. Docker CLI and Compose v5.5.1 exist;
`docker info --format '{{.MemTotal}}'` failed:

```
Cannot connect to the Docker daemon at unix:///Users/risto/.colima/default/docker.sock.
```

No daemon was started or shared validator workload launched. Native genesis/key
validation used **N=3**, serialized by the workspace's `briefs/devnet-lock.sh`.

Commands from this PR checkout:

```sh
python3 -m unittest discover -s deploy/testnet -p test_package.py -v
python3 -m unittest discover -s deploy/testnet/faucet -v
python3 -m py_compile deploy/testnet/*.py
go build -o build/tn-keygen ./deploy/testnet/keygen
# ubft built with make build in a clean detached checkout at pins.json's BFT SHA
../briefs/devnet-lock.sh tnops-validation python3 deploy/testnet/validate-generation.py \
  --ubft /private/tmp/tnops-bft-source/build/ubft --keygen build/tn-keygen
```

Results: seven package tests and seven existing faucet tests pass. Two N=3 native
ceremonies generated different block-zero hashes and dedicated faucet addresses;
all root/shard key files were distinct and private, authority enrollment/session
issuance succeeded, genesis contained no known Hardhat funding, and generated
Compose configs validated. The transient socket-not-ready message in ceremony.log
is an expected startup retry; both ceremonies completed successfully.

**Offline fixture image IDs were used, not built/deployed images.** The native
ceremonies terminate their temporary in-memory authorities; their generated
configs are explicitly profiled as OFFLINE-VALIDATION-DO-NOT-START and discarded.
Real generation enrolls keys in the long-lived Docker authority containers and
never stops them. No authority key persistence/restore was added.

Not exercised locally: Linux binary/image packaging, container startup, external
client transfer through the deployed gateway, actual faucet dispense, validator
restart, quiesced live-authority restore, asset-losing deployed reset, real TLS,
hCaptcha, public host access, 24-hour observation or a second operator. Those
require the server/daemon rehearsal and independent review before #432/#434
acceptance. CI adds RPC image build and promtool validation; it does not establish
live paired-node certification. Earlier faucet native evidence remains in
faucet/evidence with its original pins and limits.

All committed evidence is public output; no generated private keys, keystores,
passwords, client/operator credentials or authority files are included.
