# syntax=docker/dockerfile:1
FROM debian:bookworm-slim@sha256:7c7b2c966bc9ee8cedfeef67e0e279108992c77681fa595db4a9d65c06ccc587
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates libstdc++6 libssl3 python3 jq \
    && find /var/lib/apt/lists -type f -delete \
    && install -d -m 0700 -o 10001 -g 10001 /data
COPY --chmod=755 ubft unicity-reth cast handoff-ubft /usr/local/bin/
COPY --chmod=755 validator.py /usr/local/bin/ubft-validator
COPY release-lock.json validator_rpc.py gateway.py public_relay.py /opt/validator/
COPY faucet/gateway.py /opt/validator/faucet/
USER 10001:10001
WORKDIR /data
ENTRYPOINT ["/usr/local/bin/ubft-validator"]
