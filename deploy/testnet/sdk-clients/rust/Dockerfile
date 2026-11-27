# The public Rust SDK's trust-base acceptance client: the SDK fork at the pinned commit (pins.json) as a path dependency, built from source with the SDK's own Cargo.lock.
# docker build --build-arg SDK_REPO=... --build-arg SDK_COMMIT=... -f rust/Dockerfile rust
FROM rust:1.90-bookworm@sha256:3914072ca0c3b8aad871db9169a651ccfce30cf58303e5d6f2db16d1d8a7e58f
ARG SDK_REPO
ARG SDK_COMMIT
RUN test -n "$SDK_REPO" && test -n "$SDK_COMMIT" \
 && git init -q /work/sdk && cd /work/sdk && git remote add origin "$SDK_REPO" && git fetch -q --depth 1 origin "$SDK_COMMIT" && git checkout -q --detach FETCH_HEAD \
 && test "$(git rev-parse HEAD)" = "$SDK_COMMIT"
COPY Cargo.toml /work/client/Cargo.toml
COPY src /work/client/src
RUN cp /work/sdk/Cargo.lock /work/client/Cargo.lock && cd /work/client && cargo build --release \
 && install -m 0755 target/release/sdk-trustbase-client /usr/local/bin/sdk-trustbase-client && rm -rf /work/client/target /usr/local/cargo/registry
ENV SDK_COMMIT=$SDK_COMMIT
USER 10001:10001
ENTRYPOINT ["/usr/local/bin/sdk-trustbase-client"]
