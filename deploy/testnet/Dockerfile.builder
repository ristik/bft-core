# Debian 12 builder for the TN-1 package images (OPERATOR.md section 3: the runtime ABI is bookworm's glibc)
FROM debian:bookworm-slim@sha256:7c7b2c966bc9ee8cedfeef67e0e279108992c77681fa595db4a9d65c06ccc587
RUN apt-get update && apt-get install -y --no-install-recommends build-essential clang libclang-dev pkg-config libssl-dev git curl jq python3 ca-certificates make xz-utils && rm -rf /var/lib/apt/lists/*
RUN curl -fsSL https://go.dev/dl/go1.27.1.linux-amd64.tar.gz | tar -C /usr/local -xz
ENV PATH=/usr/local/go/bin:/root/.cargo/bin:$PATH CARGO_HOME=/root/.cargo RUSTUP_HOME=/root/.rustup
RUN curl -fsSL https://sh.rustup.rs | sh -s -- -y --profile minimal --default-toolchain 1.97.1
COPY --from=docker:cli /usr/local/bin/docker /usr/local/bin/docker
