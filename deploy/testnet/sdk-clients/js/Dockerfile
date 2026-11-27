# The public JS SDK's trust-base acceptance client: the SDK fork at the pinned commit (pins.json), built from source, and client.mjs.
# docker build --build-arg SDK_REPO=... --build-arg SDK_COMMIT=... -f js/Dockerfile js
FROM node:22.23.4-bookworm-slim@sha256:de170b39439eb0e5a3444ad7d60b015614a381e10fecae2e30ec9e735122f38d
ARG SDK_REPO
ARG SDK_COMMIT
RUN apt-get update && apt-get install -y --no-install-recommends git ca-certificates && rm -rf /var/lib/apt/lists/*
RUN test -n "$SDK_REPO" && test -n "$SDK_COMMIT" \
 && git init -q /sdk && cd /sdk && git remote add origin "$SDK_REPO" && git fetch -q --depth 1 origin "$SDK_COMMIT" && git checkout -q --detach FETCH_HEAD \
 && test "$(git rev-parse HEAD)" = "$SDK_COMMIT" \
 && npm ci --ignore-scripts --no-audit --no-fund && npm run build
COPY client.mjs /client/client.mjs
ENV SDK_DIR=/sdk
ENV SDK_COMMIT=$SDK_COMMIT
USER 10001:10001
ENTRYPOINT ["node", "/client/client.mjs"]
