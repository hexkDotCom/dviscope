# DVIScope images, built from the source tree (the release bundle has its own Dockerfile,
# built from its packaged binaries):
#   server  static musl binary and the web UI on an empty base, non-root (UID 10001),
#           meant to run with a read-only root file system (the default target)
#   ops     the same binary beside the PostgreSQL 17 client tools, for backup and restore
FROM rust:1.99.1-bookworm AS build
RUN apt-get update && apt-get install -y --no-install-recommends musl-tools && rm -rf /var/lib/apt/lists/*
RUN rustup target add x86_64-unknown-linux-musl
WORKDIR /src
COPY . .
RUN cargo build --release --locked --target x86_64-unknown-linux-musl -p dviscope-server

FROM node:24.11.0-bookworm-slim AS ui
WORKDIR /web
COPY web/package.json web/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY web/ ./
RUN npm run build

FROM postgres:17-bookworm AS ops
COPY --from=build /src/target/x86_64-unknown-linux-musl/release/dviscope-server /usr/local/bin/dviscope-server
USER 10001:10001
ENTRYPOINT ["/usr/local/bin/dviscope-server", "--config", "/etc/dviscope/dviscope-server.toml"]

FROM scratch AS server
COPY --from=build /src/target/x86_64-unknown-linux-musl/release/dviscope-server /dviscope-server
COPY --from=ui /web/dist /ui
ENV DVISCOPE_SERVER_UI_DIR=/ui
USER 10001:10001
EXPOSE 8443
ENTRYPOINT ["/dviscope-server", "--config", "/etc/dviscope/dviscope-server.toml"]
