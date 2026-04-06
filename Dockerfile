# Multi-stage build for blossom-server
FROM rust:1.80-slim AS builder

RUN apt-get update && apt-get install -y pkg-config libssl-dev && rm -rf /var/lib/apt/lists/*

WORKDIR /build
COPY . .

RUN cargo build --release -p blossom-server

# Runtime image
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*

COPY --from=builder /build/target/release/blossom-server /usr/local/bin/blossom-server

RUN mkdir -p /data/blobs

ENV RUST_LOG=info

EXPOSE 3000

ENTRYPOINT ["blossom-server"]
CMD ["--bind", "0.0.0.0:3000", "--data-dir", "/data/blobs", "--db-path", "/data/blossom.db"]
