FROM rust:1.89-slim as builder
WORKDIR /usr/src/axum-seaorm-demo
COPY . .
RUN cargo install --path .

# Use the same base image instead of bullseye
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y \
    libssl-dev \
    libpq-dev \
    ca-certificates \
 && rm -rf /var/lib/apt/lists/*

COPY --from=builder /usr/local/cargo/bin/axum-seaorm-demo /usr/local/bin/axum-seaorm-demo
CMD ["axum-seaorm-demo"]