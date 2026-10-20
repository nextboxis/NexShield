# Multi-stage pure Rust build for NexShield v6.1
FROM rust:1.80-slim as builder

WORKDIR /usr/src/nexshield

# Copy Rust workspace definition and crates
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates

# Build optimized release binaries
RUN cargo build --release

# Final runtime image (pure native execution, zero Python runtime)
FROM debian:bookworm-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Copy compiled binaries from builder
COPY --from=builder /usr/src/nexshield/target/release/nexshield-cli /app/nexshield-cli
COPY --from=builder /usr/src/nexshield/target/release/nexshield-server /app/nexshield-server
COPY --from=builder /usr/src/nexshield/target/release/nexshield-scanner /app/nexshield-scanner

# Copy templates, static assets, and data directory
COPY templates ./templates
COPY static ./static
COPY data ./data

# Create non-root user
RUN useradd -m -u 1000 -s /bin/bash nexshield \
    && chown -R nexshield:nexshield /app

USER nexshield

EXPOSE 5000

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD curl -f http://127.0.0.1:5000/api/stats || exit 1

CMD ["/app/nexshield-cli", "run", "5000", "0.0.0.0"]
