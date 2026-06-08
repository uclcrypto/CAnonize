FROM rust:1.85 AS builder

WORKDIR /app

# 1. Cache dependencies before copying source
COPY Cargo.toml Cargo.lock ./
RUN mkdir src benches \
    && echo "fn main() {}" > src/main.rs \
    && echo "fn main() {}" > benches/my_benchmark.rs
RUN cargo build --release && cargo test --no-run --release && cargo bench --no-run
RUN rm -f target/release/deps/anonymous_survey*

# 2. Build real source
COPY src ./src
COPY benches ./benches
RUN cargo build --release && cargo test --no-run --release && cargo bench --no-run

# ── Runtime ────────────────────────────────────────────────────
FROM rust:1.85-slim

WORKDIR /app

# 3. Install Python only in final image
RUN apt-get update && apt-get install -y \
    python3 \
    python3-pip \
    && pip3 install pandas --break-system-packages \
    && rm -rf /var/lib/apt/lists/*
# Cargo registry cache
COPY --from=builder /usr/local/cargo /usr/local/cargo

COPY --from=builder /app/target /app/target
COPY --from=builder /app/src ./src
COPY --from=builder /app/benches ./benches
COPY --from=builder /app/Cargo.toml /app/Cargo.lock ./
COPY bench.py bench.sh ./
RUN chmod +x bench.sh
COPY theo_size_time.py ./

CMD ["./anonymous_survey"]
