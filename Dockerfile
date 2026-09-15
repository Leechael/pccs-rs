FROM public.ecr.aws/docker/library/rust:1-bookworm AS builder
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        clang \
        libclang-dev \
        llvm-dev \
        pkg-config \
        zlib1g-dev \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY src ./src
COPY packaging/config.toml ./packaging/config.toml
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    --mount=type=cache,target=/src/target \
    cargo build --release --locked --bin pccs-rs \
    && cp /src/target/release/pccs-rs /pccs-rs

FROM public.ecr.aws/docker/library/debian:bookworm-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        libstdc++6 \
        zlib1g \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --uid 10001 --home-dir /var/lib/pccs-rs \
        --create-home --shell /usr/sbin/nologin pccs \
    && mkdir -p /etc/pccs-rs
COPY --from=builder /pccs-rs /usr/bin/pccs-rs
COPY packaging/config.toml /etc/pccs-rs/config.toml
# Bind-mounts of /var/lib/pccs-rs must be writable by uid 10001.
USER 10001
WORKDIR /var/lib/pccs-rs
EXPOSE 8081
ENV PCCS_HOST=0.0.0.0 \
    PCCS_PORT=8081 \
    PCCS_DB_PATH=/var/lib/pccs-rs
ENTRYPOINT ["/usr/bin/pccs-rs"]
CMD ["serve"]
