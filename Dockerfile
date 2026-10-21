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

# bookworm-slim, pinned by index digest. Bump the digest to pick up new base
# layers; apt-get below still pulls the current bookworm(-security) packages.
FROM public.ecr.aws/docker/library/debian:bookworm-slim@sha256:7ff6ba31527b9e336162fa061746c366c4b2032f4d2cff2078bea43f78efe3f8
# The upstream PCS client trusts the system store (rustls-native-certs).
# ca-certificates 20250419~deb12u2 drops the emSign ECC Root CA - G3 and Comodo
# AAA roots behind the compromised eMudhra intermediates (CVE-2026-111943).
# Fail the build if an older package or either root is present.
ARG CA_CERTIFICATES_MIN_VERSION=20250419~deb12u2
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        libstdc++6 \
        zlib1g \
    && rm -rf /var/lib/apt/lists/* \
    && ca_version="$(dpkg-query -W -f='${Version}' ca-certificates)" \
    && if ! dpkg --compare-versions "$ca_version" ge "$CA_CERTIFICATES_MIN_VERSION"; then \
        echo "ca-certificates $ca_version < $CA_CERTIFICATES_MIN_VERSION" >&2; exit 1; \
    fi \
    && if ls /etc/ssl/certs /usr/share/ca-certificates/mozilla \
        | grep -E -i 'emSign_ECC_Root_CA_-_G3|AAA_Services_root|AAA_Certificate_Services'; then \
        echo "distrusted root present in the system trust store" >&2; exit 1; \
    fi \
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
CMD ["serve", "--no-seed"]
