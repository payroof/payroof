# syntax=docker/dockerfile:1
# Build: a static, size-optimised musl binary (see [profile.release] in Cargo.toml).
FROM rust:1.99.1-alpine3.24@sha256:dc578ff3ca62ef489ad9ae743f477b94d98739c3092d0023490ecd417c2eebea AS builder
RUN apk add --no-cache build-base ca-certificates
WORKDIR /build
ENV CARGO_BUILD_JOBS=2
# The image already contains the pinned toolchain; rustfmt/clippy aren't needed here.
ENV RUSTUP_TOOLCHAIN=1.99.1
COPY Cargo.toml Cargo.lock ./
COPY migrations migrations
COPY src src
RUN --mount=type=cache,id=payroof-registry,target=/usr/local/cargo/registry \
    --mount=type=cache,id=payroof-musl,target=/build/target \
    cargo build --locked --release \
    && mkdir -p /out/data /out/tmp && chmod 1777 /out/tmp \
    && cp target/release/payroof /out/payroof \
    && ! readelf -l /out/payroof | grep -q INTERP

# Runtime: nothing but the binary, CA certificates and two writable directories.
FROM scratch
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=builder /out/payroof /usr/local/bin/payroof
COPY --from=builder --chown=10001:10001 /out/data /data
COPY --from=builder /out/tmp /tmp
ENV SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt
USER 10001:10001
WORKDIR /data
EXPOSE 8080
STOPSIGNAL SIGTERM
HEALTHCHECK --interval=10s --timeout=3s --start-period=30s --retries=6 \
    CMD ["/usr/local/bin/payroof", "healthcheck", "http://127.0.0.1:8080/readyz"]
ENTRYPOINT ["/usr/local/bin/payroof"]
CMD ["/etc/payroof/payroof.toml"]
