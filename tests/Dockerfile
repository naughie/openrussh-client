FROM rust:1-alpine AS toolchain

ARG OPENRUSSH_TEST_ID

ENV CARGO_HOME=/usr/local/cargo \
    RUSTUP_HOME=/usr/local/rustup \
    CARGO_TARGET_DIR=/cargo-target \
    PATH=/usr/local/cargo/bin:$PATH

WORKDIR /repo
COPY . .

RUN mkdir /dist \
    && cp ./tests/${OPENRUSSH_TEST_ID}/docker/entrypoint.sh /dist/entrypoint.sh \
    && cp ./tests/${OPENRUSSH_TEST_ID}/docker/setup.sh /dist/setup.sh

RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    --mount=type=cache,target=/cargo-target \
       cargo build --manifest-path ./tests/${OPENRUSSH_TEST_ID}/Cargo.toml \
    && cp /cargo-target/debug/test-${OPENRUSSH_TEST_ID} /dist/run-test


FROM debian:13.7-slim

ARG OPENSSH_VERSION
ARG APT_SNAPSHOT

RUN rm -f /etc/apt/sources.list /etc/apt/sources.list.d/* \
    && printf '%s\n' \
       "deb [check-valid-until=no] http://snapshot.debian.org/archive/debian/${APT_SNAPSHOT}/ trixie main" \
       "deb [check-valid-until=no] http://snapshot.debian.org/archive/debian-security/${APT_SNAPSHOT}/ trixie-security main" \
       > /etc/apt/sources.list \
    && apt-get update \
    && apt-get install -y --no-install-recommends \
       "openssh-server=${OPENSSH_VERSION}" \
       ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=toolchain /dist/setup.sh /opt/tests/setup.sh
RUN /bin/sh /opt/tests/setup.sh

COPY --chown=alice:alice --from=toolchain /dist/run-test /opt/tests/run-test
COPY --chown=alice:alice --from=toolchain /dist/entrypoint.sh /opt/tests/test-entrypoint
RUN chmod 0700 /opt/tests/test-entrypoint

ENTRYPOINT ["/opt/tests/test-entrypoint"]
CMD ["/opt/tests/run-test"]
