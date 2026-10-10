FROM rust:1-alpine AS toolchain

ENV OPENRUSSH_TEST_ID=process

ENV CARGO_HOME=/usr/local/cargo \
    RUSTUP_HOME=/usr/local/rustup \
    CARGO_TARGET_DIR=/cargo-target \
    PATH=/usr/local/cargo/bin:$PATH

WORKDIR /repo
COPY . .

RUN mkdir /dist \
    && cp ./tests/${OPENRUSSH_TEST_ID}/docker/entrypoint.sh /dist/entrypoint.sh

RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    --mount=type=cache,target=/cargo-target \
       cargo build --manifest-path ./tests/${OPENRUSSH_TEST_ID}/Cargo.toml \
    && cp /cargo-target/debug/test-${OPENRUSSH_TEST_ID} /dist/run-test


FROM debian:13.7-slim

ARG OPENSSH_VERSION=1:10.0p1-7+deb13u4

RUN rm -f /etc/apt/sources.list /etc/apt/sources.list.d/* \
    && printf '%s\n' \
       'deb [check-valid-until=no] http://snapshot.debian.org/archive/debian/20261005T000000Z/ trixie main' \
       'deb [check-valid-until=no] http://snapshot.debian.org/archive/debian-security/20261005T000000Z/ trixie-security main' \
       > /etc/apt/sources.list \
    && apt-get update \
    && apt-get install -y --no-install-recommends \
       "openssh-server=${OPENSSH_VERSION}" \
       ca-certificates \
    && rm -rf /var/lib/apt/lists/*

RUN groupadd -g 1001 bob \
    && useradd --create-home --shell /bin/sh bob -u 1001 -g 1001 \
    && passwd -d bob \
    && groupadd -g 1002 alice \
    && useradd --create-home --shell /bin/sh alice -u 1002 -g 1002

RUN install -d -m 0700 -o bob -g bob /home/bob/.ssh \
    && install -d -m 0700 -o alice -g alice /home/alice/.ssh \
    && ssh-keygen -q -t ed25519 -N '' \
       -f /home/alice/.ssh/id_ed25519 \
    && install -m 0600 -o bob -g bob \
       /home/alice/.ssh/id_ed25519.pub \
       /home/bob/.ssh/authorized_keys \
    && rm /home/alice/.ssh/id_ed25519.pub \
    && printf '%s\n' \
       'Host *' \
       '    HostName 127.0.0.1' \
       '    Port 2222' \
       '    User bob' \
       > /home/alice/.ssh/config \
    && chmod 0600 /home/alice/.ssh/config \
    && chown -R alice:alice /home/alice/.ssh

RUN rm -f /etc/ssh/ssh_host_* \
    && ssh-keygen -q -t ed25519 -N '' \
       -f /etc/ssh/ssh_host_ed25519_key \
    && { \
         printf '[127.0.0.1]:2222 '; \
         cat /etc/ssh/ssh_host_ed25519_key.pub; \
       } > /home/alice/.ssh/known_hosts \
    && ssh-keygen -H -f /home/alice/.ssh/known_hosts \
    && rm -f /home/alice/.ssh/known_hosts.old \
    && chmod 0600 /home/alice/.ssh/known_hosts \
    && chown alice:alice /home/alice/.ssh/known_hosts \
    && mkdir -p /run/sshd \
    && printf '%s\n' \
       'ListenAddress 127.0.0.1' \
       'Port 2222' \
       'HostKey /etc/ssh/ssh_host_ed25519_key' \
       'AllowUsers bob' \
       'PubkeyAuthentication yes' \
       'AuthenticationMethods publickey' \
       'AuthorizedKeysFile .ssh/authorized_keys' \
       'PasswordAuthentication no' \
       'KbdInteractiveAuthentication no' \
       'PermitEmptyPasswords no' \
       'PermitRootLogin no' \
       'UsePAM no' \
       'AllowTcpForwarding yes' \
       'AllowStreamLocalForwarding yes' \
       > /etc/ssh/sshd_config

COPY --chown=alice:alice --from=toolchain /dist/run-test /opt/tests/run-test
COPY --chown=alice:alice --from=toolchain /dist/entrypoint.sh /opt/tests/test-entrypoint
RUN chmod 0700 /opt/tests/test-entrypoint

ENTRYPOINT ["/opt/tests/test-entrypoint"]
CMD ["/opt/tests/run-test"]
