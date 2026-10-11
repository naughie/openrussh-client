FROM rust:1-alpine AS toolchain

ENV OPENRUSSH_TEST_ID=proxy-jump

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

RUN groupadd -g 1002 alice \
    && useradd --create-home --shell /bin/sh alice -u 1002 -g 1002

RUN set -eu; \
    install -d -m 0700 -o alice -g alice /home/alice/.ssh; \
    rm -f /etc/ssh/ssh_host_*; \
    mkdir -p /run/sshd; \
    for i in 1 2 3; do \
        user=bob$i; \
        port=222$i; \
        identity=id_ed25519_bob$i; \
        forwarding=local; \
        if [ "$i" -eq 1 ]; then forwarding=no; fi; \
        id=$((1002 + i)); \
        groupadd -g "$id" "$user"; \
        useradd --create-home --shell /bin/sh "$user" -u "$id" -g "$id"; \
        passwd -d "$user"; \
        install -d -m 0700 -o "$user" -g "$user" "/home/$user/.ssh"; \
        ssh-keygen -q -t ed25519 -N '' -f "/home/alice/.ssh/$identity"; \
        install -m 0600 -o "$user" -g "$user" \
            "/home/alice/.ssh/$identity.pub" "/home/$user/.ssh/authorized_keys"; \
        rm "/home/alice/.ssh/$identity.pub"; \
        ssh-keygen -q -t ed25519 -N '' -f "/etc/ssh/ssh_host_${user}_key"; \
        { \
            printf '[127.0.0.1]:%s ' "$port"; \
            cat "/etc/ssh/ssh_host_${user}_key.pub"; \
        } >> /home/alice/.ssh/known_hosts; \
        { \
            printf '%s\n' \
                'ListenAddress 127.0.0.1' \
                "Port $port" \
                "HostKey /etc/ssh/ssh_host_${user}_key" \
                "PidFile /run/sshd/${user}.pid" \
                "AllowUsers $user" \
                'PubkeyAuthentication yes' \
                'AuthenticationMethods publickey' \
                'AuthorizedKeysFile .ssh/authorized_keys' \
                'PasswordAuthentication no' \
                'KbdInteractiveAuthentication no' \
                'PermitEmptyPasswords no' \
                'PermitRootLogin no' \
                'UsePAM no' \
                'AllowAgentForwarding no' \
                'AllowStreamLocalForwarding no' \
                "AllowTcpForwarding $forwarding" \
                'PermitOpen 127.0.0.1:2221 127.0.0.1:2222 127.0.0.1:2223 127.0.0.1:2224'; \
        } > "/etc/ssh/sshd_config_${user}"; \
    done; \
    ssh-keygen -H -f /home/alice/.ssh/known_hosts; \
    rm -f /home/alice/.ssh/known_hosts.old; \
    chmod 0600 /home/alice/.ssh/known_hosts; \
    chown -R alice:alice /home/alice/.ssh

RUN printf '%s\n' \
       'Host *' \
       '    HostName 127.0.0.1' \
       'Host bob1*' \
       '    Port 2221' \
       '    User bob1' \
       'Host bob2*' \
       '    Port 2222' \
       '    User bob2' \
       'Host bob3*' \
       '    Port 2223' \
       '    User bob3' \
       > /home/alice/.ssh/config \
    && chmod 0600 /home/alice/.ssh/config \
    && chown alice:alice /home/alice/.ssh/config

COPY --chown=alice:alice --from=toolchain /dist/run-test /opt/tests/run-test
COPY --chown=alice:alice --from=toolchain /dist/entrypoint.sh /opt/tests/test-entrypoint
RUN chmod 0700 /opt/tests/test-entrypoint

ENTRYPOINT ["/opt/tests/test-entrypoint"]
CMD ["/opt/tests/run-test"]
