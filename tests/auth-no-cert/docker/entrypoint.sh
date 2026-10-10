#!/bin/sh
set -eu

/usr/sbin/sshd -t
/usr/sbin/sshd -e

exec runuser -u bob -- ssh-agent -a "$MY_AGENT_SOCK" /bin/sh -eu -c '
    mkdir -p "$HOME/.ssh/dummy"
    chmod 0700 "$HOME/.ssh/dummy"
    _i=1
    while [ "$_i" -le 32 ]; do
        _key="$HOME/.ssh/dummy/key_$_i"
        ssh-keygen -q -t ed25519 -N "" -f "$_key"
        ssh-add "$_key" >/dev/null 2>&1
        _i=$((_i + 1))
    done

    ssh-add "$HOME/.ssh/unknown_id" >/dev/null 2>&1
    ssh-add "$HOME/.ssh/id_ed25519" >/dev/null 2>&1
    exec "$@"
' sh "$@"
