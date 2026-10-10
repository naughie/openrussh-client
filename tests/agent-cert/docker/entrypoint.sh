#!/bin/sh
set -eu

/usr/sbin/sshd -t
/usr/sbin/sshd -e

exec runuser -u alice -- /bin/sh -eu -c '
    _agent_pids=""
    for _kind in valid expired untrusted; do
        case "$_kind" in
            valid)
                _key="$HOME/.ssh/id_ed25519"
                _sock="$MY_AGENT_SOCK"
                ;;
            expired)
                _key="$HOME/.ssh/dummy/expired"
                _sock="$EXPIRED_AGENT_SOCK"
                cp "$HOME/.ssh/id_ed25519" "$_key"
                ;;
            untrusted)
                _key="$HOME/.ssh/dummy/untrusted"
                _sock="$UNTRUSTED_AGENT_SOCK"
                cp "$HOME/.ssh/id_ed25519" "$_key"
                ;;
        esac

        _agent_env=$(ssh-agent -s -a "$_sock")
        eval "$_agent_env" >/dev/null
        _agent_pids="$_agent_pids $SSH_AGENT_PID"
        trap "kill $_agent_pids" EXIT
        ssh-add -q -t 3600 "$_key"
        ssh-add -q -k -d "$_key"
        ssh-add -L >/dev/null
    done

    unset SSH_AUTH_SOCK SSH_AGENT_PID
    "$@"
' sh "$@"
