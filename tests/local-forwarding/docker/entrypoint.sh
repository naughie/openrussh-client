#!/bin/sh
set -eu

/usr/sbin/sshd -e

export MY_TCP_SERVER=tcp.test.openrussh
export MY_TCP_SERVER_PORT=8888
export MY_SOCKET="/opt/tests/bob/uds.test.openrussh.sock"

printf '127.0.0.1 %s\n' "$MY_TCP_SERVER" >> /etc/hosts
install -d -m 0755 -o bob -g bob "$(dirname "$MY_SOCKET")"

runuser -u bob -- caddy start --config /opt/tests/Caddyfile --adapter caddyfile >/dev/null
runuser -u bob -- socat \
    "UNIX-LISTEN:$MY_SOCKET,fork,mode=0600" EXEC:/opt/tests/uds-server &
uds_pid=$!

i=0
while [ ! -S "$MY_SOCKET" ]; do
    kill -0 "$uds_pid"
    if [ "$i" -ge 50 ]; then
        printf 'UDS server did not start\n' >&2
        exit 1
    fi
    sleep 0.1
    i=$((i + 1))
done

response="$(curl -fsS --noproxy '*' --max-time 5 \
    "http://$MY_TCP_SERVER:$MY_TCP_SERVER_PORT/test")"
test "$response" = 'Hello, TCP'

exec runuser -u alice -- "$@"
