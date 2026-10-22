#!/bin/sh
set -eu

/usr/sbin/sshd -e

export MY_TCP_SERVER=tcp.test.openrussh
export MY_TCP_SERVER_PORT_1=8888
export MY_TCP_SERVER_PORT_2=8889
export MY_TCP_SERVER_CA_CERT=/opt/tests/tls/ca.crt
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

response="$(curl -fsS --http1.1 --noproxy '*' --max-time 5 \
    "http://$MY_TCP_SERVER:$MY_TCP_SERVER_PORT_1/test")"
test "$response" = 'Hello, HTTP/1.1'

response="$(curl -fsS --http2 --cacert "$MY_TCP_SERVER_CA_CERT" \
    --noproxy '*' --max-time 5 \
    "https://$MY_TCP_SERVER:$MY_TCP_SERVER_PORT_2/test")"
test "$response" = 'Hello, HTTP/2'

exec runuser -u alice -- "$@"
