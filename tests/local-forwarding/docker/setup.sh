#!/bin/sh
set -eu

ssh-keygen -q -t ed25519 -N '' \
       -f /home/alice/.ssh/id_ed25519
install -m 0600 -o bob -g bob \
       /home/alice/.ssh/id_ed25519.pub \
       /home/bob/.ssh/authorized_keys
rm /home/alice/.ssh/id_ed25519.pub
chown -R alice:alice /home/alice/.ssh

apt-get update
apt-get install -y --no-install-recommends ca-certificates curl socat
rm -rf /var/lib/apt/lists/*

version=2.11.7
arch="$(dpkg --print-architecture)"
case "$arch" in
    armhf) arch=armv7 ;;
    armel) arch=armv6 ;;
    i386) arch=386 ;;
    ppc64el) arch=ppc64le ;;
esac
curl -fsSL \
    "https://github.com/caddyserver/caddy/releases/download/v$version/caddy_${version}_linux_${arch}.tar.gz" \
    -o /tmp/caddy.tar.gz
tar -xzf /tmp/caddy.tar.gz -C /usr/local/bin caddy
chmod 0555 /usr/local/bin/caddy
rm /tmp/caddy.tar.gz

printf '%s\n' \
       '{' \
       '    admin off' \
       '    log {' \
       '        level ERROR' \
       '    }' \
       '}' \
       'http://{$MY_TCP_SERVER}:{$MY_TCP_SERVER_PORT} {' \
       '    bind 127.0.0.1' \
       '    respond /test "Hello, TCP"' \
       '}' \
       > /opt/tests/Caddyfile

cat > /opt/tests/uds-server <<'EOF'
#!/bin/sh
set -eu

while IFS= read -r msg; do
    printf 'received: %s\n' "$msg"
done
EOF
chmod 0555 /opt/tests/uds-server
