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
apt-get install -y --no-install-recommends ca-certificates curl openssl socat
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

install -d -m 0755 /opt/tests/tls
(
    umask 077
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
        -noenc -sha256 -days 3650 \
        -subj '/CN=Local forwarding test CA' \
        -addext 'basicConstraints=critical,CA:TRUE,pathlen:0' \
        -addext 'keyUsage=critical,keyCertSign,cRLSign' \
        -keyout /opt/tests/tls/ca.key -out /opt/tests/tls/ca.crt

    openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
        -noenc -sha256 -subj '/CN=tcp.test.openrussh' \
        -keyout /opt/tests/tls/server.key -out /opt/tests/tls/server.csr

    cat > /opt/tests/tls/server.ext <<'EOF'
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=serverAuth
subjectAltName=DNS:tcp.test.openrussh
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid,issuer
EOF

    openssl x509 -req -in /opt/tests/tls/server.csr \
        -CA /opt/tests/tls/ca.crt -CAkey /opt/tests/tls/ca.key \
        -set_serial 1 -sha256 -days 3650 \
        -extfile /opt/tests/tls/server.ext -out /opt/tests/tls/server.crt
)
chmod 0644 /opt/tests/tls/ca.crt /opt/tests/tls/server.crt
chown bob:bob /opt/tests/tls/server.key
rm /opt/tests/tls/ca.key /opt/tests/tls/server.csr /opt/tests/tls/server.ext

install -d -m 0755 /opt/tests/http-data
dd if=/dev/urandom of=/opt/tests/http-data/download bs=1024 count=256
chmod 0644 /opt/tests/http-data/download

cat > /opt/tests/Caddyfile <<'EOF'
{
    admin off
    auto_https disable_redirects
    servers 127.0.0.1:{$MY_TCP_SERVER_PORT_1} {
        protocols h1
    }
    servers 127.0.0.1:{$MY_TCP_SERVER_PORT_2} {
        protocols h2
    }
    log {
        level ERROR
    }
}

http://{$MY_TCP_SERVER}:{$MY_TCP_SERVER_PORT_1} {
    bind 127.0.0.1
    respond /test "Hello, HTTP/1.1"
}

https://{$MY_TCP_SERVER}:{$MY_TCP_SERVER_PORT_2} {
    bind 127.0.0.1
    tls /opt/tests/tls/server.crt /opt/tests/tls/server.key
    handle /test {
        respond "Hello, HTTP/2"
    }
    handle /download {
        root * /opt/tests/http-data
        file_server
    }
}
EOF

cat > /opt/tests/uds-server <<'EOF'
#!/bin/sh
set -eu

while IFS= read -r msg; do
    printf 'received: %s\n' "$msg"
done
EOF
chmod 0555 /opt/tests/uds-server
