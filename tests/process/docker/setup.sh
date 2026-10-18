#!/bin/sh
set -eu

groupadd -g 1001 bob
useradd --create-home --shell /bin/sh bob -u 1001 -g 1001
passwd -d bob
groupadd -g 1002 alice
useradd --create-home --shell /bin/sh alice -u 1002 -g 1002

install -d -m 0700 -o bob -g bob /home/bob/.ssh
install -d -m 0700 -o alice -g alice /home/alice/.ssh
ssh-keygen -q -t ed25519 -N '' \
       -f /home/alice/.ssh/id_ed25519
install -m 0600 -o bob -g bob \
       /home/alice/.ssh/id_ed25519.pub \
       /home/bob/.ssh/authorized_keys
rm /home/alice/.ssh/id_ed25519.pub
printf '%s\n' \
       'Host *' \
       '    HostName 127.0.0.1' \
       '    Port 2222' \
       '    User bob' \
       > /home/alice/.ssh/config
chmod 0600 /home/alice/.ssh/config
chown -R alice:alice /home/alice/.ssh

rm -f /etc/ssh/ssh_host_*
ssh-keygen -q -t ed25519 -N '' \
       -f /etc/ssh/ssh_host_ed25519_key
{
    printf '[127.0.0.1]:2222 '
    cat /etc/ssh/ssh_host_ed25519_key.pub
} > /home/alice/.ssh/known_hosts
ssh-keygen -H -f /home/alice/.ssh/known_hosts
rm -f /home/alice/.ssh/known_hosts.old
chmod 0600 /home/alice/.ssh/known_hosts
chown alice:alice /home/alice/.ssh/known_hosts
mkdir -p /run/sshd
printf '%s\n' \
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
       'PerSourcePenalties no' \
       'UsePAM no' \
       'AllowTcpForwarding yes' \
       'AllowStreamLocalForwarding yes' \
       > /etc/ssh/sshd_config
