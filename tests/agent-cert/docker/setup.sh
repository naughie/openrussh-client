#!/bin/sh
set -eu

ssh-keygen -q -t ed25519 -N '' \
       -f /etc/ssh/test_ca
ssh-keygen -q -t ed25519 -N '' \
       -f /home/alice/.ssh/id_ed25519
ssh-keygen -q -s /etc/ssh/test_ca -I alice -n bob \
       -V -1m:+52w /home/alice/.ssh/id_ed25519.pub
install -d -m 0700 -o alice -g alice /home/alice/.ssh/dummy
cp /home/alice/.ssh/id_ed25519.pub /home/alice/.ssh/dummy/expired.pub
ssh-keygen -q -s /etc/ssh/test_ca -I expired -n bob \
       -V -2d:-1d /home/alice/.ssh/dummy/expired.pub
ssh-keygen -q -t ed25519 -N '' -f /etc/ssh/untrusted_ca
cp /home/alice/.ssh/id_ed25519.pub /home/alice/.ssh/dummy/untrusted.pub
ssh-keygen -q -s /etc/ssh/untrusted_ca -I untrusted -n bob \
       -V -1m:+52w /home/alice/.ssh/dummy/untrusted.pub
cp /etc/ssh/untrusted_ca.pub /home/alice/.ssh/dummy/mismatched.pub
ssh-keygen -q -s /etc/ssh/untrusted_ca -I mismatched -n bob \
       -V -1m:+52w /home/alice/.ssh/dummy/mismatched.pub
rm /etc/ssh/untrusted_ca /etc/ssh/untrusted_ca.pub
rm /home/alice/.ssh/dummy/expired.pub \
       /home/alice/.ssh/dummy/untrusted.pub \
       /home/alice/.ssh/dummy/mismatched.pub
rm /etc/ssh/test_ca
chown -R alice:alice /home/alice/.ssh

sed -i 's/^AuthorizedKeysFile .*/AuthorizedKeysFile none/' /etc/ssh/sshd_config
printf '%s\n' \
       'PubkeyAcceptedAlgorithms ssh-ed25519-cert-v01@openssh.com' \
       'TrustedUserCAKeys /etc/ssh/test_ca.pub' \
       >> /etc/ssh/sshd_config
