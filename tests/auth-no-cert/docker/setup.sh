#!/bin/sh
set -eu

ssh-keygen -q -t ed25519 -N '' \
       -f /home/alice/.ssh/unknown_id
ssh-keygen -q -t ed25519 -N '' \
       -f /home/alice/.ssh/id_ed25519
install -m 0600 -o bob -g bob \
       /home/alice/.ssh/id_ed25519.pub \
       /home/bob/.ssh/authorized_keys
chown -R alice:alice /home/alice/.ssh
