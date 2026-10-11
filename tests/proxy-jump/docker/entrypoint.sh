#!/bin/sh
set -eu

for i in 1 2 3; do
    /usr/sbin/sshd -t -f "/etc/ssh/sshd_config_bob$i"
    /usr/sbin/sshd -e -f "/etc/ssh/sshd_config_bob$i"
done

exec runuser -u alice -- "$@"
