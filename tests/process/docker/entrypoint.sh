#!/bin/sh
set -eu

/usr/sbin/sshd -t
/usr/sbin/sshd -e

exec runuser -u bob -- "$@"
