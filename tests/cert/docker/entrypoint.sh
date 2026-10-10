#!/bin/sh
set -eu

unset SSH_AUTH_SOCK

/usr/sbin/sshd -t
/usr/sbin/sshd -e

exec runuser -u bob -- "$@"
