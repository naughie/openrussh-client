#!/bin/sh
set -eu

bobs="1 2 3"

: > /home/alice/.ssh/known_hosts
for i in $bobs; do
    user=bob$i
    port=222$i
    identity=id_ed25519_bob$i
    forwarding=local
    if [ "$i" -eq 1 ]; then forwarding=no; fi
    id=$((1002 + i))
    groupadd -g "$id" "$user"
    useradd --create-home --shell /bin/sh "$user" -u "$id" -g "$id"
    passwd -d "$user"
    install -d -m 0700 -o "$user" -g "$user" "/home/$user/.ssh"
    ssh-keygen -q -t ed25519 -N '' -f "/home/alice/.ssh/$identity"
    install -m 0600 -o "$user" -g "$user" \
        "/home/alice/.ssh/$identity.pub" "/home/$user/.ssh/authorized_keys"
    rm "/home/alice/.ssh/$identity.pub"
    ssh-keygen -q -t ed25519 -N '' -f "/etc/ssh/ssh_host_${user}_key"
    {
        printf '[127.0.0.1]:%s ' "$port"
        cat "/etc/ssh/ssh_host_${user}_key.pub"
    } >> /home/alice/.ssh/known_hosts
    sed \
        -e "s/^AllowUsers .*/AllowUsers $user/" \
        -e "s|^HostKey .*|HostKey /etc/ssh/ssh_host_${user}_key|" \
        -e "s/^Port .*/Port $port/" \
        /etc/ssh/sshd_config > "/etc/ssh/sshd_config_${user}"
    printf '%s\n' \
        "AllowTcpForwarding $forwarding" \
        'PermitOpen 127.0.0.1:2221 127.0.0.1:2222 127.0.0.1:2223 127.0.0.1:2224' \
        "PidFile /run/sshd/${user}.pid" \
        >> "/etc/ssh/sshd_config_${user}"
done
ssh-keygen -H -f /home/alice/.ssh/known_hosts
rm -f /home/alice/.ssh/known_hosts.old
chmod 0600 /home/alice/.ssh/known_hosts
chown -R alice:alice /home/alice/.ssh

config="$(cat /home/alice/.ssh/config)"
{
    for i in $bobs; do
        printf '%s\n' \
            "Host bob$i*" \
            "    Port 222$i" \
            "    User bob$i"
    done
    printf '%s\n' "$config"
} > /home/alice/.ssh/config
