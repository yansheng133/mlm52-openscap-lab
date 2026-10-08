#!/bin/bash
# Run as root on each RHEL client before registering it through the reverse tunnel.
# Usage: bash client-prep.sh <client-hostname> <mlm-fqdn>
set -euo pipefail
NAME=${1:?client hostname}; FQDN=${2:?MLM FQDN, must match the MLM TLS certificate CN/SAN}
hostnamectl set-hostname "$NAME"
# let the unprivileged SSH user bind the reverse-forwarded 443
echo 'net.ipv4.ip_unprivileged_port_start=443' > /etc/sysctl.d/90-mlm-tunnel.conf
sysctl -q -p /etc/sysctl.d/90-mlm-tunnel.conf
# Salt master name and TLS verification must use the MLM FQDN, which now lives on loopback
grep -q " $FQDN" /etc/hosts || echo "127.0.0.1 $FQDN" >> /etc/hosts
grep -q '^ClientAliveInterval' /etc/ssh/sshd_config || { echo 'ClientAliveInterval 30' >> /etc/ssh/sshd_config; systemctl reload sshd; }
echo "== $(hostname) $(cat /etc/redhat-release) kernel $(uname -r)"
sysctl net.ipv4.ip_unprivileged_port_start
dnf -q repolist
