#!/bin/bash
# Reverse SSH tunnel: workstation -> cloud client.
# On the client, 127.0.0.1:{4505,4506,443} are forwarded back to the MLM server,
# so a Salt (ZeroMQ) minion in the cloud can reach an MLM server that is only
# reachable from the workstation. Nothing on the MLM side is exposed.
#
# Usage:  MLM_IP=192.0.2.10 SSH_KEY=~/.ssh/lab-key caffeinate -i bash tunnel.sh <client-public-ip>
# Foreground loop; reconnects 10 s after any drop. Stop with Ctrl-C.
# Requires on the client: net.ipv4.ip_unprivileged_port_start=443 (see client-prep.sh)
set -u
IP=${1:?usage: tunnel.sh <client-ip>}
MLM_IP=${MLM_IP:?set MLM_IP to the MLM server address reachable from this workstation}
SSH_KEY=${SSH_KEY:?set SSH_KEY to the client private key}
SSH_USER=${SSH_USER:-ec2-user}
while true; do
  echo "$(date '+%F %T') connect $IP"
  # ExitOnForwardFailure: without it ssh stays connected even when a -R bind failed
  ssh -N -i "$SSH_KEY" -o IdentitiesOnly=yes -o BatchMode=yes \
      -o ServerAliveInterval=30 -o ServerAliveCountMax=3 -o ExitOnForwardFailure=yes \
      -R 127.0.0.1:4505:"$MLM_IP":4505 -R 127.0.0.1:4506:"$MLM_IP":4506 -R 127.0.0.1:443:"$MLM_IP":443 \
      "$SSH_USER@$IP"
  echo "$(date '+%F %T') ssh exited rc=$? ; retry in 10s"
  sleep 10
done
