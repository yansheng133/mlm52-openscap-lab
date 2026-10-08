#!/bin/bash
# Run on the client after tunnel.sh is up. Proves the forwards exist and TLS matches the MLM FQDN.
# Usage: bash verify-tunnel.sh <mlm-fqdn> <path-to-RHN-ORG-TRUSTED-SSL-CERT>
FQDN=${1:?}; CA=${2:?}
echo "== listeners (expect 3)"; ss -ltn | grep -E '127.0.0.1:(4505|4506|443) ' || echo none
# no -k on purpose: a 200 here proves the certificate name matches
curl -s -o /dev/null -w "https://$FQDN/pub/ -> %{http_code}\n" --cacert "$CA" "https://$FQDN/pub/"
