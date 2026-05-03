#!/bin/sh
# Build and run the rawhttp container detached. Maps host:8443 -> container:443
# (the TLS server) and grants NET_RAW (AF_PACKET) and NET_ADMIN (iptables for
# kernel-RST suppression and tc/netem fault injection — see netem.sh).
set -eu

docker build -q -t rawhttp .
docker rm -f rawhttp-test 2>/dev/null || true
docker run -d --rm --name rawhttp-test \
    --cap-add=NET_RAW --cap-add=NET_ADMIN \
    -p 8443:443 rawhttp
