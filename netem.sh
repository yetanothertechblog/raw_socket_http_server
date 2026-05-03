#!/bin/sh
# Inject latency / loss / reorder / duplicate / corruption against the running
# rawhttp container's egress (server -> client) traffic, via the kernel netem
# qdisc. Requires NET_ADMIN (run.sh already grants it) and iproute2 in the
# image (the Dockerfile installs it).
#
# Usage:
#   ./netem.sh apply [tc-netem args...]   # add netem qdisc with the given args
#   ./netem.sh clear                      # remove netem qdisc
#   ./netem.sh show                       # show current qdisc
#
# Examples:
#   ./netem.sh apply delay 100ms 20ms distribution normal
#   ./netem.sh apply delay 50ms loss 5%
#   ./netem.sh apply loss 10% reorder 25% 50% duplicate 1% corrupt 0.1%
#   ./netem.sh clear
#
# Notes:
#   - This shapes EGRESS only (packets the server sends). For ingress loss you
#     need an IFB device + tc filter mirror, which we don't set up here.
#   - The container's interface is assumed to be eth0.
#   - Picks the most recently started rawhttp container by image name.

set -eu

IFACE=${IFACE:-eth0}
CID=$(docker ps -q --filter "ancestor=rawhttp" | head -n1)

if [ -z "$CID" ]; then
    echo "no running rawhttp container found (filter: ancestor=rawhttp)" >&2
    exit 1
fi

cmd=${1:-show}
shift || true

case "$cmd" in
    apply)
        # Replace any existing root qdisc so repeat 'apply' calls are idempotent.
        docker exec "$CID" tc qdisc replace dev "$IFACE" root netem "$@"
        echo "applied on $CID:$IFACE -> netem $*"
        ;;
    clear)
        docker exec "$CID" tc qdisc del dev "$IFACE" root 2>/dev/null || true
        echo "cleared $CID:$IFACE"
        ;;
    show)
        docker exec "$CID" tc -s qdisc show dev "$IFACE"
        ;;
    *)
        echo "usage: $0 {apply [netem args...] | clear | show}" >&2
        exit 2
        ;;
esac
