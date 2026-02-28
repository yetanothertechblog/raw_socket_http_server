# HTTP Server from Scratch

HTTP server built from raw Ethernet frames (L2) up to HTTP (L7) in Go, using Linux AF_PACKET sockets.

## Run

```bash
docker build -t rawhttp .
docker run --rm --cap-add=NET_RAW --cap-add=NET_ADMIN -p 8080:80 rawhttp
```

iptables drops incoming TCP on port 80 so the kernel doesn't interfere. The AF_PACKET socket still sees all frames.

## Test

ICMP echo:
```bash
# Must ping from another container, not from macOS host.
# Docker Desktop routes host traffic through a VM NAT, so raw frames
# don't appear on the container's eth0.
docker run --rm alpine ping -c3 172.17.0.2
```

HTTP (once implemented):
```bash
curl http://localhost:8080
```
