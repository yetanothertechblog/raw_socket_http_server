# TCP Status

What's done, what's left, and how to exercise the stack.

## How to test (today)

`main.go` runs an echo server on port 80 over our custom TCP. The container
drops kernel-originated RSTs via iptables so only our stack replies.

```sh
./run.sh
```

In another terminal, find the container IP:

```sh
docker ps
docker inspect <id> | grep IPAddress
```

### Basic connect + echo

From a sibling container (the host's Docker Desktop VM NAT hides raw frames,
so tests must run container→container):

```sh
docker run --rm -it alpine sh -c 'apk add --no-cache busybox-extras && \
  nc <container-ip> 80'
```

Type a line, see it echoed. Ctrl-D sends FIN.

### Observe the handshake / teardown

```sh
docker run --rm --net=container:<id> nicolaka/netshoot tcpdump -i eth0 -nn tcp
```

You should see: SYN → SYN-ACK (with MSS option) → ACK → data → ACK → FIN → ACK.

### Stress the retransmit path

Drop packets on the client side to force our RTO to fire:

```sh
docker run --rm --cap-add=NET_ADMIN -it alpine sh -c '
  apk add --no-cache iproute2 busybox-extras &&
  tc qdisc add dev eth0 root netem loss 30% &&
  nc <container-ip> 80'
```

Watch tcpdump on the server side — duplicate SEQs with the same payload
indicate `onRTO` firing. RTO should double on each expiry up to 60s.

### What we can't easily test yet

- TLS / HTTPS — `TCPConnection` doesn't implement `net.Conn` (missing
  `LocalAddr`, `RemoteAddr`, `Set*Deadline`), so `tls.Server` won't wrap it.
- Browser end-to-end — blocked on the above.

## Implemented

- Three-way handshake (SYN / SYN-ACK / ACK) with MSS option negotiation.
- State machine: LISTEN, SYN_RECEIVED, ESTABLISHED, FIN_WAIT_1/2, CLOSING,
  TIME_WAIT, CLOSE_WAIT, LAST_ACK, CLOSED.
- In-order data receive → app via `Read()` (channel-based, blocking).
- `Write()` buffers into `sendUnsent`, `pumpSendLocked` chunks it by MSS and
  peer's SND.WND, tracks in-flight against SND.UNA.
- Retransmit queue with single RFC 6298 timer per connection (1s initial RTO,
  doubles on expiry, capped at 60s).
- SND.WND update rule with WL1/WL2 freshness check (RFC 9293 §3.10.7.4).
- ACK validity range check — drops ACKs outside `(SND.UNA, SND.NXT]`,
  challenge-ACKs future ACKs.
- RST accept on exact `SEG.SEQ == RCV.NXT` → abort + EOF to reader.
- Mod-2³² sequence arithmetic helpers (`seqLT` / `seqLE` / ...).
- Per-connection mutex coordinating app / recv / timer goroutines.

## Remaining (rough priority toward HTTPS-to-browser)

### Blocking the browser test
- [ ] `net.Conn` methods on `TCPConnection`: `LocalAddr`, `RemoteAddr`,
      `SetDeadline`, `SetReadDeadline`, `SetWriteDeadline`.
- [ ] Wire `tls.Server` + mkcert cert, serve a static HTML page.

### Correctness gaps likely to bite on real traffic
- [ ] FIN retransmit — `Close()` sends FIN once, nothing queues it.
- [ ] SYN-ACK retransmit — same issue on handshake.
- [ ] Outgoing RST on SYN to closed port (existing TODO at `stack.go:111`)
      and on unknown-connection segments.
- [ ] Pure-ACK window updates — window in an ACK-only segment is ignored
      unless the segment advanced SND.UNA.
- [ ] Zero-window probing — if peer advertises `WND=0`, `pumpSendLocked`
      stalls forever (no persist timer).
- [ ] Out-of-order reassembly — non-matching SEQ segments are dropped
      instead of queued. Relies on peer RTO to recover.
- [ ] Strict ACK validation in SYN_RECEIVED, CLOSING, LAST_ACK.
- [ ] Challenge-ACK per RFC 5961 for in-window-but-not-expected RST / SYN.

### Deferred (non-blocking, optimization)
- [ ] RTT measurement (Karn's algorithm, SRTT / RTTVAR).
- [ ] Fast retransmit (3 duplicate ACKs).
- [ ] Congestion control (slow start, AIMD).
- [ ] SACK, window scaling, timestamps.
- [ ] Nagle, delayed ACK.

## Useful references

- RFC 9293 — TCP (core).
- RFC 6298 — RTO algorithm.
- RFC 5961 — challenge-ACK mitigations.
- `tcpdump -nn -i eth0 tcp` inside the container for wire-level view.
