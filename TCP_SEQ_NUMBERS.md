# TCP Sequence Numbers

## What they are

Every byte sent over a TCP connection has a sequence number. If you send 100 bytes
starting at sequence number 5000, those bytes are numbered 5000 through 5099.
The next byte you send would be sequence number 5100.

## Two sides, two counters

Each side of the connection tracks its own independent sequence:

```
Client                          Server
SendSeqNum = 1000               SendSeqNum = 5000
       ──── 10 bytes (seq=1000) ────>
                                RecvSeqNum = 1010
       <──── ACK (ack=1010) ────

       means: "I've received everything
               up to byte 1010, send
               that next"
```

## What the fields mean

**In the TCP header of a sent segment:**
- `SeqNum`: the sequence number of the first byte in this segment's payload
- `AckNum`: the next sequence number I expect to receive from you

**In our TCPConnection struct:**
- `SendSeqNum`: the next sequence number we'll assign to outgoing data
- `RecvSeqNum`: the next sequence number we expect from the remote side

## Why RecvSeqNum += len(payload)

When we receive 50 bytes with `SeqNum = 3000`, we know bytes 3000–3049 arrived.
The next byte we expect is 3050. So:

```
RecvSeqNum = 3000 + 50 = 3050
```

We then put this value in the `AckNum` field of our ACK packet, telling the sender:
"I have everything up to 3050, continue from there."

## Why SYN and FIN consume a sequence number

SYN and FIN don't carry data, but they still consume one sequence number each.
This is so they can be ACKed reliably — if a SYN has seq=1000, the ACK will
have ack=1001, confirming the SYN was received. Same for FIN.

```
Client (ISN=1000)              Server (ISN=5000)

SYN        seq=1000 ──────>
                              RecvSeqNum = 1001 (SYN consumed 1)
           <────── SYN+ACK    seq=5000, ack=1001
SendSeqNum = 5001
ACK        ack=5001 ──────>

           ── 20 bytes ──>    seq=1001
                              RecvSeqNum = 1021
           <────── ACK        ack=1021
```

## The invariant

At any point, `RecvSeqNum` on one side equals what the other side should use as
`SeqNum` for its next segment. The ACK number we send back is always our `RecvSeqNum`.
