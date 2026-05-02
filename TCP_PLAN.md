# TCP Stack Implementation Plan

## What is the "Stack"?

In a normal program, when you call `net.Listen("tcp", ":80")`, the OS kernel handles
everything: reading raw packets off the network interface, parsing IP headers, managing
TCP state machines, reassembling byte streams, and presenting your application with a
clean connection to read/write from.

That entire chain of processing — from raw ethernet frames up to application-usable
connections — is called the **network stack** (or TCP/IP stack). It's layered:

```
┌──────────────────────────┐
│  Application (HTTP)      │  reads/writes bytes
├──────────────────────────┤
│  Transport (TCP)         │  connections, seq numbers, reliability
├──────────────────────────┤
│  Network (IPv4)          │  addressing, routing
├──────────────────────────┤
│  Link (Ethernet)         │  framing, MAC addresses
├──────────────────────────┤
│  Physical (NIC)          │  raw bits on the wire
└──────────────────────────┘
```

Normally the kernel owns all of this. We bypass it with a raw socket (`AF_PACKET, SOCK_RAW`),
which gives us raw ethernet frames directly from the NIC. Our `Stack` struct replaces what
the kernel would do — it sits between the raw socket and the application, handling layers
2 through 4.

## The Stack struct

The `Stack` is the central piece. It:

1. **Owns the raw socket fd** — it's the only thing that reads from and writes to the wire
2. **Runs a background receive loop** — a goroutine that calls `Recvfrom` in a loop,
   parsing each packet through Ethernet → IPv4 → TCP
3. **Manages all TCP connections** — a map of 4-tuple keys to connection state machines,
   protected by a mutex
4. **Holds listeners** — when we want to accept connections on a port, we register a
   listener with the stack. The stack's recv loop routes incoming SYNs to the right listener.

```go
type Stack struct {
    fd          int                          // raw socket
    connections map[ConnectionKey]*TCPConnection
    mu          sync.RWMutex
    listeners   map[uint16]*Listener         // port -> listener
}
```

## The Listener

A `Listener` is what you get when you call `stack.Listen(port)`. It represents a port
in the LISTEN state, waiting for incoming connections. Internally it holds a channel —
when the stack's recv loop completes a 3-way handshake for this port, it pushes the
new connection onto the channel.

```go
type Listener struct {
    port   uint16
    accept chan *TCPConnection    // handshake-complete connections arrive here
}
```

`listener.Accept()` blocks until a connection is ready — same as `net.Listener.Accept()`.

## Packet flow through the Stack

```
NIC → raw socket fd
        │
        ▼
  Stack.recvLoop() goroutine
        │
        ├─ parse Ethernet frame
        ├─ parse IPv4 packet
        ├─ if protocol != TCP, skip
        ├─ parse TCP segment
        │
        ├─ look up ConnectionKey in connections map
        │     ├─ found: pass segment to that connection's state machine
        │     └─ not found + SYN flag + port has a Listener:
        │           create new connection in SYN_RECEIVED, send SYN+ACK
        │
        └─ when connection reaches ESTABLISHED:
              push it onto the Listener's accept channel
```

## Build order

### Step 1: Stack + recv loop + demux
- Stack struct with fd, connection map, listener map
- Listener struct with accept channel
- NewStack(fd) starts the recv loop goroutine
- stack.Listen(port) registers a listener
- listener.Accept() blocks on the channel
- recvLoop: recv → parse Ethernet → IPv4 → TCP → look up or create connection

### Step 2: Checksum + segment building
- TCP checksum with pseudo-header
- Helper to build a TCP segment + IPv4 packet + Ethernet frame and send it
- ISN generation

### Step 3: 3-way handshake
- Recv SYN → create connection, send SYN+ACK, state = SYN_RECEIVED
- Recv ACK → state = ESTABLISHED, push to listener's accept channel

### Step 4: Read
- conn.Read() blocks on a channel
- When recv loop gets data (PSH+ACK), append to recv buffer, push to channel
- ACK the received data

### Step 5: Write
- conn.Write(data) builds TCP segments with correct seq numbers
- Sends through the stack's fd

### Step 6: Close
- conn.Close() sends FIN
- Handle FIN from peer, send ACK
- TIME_WAIT cleanup

## Echo server target

```go
func main() {
    fd := openRawSocket()
    stack := tcp.NewStack(fd)
    listener := stack.Listen(80)

    for {
        conn := listener.Accept()
        data := conn.Read()
        conn.Write(data)
        conn.Close()
    }
}
```
