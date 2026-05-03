#!/usr/bin/env python3
"""End-to-end smoke tests against the running rawhttp server.

Boots the docker image on localhost:8443, waits for /healthz to come up
over TLS 1.3, runs a series of HTTPS checks, then tears the container
down. Exits non-zero on the first failure.

We use Python's ssl module (OpenSSL-backed) instead of host curl because
macOS curl ships against LibreSSL/SecureTransport, neither of which
reliably negotiates ed25519 server certs in TLS 1.3.
"""

import http.client
import json
import socket
import ssl
import subprocess
import sys
import time

IMAGE = "rawhttp"
NAME = "rawhttp-test"
HOST = "localhost"
PORT = 8443

failures = 0


# macOS system Python links against an ancient LibreSSL that lacks TLS 1.3.
# Force the user onto a real OpenSSL build (homebrew or python.org).
if "openssl" not in ssl.OPENSSL_VERSION.lower():
    print(f"this script needs OpenSSL-backed Python, got: {ssl.OPENSSL_VERSION}")
    print("try: /opt/homebrew/bin/python3 test_e2e.py")
    sys.exit(2)


def tls_context():
    # Self-signed ed25519 cert + locked to TLS 1.3. We disable verification
    # because the cert is generated fresh at server startup.
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.maximum_version = ssl.TLSVersion.TLSv1_3
    return ctx


def fail(name, expected, actual):
    global failures
    failures += 1
    print(f"FAIL: {name}")
    print(f"  expected: {expected!r}")
    print(f"  got:      {actual!r}")


def assert_eq(name, expected, actual):
    if expected != actual:
        fail(name, expected, actual)
    else:
        print(f"PASS: {name}")


def http_get(path, method="GET", body=None, headers=None):
    conn = http.client.HTTPSConnection(HOST, PORT, context=tls_context(), timeout=5)
    try:
        conn.request(method, path, body=body, headers=headers or {})
        resp = conn.getresponse()
        data = resp.read()
        # resp.getheader() is case-insensitive; expose it via a wrapper.
        return resp.status, resp, data
    finally:
        conn.close()


def http_json(path, method="GET", payload=None):
    """JSON helper: marshals payload, parses response body, returns (status, dict).

    Pre-sets Content-Length because our server is strict about POST bodies.
    """
    body = json.dumps(payload).encode() if payload is not None else None
    headers = {"Content-Type": "application/json"} if body else {}
    status, resp, data = http_get(path, method=method, body=body, headers=headers)
    parsed = json.loads(data) if data else None
    return status, parsed


def tls_raw_first_line(raw_bytes: bytes) -> str:
    """Open a fresh TLS 1.3 connection, send raw HTTP bytes, return the
    first line of the response with CR stripped."""
    sock = socket.create_connection((HOST, PORT), timeout=5)
    with tls_context().wrap_socket(sock, server_hostname=HOST) as ssock:
        ssock.sendall(raw_bytes)
        buf = b""
        while b"\n" not in buf:
            chunk = ssock.recv(4096)
            if not chunk:
                break
            buf += chunk
        line, _, _ = buf.partition(b"\n")
        return line.rstrip(b"\r").decode("latin-1")


def run(cmd, **kwargs):
    return subprocess.run(cmd, check=True, **kwargs)


def cleanup():
    subprocess.run(["docker", "rm", "-f", NAME],
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def host_port_in_use() -> bool:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.bind(("127.0.0.1", PORT))
    except OSError:
        return True
    finally:
        s.close()
    return False


def wait_for_ready(timeout_s: float = 10.0):
    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            status, _, _ = http_get("/healthz")
            if status == 200:
                return
            last_err = f"status={status}"
        except Exception as e:
            last_err = repr(e)
        time.sleep(0.2)
    print(f"server never became ready (last error: {last_err})")
    subprocess.run(["docker", "logs", NAME])
    sys.exit(1)


def main():
    if host_port_in_use():
        print(f"port {PORT} is already in use on the host.")
        print(f"either stop the listener or edit PORT in {sys.argv[0]}")
        sys.exit(1)

    print("=== Building image ===")
    run(["docker", "build", "-q", "-t", IMAGE, "."], stdout=subprocess.DEVNULL)

    print("=== Starting container ===")
    cleanup()
    run(["docker", "run", "-d", "--rm", "--name", NAME,
         "--cap-add=NET_RAW", "--cap-add=NET_ADMIN",
         "-p", f"{PORT}:443", IMAGE], stdout=subprocess.DEVNULL)

    try:
        print("=== Waiting for server ===")
        wait_for_ready()

        print()
        print("=== Running tests ===")

        # 1. GET / → 200, body greets us.
        _, _, body = http_get("/")
        assert_eq("GET /  body", b"Hello over our own TLS!\n", body)

        # 2. GET /healthz → 200, body "ok".
        _, _, body = http_get("/healthz")
        assert_eq("GET /healthz  body", b"ok\n", body)

        # 3. GET /echo/<x> → 200, body "<x>".
        _, _, body = http_get("/echo/world")
        assert_eq("GET /echo/world  body", b"world\n", body)

        # 4. GET /nope → 404.
        status, _, _ = http_get("/nope")
        assert_eq("GET /nope  status", 404, status)

        # 5. Server header is rawhttp.
        _, resp, _ = http_get("/healthz")
        assert_eq("Server header", "rawhttp", resp.getheader("Server"))

        # 6. Connection: close is always set.
        _, resp, _ = http_get("/healthz")
        assert_eq("Connection header", "close",
                  (resp.getheader("Connection") or "").lower())

        # 7. Date header is present (just check non-empty).
        _, resp, _ = http_get("/healthz")
        date = resp.getheader("Date") or ""
        if not date:
            fail("Date header", "non-empty", "(empty)")
        else:
            print(f"PASS: Date header present ({date})")

        # 8. TLS 1.3 was actually negotiated (not 1.2).
        sock = socket.create_connection((HOST, PORT), timeout=5)
        with tls_context().wrap_socket(sock, server_hostname=HOST) as ssock:
            assert_eq("TLS protocol", "TLSv1.3", ssock.version())

        # 9. HTTP/1.0 → 505 (we only speak 1.1).
        line = tls_raw_first_line(b"GET / HTTP/1.0\r\nHost: x\r\n\r\n")
        assert_eq("HTTP/1.0 status line",
                  "HTTP/1.1 505 HTTP Version Not Supported", line)

        # 10. Missing Host → 400.
        line = tls_raw_first_line(b"GET / HTTP/1.1\r\n\r\n")
        assert_eq("missing Host status line", "HTTP/1.1 400 Bad Request", line)

        # 11. POST without Content-Length → 411.
        line = tls_raw_first_line(b"POST /echo/x HTTP/1.1\r\nHost: x\r\n\r\n")
        assert_eq("POST no CL status line",
                  "HTTP/1.1 411 Length Required", line)

        # --- orders API ---

        # 12. List on empty store → [].
        status, parsed = http_json("/orders")
        assert_eq("GET /orders empty status", 200, status)
        assert_eq("GET /orders empty body", [], parsed)

        # 13. Create order → 201, echoes fields, populates id+created_at.
        status, created = http_json("/orders", method="POST", payload={
            "customer": "alice",
            "item":     "widget",
            "quantity": 3,
            "price_cents": 1299,
        })
        assert_eq("POST /orders status", 201, status)
        assert_eq("POST /orders customer", "alice", created.get("customer"))
        assert_eq("POST /orders item", "widget", created.get("item"))
        assert_eq("POST /orders quantity", 3, created.get("quantity"))
        assert_eq("POST /orders price_cents", 1299, created.get("price_cents"))
        if not isinstance(created.get("id"), int) or created["id"] <= 0:
            fail("POST /orders id", "positive int", created.get("id"))
        else:
            print(f"PASS: POST /orders id ({created['id']})")
        if not created.get("created_at"):
            fail("POST /orders created_at", "non-empty", created.get("created_at"))
        else:
            print(f"PASS: POST /orders created_at ({created['created_at']})")

        order_id = created["id"]

        # 14. Get by id → matches what we created.
        status, fetched = http_json(f"/orders/{order_id}")
        assert_eq("GET /orders/{id} status", 200, status)
        assert_eq("GET /orders/{id} round-trip", created, fetched)

        # 15. Get unknown id → 404.
        status, _ = http_json("/orders/99999")
        assert_eq("GET /orders/{id} not found", 404, status)

        # 16. Bad id format → 400.
        status, _ = http_json("/orders/abc")
        assert_eq("GET /orders/abc status", 400, status)

        # 17. Create a second order → list now has 2 in id order.
        _, second = http_json("/orders", method="POST", payload={
            "customer": "bob",
            "item":     "gadget",
            "quantity": 1,
            "price_cents": 500,
        })
        status, listed = http_json("/orders")
        assert_eq("GET /orders list status", 200, status)
        assert_eq("GET /orders list length", 2, len(listed or []))
        assert_eq("GET /orders list[0] id", order_id, listed[0]["id"])
        assert_eq("GET /orders list[1] id", second["id"], listed[1]["id"])

        # 18. Validation: missing customer → 400.
        status, _ = http_json("/orders", method="POST", payload={
            "item": "x", "quantity": 1, "price_cents": 100,
        })
        assert_eq("POST /orders missing customer", 400, status)

        # 19. Method not allowed: PUT /orders → 405.
        status, _, _ = http_get("/orders", method="PUT",
                                body=b"{}", headers={"Content-Length": "2"})
        assert_eq("PUT /orders status", 405, status)

        print()
        if failures:
            print(f"{failures} test(s) failed.")
            sys.exit(1)
        print("All tests passed.")
    finally:
        cleanup()


if __name__ == "__main__":
    main()
