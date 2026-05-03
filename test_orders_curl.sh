#!/bin/sh
# curl-driven smoke tests for the /orders API over TLS 1.3.
#
# Assumes the rawhttp container is already running with port 8443 mapped to
# 443 (e.g. via test_e2e.py). To spin one up by hand:
#
#   docker build -q -t rawhttp .
#   docker run -d --rm --name rawhttp-test \
#       --cap-add=NET_RAW --cap-add=NET_ADMIN \
#       -p 8443:443 rawhttp
#
# Override the host with PORT=9443 or HOST=otherhost as needed.

set -eu

HOST="${HOST:-localhost}"
PORT="${PORT:-8443}"
URL="https://${HOST}:${PORT}"

failures=0

# ccurl: insecure (self-signed cert), TLS 1.3 only, silent. Append more flags
# at the call site for things like -X, -d, -w, etc.
ccurl() {
    curl -sk --tlsv1.3 --tls-max 1.3 "$@"
}

fail() {
    failures=$((failures + 1))
    echo "FAIL: $1"
    echo "  expected: $2"
    echo "  got:      $3"
}

assert_eq() {
    if [ "$2" != "$3" ]; then
        fail "$1" "$2" "$3"
    else
        echo "PASS: $1"
    fi
}

# Extract a JSON scalar field with a tiny sed regex. Good enough for our
# numeric ids and string fields; not a general JSON parser.
json_field() {
    # $1 = field name, reads JSON on stdin
    sed -E "s/.*\"$1\"[[:space:]]*:[[:space:]]*\"?([^\",}]*)\"?.*/\1/"
}

echo "=== orders curl tests against ${URL} ==="

# 1. List on empty store → []. Body should literally be "[]".
body=$(ccurl "${URL}/orders")
assert_eq "GET /orders empty body" "[]" "$body"

# 2. Create order → 201, body echoes our fields and includes id+created_at.
resp=$(ccurl -X POST "${URL}/orders" \
    -H 'Content-Type: application/json' \
    -d '{"customer":"alice","item":"widget","quantity":3,"price_cents":1299}' \
    -w '\n%{http_code}')
status=$(echo "$resp" | tail -n1)
body=$(echo "$resp" | sed '$d')

assert_eq "POST /orders status" "201" "$status"
assert_eq "POST /orders customer" "alice" "$(echo "$body" | json_field customer)"
assert_eq "POST /orders item"     "widget" "$(echo "$body" | json_field item)"
assert_eq "POST /orders quantity" "3"      "$(echo "$body" | json_field quantity)"
assert_eq "POST /orders price"    "1299"   "$(echo "$body" | json_field price_cents)"

ID=$(echo "$body" | json_field id)
if ! [ "$ID" -gt 0 ] 2>/dev/null; then
    fail "POST /orders id" "positive int" "$ID"
else
    echo "PASS: POST /orders id ($ID)"
fi

# 3. GET by id → roundtrips identical body.
fetched=$(ccurl "${URL}/orders/${ID}")
assert_eq "GET /orders/{id} body" "$body" "$fetched"

# 4. GET unknown id → 404.
status=$(ccurl -o /dev/null -w '%{http_code}' "${URL}/orders/99999")
assert_eq "GET /orders/99999 status" "404" "$status"

# 5. GET malformed id → 400.
status=$(ccurl -o /dev/null -w '%{http_code}' "${URL}/orders/abc")
assert_eq "GET /orders/abc status" "400" "$status"

# 6. POST missing customer → 400.
status=$(ccurl -o /dev/null -w '%{http_code}' \
    -X POST "${URL}/orders" \
    -H 'Content-Type: application/json' \
    -d '{"item":"x","quantity":1,"price_cents":100}')
assert_eq "POST /orders missing customer" "400" "$status"

# 7. PUT /orders → 405.
status=$(ccurl -o /dev/null -w '%{http_code}' \
    -X PUT "${URL}/orders" \
    -H 'Content-Type: application/json' \
    -d '{}')
assert_eq "PUT /orders status" "405" "$status"

# 8. Create a second order, list now has at least 2 entries.
ccurl -X POST "${URL}/orders" \
    -H 'Content-Type: application/json' \
    -d '{"customer":"bob","item":"gadget","quantity":1,"price_cents":500}' \
    >/dev/null
list=$(ccurl "${URL}/orders")
# Count top-level objects by counting `"id":` occurrences — crude but works
# for our flat schema.
count=$(echo "$list" | grep -o '"id"' | wc -l | tr -d ' ')
if [ "$count" -lt 2 ]; then
    fail "GET /orders list size" "≥2" "$count"
else
    echo "PASS: GET /orders list size ($count)"
fi

echo
if [ "$failures" -gt 0 ]; then
    echo "${failures} test(s) failed."
    exit 1
fi
echo "All orders curl tests passed."
