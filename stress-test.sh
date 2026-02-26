#!/bin/bash
# Comprehensive stress test for ToastyFS HTTP proxy
set -e

PROXY="http://127.0.0.1:3000"
PASS=0
FAIL=0

pass() { echo "  PASS: $1"; PASS=$((PASS + 1)); }
fail() { echo "  FAIL: $1"; FAIL=$((FAIL + 1)); }

echo "=== ToastyFS Stress Test Suite ==="
echo ""

# -------------------------------------------------------
# Test 1: Basic sanity check
# -------------------------------------------------------
echo "--- Test 1: Basic PUT/GET/DELETE ---"
STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X PUT -d "hello" "$PROXY/sanity-key")
if [ "$STATUS" = "201" ]; then pass "PUT returns 201"; else fail "PUT returned $STATUS instead of 201"; fi

BODY=$(curl -s "$PROXY/sanity-key")
if [ "$BODY" = "hello" ]; then pass "GET returns correct data"; else fail "GET returned '$BODY' instead of 'hello'"; fi

STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X DELETE "$PROXY/sanity-key")
if [ "$STATUS" = "204" ]; then pass "DELETE returns 204"; else fail "DELETE returned $STATUS instead of 204"; fi

echo ""

# -------------------------------------------------------
# Test 2: wrk PUT stress test with response tracking
# -------------------------------------------------------
echo "--- Test 2: PUT stress test (4 threads, 16 connections, 10s) ---"
WRK_OUT=$(wrk -t4 -c16 -d10s -s stress-put.lua --timeout 10s "$PROXY" 2>&1)
echo "$WRK_OUT"
echo ""

TOTAL_REQ=$(echo "$WRK_OUT" | grep "requests in" | awk '{print $1}')
NON_2XX=$(echo "$WRK_OUT" | grep "Non-2xx" | awk '{print $NF}')
if [ -z "$NON_2XX" ]; then NON_2XX=0; fi

echo "  Total requests: $TOTAL_REQ"
echo "  Non-2xx responses: $NON_2XX"

if [ "$NON_2XX" -gt 0 ]; then
    fail "Got $NON_2XX error responses during PUT stress test"
else
    pass "All PUT requests succeeded"
fi
echo ""

# -------------------------------------------------------
# Test 3: Post-stress responsiveness check
# -------------------------------------------------------
echo "--- Test 3: Post-stress responsiveness ---"
# Immediately try to PUT a key after wrk ends
START=$(date +%s%3N)
STATUS=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 -X PUT -d "post-stress" "$PROXY/post-stress-key" 2>&1)
END=$(date +%s%3N)
LATENCY=$((END - START))

if [ "$STATUS" = "201" ]; then
    pass "Proxy responsive after stress (${LATENCY}ms)"
else
    fail "Proxy unresponsive after stress: status=$STATUS latency=${LATENCY}ms"
fi
echo ""

# -------------------------------------------------------
# Test 4: High concurrency test (many connections)
# -------------------------------------------------------
echo "--- Test 4: High concurrency (4 threads, 64 connections, 10s) ---"
WRK_OUT=$(wrk -t4 -c64 -d10s -s stress-put.lua --timeout 10s "$PROXY" 2>&1)
echo "$WRK_OUT"
echo ""

NON_2XX=$(echo "$WRK_OUT" | grep "Non-2xx" | awk '{print $NF}')
ERRORS=$(echo "$WRK_OUT" | grep -E "Socket errors|connect" || echo "")
if [ -z "$NON_2XX" ]; then NON_2XX=0; fi

echo "  Non-2xx: $NON_2XX"
echo "  Socket errors: $ERRORS"

if [ "$NON_2XX" -gt 0 ]; then
    fail "Got $NON_2XX error responses under high concurrency"
else
    pass "High concurrency test passed"
fi
echo ""

# -------------------------------------------------------
# Test 5: Post-high-concurrency responsiveness
# -------------------------------------------------------
echo "--- Test 5: Post-high-concurrency responsiveness ---"
START=$(date +%s%3N)
STATUS=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 -X PUT -d "post-hc" "$PROXY/post-hc-key" 2>&1)
END=$(date +%s%3N)
LATENCY=$((END - START))

if [ "$STATUS" = "201" ]; then
    pass "Proxy responsive after high concurrency (${LATENCY}ms)"
else
    fail "Proxy unresponsive after high concurrency: status=$STATUS latency=${LATENCY}ms"
fi
echo ""

# -------------------------------------------------------
# Test 6: Mixed workload
# -------------------------------------------------------
echo "--- Test 6: Mixed workload (4 threads, 32 connections, 10s) ---"
# Seed some data first
for i in $(seq 1 50); do
    curl -s -o /dev/null -X PUT -d "seed-$i" "$PROXY/mixed-key-$i"
done

WRK_OUT=$(wrk -t4 -c32 -d10s -s stress-mixed.lua --timeout 10s "$PROXY" 2>&1)
echo "$WRK_OUT"
echo ""

# -------------------------------------------------------
# Test 7: GET stress test
# -------------------------------------------------------
echo "--- Test 7: GET stress test (4 threads, 16 connections, 10s) ---"
# Seed data for GET test
for i in $(seq 1 100); do
    curl -s -o /dev/null -X PUT -d "get-test-data-$i" "$PROXY/stress-key-$i"
done

WRK_OUT=$(wrk -t4 -c16 -d10s -s stress-get.lua --timeout 10s "$PROXY" 2>&1)
echo "$WRK_OUT"
echo ""

# -------------------------------------------------------
# Summary
# -------------------------------------------------------
echo "================================"
echo "Results: $PASS passed, $FAIL failed"
echo "================================"
