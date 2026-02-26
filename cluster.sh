#!/bin/bash
#
# Cluster management script for ToastyFS.
# Manages a 3-node server cluster with 1 HTTP proxy.
#
# Usage:
#   ./cluster.sh start   - Build (if needed) and start all nodes + proxy
#   ./cluster.sh stop    - Stop all running nodes and the proxy
#   ./cluster.sh status  - Show the status of each process
#   ./cluster.sh restart - Stop then start
#   ./cluster.sh clean   - Stop everything and remove data/log directories
#

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
DATA_DIR="$SCRIPT_DIR/cluster-data"
LOG_DIR="$DATA_DIR/logs"
PID_DIR="$DATA_DIR/pids"

NODE1_ADDR="127.0.0.1:8001"
NODE2_ADDR="127.0.0.1:8002"
NODE3_ADDR="127.0.0.1:8003"

build() {
    echo "Building ToastyFS..."
    (cd "$SCRIPT_DIR" && bash build.sh)
    echo "Build complete."
}

ensure_dirs() {
    mkdir -p "$LOG_DIR" "$PID_DIR"
    mkdir -p "$DATA_DIR/chunks-node1"
    mkdir -p "$DATA_DIR/chunks-node2"
    mkdir -p "$DATA_DIR/chunks-node3"
}

start_node() {
    local name="$1"
    local addr="$2"
    local peer1="$3"
    local peer2="$4"
    local chunks="$5"

    local pidfile="$PID_DIR/$name.pid"
    local logfile="$LOG_DIR/$name.log"

    if [ -f "$pidfile" ] && kill -0 "$(cat "$pidfile")" 2>/dev/null; then
        echo "  $name is already running (pid $(cat "$pidfile"))"
        return
    fi

    "$SCRIPT_DIR/toasty" \
        --addr "$addr" \
        --peer "$peer1" \
        --peer "$peer2" \
        --chunks "$chunks" \
        > "$logfile" 2>&1 &

    local pid=$!
    echo "$pid" > "$pidfile"
    echo "  $name started (pid $pid) on $addr"
}

start_proxy() {
    local pidfile="$PID_DIR/proxy.pid"
    local logfile="$LOG_DIR/proxy.log"

    if [ -f "$pidfile" ] && kill -0 "$(cat "$pidfile")" 2>/dev/null; then
        echo "  proxy is already running (pid $(cat "$pidfile"))"
        return
    fi

    "$SCRIPT_DIR/toasty_proxy" \
        --server "$NODE1_ADDR" \
        --server "$NODE2_ADDR" \
        --server "$NODE3_ADDR" \
        > "$logfile" 2>&1 &

    local pid=$!
    echo "$pid" > "$pidfile"
    echo "  proxy started (pid $pid) on 127.0.0.1:3000"
}

stop_process() {
    local name="$1"
    local pidfile="$PID_DIR/$name.pid"

    if [ ! -f "$pidfile" ]; then
        echo "  $name is not running (no pid file)"
        return
    fi

    local pid
    pid=$(cat "$pidfile")

    if kill -0 "$pid" 2>/dev/null; then
        kill "$pid"
        # Wait briefly for graceful shutdown
        local i=0
        while kill -0 "$pid" 2>/dev/null && [ $i -lt 10 ]; do
            sleep 0.1
            i=$((i + 1))
        done
        if kill -0 "$pid" 2>/dev/null; then
            kill -9 "$pid" 2>/dev/null || true
        fi
        echo "  $name stopped (was pid $pid)"
    else
        echo "  $name was not running (stale pid $pid)"
    fi

    rm -f "$pidfile"
}

do_start() {
    if [ ! -f "$SCRIPT_DIR/toasty" ] || [ ! -f "$SCRIPT_DIR/toasty_proxy" ]; then
        build
    fi

    ensure_dirs

    echo "Starting cluster..."
    start_node "node1" "$NODE1_ADDR" "$NODE2_ADDR" "$NODE3_ADDR" "$DATA_DIR/chunks-node1"
    start_node "node2" "$NODE2_ADDR" "$NODE1_ADDR" "$NODE3_ADDR" "$DATA_DIR/chunks-node2"
    start_node "node3" "$NODE3_ADDR" "$NODE1_ADDR" "$NODE2_ADDR" "$DATA_DIR/chunks-node3"

    # Give servers a moment to start listening before launching the proxy
    sleep 1

    start_proxy
    echo "Cluster is running. HTTP proxy at http://127.0.0.1:3000"
}

do_stop() {
    echo "Stopping cluster..."
    stop_process "proxy"
    stop_process "node1"
    stop_process "node2"
    stop_process "node3"
    echo "Cluster stopped."
}

do_status() {
    local all_stopped=true
    for name in node1 node2 node3 proxy; do
        local pidfile="$PID_DIR/$name.pid"
        if [ -f "$pidfile" ] && kill -0 "$(cat "$pidfile")" 2>/dev/null; then
            echo "  $name: running (pid $(cat "$pidfile"))"
            all_stopped=false
        else
            echo "  $name: stopped"
        fi
    done
    if $all_stopped; then
        echo "Cluster is not running."
    fi
}

do_clean() {
    do_stop
    echo "Removing cluster data..."
    rm -rf "$DATA_DIR"
    echo "Clean complete."
}

case "${1:-}" in
    start)   do_start   ;;
    stop)    do_stop    ;;
    status)  do_status  ;;
    restart) do_stop; do_start ;;
    clean)   do_clean   ;;
    *)
        echo "Usage: $0 {start|stop|status|restart|clean}"
        exit 1
        ;;
esac
