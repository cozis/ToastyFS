#!/usr/bin/env bash
#
# cluster.sh - Manage a local 3-node ToastyFS cluster.
#
# Usage:
#   ./cluster.sh up                     Build the server and start 3 nodes
#   ./cluster.sh down                   Stop all nodes
#   ./cluster.sh status                 Show which nodes are running
#   ./cluster.sh logs [1|2|3]           Tail logs (all nodes, or one)
#   ./cluster.sh run <source.c>         Build the library, compile <source.c>
#                                       against it, start the cluster, run the
#                                       binary, then tear down the cluster.
#
# The three server nodes listen on:
#   127.0.0.1:8081   127.0.0.1:8082   127.0.0.1:8083
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
CLUSTER_DIR="$SCRIPT_DIR/.cluster"
ADDRS=("127.0.0.1:8081" "127.0.0.1:8082" "127.0.0.1:8083")

usage() {
    sed -n '3,14s/^# \?//p' "$0"
    exit 1
}

cluster_up() {
    echo "==> Building server..."
    make -C "$SCRIPT_DIR" toastyfs

    mkdir -p "$CLUSTER_DIR"

    for i in 1 2 3; do
        pidfile="$CLUSTER_DIR/node${i}.pid"
        if [ -f "$pidfile" ] && kill -0 "$(cat "$pidfile")" 2>/dev/null; then
            echo "    Node $i already running (pid $(cat "$pidfile"))"
            continue
        fi

        node_dir="$CLUSTER_DIR/node${i}"
        mkdir -p "$node_dir"

        # Build argument list: --addr for self, --peer for the others.
        args=()
        for j in 1 2 3; do
            idx=$((j - 1))
            if [ "$j" -eq "$i" ]; then
                args+=(--addr "${ADDRS[$idx]}")
            else
                args+=(--peer "${ADDRS[$idx]}")
            fi
        done

        (
            cd "$node_dir"
            # ServerState is ~40 MB (MetaStore), which exceeds the
            # default 8 MB stack.  Raise the limit for the server.
            ulimit -s unlimited
            "$SCRIPT_DIR/toastyfs" "${args[@]}" \
                >> "$CLUSTER_DIR/node${i}.log" 2>&1 &
            echo $! > "$pidfile"
        )
        echo "    Node $i started (pid $(cat "$pidfile")) on ${ADDRS[$((i-1))]}"
    done
    echo "==> Cluster is running."
}

cluster_down() {
    if [ ! -d "$CLUSTER_DIR" ]; then
        echo "No cluster state found."
        return
    fi

    for i in 1 2 3; do
        pidfile="$CLUSTER_DIR/node${i}.pid"
        if [ -f "$pidfile" ]; then
            pid="$(cat "$pidfile")"
            if kill -0 "$pid" 2>/dev/null; then
                kill "$pid" 2>/dev/null || true
                echo "    Node $i stopped (pid $pid)"
            else
                echo "    Node $i was not running"
            fi
            rm -f "$pidfile"
        fi
    done

    # Clean up node data directories so fresh starts don't trigger
    # the crash-recovery path (vsr_boot_marker).
    rm -rf "$CLUSTER_DIR"
    echo "==> Cluster stopped."
}

cluster_status() {
    if [ ! -d "$CLUSTER_DIR" ]; then
        echo "No cluster state found. Run './cluster.sh up' first."
        return
    fi

    printf "%-8s %-8s %-20s %s\n" "NODE" "PID" "ADDRESS" "STATUS"
    for i in 1 2 3; do
        pidfile="$CLUSTER_DIR/node${i}.pid"
        addr="${ADDRS[$((i-1))]}"
        if [ -f "$pidfile" ]; then
            pid="$(cat "$pidfile")"
            if kill -0 "$pid" 2>/dev/null; then
                printf "%-8s %-8s %-20s %s\n" "node$i" "$pid" "$addr" "running"
            else
                printf "%-8s %-8s %-20s %s\n" "node$i" "$pid" "$addr" "dead"
            fi
        else
            printf "%-8s %-8s %-20s %s\n" "node$i" "-" "$addr" "not started"
        fi
    done
}

cluster_logs() {
    if [ $# -gt 0 ]; then
        logfile="$CLUSTER_DIR/node${1}.log"
        if [ ! -f "$logfile" ]; then
            echo "No log file for node $1."
            return 1
        fi
        tail -f "$logfile"
    else
        tail -f "$CLUSTER_DIR"/node*.log
    fi
}

cluster_run() {
    local src="$1"
    local bin
    bin="$(basename "${src%.c}")"

    echo "==> Building libtoastyfs..."
    make -C "$SCRIPT_DIR" lib

    echo "==> Compiling $src..."
    ${CC:-gcc} -Wall -Wextra -o "$bin" "$src" \
        -I"$SCRIPT_DIR/include" \
        -L"$SCRIPT_DIR" \
        -ltoastyfs

    echo "==> Starting cluster..."
    cluster_up
    # Give the servers a moment to elect a leader.
    sleep 2

    echo "==> Running ./$bin"
    echo "---"
    LD_LIBRARY_PATH="$SCRIPT_DIR:${LD_LIBRARY_PATH:-}" "./$bin" || true
    echo "---"

    echo "==> Stopping cluster..."
    cluster_down
}

if [ $# -lt 1 ]; then
    usage
fi

case "$1" in
    up)     cluster_up ;;
    down)   cluster_down ;;
    status) cluster_status ;;
    logs)   shift; cluster_logs "$@" ;;
    run)
        if [ $# -lt 2 ]; then
            echo "Error: 'run' requires a source file argument." >&2
            usage
        fi
        cluster_run "$2"
        ;;
    *)      usage ;;
esac
