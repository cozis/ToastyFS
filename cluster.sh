#!/usr/bin/env bash
#
# cluster.sh - Spin up a ToastyFS cluster and optionally build & run
#              an application that links against libtoastyfs.
#
# Usage:
#   ./cluster.sh up                     Start the 3-node cluster
#   ./cluster.sh down                   Stop the cluster
#   ./cluster.sh status                 Show cluster status
#   ./cluster.sh logs [node]            Tail cluster logs (or a single node)
#   ./cluster.sh run <source.c>         Build the library, compile <source.c>
#                                       against it, start the cluster, run the
#                                       binary, then tear down the cluster.
#
# The cluster exposes ports 8081-8083 on localhost, mapped to the three
# server nodes.  Client applications should connect to:
#   127.0.0.1:8081  127.0.0.1:8082  127.0.0.1:8083
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

usage() {
    sed -n '3,14s/^# \?//p' "$0"
    exit 1
}

cluster_up() {
    echo "==> Building server image and starting cluster..."
    docker compose up --build -d
    echo "==> Cluster is running."
    echo "    Nodes: 127.0.0.1:8081  127.0.0.1:8082  127.0.0.1:8083"
}

cluster_down() {
    echo "==> Stopping cluster..."
    docker compose down
}

cluster_status() {
    docker compose ps
}

cluster_logs() {
    if [ $# -gt 0 ]; then
        docker compose logs -f "$1"
    else
        docker compose logs -f
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
