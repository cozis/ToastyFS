#!/bin/bash
#
# ToastyFS Cluster Demo Script
# ===========================
# This script allows you to easily spawn and manage a ToastyFS cluster for demo purposes.
#
# Usage:
#   ./scripts/cluster_demo.sh start [num_chunk_servers]  - Start a cluster
#   ./scripts/cluster_demo.sh stop                       - Stop the cluster
#   ./scripts/cluster_demo.sh status                     - Show cluster status
#   ./scripts/cluster_demo.sh clean                      - Clean data and log files
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
PID_FILE="$PROJECT_DIR/.cluster_demo.pids"
LOG_DIR="$PROJECT_DIR/cluster_logs"
DATA_DIR="$PROJECT_DIR/cluster_data"

METADATA_PORT=8080
CHUNK_SERVER_BASE_PORT=8081

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

print_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

build_if_needed() {
    if [ ! -f "$PROJECT_DIR/toastyfs.out" ] && [ ! -f "$PROJECT_DIR/toastyfs.exe" ]; then
        print_info "Binary not found. Building ToastyFS..."
        cd "$PROJECT_DIR"
        make
        print_success "Build complete"
    fi
}

get_binary() {
    if [ -f "$PROJECT_DIR/toastyfs.out" ]; then
        echo "$PROJECT_DIR/toastyfs.out"
    elif [ -f "$PROJECT_DIR/toastyfs.exe" ]; then
        echo "$PROJECT_DIR/toastyfs.exe"
    else
        print_error "ToastyFS binary not found"
        exit 1
    fi
}

start_cluster() {
    local num_chunk_servers=${1:-3}

    if [ -f "$PID_FILE" ]; then
        print_error "Cluster already running (PID file exists)"
        print_info "Run '$0 stop' first or remove $PID_FILE if the cluster is not running"
        exit 1
    fi

    build_if_needed
    local binary=$(get_binary)

    # Create directories
    mkdir -p "$LOG_DIR"
    mkdir -p "$DATA_DIR"

    print_info "Starting ToastyFS cluster..."
    print_info "  Metadata server: 127.0.0.1:$METADATA_PORT"
    print_info "  Chunk servers: $num_chunk_servers"
    echo

    # Start metadata server
    print_info "Starting metadata server on port $METADATA_PORT..."
    local metadata_wal="$DATA_DIR/metadata.wal"
    "$binary" --leader \
        --addr 127.0.0.1 \
        --port $METADATA_PORT \
        --wal-file "$metadata_wal" \
        > "$LOG_DIR/metadata.log" 2>&1 &

    local metadata_pid=$!
    echo "$metadata_pid" > "$PID_FILE"
    print_success "Metadata server started (PID: $metadata_pid)"

    # Wait a bit for metadata server to start
    sleep 1

    # Start chunk servers
    for i in $(seq 1 $num_chunk_servers); do
        local port=$((CHUNK_SERVER_BASE_PORT + i - 1))
        local data_path="$DATA_DIR/chunk_server_$i/"

        print_info "Starting chunk server $i on port $port..."
        mkdir -p "$data_path"

        "$binary" \
            --addr 127.0.0.1 \
            --port $port \
            --path "$data_path" \
            --remote-addr 127.0.0.1 \
            --remote-port $METADATA_PORT \
            > "$LOG_DIR/chunk_server_$i.log" 2>&1 &

        local chunk_pid=$!
        echo "$chunk_pid" >> "$PID_FILE"
        print_success "Chunk server $i started (PID: $chunk_pid)"

        # Small delay between starting servers
        sleep 0.5
    done

    echo
    print_success "Cluster started successfully!"
    echo
    print_info "Connect to the cluster using:"
    print_info "  Address: 127.0.0.1"
    print_info "  Port: $METADATA_PORT"
    echo
    print_info "View logs at: $LOG_DIR/"
    print_info "Data stored at: $DATA_DIR/"
    echo
    print_info "To stop the cluster, run: $0 stop"
}

stop_cluster() {
    if [ ! -f "$PID_FILE" ]; then
        print_warning "No PID file found. Cluster may not be running."
        exit 0
    fi

    print_info "Stopping ToastyFS cluster..."

    local stopped=0
    local failed=0

    while IFS= read -r pid; do
        if [ -n "$pid" ]; then
            if kill -0 "$pid" 2>/dev/null; then
                kill "$pid" 2>/dev/null && {
                    print_success "Stopped process $pid"
                    stopped=$((stopped + 1))
                } || {
                    print_error "Failed to stop process $pid"
                    failed=$((failed + 1))
                }
            else
                print_warning "Process $pid not running"
            fi
        fi
    done < "$PID_FILE"

    rm -f "$PID_FILE"

    echo
    print_success "Cluster stopped (Stopped: $stopped, Failed: $failed)"
}

show_status() {
    if [ ! -f "$PID_FILE" ]; then
        print_info "Cluster is NOT running"
        exit 0
    fi

    print_info "Cluster status:"
    echo

    local running=0
    local not_running=0
    local line_num=0

    while IFS= read -r pid; do
        if [ -n "$pid" ]; then
            line_num=$((line_num + 1))
            local server_type="Chunk server $((line_num - 1))"
            [ $line_num -eq 1 ] && server_type="Metadata server"

            if kill -0 "$pid" 2>/dev/null; then
                echo -e "  ${GREEN}●${NC} $server_type (PID: $pid) - ${GREEN}running${NC}"
                running=$((running + 1))
            else
                echo -e "  ${RED}●${NC} $server_type (PID: $pid) - ${RED}not running${NC}"
                not_running=$((not_running + 1))
            fi
        fi
    done < "$PID_FILE"

    echo
    if [ $not_running -eq 0 ]; then
        print_success "All $running servers are running"
    else
        print_warning "$running running, $not_running not running"
    fi

    if [ -d "$LOG_DIR" ]; then
        echo
        print_info "Log directory: $LOG_DIR"
        print_info "Recent log files:"
        ls -lht "$LOG_DIR" | head -n 6 | tail -n 5 | awk '{print "  " $9 " (" $5 ")"}'
    fi
}

clean_data() {
    if [ -f "$PID_FILE" ]; then
        print_error "Cluster is running. Stop it first with: $0 stop"
        exit 1
    fi

    print_warning "This will delete all cluster data and logs!"
    read -p "Are you sure? (y/N) " -n 1 -r
    echo

    if [[ $REPLY =~ ^[Yy]$ ]]; then
        print_info "Cleaning data and logs..."
        rm -rf "$DATA_DIR"
        rm -rf "$LOG_DIR"
        print_success "Cleaned successfully"
    else
        print_info "Cancelled"
    fi
}

# Main command dispatcher
case "${1:-}" in
    start)
        start_cluster "${2:-3}"
        ;;
    stop)
        stop_cluster
        ;;
    status)
        show_status
        ;;
    clean)
        clean_data
        ;;
    *)
        echo "ToastyFS Cluster Demo Script"
        echo
        echo "Usage:"
        echo "  $0 start [num_chunk_servers]  - Start a cluster (default: 3 chunk servers)"
        echo "  $0 stop                       - Stop the cluster"
        echo "  $0 status                     - Show cluster status"
        echo "  $0 clean                      - Clean data and log files"
        echo
        echo "Examples:"
        echo "  $0 start           # Start with 3 chunk servers"
        echo "  $0 start 5         # Start with 5 chunk servers"
        echo "  $0 status          # Check if cluster is running"
        echo "  $0 stop            # Stop all servers"
        exit 1
        ;;
esac
