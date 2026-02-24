// VSR invariant checker with external shadow log tracking.
//
// This file runs in the main simulation loop outside Quakey-scheduled
// processes. It includes node.h for struct definitions, then restores
// real allocators since mock_malloc/realloc/free abort outside process
// context.

#include "server.h"
#include "chunk_store.h"

#include <assert.h>
#include <stdio.h>

// Restore real allocators (see checker/linearizability.c for precedent).
#undef malloc
#undef realloc
#undef free
#include <stdlib.h>
#include <string.h>

// Forward declarations for quakey host context functions
// (we can't include quakey.h because it would re-mock malloc/realloc/free)
void quakey_enter_host(unsigned long long node);
void quakey_leave_host(void);

// These helpers are static in node.c; duplicated here for the checker.

static int self_idx(Server *state)
{
    for (int i = 0; i < state->num_nodes; i++)
        if (addr_eql(state->node_addrs[i], state->self_addr))
            return i;
    UNREACHABLE;
}

static int leader_idx(Server *state)
{
    return state->view_number % state->num_nodes;
}

static bool is_leader(Server *state)
{
    if (state->status == STATUS_RECOVERY)
        return false;
    return self_idx(state) == leader_idx(state);
}

static int shadow_log_append(InvariantChecker *ic, MetaOper oper)
{
    if (ic->shadow_count == ic->shadow_capacity) {
        int n = 2 * ic->shadow_capacity;
        if (n < 8)
            n = 8;
        MetaOper *p = realloc(ic->shadow_log, n * sizeof(MetaOper));
        if (p == NULL)
            return -1;
        ic->shadow_log = p;
        ic->shadow_capacity = n;
    }
    ic->shadow_log[ic->shadow_count++] = oper;
    return 0;
}

void invariant_checker_init(InvariantChecker *ic)
{
    ic->last_min_commit = -1;
    ic->last_max_commit = -1;
    for (int i = 0; i < NODE_LIMIT; i++)
        ic->prev_status[i] = STATUS_NORMAL;
    ic->shadow_log = NULL;
    ic->shadow_count = 0;
    ic->shadow_capacity = 0;
}

void invariant_checker_free(InvariantChecker *ic)
{
    fprintf(stderr, "INVARIANT CHECKER: shadow log tracked %d committed entries\n",
        ic->shadow_count);
    free(ic->shadow_log);
}

void invariant_checker_run(InvariantChecker *ic, Server **nodes, int num_nodes,
    unsigned long long *node_handles)
{
    int min_commit = -1;
    int max_commit = -1;

    bool primary = false;
    uint64_t primary_view_number = 0;

    bool min_commit_just_recovered = false;

    uint64_t max_view_number = 0;
    for (int i = 0; i < num_nodes; i++) {
        if (nodes[i])
            max_view_number = MAX(max_view_number, nodes[i]->view_number);
    }

    for (int i = 0; i < num_nodes; i++) {
        Server *n = nodes[i];
        if (n == NULL || n->status == STATUS_RECOVERY)
            continue;

        if (min_commit < 0 || min_commit > n->commit_index) {
            min_commit = n->commit_index;
            min_commit_just_recovered = (ic->prev_status[i] == STATUS_RECOVERY);
        }

        if (max_commit < 0 || max_commit < n->commit_index) {
            max_commit = n->commit_index;
        }

        if (is_leader(n) && n->view_number > primary_view_number) {
            primary = true;
            primary_view_number = n->view_number;
        }
    }

    // If the primary isn't up to date, it's not the
    // real primary.
    if (primary_view_number < max_view_number)
        primary = false;

    if (min_commit < 0) {
        assert(ic->last_min_commit == -1);
    } else {
        // The minimum number of committed entries should
        // only increase, but there are some corner-cases
        // when this is not true.
        // When a node completes the recovery state, its
        // log is technically outdated as it was sent some
        // point in the past. If operations are committed
        // while the recovery response is in transit over
        // the network, the minimum number of committed
        // entries will decrease.
        if (!min_commit_just_recovered) {
            assert(ic->last_min_commit <= min_commit);
        }
    }

    if (max_commit < 0) {
        assert(ic->last_max_commit == -1);
    } else {
        // The maximum number of committed entries
        // should only increase. The primary generally
        // has more committed entries than replicas. If
        // the primary dies, the maximum commit number
        // of the live nodes may decrease. This is still
        // okay since the new primary will commit up to
        // that point as the view change completes. This
        // implies that the maximum commit number should
        // always increase unless there is no primary.
        if (!primary) {
            max_commit = ic->last_max_commit;
        } else {
            //assert(ic->last_max_commit <= max_commit);
        }
    }

    ic->last_min_commit = min_commit;
    ic->last_max_commit = max_commit;
    for (int i = 0; i < num_nodes; i++) {
        if (nodes[i])
            ic->prev_status[i] = nodes[i]->status;
    }

    for (int i = 0; i < num_nodes; i++) {
        Server *s = nodes[i];
        if (s == NULL)
            continue;

        // 1. commit_index <= log.count
        //    A node cannot have committed more entries than it has in its log.
        if (s->commit_index > s->log.count) {
            fprintf(stderr, "INVARIANT VIOLATED: node %d: commit_index (%d) > log.count (%d)\n",
                i, s->commit_index, s->log.count);
            __builtin_trap();
        }

        // 2. commit_index >= 0
        if (s->commit_index < 0) {
            fprintf(stderr, "INVARIANT VIOLATED: node %d: commit_index (%d) < 0\n",
                i, s->commit_index);
            __builtin_trap();
        }

        // 4. Future buffer count is in valid range.
        if (s->num_future < 0 || s->num_future > FUTURE_LIMIT) {
            fprintf(stderr, "INVARIANT VIOLATED: node %d: num_future (%d) out of range [0, %d]\n",
                i, s->num_future, FUTURE_LIMIT);
            __builtin_trap();
        }

        // 7. last_normal_view <= view_number
        //    The most recent view in which this node was in NORMAL status
        //    cannot exceed its current view number.
        if (s->last_normal_view > s->view_number) {
            fprintf(stderr, "INVARIANT VIOLATED: node %d: last_normal_view (%lu) > view_number (%lu)\n",
                i, (unsigned long)s->last_normal_view, (unsigned long)s->view_number);
            __builtin_trap();
        }

        // 8. When status is NORMAL, last_normal_view must equal view_number.
        //    Every transition to NORMAL status sets last_normal_view = view_number.
        //    If they diverge while in NORMAL, a transition forgot to update it.
        if (s->status == STATUS_NORMAL && s->last_normal_view != s->view_number) {
            fprintf(stderr, "INVARIANT VIOLATED: node %d: status is NORMAL but "
                "last_normal_view (%lu) != view_number (%lu)\n",
                i, (unsigned long)s->last_normal_view, (unsigned long)s->view_number);
            __builtin_trap();
        }

        // 9. Log entry view numbers must not exceed the node's current view.
        //    Entries are created in the view they were proposed. No entry
        //    should carry a view number from the future.
        for (int k = 0; k < s->log.count; k++) {
            if ((uint64_t)s->log.entries[k].view_number > s->view_number) {
                fprintf(stderr, "INVARIANT VIOLATED: node %d: log[%d].view_number (%d) "
                    "> view_number (%lu)\n",
                    i, k, s->log.entries[k].view_number,
                    (unsigned long)s->view_number);
                __builtin_trap();
            }
        }

        // 10. For a leader in NORMAL status, every uncommitted log entry
        //     must have the leader's own vote bit set. The leader always
        //     votes for its own entries.
        if (s->status == STATUS_NORMAL && is_leader(s)) {
            int idx = self_idx(s);
            for (int k = s->commit_index; k < s->log.count; k++) {
                if (!(s->log.entries[k].votes & (1 << idx))) {
                    fprintf(stderr, "INVARIANT VIOLATED: node %d (leader): "
                        "uncommitted log[%d] missing leader's own vote bit\n",
                        i, k);
                    __builtin_trap();
                }
            }
        }
    }

    // Cross-node invariants

    // 5. At most one leader in normal status per view.
    for (int i = 0; i < num_nodes; i++) {
        if (nodes[i] == NULL || nodes[i]->status != STATUS_NORMAL || !is_leader(nodes[i]))
            continue;
        for (int j = i + 1; j < num_nodes; j++) {
            if (nodes[j] == NULL || nodes[j]->status != STATUS_NORMAL || !is_leader(nodes[j]))
                continue;
            if (nodes[i]->view_number == nodes[j]->view_number) {
                fprintf(stderr, "INVARIANT VIOLATED: two normal leaders in view %lu: node %d and node %d\n",
                    (unsigned long)nodes[i]->view_number, i, j);
                __builtin_trap();
            }
        }
    }

    // 6. Committed prefix agreement (State Machine Safety).
    //    For any two nodes, their logs must agree on all entries up to
    //    min(commit_index_i, commit_index_j). This is the core safety
    //    property of VSR: all committed operations are identical across
    //    replicas.
    for (int i = 0; i < num_nodes; i++) {
        if (nodes[i] == NULL)
            continue;
        for (int j = i + 1; j < num_nodes; j++) {
            if (nodes[j] == NULL)
                continue;

            int mc = nodes[i]->commit_index;
            if (nodes[j]->commit_index < mc)
                mc = nodes[j]->commit_index;

            for (int k = 0; k < mc; k++) {
                if (memcmp(&nodes[i]->log.entries[k].oper, &nodes[j]->log.entries[k].oper, sizeof(MetaOper)) != 0) {
                    fprintf(stderr, "INVARIANT VIOLATED: committed log operation mismatch at index %d "
                        "between node %d and node %d\n", k, i, j);
                    __builtin_trap();
                }
            }
        }
    }

    ////////////////////////////////////////////////////////////////////
    // Shadow log: external commit tracking
    ////////////////////////////////////////////////////////////////////

    // Phase 1: Find the observed max commit index and a source node.
    int observed_max_commit = 0;
    int source_node_idx = -1;

    for (int i = 0; i < num_nodes; i++) {
        if (nodes[i] == NULL)
            continue;
        if (nodes[i]->status == STATUS_RECOVERY)
            continue;
        if (nodes[i]->commit_index > observed_max_commit) {
            observed_max_commit = nodes[i]->commit_index;
            source_node_idx = i;
        }
    }

    // Phase 2: Append newly committed entries to the shadow log.
    if (source_node_idx >= 0 && observed_max_commit > ic->shadow_count) {

        Server *source = nodes[source_node_idx];
        assert(source->log.count >= observed_max_commit);

        for (int k = ic->shadow_count; k < observed_max_commit; k++) {

            MetaOper *source_oper = &source->log.entries[k].oper;

            // Cross-validate against other live non-recovering nodes
            // that have also committed this entry.
            for (int j = 0; j < num_nodes; j++) {
                if (j == source_node_idx)
                    continue;
                if (nodes[j] == NULL)
                    continue;
                if (nodes[j]->status == STATUS_RECOVERY)
                    continue;
                if (nodes[j]->commit_index <= k)
                    continue;
                if (nodes[j]->log.count <= k)
                    continue;

                if (memcmp(&nodes[j]->log.entries[k].oper, source_oper, sizeof(MetaOper)) != 0) {
                    fprintf(stderr, "INVARIANT VIOLATED: committed entry mismatch at index %d "
                        "between source node %d and node %d during shadow log append\n",
                        k, source_node_idx, j);
                    __builtin_trap();
                }
            }

            if (shadow_log_append(ic, *source_oper) < 0) {
                fprintf(stderr, "INVARIANT CHECKER: shadow log allocation failed\n");
                __builtin_trap();
            }
        }
    }

    // Phase 3: Verify shadow log against the cluster.

    // Sub-check A: Committed entries must match the shadow log.
    for (int k = 0; k < ic->shadow_count; k++) {
        for (int i = 0; i < num_nodes; i++) {
            if (nodes[i] == NULL)
                continue;
            if (nodes[i]->log.count <= k)
                continue;
            if (nodes[i]->commit_index <= k)
                continue;

            if (memcmp(&nodes[i]->log.entries[k].oper, &ic->shadow_log[k], sizeof(MetaOper)) != 0) {
                char shadow_buf[128], node_buf[128];
                meta_snprint_oper(shadow_buf, sizeof(shadow_buf), &ic->shadow_log[k]);
                meta_snprint_oper(node_buf, sizeof(node_buf), &nodes[i]->log.entries[k].oper);
                fprintf(stderr, "INVARIANT VIOLATED: shadow log mismatch at index %d on node %d\n"
                    "  shadow: %s\n"
                    "  node:   %s\n",
                    k, i, shadow_buf, node_buf);
                __builtin_trap();
            }
        }
    }

    // Sub-check B: When commit regresses, previously committed entries
    // must still be held by a majority of the cluster.
    // Recovering nodes are treated like dead nodes: they haven't
    // restored their log yet and may still recover the entry through
    // the recovery protocol.
    if (observed_max_commit < ic->shadow_count) {
        for (int k = observed_max_commit; k < ic->shadow_count; k++) {
            int holders = 0;
            int num_dead = 0;

            for (int i = 0; i < num_nodes; i++) {
                if (nodes[i] == NULL) {
                    num_dead++;
                    continue;
                }
                if (nodes[i]->status == STATUS_RECOVERY) {
                    num_dead++;
                    continue;
                }
                if (nodes[i]->log.count <= k)
                    continue;
                if (memcmp(&nodes[i]->log.entries[k].oper, &ic->shadow_log[k], sizeof(MetaOper)) == 0)
                    holders++;
            }

            if (holders + num_dead <= num_nodes / 2) {
                char oper_buf[128];
                meta_snprint_oper(oper_buf, sizeof(oper_buf), &ic->shadow_log[k]);
                fprintf(stderr, "INVARIANT VIOLATED: previously committed entry at index %d "
                    "no longer held by majority (holders=%d, dead=%d, total=%d)\n"
                    "  entry: %s\n",
                    k, holders, num_dead, num_nodes, oper_buf);
                __builtin_trap();
            }
        }
    }

    ////////////////////////////////////////////////////////////////////
    // Blob invariants: newly committed PUT entries must have their
    // chunks stored on at least one live server's disk.
    ////////////////////////////////////////////////////////////////////
    //
    // Only check newly committed entries (since last run) to avoid
    // O(total_entries * ticks) cost. Uses quakey_enter_host to access
    // each server's mock filesystem.
    if (node_handles != NULL && observed_max_commit > 0) {

        // Check the most recently committed entries for chunk presence
        for (int k = MAX(0, ic->shadow_count - 5); k < ic->shadow_count; k++) {
            MetaOper *oper = &ic->shadow_log[k];
            if (oper->type != META_OPER_PUT)
                continue;

            for (uint32_t c = 0; c < oper->num_chunks; c++) {
                SHA256 hash = oper->chunks[c].hash;

                int holders = 0;
                int num_dead = 0;
                for (int i = 0; i < num_nodes; i++) {
                    if (nodes[i] == NULL) {
                        num_dead++;
                        continue;
                    }
                    // Enter host context to access its mock filesystem
                    quakey_enter_host(node_handles[i]);
                    bool has_chunk = chunk_store_exists(&nodes[i]->chunk_store, hash);
                    quakey_leave_host();

                    if (has_chunk)
                        holders++;
                }

                // Chunk must exist on at least one server, OR all
                // non-holders are dead (they may have had it before crash).
                if (holders == 0 && num_dead < num_nodes) {
                    fprintf(stderr, "INVARIANT VIOLATED: committed blob %s/%s "
                        "chunk %u not found on any live server "
                        "(holders=%d, dead=%d)\n",
                        oper->bucket, oper->key, c, holders, num_dead);
                    __builtin_trap();
                }
            }
        }
    }
}
