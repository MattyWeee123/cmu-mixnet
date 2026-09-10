/**
 * Copyright (C) 2023 Carnegie Mellon University
 *
 * This file is part of the Mixnet course project developed for
 * the Computer Networks course (15-441/641) taught at Carnegie
 * Mellon University.
 *
 * No part of the Mixnet project may be copied and/or distributed
 * without the express permission of the 15-441/641 course staff.
 */
#include "common/testing.h"

#include <stdio.h>

/**
 * This test-case checks STP reconvergence when a link *inside* the tree
 * fails while the root stays up. testcase_link_failure_root covers the
 * complementary case (the root itself disappears, forcing re-election);
 * here the root never changes, so the interesting work is re-parenting
 * and, crucially, un-blocking a link that STP had previously blocked.
 *
 * Topology: a 5-node ring, addresses chosen so node 0 (addr 10) wins the
 * root election. STP should converge to
 *
 *      1 --- 0 --- 4              tree links: 0-1, 1-2, 0-4, 4-3
 *      |           |              blocked:    2-3 (both ends sit 2 hops
 *      2 -//- 3 ---+                           from the root, so neither
 *                                              improves the other)
 *
 * Killing link 0-1 strands node 1, whose only remaining neighbor is 2.
 * Recovering requires the blocked 2-3 link to come back into service and
 * the whole 1-2-3-4-0 line to become the tree. A node that never unblocks
 * 2-3 partitions FLOOD traffic into {1,2} and {0,3,4}, which shows up
 * immediately in the packet counts below.
 *
 * Restoring the link then exercises the reverse: 2-3 must be re-blocked.
 * If it isn't, the restored ring carries a broadcast storm, so that phase
 * overshoots rather than undershoots.
 *
 * As in testcase_tiebreak_pathlen, we can't observe the tree directly
 * (the pcap harness only sees packets delivered to a node's user), so
 * connectivity of FLOOD traffic is the proxy for tree shape.
 */
class testcase_reconverge_link_failure final : public testcase {
private:
    // A FLOOD from any source reaches every *other* node exactly once
    static constexpr uint64_t kPcapPerFlood = 4;

    // Per-phase pcap counts, measured post-convergence (see note in run())
    uint64_t counted_[3] = {0, 0, 0};

    // Flood once from every node and return the resulting pcap count
    error_code flood_from_all(orchestrator& o, uint64_t *const out) {
        const uint64_t before = pcap_count_;
        for (uint16_t i = 0; i < graph_->num_nodes; i++) {
            DIE_ON_ERROR(o.send_packet(i, 0, PACKET_TYPE_FLOOD));
        }
        await_packet_propagation();

        *out = (pcap_count_ - before);
        return error_code::NONE;
    }

public:
    explicit testcase_reconverge_link_failure() :
        testcase("testcase_reconverge_link_failure") {}

    virtual void pcap(const uint16_t, const mixnet_packet
                                *const packet) override {
        if (packet->type == PACKET_TYPE_FLOOD) {
            pcap_count_++;
        }
    }

    virtual void setup() override {
        init_graph(5);
        graph_->generate_topology(graph::type::RING);

        // Node 0 has the lowest address, so it is the root both before
        // and after the failure. Spacing the rest out keeps the parent
        // tie-break (lowest neighbor address) unambiguous.
        graph_->set_mixaddrs({10, 20, 30, 40, 50});
    }

    /**
     * Note on measurement: each phase is counted as a delta taken *after*
     * that phase's await_convergence(), never across a change_link_state().
     * A disabled link is only half-disabled by the harness -- fragment::
     * node_send() ignores link_states, so the peer keeps writing into the
     * socket, while the receiver stops draining it (fragment.cpp:220) and
     * only flushes on disable, not on re-enable (fragment.cpp:1057). So
     * re-enabling a link dumps every packet sent at it while it was down.
     * That backlog lands during the convergence window; counting from a
     * post-convergence baseline keeps it out of the assertions.
     */
    virtual error_code run(orchestrator& o) override {
        await_convergence(); // Await initial STP convergence

        // Subscribe to packets from all nodes
        for (uint16_t i = 0; i < graph_->num_nodes; i++) {
            DIE_ON_ERROR(o.pcap_change_subscription(i, true));
        }

        // Phase 1: baseline. The ring is intact and 2-3 is blocked, so a
        // FLOOD from each node reaches every other node exactly once.
        DIE_ON_ERROR(flood_from_all(o, &counted_[0]));

        // Phase 2: sever an active tree link, leaving the root reachable.
        // Every node must still reach every other node, which is only
        // possible if the formerly-blocked 2-3 link is now forwarding.
        DIE_ON_ERROR(o.change_link_state(0, 1, false));
        await_convergence(); // Await STP reconvergence
        DIE_ON_ERROR(flood_from_all(o, &counted_[1]));

        // Phase 3: heal the link. The ring is cyclic again, so STP has to
        // re-block 2-3 or FLOOD packets will loop.
        DIE_ON_ERROR(o.change_link_state(0, 1, true));
        await_convergence(); // Await STP reconvergence
        DIE_ON_ERROR(flood_from_all(o, &counted_[2]));

        return error_code::NONE;
    }

    virtual void teardown() override {
        const uint64_t expected = (kPcapPerFlood * graph_->num_nodes);

        pass_teardown_ = ((counted_[0] == expected) &&
                          (counted_[1] == expected) &&
                          (counted_[2] == expected));

        if (!pass_teardown_) {
            fprintf(stderr, "[%s] expected %lu pcaps per phase, got "
                    "%lu (intact), %lu (link down), %lu (link back)\n",
                    name.c_str(), (unsigned long) expected,
                    (unsigned long) counted_[0],
                    (unsigned long) counted_[1],
                    (unsigned long) counted_[2]);
        }
    }
};

int main(int argc, char **argv) {
    testcase_reconverge_link_failure tc; // Run testcase
    return testcase::run_testcase(tc, argc, argv);
}
