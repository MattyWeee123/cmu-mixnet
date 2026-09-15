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
 * FLOOD on an even-length ring. Every public ring test uses an odd ring,
 * where the two deepest nodes sit at equal depth and block each other as
 * siblings. On an even ring the single deepest node has *two* neighbors
 * one hop closer to the root, only one of which is its parent. The other
 * one must be blocked too, or the ring stays cyclic and FLOODs storm.
 *
 *      0 (root)
 *     / \
 *    1   3        tree: 0-1, 0-3, 1-2.   Must be blocked: 2-3.
 *     \ /
 *      2
 */
class testcase_ring_even final : public testcase {
private:
    static constexpr uint16_t kNumNodes = 4;
    static constexpr uint64_t kRounds = 3;
    uint64_t counted_ = 0;

public:
    explicit testcase_ring_even() :
        testcase("testcase_ring_even") {}

    virtual void pcap(const uint16_t, const mixnet_packet
                                *const packet) override {
        if (packet->type == PACKET_TYPE_FLOOD) { pcap_count_++; }
    }

    virtual void setup() override {
        init_graph(kNumNodes);
        graph_->generate_topology(graph::type::RING);
        // Node 0 is the root; node 2 tie-breaks onto node 1 (20 < 40)
        graph_->set_mixaddrs({10, 20, 30, 40});
    }

    virtual error_code run(orchestrator& o) override {
        await_convergence();

        for (uint16_t i = 0; i < graph_->num_nodes; i++) {
            DIE_ON_ERROR(o.pcap_change_subscription(i, true));
        }
        for (uint64_t r = 0; r < kRounds; r++) {
            for (uint16_t i = 0; i < graph_->num_nodes; i++) {
                DIE_ON_ERROR(o.send_packet(i, 0, PACKET_TYPE_FLOOD));
            }
        }
        await_packet_propagation();
        counted_ = pcap_count_;
        return error_code::NONE;
    }

    virtual void teardown() override {
        // Each FLOOD reaches every *other* node exactly once
        const uint64_t expected = kRounds * kNumNodes * (kNumNodes - 1);
        pass_teardown_ = (counted_ == expected);
        if (!pass_teardown_) {
            fprintf(stderr, "[%s] expected %lu pcaps, got %lu\n",
                    name.c_str(), (unsigned long) expected,
                    (unsigned long) counted_);
        }
    }
};

int main(int argc, char **argv) {
    testcase_ring_even tc;
    return testcase::run_testcase(tc, argc, argv);
}
