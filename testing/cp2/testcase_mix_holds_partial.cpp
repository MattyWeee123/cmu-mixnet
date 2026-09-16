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

/**
 * "Exact number" means exact. A line of three whose middle node mixes two:
 *
 *     10 --- [20, k=2] --- 30
 *
 * One packet is not a batch, so node 20 holds it for the rest of the run and
 * node 30 never hears from node 10. The non-delivery is the assertion: an
 * implementation that flushed a partial batch, on a timer or at shutdown,
 * would pass every other mixing test and fail only this one.
 *
 * It also pins down what mixing does *not* apply to. Node 20 keeps sending
 * STP and LSA traffic while it holds the packet, so the tree stays converged
 * and the failure below can only be the DATA packet arriving early.
 */
class testcase_mix_holds_partial final : public testcase {
public:
    explicit testcase_mix_holds_partial() :
        testcase("testcase_mix_holds_partial") {}

    virtual void pcap(const uint16_t fragment_id,
                      const mixnet_packet *const packet) override {

        fprintf(stderr, "[%s] node %u received a type-%u packet, but the "
                "batch at node 20 was one packet short\n", name.c_str(),
                (unsigned) fragment_id, (unsigned) packet->type);

        pass_pcap_ = false;
        pcap_count_++;
    }

    virtual void setup() override {
        init_graph(3);
        graph_->generate_topology(graph::type::LINE);
        graph_->set_mixaddrs({10, 20, 30});
        graph_->get_node(1).set_mixing_factor(2);
    }

    virtual error_code run(orchestrator& o) override {
        await_convergence(); // STP, then LSA flooding and Dijkstra

        for (uint16_t i = 0; i < graph_->num_nodes; i++) {
            DIE_ON_ERROR(o.pcap_change_subscription(i, true));
        }
        DIE_ON_ERROR(o.send_packet(0, 2, PACKET_TYPE_DATA, "held forever"));

        await_packet_propagation();
        return error_code::NONE;
    }

    virtual void teardown() override {
        pass_teardown_ = (pcap_count_ == 0);
    }
};

int main(int argc, char **argv) {
    testcase_mix_holds_partial tc; // Run testcase
    return testcase::run_testcase(tc, argc, argv);
}
