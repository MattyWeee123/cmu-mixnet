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
#include "common/routing_testcase.h"
#include "common/testing.h"

/**
 * Two mixing nodes in series: a full batch has to survive being mixed again
 * further along its path.
 *
 *     10 --- [20, k=2] --- 30 --- [40, k=2] --- 50
 *
 * Both flows run left to right, one starting at node 10 and one at node 20
 * itself, so node 20 fills its batch from a forwarded packet and one of its
 * own and releases both; node 40 then fills its batch from that pair.
 *
 * The directions are deliberate. Pairing 10 -> 50 with 50 -> 10 also gives
 * each mixer a count of two, but it deadlocks: node 20 would be holding the
 * rightbound packet while waiting for the leftbound one, which node 40 is
 * holding while waiting for the rightbound one. Neither can ever arrive.
 * Counting the packets that cross a node is necessary but not sufficient -
 * they also have to be able to reach it.
 */
class testcase_mix_chain final : public routing_testcase {
public:
    explicit testcase_mix_chain() :
        routing_testcase("testcase_mix_chain", {
            {0, 4, {20, 30, 40}, "through both mixers"},
            {1, 4, {30, 40},     "joining the batch at the first mixer"},
        }) {}

    virtual void setup() override {
        init_graph(5);
        graph_->generate_topology(graph::type::LINE);
        graph_->set_mixaddrs({10, 20, 30, 40, 50});
        graph_->get_node(1).set_mixing_factor(2);
        graph_->get_node(3).set_mixing_factor(2);
    }
};

int main(int argc, char **argv) {
    testcase_mix_chain tc; // Run testcase
    return testcase::run_testcase(tc, argc, argv);
}
