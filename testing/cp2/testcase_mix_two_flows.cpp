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
 * Mixing with one mixing node. A line of five in which only the middle node
 * batches:
 *
 *     10 --- 20 --- [30, k=2] --- 40 --- 50
 *
 * The two flows cross node 30 from opposite sides, so together they are
 * exactly the batch it waits for: neither is delivered until both have
 * reached it, and then both are. Traffic arriving on different links and
 * leaving together is the whole point of the feature.
 *
 * Node 30 must see a multiple of its mixing factor or the run ends with
 * packets still held, which is why the flow table is counted per node that
 * a packet *crosses* rather than per flow sent.
 */
class testcase_mix_two_flows final : public routing_testcase {
public:
    explicit testcase_mix_two_flows() :
        routing_testcase("testcase_mix_two_flows", {
            {0, 4, {20, 30, 40}, "Never gonna give you up"},
            {4, 0, {40, 30, 20}, "Never gonna let you down"},
        }) {}

    virtual void setup() override {
        init_graph(5);
        graph_->generate_topology(graph::type::LINE);
        graph_->set_mixaddrs({10, 20, 30, 40, 50});
        graph_->get_node(2).set_mixing_factor(2);
    }
};

int main(int argc, char **argv) {
    testcase_mix_two_flows tc; // Run testcase
    return testcase::run_testcase(tc, argc, argv);
}
