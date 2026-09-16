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
 * A mixing factor above two, so that a node releasing anything before its
 * batch is full is caught by more than an off-by-one:
 *
 *     10 --- 20 --- [30, k=4] --- 40 --- 50
 *
 * Four flows cross node 30, the two outer ones end to end and the two inner
 * ones between its immediate neighbors, so it fills exactly one batch. The
 * inner flows also make the point that a mixing node does not care how far
 * a packet has travelled, only that it is on its way out over the network.
 */
class testcase_mix_batch_of_four final : public routing_testcase {
public:
    explicit testcase_mix_batch_of_four() :
        routing_testcase("testcase_mix_batch_of_four", {
            {0, 4, {20, 30, 40}, "outer, left to right"},
            {4, 0, {40, 30, 20}, "outer, right to left"},
            {1, 3, {30},         "inner, left to right"},
            {3, 1, {30},         "inner, right to left"},
        }) {}

    virtual void setup() override {
        init_graph(5);
        graph_->generate_topology(graph::type::LINE);
        graph_->set_mixaddrs({10, 20, 30, 40, 50});
        graph_->get_node(2).set_mixing_factor(4);
    }
};

int main(int argc, char **argv) {
    testcase_mix_batch_of_four tc; // Run testcase
    return testcase::run_testcase(tc, argc, argv);
}
