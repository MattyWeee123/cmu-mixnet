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
 * Zero-cost links. Two neighbors of node 10 reach node 40 over free links,
 * so both paths to 40 cost 1 and the smaller first hop, 30, must win. This
 * is the case a Dijkstra that settles vertices by cost alone gets wrong: it
 * may settle 40 through 50 before it has looked at 30, and never revisit.
 *
 *            50
 *         1/    \0
 *       10        40 --1-- 60
 *         1\    /0
 *            30
 */
class testcase_sp_zero_cost final : public routing_testcase {
public:
    explicit testcase_sp_zero_cost() :
        routing_testcase("testcase_sp_zero_cost", {
            {0, 3, {30},     "free hop"},
            {0, 4, {30, 40}, "free hop, then a paid one"},
            {3, 0, {30},     "free hop back"},
        }) {}

    virtual void setup() override {
        init_graph(5);
        graph_->set_mixaddrs({10, 50, 30, 40, 60});
        graph_->add_edge(0, 1).add_edge({1, 0}, {3, 0});   // Via 50, then free
        graph_->add_edge(0, 2).add_edge({2, 0}, {3, 0});   // Via 30, then free
        graph_->add_edge(3, 4);
    }
};

int main(int argc, char **argv) {
    testcase_sp_zero_cost tc; // Run testcase
    return testcase::run_testcase(tc, argc, argv);
}
