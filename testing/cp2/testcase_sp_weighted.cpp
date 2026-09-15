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
 * Shortest path by cost, not by hop count. A 5-node ring where the one link
 * closing the ring is expensive, so the cheapest path between its endpoints
 * is the long way round, and every path that would use it loses to one that
 * does not.
 *
 *     10 --1-- 20 --1-- 30 --1-- 40 --1-- 50
 *      \_________________10_______________/
 */
class testcase_sp_weighted final : public routing_testcase {
public:
    explicit testcase_sp_weighted() :
        routing_testcase("testcase_sp_weighted", {
            {0, 4, {20, 30, 40}, "four beats ten"},
            {4, 0, {40, 30, 20}, "and back again"},
            {1, 4, {30, 40},     "three beats eleven"},
            {3, 0, {30, 20},     "three beats eleven, other side"},
        }) {}

    virtual void setup() override {
        init_graph(5);
        graph_->set_mixaddrs({10, 20, 30, 40, 50});
        for (uint16_t i = 0; i < 4; i++) { graph_->add_edge(i, i + 1); }
        graph_->add_edge({4, 10}, {0, 10});
    }
};

int main(int argc, char **argv) {
    testcase_sp_weighted tc; // Run testcase
    return testcase::run_testcase(tc, argc, argv);
}
