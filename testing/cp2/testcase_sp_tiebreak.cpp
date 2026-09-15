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
 * Equal-cost paths are broken by the smallest first-hop address: not by
 * port order, not by the smallest address anywhere on the path, and not
 * by the smallest predecessor of the destination.
 *
 *          70 ---- 5
 *         /         \
 *       10           40         every link costs 1
 *         \         /
 *          25 ---- 90
 *
 * From 10 to 40 both paths cost 3. The first hops are 70 and 25, so 25 wins,
 * even though 70 is on 10's port 0, even though the other path runs through
 * the smallest address of all (5), and even though 5 is the smaller of 40's
 * two predecessors. From 40 to 10 the first hops are 5 and 90, so 5 wins.
 */
class testcase_sp_tiebreak final : public routing_testcase {
public:
    explicit testcase_sp_tiebreak() :
        routing_testcase("testcase_sp_tiebreak", {
            {0, 3, {25, 90}, "smallest first hop"},
            {3, 0, {5, 70},  "smallest first hop, other way"},
        }) {}

    virtual void setup() override {
        init_graph(6);
        graph_->set_mixaddrs({10, 70, 25, 40, 5, 90});
        graph_->add_edge(0, 1).add_edge(1, 4).add_edge(4, 3);   // Upper path
        graph_->add_edge(0, 2).add_edge(2, 5).add_edge(5, 3);   // Lower path
    }
};

int main(int argc, char **argv) {
    testcase_sp_tiebreak tc; // Run testcase
    return testcase::run_testcase(tc, argc, argv);
}
