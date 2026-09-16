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

#include <set>
#include <vector>

/**
 * Random routing, on the handout's own hub-and-spoke figure:
 *
 *          20        30
 *            \      /
 *             \    /
 *      [10] --- 1 --- 40
 *
 * Node 10 randomizes; every other node routes normally. The handout's bar is
 * that a node "generates at least two distinct routes" given enough packets,
 * so a single delivery proves nothing and this sends a run of them.
 *
 * Exact-route assertions are what the sp_* tests do and they cannot work
 * here, so the checks are the two properties that survive randomness: every
 * delivered route has to be a walk the topology can actually carry, and the
 * set of them has to contain more than one. A star is the right shape for
 * this - every detour doubles back through the hub, which is exactly where a
 * route assembled without its waypoint would come apart.
 */
class testcase_random_routing final : public testcase {
private:
    static const unsigned NUM_PACKETS = 24;

    std::set<std::vector<mixnet_address>> routes_;  // Distinct routes seen
    unsigned unwalkable_ = 0;
    const std::string data_ = "the scenic route";

    /** Are two nodes, named by mixnet address, joined by a link? */
    bool adjacent(const mixnet_address a, const mixnet_address b) const {
        const int ia = graph_->get_node_id(a);
        const int ib = graph_->get_node_id(b);
        if ((ia < 0) || (ib < 0)) { return false; }

        for (const uint16_t n : graph_->topology().at(ia)) {
            if (n == ib) { return true; }
        }
        return false;
    }

public:
    explicit testcase_random_routing() : testcase("testcase_random_routing") {}

    virtual void pcap(const uint16_t fragment_id,
                      const mixnet_packet *const packet) override {

        if (packet->type != PACKET_TYPE_DATA) { pass_pcap_ = false; return; }
        auto rh = reinterpret_cast<const
            mixnet_packet_routing_header*>(packet->payload());

        pass_pcap_ &= (fragment_id == 4);                       // Only 40 delivers
        pass_pcap_ &= (rh->src_address == graph_->get_node(0).mixaddr());
        pass_pcap_ &= (rh->dst_address == graph_->get_node(4).mixaddr());
        pass_pcap_ &= check_data(packet, data_);

        // Every consecutive pair on src -> route -> dst must be a real link
        std::vector<mixnet_address> route;
        mixnet_address prev = rh->src_address;
        bool ok = true;
        for (uint16_t i = 0; i < rh->route_length; i++) {
            const mixnet_address hop = rh->route()[i];
            ok &= adjacent(prev, hop);
            route.push_back(hop);
            prev = hop;
        }
        ok &= adjacent(prev, rh->dst_address);

        if (!ok) {
            fprintf(stderr, "[%s] delivered an unwalkable route of %u hops\n",
                    name.c_str(), (unsigned) rh->route_length);
            unwalkable_++;
            pass_pcap_ = false;
        }
        routes_.insert(route);
        pcap_count_++;
    }

    virtual void setup() override {
        init_graph(5);
        graph_->set_mixaddrs({10, 1, 20, 30, 40});
        for (uint16_t spoke = 2; spoke < 5; spoke++) {
            graph_->add_edge(1, spoke);         // Hub is node id 1 (address 1)
        }
        graph_->add_edge(1, 0);                 // ... and node id 0 (address 10)
        graph_->get_node(0).set_use_random_routing(true);
    }

    virtual error_code run(orchestrator& o) override {
        await_convergence(); // STP, then LSA flooding and Dijkstra

        for (uint16_t i = 0; i < graph_->num_nodes; i++) {
            DIE_ON_ERROR(o.pcap_change_subscription(i, true));
        }
        for (unsigned i = 0; i < NUM_PACKETS; i++) {
            DIE_ON_ERROR(o.send_packet(0, 4, PACKET_TYPE_DATA, data_));
        }
        await_packet_propagation();
        return error_code::NONE;
    }

    virtual void teardown() override {
        pass_teardown_ = true;

        if (pcap_count_ != NUM_PACKETS) {
            fprintf(stderr, "[%s] %lu of %u packets were delivered\n",
                    name.c_str(), (unsigned long) pcap_count_, NUM_PACKETS);
            pass_teardown_ = false;
        }
        if (unwalkable_ != 0) {
            fprintf(stderr, "[%s] %u routes could not be walked\n",
                    name.c_str(), unwalkable_);
            pass_teardown_ = false;
        }
        if (routes_.size() < 2) {
            fprintf(stderr, "[%s] only %lu distinct route(s) in %u packets; "
                    "the handout requires at least two\n", name.c_str(),
                    (unsigned long) routes_.size(), NUM_PACKETS);
            pass_teardown_ = false;
        }
    }
};

int main(int argc, char **argv) {
    testcase_random_routing tc; // Run testcase
    return testcase::run_testcase(tc, argc, argv);
}
