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
#ifndef TESTING_COMMON_ROUTING_TESTCASE_H_
#define TESTING_COMMON_ROUTING_TESTCASE_H_

#include "graph.h"
#include "testcase.h"
#include "framework/orchestrator.h"
#include "mixnet/packet.h"

#include <stdio.h>
#include <string>
#include <utility>
#include <vector>

namespace testing {

/**
 * Base class for source-routing tests. A test declares a table of flows,
 * each one DATA packet from a source node to a destination node together
 * with the route the source is expected to choose, and builds its weighted
 * topology in setup(). This class sends every flow once STP and link-state
 * routing have converged, checks each delivery against the table, and
 * requires every flow to be delivered exactly once.
 *
 * A delivery is matched to its flow by source and destination address, so
 * those pairs must be unique within a test.
 */
class routing_testcase : public testcase {
protected:
    struct flow {
        uint16_t src;                           // Source node index
        uint16_t dst;                           // Destination node index
        std::vector<mixnet_address> route;      // Expected hops, excluding src and dst
        std::string data;                       // Payload, checked on delivery
    };

    const std::vector<flow> flows_;
    std::vector<uint64_t> deliveries_;          // Per flow

    routing_testcase(const std::string& name, std::vector<flow> flows) :
        testcase(name), flows_(std::move(flows)),
        deliveries_(flows_.size(), 0) {}

    // The flow a delivered packet belongs to, or -1 if none matches
    int find_flow(const mixnet_packet_routing_header *const rh) const {
        for (size_t i = 0; i < flows_.size(); i++) {
            if ((graph_->get_node(flows_[i].src).mixaddr() == rh->src_address) &&
                (graph_->get_node(flows_[i].dst).mixaddr() == rh->dst_address)) {
                return static_cast<int>(i);
            }
        }
        return -1;
    }

    static std::string route_to_string(const mixnet_address *const route,
                                       const size_t length) {
        std::string s = "{";
        for (size_t i = 0; i < length; i++) {
            s += ((i > 0) ? ", " : "") + std::to_string(route[i]);
        }
        return s + "}";
    }

public:
    virtual void pcap(const uint16_t fragment_id,
                      const mixnet_packet *const packet) override {

        if (packet->type != PACKET_TYPE_DATA) { pass_pcap_ = false; return; }
        auto rh = reinterpret_cast<const
            mixnet_packet_routing_header*>(packet->payload());

        const int idx = find_flow(rh);
        if (idx < 0) {
            fprintf(stderr, "[%s] unexpected packet %u -> %u at node %u\n",
                    name.c_str(), (unsigned) rh->src_address,
                    (unsigned) rh->dst_address, (unsigned) fragment_id);
            pass_pcap_ = false;
            return;
        }
        const flow& f = flows_[idx];
        const bool ok = ((fragment_id == f.dst) &&
                         check_route(rh, f.route) &&
                         check_data(packet, f.data));
        if (!ok) {
            fprintf(stderr, "[%s] flow %u -> %u: delivered at node %u with "
                    "route %s, expected node %u with route %s\n",
                    name.c_str(), (unsigned) f.src, (unsigned) f.dst,
                    (unsigned) fragment_id,
                    route_to_string(rh->route(), rh->route_length).c_str(),
                    (unsigned) f.dst,
                    route_to_string(f.route.data(), f.route.size()).c_str());
        }
        pass_pcap_ &= ok;
        deliveries_[idx]++;
        pcap_count_++;
    }

    virtual framework::error_code run(framework::orchestrator& o) override {
        await_convergence(); // STP, then LSA flooding and Dijkstra

        for (uint16_t i = 0; i < graph_->num_nodes; i++) {
            error_ = o.pcap_change_subscription(i, true);
            if (error_ != framework::error_code::NONE) { return error_; }
        }
        for (const flow& f : flows_) {
            error_ = o.send_packet(f.src, f.dst, PACKET_TYPE_DATA, f.data);
            if (error_ != framework::error_code::NONE) { return error_; }
        }
        await_packet_propagation();
        return framework::error_code::NONE;
    }

    virtual void teardown() override {
        pass_teardown_ = true;
        for (size_t i = 0; i < flows_.size(); i++) {
            if (deliveries_[i] != 1) {
                pass_teardown_ = false;
                fprintf(stderr, "[%s] flow %u -> %u: delivered %lu times, "
                        "expected once\n", name.c_str(),
                        (unsigned) flows_[i].src, (unsigned) flows_[i].dst,
                        (unsigned long) deliveries_[i]);
            }
        }
    }
};

} // namespace testing

#endif // TESTING_COMMON_ROUTING_TESTCASE_H_
