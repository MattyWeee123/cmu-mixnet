/**
 * Unit tests for CP2 mixing (see docs/cp2-lsa-plan.md §3).
 *
 * Mixing is hard to pin down from the orchestrator: pcap shows a node's user
 * port, so it can say that k packets eventually arrived but not that they
 * left the mixing node together, and never that the k-1'th one was still
 * being held. Both of those are the actual specification. So, as in
 * test_lsa.c, this links node.c directly and stubs the framework, which lets
 * each test watch the wire one packet at a time.
 */
#include "mixnet/node.c"

#include <stdio.h>

/**
 * Test harness.
 */
static unsigned checks_run = 0;
static unsigned checks_failed = 0;
static const char *current_test = "";

#define CHECK(cond, ...)                                                \
    do {                                                                \
        checks_run++;                                                   \
        if (!(cond)) {                                                  \
            checks_failed++;                                            \
            printf("  FAIL %s:%d: ", current_test, __LINE__);           \
            printf(__VA_ARGS__);                                        \
            printf("\n");                                               \
        }                                                               \
    } while (0)

#define RUN(test)                                                       \
    do {                                                                \
        current_test = #test;                                           \
        const unsigned before = checks_failed;                          \
        printf("%s\n", #test);                                          \
        test();                                                         \
        printf("  %s\n", (checks_failed == before) ? "ok" : "FAILED");  \
    } while (0)

/**
 * Framework stubs. mixnet_send() takes ownership, so each send is recorded
 * and the packet freed; the tests assert on the recording.
 */
#define MAX_SENT (64)

struct sent_packet {
    uint8_t port;
    mixnet_packet_type_t type;
    mixnet_address src;         // Routing header, for DATA and PING
    mixnet_address dst;
    bool is_request;            // PING only
};

static struct sent_packet sent[MAX_SENT];
static unsigned sent_count = 0;

static void sent_reset(void) { sent_count = 0; }

int mixnet_recv(void *handle, uint8_t *port, mixnet_packet **packet) {
    (void) handle; (void) port; (void) packet;
    return 0;   // Never used: the tests drive the handlers directly
}

/*
 * noinline because the real mixnet_send() lives in the framework, a separate
 * translation unit. Inlined here it lands inside broadcast_stp(), where the
 * compiler can see that the packet is an 18-byte STP packet, and warns that
 * the routing-header branch below would read past it - a branch that type
 * tag and size check between them make unreachable. Keeping the stub out of
 * line restores the boundary the real build has anyway.
 */
__attribute__((noinline))
int mixnet_send(void *handle, const uint8_t port, mixnet_packet *packet) {
    (void) handle;

    if (sent_count < MAX_SENT) {
        struct sent_packet *rec = &sent[sent_count++];
        rec->port = port;
        rec->type = packet->type;
        rec->src = INVALID_MIXADDR;
        rec->dst = INVALID_MIXADDR;
        rec->is_request = false;

        // The size check is what keeps this honest: STP packets also reach
        // this stub, and they are far too short to carry a routing header.
        if (((packet->type == PACKET_TYPE_DATA) ||
             (packet->type == PACKET_TYPE_PING)) &&
            routed_packet_is_well_formed(
                packet, packet->type == PACKET_TYPE_PING)) {

            const mixnet_packet_routing_header *rh = routing_header(packet);
            rec->src = rh->src_address;
            rec->dst = rh->dst_address;

            if (packet->type == PACKET_TYPE_PING) {
                rec->is_request = ping_fields(packet)->is_request;
            }
        }
    }
    free(packet);   // The real mixnet_send() owns the packet too
    return 1;
}

/**
 * Test fixtures.
 *
 * The topology under test, with costs of 1 throughout:
 *
 *     300 --- 200 --- [100] --- 201 --- 301
 *
 * Node 100 is the node under test: 200 is on port 0, 201 on port 1, and its
 * user port is 2. So a packet for 300 leaves on port 0, one for 301 on port
 * 1, and the two destinations exercise both ports within one batch.
 */
#define SELF        ((mixnet_address) 100)
#define NEIGHBOR_A  ((mixnet_address) 200)  // Port 0
#define NEIGHBOR_B  ((mixnet_address) 201)  // Port 1
#define FAR_A       ((mixnet_address) 300)  // Behind NEIGHBOR_A
#define FAR_B       ((mixnet_address) 301)  // Behind NEIGHBOR_B
#define USER_PORT   ((uint8_t) 2)

static uint16_t fixture_costs[2];

/** Advertise `origin`'s two links into the topology under test. */
static void advertise(struct node_state *s, const mixnet_address origin,
                      const mixnet_address peer_a, const mixnet_address peer_b) {

    const mixnet_lsa_link_params links[2] = { { peer_a, 1 }, { peer_b, 1 } };
    graph_update(&s->topology, origin, (peer_b == INVALID_MIXADDR) ? 1 : 2, links);
}

/**
 * A node with a converged tree, a full topology and a built FIB, mixing k
 * packets per batch. This is the state a node reaches before any of the
 * traffic in these tests arrives.
 */
static void fixture_init(struct mixnet_node_config *c, struct node_state *s,
                         const uint16_t mixing_factor) {

    fixture_costs[0] = 1;
    fixture_costs[1] = 1;

    c->node_addr = SELF;
    c->num_neighbors = 2;
    c->root_hello_interval_ms = 100;
    c->reelection_interval_ms = 1000;
    c->do_random_routing = false;
    c->mixing_factor = mixing_factor;
    c->link_costs = fixture_costs;

    if (!state_init(c, s)) { printf("  FATAL: state_init failed\n"); exit(1); }

    s->neighbor_addr[0] = NEIGHBOR_A;
    s->neighbor_addr[1] = NEIGHBOR_B;

    originate_lsa(NULL, c, s);              // Installs our own row
    advertise(s, NEIGHBOR_A, SELF, FAR_A);
    advertise(s, NEIGHBOR_B, SELF, FAR_B);
    advertise(s, FAR_A, NEIGHBOR_A, INVALID_MIXADDR);
    advertise(s, FAR_B, NEIGHBOR_B, INVALID_MIXADDR);
    update_shortest_path(c, s);

    sent_reset();   // Discard the LSA flood originate_lsa() produced
}

/**
 * A DATA packet as the user layer hands it over: source and destination set,
 * no route yet. The framework allocates user packets at the maximum size,
 * and source_route() relies on that room to insert the route, so the test
 * has to do the same.
 */
static mixnet_packet *make_user_data(const mixnet_address dst) {
    mixnet_packet *packet = calloc(1, MAX_MIXNET_PACKET_SIZE);
    if (packet == NULL) { printf("  FATAL: OOM\n"); exit(1); }

    packet->type = PACKET_TYPE_DATA;
    packet->total_size = (uint16_t) (sizeof(mixnet_packet) +
                                     sizeof(mixnet_packet_routing_header));
    mixnet_packet_routing_header *rh = routing_header(packet);
    rh->src_address = SELF;
    rh->dst_address = dst;
    rh->route_length = 0;
    rh->hop_index = 0;
    return packet;
}

/**
 * A DATA packet in flight, as it arrives from a neighbor: `route` is the
 * full list of intermediate hops and `hop_index` points at whichever one is
 * next, which for a packet arriving here is usually us.
 */
static mixnet_packet *make_transit_data(const mixnet_address src,
                                        const mixnet_address dst,
                                        const mixnet_address *const route,
                                        const uint16_t route_len,
                                        const uint16_t hop_index) {

    const size_t size = sizeof(mixnet_packet) +
                        sizeof(mixnet_packet_routing_header) +
                        (sizeof(mixnet_address) * route_len);

    mixnet_packet *packet = calloc(1, size);
    if (packet == NULL) { printf("  FATAL: OOM\n"); exit(1); }

    packet->type = PACKET_TYPE_DATA;
    packet->total_size = (uint16_t) size;

    mixnet_packet_routing_header *rh = routing_header(packet);
    rh->src_address = src;
    rh->dst_address = dst;
    rh->route_length = route_len;
    rh->hop_index = hop_index;
    for (uint16_t i = 0; i < route_len; i++) { rh->route[i] = route[i]; }
    return packet;
}

/** A PING request addressed to us, arriving from FAR_A via NEIGHBOR_A. */
static mixnet_packet *make_ping_for_us(void) {
    const mixnet_address route[1] = { NEIGHBOR_A };

    const size_t size = sizeof(mixnet_packet) +
                        sizeof(mixnet_packet_routing_header) +
                        sizeof(mixnet_address) + sizeof(mixnet_packet_ping);

    mixnet_packet *packet = calloc(1, size);
    if (packet == NULL) { printf("  FATAL: OOM\n"); exit(1); }

    packet->type = PACKET_TYPE_PING;
    packet->total_size = (uint16_t) size;

    mixnet_packet_routing_header *rh = routing_header(packet);
    rh->src_address = FAR_A;
    rh->dst_address = SELF;
    rh->route_length = 1;
    rh->hop_index = 1;           // Consumed: we are the destination
    rh->route[0] = route[0];

    mixnet_packet_ping *ping = ping_fields(packet);
    ping->is_request = true;
    ping->_pad[0] = 0;
    ping->send_time = 0;
    return packet;
}

/** How many packets of a type have gone out, on any port. */
static unsigned sends_of_type(const mixnet_packet_type_t type) {
    unsigned n = 0;
    for (unsigned i = 0; i < sent_count; i++) {
        if (sent[i].type == type) { n++; }
    }
    return n;
}

/**
 * A node holds packets back until it has exactly `mixing_factor` of them.
 * The k-1'th packet must produce no traffic at all: releasing anything
 * earlier would be a delay line rather than a mix.
 */
static void test_below_factor_holds_everything(void) {
    struct mixnet_node_config c; struct node_state s;
    fixture_init(&c, &s, 4);

    for (unsigned i = 0; i < 3; i++) {
        handle_routed(NULL, &c, &s, USER_PORT, make_user_data(FAR_A));
        CHECK(sent_count == 0, "packet %u of 4 should still be held, saw %u sends",
              i + 1, sent_count);
        CHECK(s.mix_count == (i + 1), "expected %u held, got %u",
              i + 1, (unsigned) s.mix_count);
    }
    state_free(&s);
}

/**
 * The k'th packet releases the whole batch, in arrival order, each on the
 * port its own route chose. Collect k, send k.
 */
static void test_batch_releases_all_in_order(void) {
    struct mixnet_node_config c; struct node_state s;
    fixture_init(&c, &s, 3);

    handle_routed(NULL, &c, &s, USER_PORT, make_user_data(FAR_A));
    handle_routed(NULL, &c, &s, USER_PORT, make_user_data(FAR_B));
    CHECK(sent_count == 0, "nothing should leave before the batch is full");

    handle_routed(NULL, &c, &s, USER_PORT, make_user_data(NEIGHBOR_A));
    CHECK(sent_count == 3, "expected the batch of 3, got %u", sent_count);
    CHECK(s.mix_count == 0, "the buffer should drain to empty, %u left",
          (unsigned) s.mix_count);

    // FIFO, and each on the port its destination implies
    CHECK((sent_count > 0) && (sent[0].dst == FAR_A) && (sent[0].port == 0),
          "first out should be FAR_A on port 0");
    CHECK((sent_count > 1) && (sent[1].dst == FAR_B) && (sent[1].port == 1),
          "second out should be FAR_B on port 1");
    CHECK((sent_count > 2) && (sent[2].dst == NEIGHBOR_A) && (sent[2].port == 0),
          "third out should be NEIGHBOR_A on port 0");

    state_free(&s);
}

/**
 * The buffer really is reusable: a second batch behaves like the first.
 * A node that released one packet per arrival instead of the batch would
 * pass the first assertion here and then trail permanently behind.
 */
static void test_second_batch_behaves_like_the_first(void) {
    struct mixnet_node_config c; struct node_state s;
    fixture_init(&c, &s, 2);

    for (unsigned batch = 0; batch < 3; batch++) {
        sent_reset();
        handle_routed(NULL, &c, &s, USER_PORT, make_user_data(FAR_A));
        CHECK(sent_count == 0, "batch %u: first packet should be held", batch);

        handle_routed(NULL, &c, &s, USER_PORT, make_user_data(FAR_A));
        CHECK(sent_count == 2, "batch %u: expected 2 sends, got %u",
              batch, sent_count);
    }
    state_free(&s);
}

/** A mixing factor of 1, the default, is the no-mixing case. */
static void test_factor_one_sends_immediately(void) {
    struct mixnet_node_config c; struct node_state s;
    fixture_init(&c, &s, 1);

    CHECK(s.mix == NULL, "factor 1 should not allocate a buffer");

    handle_routed(NULL, &c, &s, USER_PORT, make_user_data(FAR_A));
    CHECK(sent_count == 1, "expected an immediate send, got %u", sent_count);
    CHECK(s.mix_count == 0, "nothing should be held at factor 1");

    state_free(&s);
}

/**
 * One budget per node, not per port: the handout counts packets from the
 * user layer and from neighbors against a single number. A forwarded packet
 * and a sourced one therefore fill the same batch.
 */
static void test_forwarded_and_sourced_share_one_budget(void) {
    struct mixnet_node_config c; struct node_state s;
    fixture_init(&c, &s, 3);

    // From our user, bound for FAR_B
    handle_routed(NULL, &c, &s, USER_PORT, make_user_data(FAR_B));

    // In transit from FAR_A to FAR_B: ... -> 200 -> [100] -> 201 -> ...
    const mixnet_address route[3] = { NEIGHBOR_A, SELF, NEIGHBOR_B };
    handle_routed(NULL, &c, &s, 0,
                  make_transit_data(FAR_A, FAR_B, route, 3, 1));
    CHECK(sent_count == 0, "two packets from two sources, batch of 3: none out");
    CHECK(s.mix_count == 2, "both should share one buffer, got %u held",
          (unsigned) s.mix_count);

    handle_routed(NULL, &c, &s, 0,
                  make_transit_data(FAR_A, FAR_B, route, 3, 1));
    CHECK(sent_count == 3, "the third should release all 3, got %u", sent_count);

    state_free(&s);
}

/**
 * Control traffic bypasses mixing. A node that batched its own hellos and
 * advertisements would stop refreshing the tree while waiting on a batch
 * that may never fill, so STP and LSA must flow with packets still held.
 */
static void test_control_traffic_bypasses_the_buffer(void) {
    struct mixnet_node_config c; struct node_state s;
    fixture_init(&c, &s, 4);

    handle_routed(NULL, &c, &s, USER_PORT, make_user_data(FAR_A));
    CHECK(s.mix_count == 1, "one packet should be held");

    broadcast_stp(NULL, &c, &s, -1);
    CHECK(sends_of_type(PACKET_TYPE_STP) == 2,
          "STP should reach both neighbors, saw %u",
          sends_of_type(PACKET_TYPE_STP));

    originate_lsa(NULL, &c, &s);
    CHECK(sends_of_type(PACKET_TYPE_LSA) == 2,
          "LSA should reach both neighbors, saw %u",
          sends_of_type(PACKET_TYPE_LSA));

    CHECK(s.mix_count == 1, "control traffic must not disturb the batch, %u held",
          (unsigned) s.mix_count);
    CHECK(sends_of_type(PACKET_TYPE_DATA) == 0,
          "the held DATA packet must not have leaked out");

    state_free(&s);
}

/**
 * A packet addressed to us goes up to our user immediately. The user port is
 * not "the network", and buffering these would deadlock a destination that
 * receives fewer than k packets.
 */
static void test_packet_for_us_goes_straight_up(void) {
    struct mixnet_node_config c; struct node_state s;
    fixture_init(&c, &s, 4);

    const mixnet_address route[1] = { NEIGHBOR_A };
    handle_routed(NULL, &c, &s, 0,
                  make_transit_data(FAR_A, SELF, route, 1, 1));

    CHECK(sent_count == 1, "expected immediate delivery, got %u sends", sent_count);
    CHECK((sent_count > 0) && (sent[0].port == USER_PORT),
          "delivery should go out the user port");
    CHECK(s.mix_count == 0, "a packet for us must not take a slot");

    state_free(&s);
}

/**
 * A PING request addressed to us splits in two: the request goes up to the
 * user right away, while the reply we generate is network-bound and so joins
 * the batch like anything else.
 */
static void test_ping_reply_is_mixed_but_the_request_is_not(void) {
    struct mixnet_node_config c; struct node_state s;
    fixture_init(&c, &s, 2);

    handle_routed(NULL, &c, &s, 0, make_ping_for_us());

    CHECK(sent_count == 1, "only the request should be up at the user, got %u",
          sent_count);
    CHECK((sent_count > 0) && (sent[0].port == USER_PORT) && sent[0].is_request,
          "the user should see the request");
    CHECK(s.mix_count == 1, "the reply should be held, %u held",
          (unsigned) s.mix_count);

    // A second network-bound packet completes the batch and frees the reply
    handle_routed(NULL, &c, &s, USER_PORT, make_user_data(FAR_B));
    CHECK(sent_count == 3, "expected the reply plus the DATA out, got %u",
          sent_count);
    CHECK((sent_count > 1) && (sent[1].type == PACKET_TYPE_PING) &&
          !sent[1].is_request && (sent[1].dst == FAR_A) && (sent[1].port == 0),
          "the reply should go back toward FAR_A on port 0");

    state_free(&s);
}

/**
 * A packet with nowhere to go is dropped before it is enqueued. If a drop
 * could take a slot, the batch would be one short of full forever and every
 * packet behind it would be stranded.
 */
static void test_undeliverable_packet_takes_no_slot(void) {
    struct mixnet_node_config c; struct node_state s;
    fixture_init(&c, &s, 2);

    // We are hop 0, and the hop after us is not one of our neighbors
    const mixnet_address route[2] = { SELF, (mixnet_address) 999 };
    handle_routed(NULL, &c, &s, 0,
                  make_transit_data(FAR_A, (mixnet_address) 555, route, 2, 0));

    CHECK(sent_count == 0, "an undeliverable packet should not be sent");
    CHECK(s.mix_count == 0, "a dropped packet must not occupy a slot, %u held",
          (unsigned) s.mix_count);

    // The batch is still two real packets away, not one
    handle_routed(NULL, &c, &s, USER_PORT, make_user_data(FAR_A));
    CHECK(sent_count == 0, "the drop should not have counted toward the batch");
    handle_routed(NULL, &c, &s, USER_PORT, make_user_data(FAR_A));
    CHECK(sent_count == 2, "expected a batch of 2, got %u", sent_count);

    state_free(&s);
}

/**
 * A packet the FIB cannot route is dropped at the source, likewise without
 * taking a slot.
 */
static void test_unroutable_source_packet_takes_no_slot(void) {
    struct mixnet_node_config c; struct node_state s;
    fixture_init(&c, &s, 2);

    handle_routed(NULL, &c, &s, USER_PORT, make_user_data((mixnet_address) 777));
    CHECK(sent_count == 0, "a packet with no route should not be sent");
    CHECK(s.mix_count == 0, "no route means no slot, %u held",
          (unsigned) s.mix_count);

    state_free(&s);
}

/**
 * A node that reaches the end of the run mid-batch still owns the packets it
 * is holding. Under -DDEBUG=ON this test is what tells ASan about the leak;
 * without it, it at least pins the invariant that state_free() may be called
 * with a partial batch outstanding.
 */
static void test_teardown_with_a_partial_batch(void) {
    struct mixnet_node_config c; struct node_state s;
    fixture_init(&c, &s, 8);

    for (unsigned i = 0; i < 5; i++) {
        handle_routed(NULL, &c, &s, USER_PORT, make_user_data(FAR_A));
    }
    CHECK(s.mix_count == 5, "expected 5 held, got %u", (unsigned) s.mix_count);
    CHECK(sent_count == 0, "a partial batch should never have been sent");

    state_free(&s);
    CHECK(s.mix == NULL, "state_free() should release the buffer");
    CHECK(s.mix_count == 0, "state_free() should reset the count");
}

/**
 * The buffer is sized for exactly one batch, so a long run at the largest
 * legal factor must never exceed it. Every batch should come out whole.
 */
static void test_long_run_at_max_factor(void) {
    struct mixnet_node_config c; struct node_state s;
    fixture_init(&c, &s, 16);

    unsigned batches = 0;
    for (unsigned i = 1; i <= 64; i++) {
        sent_reset();
        handle_routed(NULL, &c, &s, USER_PORT, make_user_data(FAR_A));

        if ((i % 16) == 0) {
            batches++;
            CHECK(sent_count == 16, "packet %u should close a batch of 16, saw %u",
                  i, sent_count);
        } else {
            CHECK(sent_count == 0, "packet %u should be held, saw %u sends",
                  i, sent_count);
        }
        CHECK(s.mix_count < 16, "the buffer overran: %u held",
              (unsigned) s.mix_count);
    }
    CHECK(batches == 4, "expected 4 batches, got %u", batches);

    state_free(&s);
}

int main(void) {
    printf("test_mixing\n\n");

    RUN(test_below_factor_holds_everything);
    RUN(test_batch_releases_all_in_order);
    RUN(test_second_batch_behaves_like_the_first);
    RUN(test_factor_one_sends_immediately);
    RUN(test_forwarded_and_sourced_share_one_budget);
    RUN(test_control_traffic_bypasses_the_buffer);
    RUN(test_packet_for_us_goes_straight_up);
    RUN(test_ping_reply_is_mixed_but_the_request_is_not);
    RUN(test_undeliverable_packet_takes_no_slot);
    RUN(test_unroutable_source_packet_takes_no_slot);
    RUN(test_teardown_with_a_partial_batch);
    RUN(test_long_run_at_max_factor);

    printf("\n%u checks, %u failed\n", checks_run, checks_failed);
    printf("%s\n", (checks_failed == 0) ? "PASS" : "FAIL");

    return (checks_failed == 0) ? 0 : 1;
}
