/**
 * Unit tests for CP2 random routing (see docs/cp2-lsa-plan.md §4).
 *
 * Random routes cannot be asserted from the orchestrator the way shortest
 * paths can: pcap sees one delivery at a time, and the route it carries is a
 * different one on every packet. What needs pinning down is the shape of the
 * whole distribution - that every route is a walk the network can actually
 * carry, that more than one of them exists, and that the failure paths fall
 * back rather than drop. So this links node.c directly, as test_lsa.c does.
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
 * Framework stubs. See the note in test_mixing.c for why mixnet_send() is
 * kept out of line.
 */
#define MAX_SENT (8)
#define MAX_HOPS (16)

struct sent_packet {
    uint8_t port;
    mixnet_packet_type_t type;
    mixnet_address dst;
    uint16_t route_len;
    mixnet_address route[MAX_HOPS];
};

static struct sent_packet sent[MAX_SENT];
static unsigned sent_count = 0;

static void sent_reset(void) { sent_count = 0; }

int mixnet_recv(void *handle, uint8_t *port, mixnet_packet **packet) {
    (void) handle; (void) port; (void) packet;
    return 0;   // Never used: the tests drive the handlers directly
}

__attribute__((noinline))
int mixnet_send(void *handle, const uint8_t port, mixnet_packet *packet) {
    (void) handle;

    if (sent_count < MAX_SENT) {
        struct sent_packet *rec = &sent[sent_count++];
        rec->port = port;
        rec->type = packet->type;
        rec->dst = INVALID_MIXADDR;
        rec->route_len = 0;

        if (((packet->type == PACKET_TYPE_DATA) ||
             (packet->type == PACKET_TYPE_PING)) &&
            routed_packet_is_well_formed(
                packet, packet->type == PACKET_TYPE_PING)) {

            const mixnet_packet_routing_header *rh = routing_header(packet);
            rec->dst = rh->dst_address;
            rec->route_len = rh->route_length;

            for (uint16_t i = 0; (i < rh->route_length) && (i < MAX_HOPS); i++) {
                rec->route[i] = rh->route[i];
            }
        }
    }
    free(packet);   // The real mixnet_send() owns the packet too
    return 1;
}

/**
 * Test fixtures.
 *
 * The topology under test is the handout's Figure 1, a star, because it is
 * the case that makes the waypoint visible: every detour doubles back
 * through the hub, so a route that forgot to splice W in shows up as a hop
 * that goes nowhere.
 *
 *          20        30
 *            \      /
 *             \    /
 *     [10] --- (1) --- 40
 *
 * Node 10 is the node under test and its only neighbor is the hub. Routing
 * 10 -> 40, the shortest path is {1}; the detours are {1, 20, 1} and
 * {1, 30, 1}, one per eligible waypoint.
 */
#define SELF        ((mixnet_address) 10)
#define HUB         ((mixnet_address)  1)
#define SPOKE_B     ((mixnet_address) 20)
#define SPOKE_C     ((mixnet_address) 30)
#define DEST        ((mixnet_address) 40)
#define USER_PORT   ((uint8_t) 1)

static uint16_t fixture_costs[1];

/** Advertise one vertex's links into the topology under test. */
static void advertise(struct node_state *s, const mixnet_address origin,
                      const mixnet_address *const peers, const uint16_t count) {

    mixnet_lsa_link_params links[8];
    for (uint16_t i = 0; i < count; i++) {
        links[i].neighbor_mixaddr = peers[i];
        links[i].cost = 1;
    }
    graph_update(&s->topology, origin, count, links);
}

/** A node with one neighbor (the hub), before any topology is installed. */
static void fixture_base(struct mixnet_node_config *c, struct node_state *s,
                         const bool random_routing) {

    fixture_costs[0] = 1;

    c->node_addr = SELF;
    c->num_neighbors = 1;
    c->root_hello_interval_ms = 100;
    c->reelection_interval_ms = 1000;
    c->do_random_routing = random_routing;
    c->mixing_factor = 1;
    c->link_costs = fixture_costs;

    if (!state_init(c, s)) { printf("  FATAL: state_init failed\n"); exit(1); }
    s->neighbor_addr[0] = HUB;

    srand(12345);   // state_init() seeds from the clock; pin it for repeatability
    sent_reset();
}

/** The star above, with the FIB built. */
static void fixture_star(struct mixnet_node_config *c, struct node_state *s,
                         const bool random_routing) {

    fixture_base(c, s, random_routing);

    const mixnet_address hub_peers[4] = { SELF, SPOKE_B, SPOKE_C, DEST };
    const mixnet_address to_hub[1] = { HUB };

    originate_lsa(NULL, c, s);                  // Our own row: 10 -- 1
    advertise(s, HUB, hub_peers, 4);
    advertise(s, SPOKE_B, to_hub, 1);
    advertise(s, SPOKE_C, to_hub, 1);
    advertise(s, DEST, to_hub, 1);
    update_shortest_path(c, s);

    sent_reset();
}

/**
 * A DATA packet as the user layer hands it over. The framework allocates
 * user packets at the maximum size and source_route() relies on that room to
 * insert the route, so the test has to do the same.
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

/** Are these two addresses neighbors in the topology we believe in? */
static bool adjacent(const struct graph *g, const mixnet_address a,
                     const mixnet_address b) {

    const int id = id_find(g, a);
    if (id < 0) { return false; }

    for (uint16_t i = 0; i < g->v[id].num_links; i++) {
        if (g->v[id].links[i].neighbor_mixaddr == b) { return true; }
    }
    return false;
}

/**
 * Is src -> route -> dst a path the network can actually carry? Every
 * consecutive pair has to be adjacent, which is exactly what
 * send_to_next_hop() requires of each hop in turn.
 */
static bool is_valid_walk(const struct graph *g, const mixnet_address src,
                          const mixnet_address dst,
                          const mixnet_address *const route,
                          const uint16_t len) {

    mixnet_address prev = src;
    for (uint16_t i = 0; i < len; i++) {
        if (!adjacent(g, prev, route[i])) { return false; }
        prev = route[i];
    }
    return adjacent(g, prev, dst);
}

/** A printable form of a route, for failure messages. */
static const char *route_str(const mixnet_address *const route,
                             const uint16_t len) {
    static char buf[128];
    int n = snprintf(buf, sizeof(buf), "{");
    for (uint16_t i = 0; i < len; i++) {
        n += snprintf(buf + n, sizeof(buf) - (size_t) n, "%s%u",
                      (i > 0) ? ", " : "", (unsigned) route[i]);
    }
    snprintf(buf + n, sizeof(buf) - (size_t) n, "}");
    return buf;
}

/**
 * The property that matters most: whatever route comes back, the network has
 * to be able to carry it. A missing waypoint splice shows up here as a hop
 * between two nodes that are not adjacent.
 */
static void test_every_route_is_a_valid_walk(void) {
    struct mixnet_node_config c; struct node_state s;
    fixture_star(&c, &s, true);

    unsigned invalid = 0, generated = 0;
    for (unsigned i = 0; i < 500; i++) {
        uint16_t len = 0;
        mixnet_address *route = random_route(&c, &s, DEST, &len);
        if (route == NULL) { continue; }    // Fell back; counted separately below

        generated++;
        if (!is_valid_walk(&s.topology, SELF, DEST, route, len)) {
            if (invalid == 0) {
                printf("    first invalid: %s\n", route_str(route, len));
            }
            invalid++;
        }
        free(route);
    }
    CHECK(generated > 0, "no routes were generated at all");
    CHECK(invalid == 0, "%u of %u routes were not walkable", invalid, generated);

    state_free(&s);
}

/** The handout's one hard requirement: at least two distinct routes. */
static void test_generates_at_least_two_distinct_routes(void) {
    struct mixnet_node_config c; struct node_state s;
    fixture_star(&c, &s, true);

    mixnet_address seen[8][MAX_HOPS];
    uint16_t seen_len[8];
    unsigned distinct = 0;

    for (unsigned i = 0; i < 500; i++) {
        uint16_t len = 0;
        mixnet_address *route = random_route(&c, &s, DEST, &len);
        if (route == NULL) { continue; }

        bool known = false;
        for (unsigned j = 0; j < distinct; j++) {
            if ((seen_len[j] == len) &&
                (memcmp(seen[j], route, sizeof(mixnet_address) * len) == 0)) {
                known = true;
                break;
            }
        }
        if (!known && (distinct < 8) && (len <= MAX_HOPS)) {
            memcpy(seen[distinct], route, sizeof(mixnet_address) * len);
            seen_len[distinct++] = len;
        }
        free(route);
    }
    CHECK(distinct >= 2, "only %u distinct route(s) in 500 packets", distinct);

    state_free(&s);
}

/**
 * The waypoint has to appear between the two legs. On this star the detour
 * is {hub, W, hub}: the hub twice, once on the way out to W and once on the
 * way back. Dropping the splice would leave {hub, hub}, which is a hop from
 * the hub to itself.
 */
static void test_waypoint_is_spliced_between_the_legs(void) {
    struct mixnet_node_config c; struct node_state s;
    fixture_star(&c, &s, true);

    bool saw_detour = false, saw_self_hop = false;
    for (unsigned i = 0; i < 500; i++) {
        uint16_t len = 0;
        mixnet_address *route = random_route(&c, &s, DEST, &len);
        if (route == NULL) { continue; }

        if (len == 3) {
            saw_detour = true;
            CHECK((route[0] == HUB) && (route[2] == HUB),
                  "a detour should leave and re-enter via the hub: %s",
                  route_str(route, len));
            CHECK((route[1] == SPOKE_B) || (route[1] == SPOKE_C),
                  "the middle hop should be the waypoint, got %u",
                  (unsigned) route[1]);
        }
        for (uint16_t j = 1; j < len; j++) {
            if (route[j] == route[j - 1]) { saw_self_hop = true; }
        }
        free(route);
    }
    CHECK(saw_detour, "500 packets produced no detour at all");
    CHECK(!saw_self_hop, "a route contained a hop from a node to itself, "
                         "which is the signature of a missing waypoint splice");

    state_free(&s);
}

/** Neither endpoint is ever chosen as the waypoint. */
static void test_endpoints_are_never_waypoints(void) {
    struct mixnet_node_config c; struct node_state s;
    fixture_star(&c, &s, true);

    unsigned self_hops = 0, dst_hops = 0;
    for (unsigned i = 0; i < 500; i++) {
        uint16_t len = 0;
        mixnet_address *route = random_route(&c, &s, DEST, &len);
        if (route == NULL) { continue; }

        for (uint16_t j = 0; j < len; j++) {
            if (route[j] == SELF) { self_hops++; }
            if (route[j] == DEST) { dst_hops++; }
        }
        free(route);
    }
    CHECK(self_hops == 0, "the source appeared as an intermediate hop %u times",
          self_hops);
    CHECK(dst_hops == 0, "the destination appeared as an intermediate hop %u times",
          dst_hops);

    state_free(&s);
}

/** No route may exceed what the routing header can carry. */
static void test_route_stays_within_the_header_cap(void) {
    struct mixnet_node_config c; struct node_state s;
    fixture_star(&c, &s, true);

    unsigned over = 0;
    for (unsigned i = 0; i < 500; i++) {
        uint16_t len = 0;
        mixnet_address *route = random_route(&c, &s, DEST, &len);
        if (route == NULL) { continue; }
        if (len > MAX_MIXNET_ROUTE_LENGTH) { over++; }
        free(route);
    }
    CHECK(over == 0, "%u routes exceeded MAX_MIXNET_ROUTE_LENGTH", over);

    state_free(&s);
}

/**
 * With only the two endpoints in the topology there is no eligible waypoint,
 * so there is no detour to build and the caller must fall back. This is the
 * two-node line, which is a real test topology, and it is also every node's
 * state early in convergence.
 */
static void test_no_eligible_waypoint_falls_back(void) {
    struct mixnet_node_config c; struct node_state s;
    fixture_base(&c, &s, true);

    const mixnet_address to_self[1] = { SELF };
    originate_lsa(NULL, &c, &s);
    advertise(&s, HUB, to_self, 1);
    update_shortest_path(&c, &s);

    for (unsigned i = 0; i < 50; i++) {
        uint16_t len = 0;
        mixnet_address *route = random_route(&c, &s, HUB, &len);
        CHECK(route == NULL, "expected a fallback with no eligible waypoint");
        free(route);
    }
    state_free(&s);
}

/**
 * A waypoint we know of but cannot reach is no waypoint at all. Here the
 * only eligible vertices sit in a disconnected component, so every attempt
 * falls back rather than producing a route into nowhere.
 */
static void test_unreachable_waypoints_fall_back(void) {
    struct mixnet_node_config c; struct node_state s;
    fixture_base(&c, &s, true);

    // Our component: 10 -- 1. Plus an island, 98 -- 99, that we have heard
    // advertised but have no path to.
    const mixnet_address to_self[1] = { SELF };
    const mixnet_address island_a[1] = { (mixnet_address) 99 };
    const mixnet_address island_b[1] = { (mixnet_address) 98 };

    originate_lsa(NULL, &c, &s);
    advertise(&s, HUB, to_self, 1);
    advertise(&s, (mixnet_address) 98, island_a, 1);
    advertise(&s, (mixnet_address) 99, island_b, 1);
    update_shortest_path(&c, &s);

    unsigned built = 0;
    for (unsigned i = 0; i < 200; i++) {
        uint16_t len = 0;
        mixnet_address *route = random_route(&c, &s, HUB, &len);
        if (route != NULL) { built++; }
        free(route);
    }
    CHECK(built == 0, "%u routes were built through an unreachable waypoint",
          built);

    state_free(&s);
}

/** With the flag off, the node routes exactly as it did before. */
static void test_flag_off_uses_the_shortest_path(void) {
    struct mixnet_node_config c; struct node_state s;
    fixture_star(&c, &s, false);

    for (unsigned i = 0; i < 20; i++) {
        sent_reset();
        handle_routed(NULL, &c, &s, USER_PORT, make_user_data(DEST));

        CHECK(sent_count == 1, "expected one send, got %u", sent_count);
        CHECK((sent_count > 0) && (sent[0].route_len == 1) &&
              (sent[0].route[0] == HUB),
              "expected the shortest path {1}, got %s",
              route_str(sent[0].route, sent[0].route_len));
    }
    state_free(&s);
}

/**
 * End to end through source_route(): the route the packet actually leaves
 * with is walkable, and varies.
 */
static void test_source_route_writes_a_varying_valid_route(void) {
    struct mixnet_node_config c; struct node_state s;
    fixture_star(&c, &s, true);

    unsigned invalid = 0, lengths[8] = { 0 };
    for (unsigned i = 0; i < 200; i++) {
        sent_reset();
        handle_routed(NULL, &c, &s, USER_PORT, make_user_data(DEST));
        if (sent_count == 0) { continue; }

        if (!is_valid_walk(&s.topology, SELF, DEST,
                           sent[0].route, sent[0].route_len)) { invalid++; }

        if (sent[0].route_len < 8) { lengths[sent[0].route_len]++; }

        // Whatever route it chose, the first hop must be out our only port
        CHECK(sent[0].port == 0, "a routed packet left on port %u, not 0",
              (unsigned) sent[0].port);
    }
    CHECK(invalid == 0, "%u packets left with an unwalkable route", invalid);
    CHECK((lengths[1] > 0) && (lengths[3] > 0),
          "expected both direct (%u) and detoured (%u) routes",
          lengths[1], lengths[3]);

    state_free(&s);
}

int main(void) {
    printf("test_random_routing\n\n");

    RUN(test_every_route_is_a_valid_walk);
    RUN(test_generates_at_least_two_distinct_routes);
    RUN(test_waypoint_is_spliced_between_the_legs);
    RUN(test_endpoints_are_never_waypoints);
    RUN(test_route_stays_within_the_header_cap);
    RUN(test_no_eligible_waypoint_falls_back);
    RUN(test_unreachable_waypoints_fall_back);
    RUN(test_flag_off_uses_the_shortest_path);
    RUN(test_source_route_writes_a_varying_valid_route);

    printf("\n%u checks, %u failed\n", checks_run, checks_failed);
    printf("%s\n", (checks_failed == 0) ? "PASS" : "FAIL");

    return (checks_failed == 0) ? 0 : 1;
}
