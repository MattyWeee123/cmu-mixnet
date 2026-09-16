/**
 * Unit tests for the CP2 link-state layer (see docs/cp2-lsa-plan.md §1).
 *
 * LSA packets are invisible to the orchestrator: pcap only mirrors packets a
 * node sends out its user port, and the framework rejects LSA there
 * (framework/fragment.cpp). The only black-box evidence that link-state works
 * is the route a DATA packet takes, which belongs to §2. So this test links
 * node.c directly, stubs the two framework calls, and inspects the topology
 * and the wire traffic that the LSA path produces.
 *
 * Including the .c file is what gives us access to its static functions; it
 * is also why this is a separate target rather than another testcase*.cpp.
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
 * Framework stubs. mixnet_send() takes ownership of the packet, so we record
 * what we need and free it; the recorded copy is what the tests assert on.
 */
#define MAX_SENT (64)

struct sent_packet {
    uint8_t port;
    mixnet_packet_type_t type;
    mixnet_address origin;      // LSA advertiser, for LSA packets
    uint16_t neighbor_count;
};

static struct sent_packet sent[MAX_SENT];
static unsigned sent_count = 0;

static void sent_reset(void) { sent_count = 0; }

int mixnet_recv(void *handle, uint8_t *port, mixnet_packet **packet) {
    (void) handle; (void) port; (void) packet;
    return 0;   // Never used: the tests drive the handlers directly
}

int mixnet_send(void *handle, const uint8_t port, mixnet_packet *packet) {
    (void) handle;

    if (sent_count < MAX_SENT) {
        struct sent_packet *rec = &sent[sent_count++];
        rec->port = port;
        rec->type = packet->type;
        rec->origin = INVALID_MIXADDR;
        rec->neighbor_count = 0;

        if (packet->type == PACKET_TYPE_LSA) {
            const mixnet_packet_lsa *lsa =
                (const mixnet_packet_lsa *) packet->payload;
            rec->origin = lsa->node_address;
            rec->neighbor_count = lsa->neighbor_count;
        }
    }
    free(packet);   // The real mixnet_send() owns the packet too
    return 1;
}

/** How many LSA packets went out on this port? */
static unsigned lsa_sends_on(const uint8_t port) {
    unsigned n = 0;
    for (unsigned i = 0; i < sent_count; i++) {
        if ((sent[i].port == port) && (sent[i].type == PACKET_TYPE_LSA)) { n++; }
    }
    return n;
}

/** Total LSA packets sent, on any port. */
static unsigned lsa_sends_total(void) {
    unsigned n = 0;
    for (unsigned i = 0; i < sent_count; i++) {
        if (sent[i].type == PACKET_TYPE_LSA) { n++; }
    }
    return n;
}

/**
 * Test fixtures.
 */
static uint16_t fixture_costs[3];

/**
 * A node with `num_neighbors` links whose neighbor addresses are already
 * known, i.e. as it stands once STP neighbor discovery has finished.
 */
static void fixture_init(struct mixnet_node_config *c, struct node_state *s,
                         const mixnet_address addr,
                         const uint16_t num_neighbors) {

    for (uint16_t p = 0; p < num_neighbors; p++) {
        fixture_costs[p] = (uint16_t) (10 + p);
    }
    c->node_addr = addr;
    c->num_neighbors = num_neighbors;
    c->root_hello_interval_ms = 100;
    c->reelection_interval_ms = 1000;
    c->do_random_routing = false;
    c->mixing_factor = 1;
    c->link_costs = fixture_costs;

    if (!state_init(c, s)) { printf("  FATAL: state_init failed\n"); exit(1); }

    for (uint16_t p = 0; p < num_neighbors; p++) {
        s->neighbor_addr[p] = (mixnet_address) (200 + p);
    }
    sent_reset();
}

/** Build an LSA packet as if it had arrived from `origin`. */
static mixnet_packet *make_lsa(const mixnet_address origin,
                               const uint16_t count,
                               const mixnet_lsa_link_params *const links) {

    mixnet_packet *packet = malloc(LSA_PACKET_SIZE(count));
    if (packet == NULL) { printf("  FATAL: OOM\n"); exit(1); }

    packet->total_size = (uint16_t) LSA_PACKET_SIZE(count);
    packet->type = PACKET_TYPE_LSA;

    mixnet_packet_lsa *lsa = (mixnet_packet_lsa *) packet->payload;
    lsa->node_address = origin;
    lsa->neighbor_count = count;
    if (count > 0) {
        memcpy((char *) lsa + sizeof(*lsa), links,
               sizeof(*links) * (size_t) count);
    }
    return packet;
}

/** The row for an address, or NULL if the graph has never seen it. */
static const struct vertex *row_of(const struct graph *g,
                                   const mixnet_address addr) {
    for (uint16_t i = 0; i < g->count; i++) {
        if (g->v[i].addr == addr) { return &g->v[i]; }
    }
    return NULL;
}

/**
 * An LSA is a complete replacement of the advertiser's row, never a delta:
 * the advertiser is the sole authority on its own links, so a merge would
 * retain edges it no longer advertises.
 */
static void test_row_is_replaced_not_merged(void) {
    struct mixnet_node_config c; struct node_state s;
    fixture_init(&c, &s, 100, 0);

    const mixnet_lsa_link_params first[3] = {
        { 11, 1 }, { 12, 2 }, { 13, 3 } };
    CHECK(graph_update(&s.topology, 500, 3, first),
          "first advertisement should be a change");

    const struct vertex *row = row_of(&s.topology, 500);
    CHECK((row != NULL) && (row->num_links == 3), "expected 3 links");

    // A shorter list must drop the edges that are gone, not keep them
    const mixnet_lsa_link_params second[1] = { { 99, 7 } };
    CHECK(graph_update(&s.topology, 500, 1, second),
          "replacement should be a change");

    row = row_of(&s.topology, 500);
    CHECK((row != NULL) && (row->num_links == 1),
          "expected 1 link after replacement, got %u",
          (row == NULL) ? 0u : (unsigned) row->num_links);
    CHECK((row != NULL) && (row->links[0].neighbor_mixaddr == 99) &&
          (row->links[0].cost == 7), "replacement content wrong");

    // Growing again must not leak or alias the previous array
    const mixnet_lsa_link_params third[2] = { { 21, 4 }, { 22, 5 } };
    CHECK(graph_update(&s.topology, 500, 2, third), "grow should be a change");
    row = row_of(&s.topology, 500);
    CHECK((row != NULL) && (row->num_links == 2) &&
          (row->links[1].neighbor_mixaddr == 22), "grow content wrong");

    state_free(&s);
}

/** Re-advertisement of identical content is not a topology change. */
static void test_identical_replay_is_not_a_change(void) {
    struct mixnet_node_config c; struct node_state s;
    fixture_init(&c, &s, 100, 0);

    const mixnet_lsa_link_params links[2] = { { 11, 1 }, { 12, 2 } };
    CHECK(graph_update(&s.topology, 500, 2, links), "first install is a change");
    CHECK(!graph_update(&s.topology, 500, 2, links), "replay is not a change");
    CHECK(!graph_update(&s.topology, 500, 2, links), "replay is still not one");

    // A differing cost on the same neighbor set must still register
    const mixnet_lsa_link_params changed[2] = { { 11, 1 }, { 12, 99 } };
    CHECK(graph_update(&s.topology, 500, 2, changed),
          "a changed cost is a change");

    state_free(&s);
}

/**
 * A node can be named in someone else's neighbor list before its own LSA
 * arrives, so it needs a row (and a vertex id) right away.
 */
static void test_insert_on_mention(void) {
    struct mixnet_node_config c; struct node_state s;
    fixture_init(&c, &s, 100, 0);

    const mixnet_lsa_link_params links[2] = { { 600, 1 }, { 700, 2 } };
    graph_update(&s.topology, 500, 2, links);

    CHECK(s.topology.count == 3,
          "expected 3 vertices (1 advertiser + 2 mentioned), got %u",
          (unsigned) s.topology.count);

    const struct vertex *mentioned = row_of(&s.topology, 600);
    CHECK(mentioned != NULL, "mentioned node has no row");
    CHECK((mentioned != NULL) && !mentioned->advertised,
          "a merely-mentioned node must not be marked advertised");
    CHECK((mentioned != NULL) && (mentioned->links == NULL),
          "a merely-mentioned node must have no links");

    // Its own LSA later fills the row in without adding a duplicate vertex
    const mixnet_lsa_link_params own[1] = { { 500, 1 } };
    CHECK(graph_update(&s.topology, 600, 1, own), "own LSA is a change");
    CHECK(s.topology.count == 3, "filling a row must not add a vertex");

    mentioned = row_of(&s.topology, 600);
    CHECK((mentioned != NULL) && mentioned->advertised,
          "should be marked advertised after its own LSA");

    state_free(&s);
}

/**
 * A node advertising zero links and a node merely mentioned both leave
 * links == NULL, so only the advertised flag can tell them apart.
 */
static void test_zero_link_advertisement(void) {
    struct mixnet_node_config c; struct node_state s;
    fixture_init(&c, &s, 100, 0);

    // Mention it first, so the row already exists but is unadvertised
    const mixnet_lsa_link_params links[1] = { { 600, 1 } };
    graph_update(&s.topology, 500, 1, links);

    CHECK(graph_update(&s.topology, 600, 0, NULL),
          "a zero-link node's first LSA is a change");
    CHECK(!graph_update(&s.topology, 600, 0, NULL),
          "replaying it is not a change");

    const struct vertex *row = row_of(&s.topology, 600);
    CHECK((row != NULL) && row->advertised && (row->num_links == 0),
          "zero-link row wrong");

    state_free(&s);
}

/**
 * Interning a mentioned address can grow the vertex array, and realloc may
 * move it. A row pointer taken before those inserts would dangle, so this
 * drives enough appends to force several reallocations.
 */
static void test_many_advertisers_survive_realloc(void) {
    struct mixnet_node_config c; struct node_state s;
    fixture_init(&c, &s, 100, 0);

    const uint16_t n = 300;
    for (uint16_t i = 0; i < n; i++) {
        const mixnet_lsa_link_params links[2] = {
            { (mixnet_address) (1000 + i), (uint16_t) i },
            { (mixnet_address) (1000 + i + 1), (uint16_t) (i + 1) } };

        CHECK(graph_update(&s.topology, (mixnet_address) (1000 + i), 2, links),
              "advertiser %u should be a change", (unsigned) i);
    }
    // n advertisers, plus the one extra address the last one mentioned
    CHECK(s.topology.count == (n + 1), "expected %u vertices, got %u",
          (unsigned) (n + 1), (unsigned) s.topology.count);

    // Every row must still be readable and hold its own content
    unsigned bad = 0;
    for (uint16_t i = 0; i < n; i++) {
        const struct vertex *row = row_of(&s.topology,
                                          (mixnet_address) (1000 + i));
        if ((row == NULL) || (row->num_links != 2) ||
            (row->links[0].neighbor_mixaddr != (mixnet_address) (1000 + i)) ||
            (row->links[0].cost != i)) { bad++; }
    }
    CHECK(bad == 0, "%u rows were corrupted across reallocations", bad);

    state_free(&s);
}

/**
 * We never receive our own LSA, so originate_lsa() is the only thing that
 * populates our own row -- and it cannot run until STP has told us who our
 * neighbors are.
 */
static void test_own_row_comes_from_config(void) {
    struct mixnet_node_config c; struct node_state s;
    fixture_init(&c, &s, 100, 3);

    // Undo discovery for one port: the LSA would misdescribe our links
    s.neighbor_addr[1] = INVALID_MIXADDR;
    originate_lsa(NULL, &c, &s);
    CHECK(lsa_sends_total() == 0,
          "must not advertise before neighbor discovery completes");
    CHECK(row_of(&s.topology, 100) == NULL, "must not build our row early");

    s.neighbor_addr[1] = 201;
    originate_lsa(NULL, &c, &s);

    const struct vertex *own = row_of(&s.topology, 100);
    CHECK(own != NULL, "our own row was never built");
    CHECK((own != NULL) && own->advertised && (own->num_links == 3),
          "our own row should hold 3 links");

    // Ports map to addresses, and link_costs is indexed by port
    for (uint16_t p = 0; (own != NULL) && (p < 3); p++) {
        CHECK(own->links[p].neighbor_mixaddr == (mixnet_address) (200 + p),
              "link %u: wrong neighbor address", (unsigned) p);
        CHECK(own->links[p].cost == (uint16_t) (10 + p),
              "link %u: cost should come from link_costs[%u]",
              (unsigned) p, (unsigned) p);
    }
    state_free(&s);
}

/** Our own advertisement goes out every tree link, and only those. */
static void test_originate_floods_tree_links_only(void) {
    struct mixnet_node_config c; struct node_state s;
    fixture_init(&c, &s, 100, 3);

    s.blocked[1] = true;    // Port 1 is not a tree edge
    originate_lsa(NULL, &c, &s);

    CHECK(lsa_sends_on(0) == 1, "port 0 should carry our LSA");
    CHECK(lsa_sends_on(1) == 0, "blocked port 1 must not carry it");
    CHECK(lsa_sends_on(2) == 1, "port 2 should carry our LSA");
    CHECK(lsa_sends_on((uint8_t) c.num_neighbors) == 0,
          "the user port must never carry an LSA");
    CHECK(lsa_sends_total() == 2, "expected exactly 2 sends, got %u",
          lsa_sends_total());

    for (unsigned i = 0; i < sent_count; i++) {
        CHECK(sent[i].origin == 100, "we should advertise our own address");
        CHECK(sent[i].neighbor_count == 3, "we should advertise 3 links");
    }
    state_free(&s);
}

/** A received LSA is re-flooded on every tree link but the one it arrived on. */
static void test_received_lsa_is_reflooded(void) {
    struct mixnet_node_config c; struct node_state s;
    fixture_init(&c, &s, 100, 3);

    const mixnet_lsa_link_params links[1] = { { 501, 4 } };
    handle_lsa(NULL, &c, &s, 0, make_lsa(500, 1, links));   // Arrives on port 0

    CHECK(lsa_sends_on(0) == 0, "must not echo back out the ingress port");
    CHECK(lsa_sends_on(1) == 1, "port 1 should carry it onward");
    CHECK(lsa_sends_on(2) == 1, "port 2 should carry it onward");
    CHECK(lsa_sends_on((uint8_t) c.num_neighbors) == 0,
          "the user port must never carry an LSA");

    const struct vertex *row = row_of(&s.topology, 500);
    CHECK((row != NULL) && row->advertised, "the advertisement was not stored");

    state_free(&s);
}

/**
 * Re-flooding must not be conditional on the row having changed. A neighbor
 * that already holds a row would otherwise stop an advertisement whose only
 * remaining job is to reach the nodes behind it, and no amount of
 * re-advertising could repair a node that missed the first flood.
 */
static void test_known_lsa_is_still_reflooded(void) {
    struct mixnet_node_config c; struct node_state s;
    fixture_init(&c, &s, 100, 3);

    const mixnet_lsa_link_params links[1] = { { 501, 4 } };
    handle_lsa(NULL, &c, &s, 0, make_lsa(500, 1, links));
    CHECK(lsa_sends_total() == 2, "first arrival should flood on 2 links");

    sent_reset();
    handle_lsa(NULL, &c, &s, 0, make_lsa(500, 1, links));   // Identical
    CHECK(lsa_sends_total() == 2,
          "an already-known LSA must still be re-flooded, got %u sends",
          lsa_sends_total());

    state_free(&s);
}

/**
 * Our own advertisement can come back to us while the blocked sets still
 * disagree during STP convergence. Our row is authoritative from config, so
 * it must be neither reinstalled nor put back on the wire.
 */
static void test_own_lsa_is_dropped(void) {
    struct mixnet_node_config c; struct node_state s;
    fixture_init(&c, &s, 100, 3);

    originate_lsa(NULL, &c, &s);
    const struct vertex *own = row_of(&s.topology, 100);
    CHECK((own != NULL) && (own->num_links == 3), "our row should be built");
    sent_reset();

    // Claims we have a single, wrong link. Must be ignored outright.
    const mixnet_lsa_link_params bogus[1] = { { 999, 1 } };
    handle_lsa(NULL, &c, &s, 0, make_lsa(100, 1, bogus));

    CHECK(lsa_sends_total() == 0, "our own LSA must not be re-flooded");
    own = row_of(&s.topology, 100);
    CHECK((own != NULL) && (own->num_links == 3),
          "our own row must not be overwritten from the wire");
    CHECK(row_of(&s.topology, 999) == NULL,
          "nothing from our own LSA should reach the graph");

    state_free(&s);
}

/** An LSA arriving over a non-tree link is dropped, as FLOOD packets are. */
static void test_lsa_on_blocked_port_is_dropped(void) {
    struct mixnet_node_config c; struct node_state s;
    fixture_init(&c, &s, 100, 3);

    s.blocked[0] = true;
    const mixnet_lsa_link_params links[1] = { { 501, 4 } };
    handle_lsa(NULL, &c, &s, 0, make_lsa(500, 1, links));

    CHECK(lsa_sends_total() == 0, "must not forward an LSA from a blocked port");
    CHECK(row_of(&s.topology, 500) == NULL,
          "must not install an LSA from a blocked port");

    state_free(&s);
}

/** LSAs are control traffic: the user neither sends nor receives one. */
static void test_lsa_from_user_port_is_dropped(void) {
    struct mixnet_node_config c; struct node_state s;
    fixture_init(&c, &s, 100, 3);

    const mixnet_lsa_link_params links[1] = { { 501, 4 } };
    handle_lsa(NULL, &c, &s, (uint8_t) c.num_neighbors,
               make_lsa(500, 1, links));

    CHECK(lsa_sends_total() == 0, "an LSA from the user must not be forwarded");
    CHECK(row_of(&s.topology, 500) == NULL,
          "an LSA from the user must not be installed");

    state_free(&s);
}

/**
 * neighbor_count drives a variable-size array, so it has to be checked
 * against total_size before the links are read.
 */
static void test_truncated_lsa_is_rejected(void) {
    struct mixnet_node_config c; struct node_state s;
    fixture_init(&c, &s, 100, 3);

    const mixnet_lsa_link_params links[1] = { { 501, 4 } };
    mixnet_packet *packet = make_lsa(500, 1, links);

    // Carries one link but claims 900: reading them would run off the end
    ((mixnet_packet_lsa *) packet->payload)->neighbor_count = 900;
    handle_lsa(NULL, &c, &s, 0, packet);

    const struct vertex *row = row_of(&s.topology, 500);
    CHECK((row == NULL) || !row->advertised,
          "a truncated LSA must not be installed");
    CHECK(lsa_sends_total() == 0, "a truncated LSA must not be re-flooded");

    // A header too short to even hold the payload struct
    mixnet_packet *runt = malloc(LSA_PACKET_SIZE(0));
    runt->total_size = (uint16_t) sizeof(mixnet_packet);
    runt->type = PACKET_TYPE_LSA;
    handle_lsa(NULL, &c, &s, 0, runt);
    CHECK(lsa_sends_total() == 0, "a runt LSA must not be re-flooded");

    state_free(&s);
}

/**
 * The topology is assembled from purely local advertisements: no node
 * describes anything but its own links, yet the union is the whole graph.
 * Mirrors testing/cp2/testcase_sp_uniform_ring.cpp.
 */
static void test_ring_topology_is_assembled(void) {
    const mixnet_address ring[7] = { 15, 31, 65534, 0, 81, 21, 42 };

    // Stand in for node 15, whose ring neighbors are 42 (port 0) and 31 (1)
    struct mixnet_node_config c; struct node_state s;
    fixture_init(&c, &s, 15, 2);
    s.neighbor_addr[0] = 42;
    s.neighbor_addr[1] = 31;
    fixture_costs[0] = 1;
    fixture_costs[1] = 1;
    originate_lsa(NULL, &c, &s);

    // Every other node's advertisement arrives, in an arbitrary order
    for (unsigned k = 1; k < 7; k++) {
        const mixnet_lsa_link_params links[2] = {
            { ring[(k + 6) % 7], 1 },   // Predecessor
            { ring[(k + 1) % 7], 1 } }; // Successor
        handle_lsa(NULL, &c, &s, 0, make_lsa(ring[k], 2, links));
    }

    CHECK(s.topology.count == 7, "expected 7 vertices, got %u",
          (unsigned) s.topology.count);

    unsigned unadvertised = 0, wrong_degree = 0;
    for (unsigned k = 0; k < 7; k++) {
        const struct vertex *row = row_of(&s.topology, ring[k]);
        if ((row == NULL) || !row->advertised) { unadvertised++; continue; }
        if (row->num_links != 2) { wrong_degree++; }
    }
    CHECK(unadvertised == 0, "%u ring nodes never advertised", unadvertised);
    CHECK(wrong_degree == 0, "%u ring nodes have the wrong degree",
          wrong_degree);

    // Every edge should be reported from both of its endpoints
    unsigned asymmetric = 0;
    for (uint16_t i = 0; i < s.topology.count; i++) {
        const struct vertex *u = &s.topology.v[i];
        for (uint16_t j = 0; j < u->num_links; j++) {
            const struct vertex *v = row_of(&s.topology,
                                            u->links[j].neighbor_mixaddr);
            bool mutual = false;
            for (uint16_t k = 0; (v != NULL) && (k < v->num_links); k++) {
                if (v->links[k].neighbor_mixaddr == u->addr) { mutual = true; }
            }
            if (!mutual) { asymmetric++; }
        }
    }
    CHECK(asymmetric == 0, "%u edges were reported by only one endpoint",
          asymmetric);

    state_free(&s);
}

int main(void) {
    printf("test_lsa\n\n");

    RUN(test_row_is_replaced_not_merged);
    RUN(test_identical_replay_is_not_a_change);
    RUN(test_insert_on_mention);
    RUN(test_zero_link_advertisement);
    RUN(test_many_advertisers_survive_realloc);
    RUN(test_own_row_comes_from_config);
    RUN(test_originate_floods_tree_links_only);
    RUN(test_received_lsa_is_reflooded);
    RUN(test_known_lsa_is_still_reflooded);
    RUN(test_own_lsa_is_dropped);
    RUN(test_lsa_on_blocked_port_is_dropped);
    RUN(test_lsa_from_user_port_is_dropped);
    RUN(test_truncated_lsa_is_rejected);
    RUN(test_ring_topology_is_assembled);

    printf("\n%u checks, %u failed\n", checks_run, checks_failed);
    printf("%s\n", (checks_failed == 0) ? "PASS" : "FAIL");

    return (checks_failed == 0) ? 0 : 1;
}
