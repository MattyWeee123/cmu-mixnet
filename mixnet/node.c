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
#include "node.h"

#include "connection.h"
#include "packet.h"

#include <stdlib.h>
#include <string.h>
#include <time.h>

/**
 * Debug logging. Compiles to nothing unless MIXNET_DEBUG is defined, since
 * the autograder parses console output.
 */
#ifdef MIXNET_DEBUG
#include <stdio.h>
#define DBG(...) fprintf(stderr, __VA_ARGS__)
#else
#define DBG(...) ((void) 0)
#endif

// Total size of an STP packet: 12B header + 6B payload
#define STP_PACKET_SIZE (sizeof(mixnet_packet) + sizeof(mixnet_packet_stp))

// Total size of an LSA packet advertising n links: 12B header + (4 + 4n)B
#define LSA_PACKET_SIZE(n) (sizeof(mixnet_packet) +                     \
                            sizeof(mixnet_packet_lsa) +                 \
                            (sizeof(mixnet_lsa_link_params) * (size_t) (n)))

/**
 * One vertex of the network topology: a mixnet node, together with the links
 * that node advertised. A vertex's index in graph.v is its id; ids are
 * stable because CP2 never removes a node.
 *
 * A vertex id and a port number are different namespaces and must never be
 * compared: a port indexes *our own* links, a vertex id indexes every node
 * we have heard of. mixnet_address is the only identifier common to both.
 */
struct vertex {
    mixnet_address addr;            // The node this vertex stands for
    bool advertised;                // Have we received this node's LSA?
    uint16_t num_links;             // Links it advertised
    mixnet_lsa_link_params *links;  // [num_links]; NULL until its LSA arrives
};

/** Adjacency list: one row per node, holding that node's own links. */
struct graph {
    struct vertex *v;               // [count], the index is the vertex id
    uint16_t count;
    uint16_t capacity;
};

/**
 * This node's protocol state.
 *
 * Spanning-tree invariant:
 *     root == config.node_addr  <=>  path_len == 0
 *                               <=>  next_hop == INVALID_MIXADDR
 */
struct node_state {
    // Spanning tree (CP1)
    mixnet_address root;        // Believed root of the spanning tree
    uint16_t path_len;          // Hop count from this node to the root
    mixnet_address next_hop;    // Parent: neighbor on the path to the root

    mixnet_address *neighbor_addr;  // [num_neighbors] port -> neighbor address
    bool *blocked;                  // [num_neighbors] port -> FLOOD blocked?

    uint64_t hello_start_ms;        // Last hello broadcast (root only)
    uint64_t reelection_start_ms;   // Last hello heard from the parent

    // Link state (CP2)
    struct graph topology;          // Global view, assembled from LSAs
    uint64_t lsa_start_ms;          // Last time we advertised our own links
};

/** Monotonic milliseconds; the STP intervals are in ms. */
static uint64_t now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (((uint64_t) ts.tv_sec) * 1000u) +
           (((uint64_t) ts.tv_nsec) / 1000000u);
}

/** Reverse lookup: neighbor address -> port, or -1 if not a known neighbor. */
static int port_of(const struct mixnet_node_config *c,
                   const struct node_state *s,
                   const mixnet_address addr) {

    if (addr == INVALID_MIXADDR) { return -1; }
    for (uint16_t p = 0; p < c->num_neighbors; p++) {
        if (s->neighbor_addr[p] == addr) { return (int) p; }
    }
    return -1;
}

/**
 * Find-or-insert: the vertex id for an address, appending a link-less vertex
 * if this is the first time we have seen it. Returns -1 only if we are out
 * of memory.
 *
 * This inserts rather than merely searching because a node can be named in
 * someone else's neighbor list before its own LSA arrives; without that, a
 * relaxation loop would hit an address with no id.
 */
static int id_lookup(struct graph *g, const mixnet_address addr) {
    for (uint16_t i = 0; i < g->count; i++) {
        if (g->v[i].addr == addr) { return (int) i; }
    }
    if (g->count == g->capacity) {
        const uint32_t cap = (g->capacity == 0) ?
            8u : ((uint32_t) g->capacity * 2u);
        if (cap > UINT16_MAX) { return -1; }

        struct vertex *grown = realloc(g->v, sizeof(*grown) * cap);
        if (grown == NULL) { return -1; }
        g->v = grown;
        g->capacity = (uint16_t) cap;
    }
    g->v[g->count].addr = addr;
    g->v[g->count].advertised = false;
    g->v[g->count].num_links = 0;
    g->v[g->count].links = NULL;

    return (int) g->count++;
}

/**
 * Install an LSA's neighbor list as the advertising node's row, and return
 * whether that changed anything.
 *
 * An advertisement is a complete replacement, never a delta: the originator
 * is the sole authority on its own links, so merging into the existing row
 * would retain edges the originator no longer advertises.
 */
static bool graph_update(struct graph *g, const mixnet_address origin,
                         const uint16_t num_links,
                         const mixnet_lsa_link_params *const links) {

    // Intern every mentioned address *before* taking a row pointer: these
    // inserts can realloc g->v, which would dangle a pointer taken earlier.
    for (uint16_t i = 0; i < num_links; i++) {
        if (id_lookup(g, links[i].neighbor_mixaddr) < 0) { return false; }
    }
    const int id = id_lookup(g, origin);
    if (id < 0) { return false; }

    struct vertex *row = &g->v[id];  // Safe: no further inserts past here
    const size_t bytes = sizeof(*links) * (size_t) num_links;

    // Byte-identical to the row we already hold, so nothing downstream of
    // the topology needs recomputing. The advertised test is what separates
    // "merely named in someone else's neighbor list" from "advertised zero
    // links": both leave links == NULL, so without it a link-less node's
    // first LSA would be mistaken for a no-op.
    if (row->advertised && (row->num_links == num_links) &&
        ((num_links == 0) || (memcmp(row->links, links, bytes) == 0))) {
        return false;
    }

    mixnet_lsa_link_params *copy = NULL;
    if (num_links > 0) {
        if ((copy = malloc(bytes)) == NULL) { return false; }
        memcpy(copy, links, bytes);
    }
    free(row->links);  // NULL on a row that was only ever interned
    row->links = copy;
    row->num_links = num_links;
    row->advertised = true;

    return true;
}

/** The links array of an LSA payload, which trails it in the packet. */
static const mixnet_lsa_link_params *lsa_links(
        const mixnet_packet_lsa *const lsa) {
    return (const mixnet_lsa_link_params *)
        (((const char *) lsa) + sizeof(*lsa));
}

/**
 * Hand a packet to the framework. On success the callee takes ownership and
 * frees it; a negative return means we built a malformed packet, in which
 * case ownership stays with us and we must free it ourselves.
 */
static void send_packet(void *const handle, const uint8_t port,
                        mixnet_packet *const packet) {
    int rc;
    while ((rc = mixnet_send(handle, port, packet)) == 0) {
        // Not sent: the docstring requires us to re-attempt until it is
    }
    if (rc < 0) {
        DBG("[node] malformed packet on port %u (type %u)\n",
            (unsigned) port, (unsigned) packet->type);
        free(packet);
    }
}

/** Allocate an STP packet carrying this node's current bid. */
static mixnet_packet *make_stp_packet(const struct mixnet_node_config *c,
                                      const struct node_state *s) {
    mixnet_packet *packet = malloc(STP_PACKET_SIZE);
    if (packet == NULL) { return NULL; }

    packet->total_size = (uint16_t) STP_PACKET_SIZE;
    packet->type = PACKET_TYPE_STP;

    mixnet_packet_stp *payload = (mixnet_packet_stp *) packet->payload;
    payload->root_address = s->root;
    payload->path_length = s->path_len;
    payload->node_address = c->node_addr;

    return packet;
}

/**
 * Allocate an LSA advertising this node's own links. This is the one place
 * the two namespaces meet: we walk our *ports* and write out the *addresses*
 * they lead to, since that is all a remote node can make sense of.
 */
static mixnet_packet *make_lsa_packet(const struct mixnet_node_config *c,
                                      const struct node_state *s) {

    const size_t size = LSA_PACKET_SIZE(c->num_neighbors);
    mixnet_packet *packet = malloc(size);
    if (packet == NULL) { return NULL; }

    packet->total_size = (uint16_t) size;
    packet->type = PACKET_TYPE_LSA;

    mixnet_packet_lsa *lsa = (mixnet_packet_lsa *) packet->payload;
    lsa->node_address = c->node_addr;
    lsa->neighbor_count = c->num_neighbors;

    mixnet_lsa_link_params *links =
        (mixnet_lsa_link_params *) (packet->payload + sizeof(*lsa));

    for (uint16_t p = 0; p < c->num_neighbors; p++) {
        links[p].neighbor_mixaddr = s->neighbor_addr[p];  // port -> address
        links[p].cost = c->link_costs[p];                 // costs are by port
    }
    return packet;
}

/** Byte-for-byte copy; mixnet_send() consumes a packet, so each port needs one. */
static mixnet_packet *clone_packet(const mixnet_packet *const packet) {
    mixnet_packet *copy = malloc(packet->total_size);
    if (copy != NULL) { memcpy(copy, packet, packet->total_size); }
    return copy;
}

/**
 * Send this node's STP bid to every neighbor, optionally skipping one port.
 * Pass except_port = -1 to send on all of them. STP is never gated by the
 * blocked state: blocking applies to FLOOD only, which is what lets a
 * wrongly-blocked port recover.
 */
static void broadcast_stp(void *const handle,
                          const struct mixnet_node_config *c,
                          const struct node_state *s,
                          const int except_port) {

    for (uint16_t p = 0; p < c->num_neighbors; p++) {
        if ((int) p == except_port) { continue; }

        mixnet_packet *packet = make_stp_packet(c, s);
        if (packet == NULL) { continue; }
        send_packet(handle, (uint8_t) p, packet);
    }
}

/**
 * Send a copy of a packet out over every spanning-tree link except one. Pass
 * except_port = -1 to use every tree link. The caller keeps ownership of
 * `packet`; only the copies are handed to the framework.
 *
 * Shared by FLOOD and LSA, whose forwarding rules are identical: tree links
 * only, never back out the link it arrived on.
 */
static void broadcast_on_tree(void *const handle,
                              const struct mixnet_node_config *c,
                              const struct node_state *s,
                              const int except_port,
                              const mixnet_packet *const packet) {

    for (uint16_t p = 0; p < c->num_neighbors; p++) {
        if (((int) p == except_port) || s->blocked[p]) { continue; }

        mixnet_packet *copy = clone_packet(packet);
        if (copy == NULL) { continue; }
        send_packet(handle, (uint8_t) p, copy);
    }
}

/**
 * TODO(CP2 §2): Dijkstra over s->topology, memoized into a FIB. Stubbed for
 * now so the link-state path is already wired to it; see §2 of
 * docs/cp2-lsa-plan.md.
 */
static void update_shortest_path(const struct mixnet_node_config *c,
                                 struct node_state *s) {
    (void) c;
    (void) s;
}

/**
 * Advertise our own links, and install them in our own row. We never receive
 * our own LSA, so this is the only thing that ever populates that row.
 *
 * Called repeatedly rather than once. Our first advertisement can go out
 * while the tree is still settling, and a flood across a tree that is still
 * changing may not reach every node; re-advertising repairs that, and is
 * idempotent at every receiver.
 */
static void originate_lsa(void *const handle,
                          const struct mixnet_node_config *c,
                          struct node_state *s) {

    // A neighbor's address is learned from the STP packets it sends, so we
    // cannot describe our own links until we have heard from all of them.
    for (uint16_t p = 0; p < c->num_neighbors; p++) {
        if (s->neighbor_addr[p] == INVALID_MIXADDR) { return; }
    }

    mixnet_packet *packet = make_lsa_packet(c, s);
    if (packet == NULL) { return; }

    const mixnet_packet_lsa *lsa = (const mixnet_packet_lsa *) packet->payload;
    if (graph_update(&s->topology, c->node_addr,
                     lsa->neighbor_count, lsa_links(lsa))) {
        update_shortest_path(c, s);
    }
    broadcast_on_tree(handle, c, s, -1, packet);
    free(packet);
}

/** Reopen every port. Blocks computed against a stale root are meaningless. */
static void unblock_all(const struct mixnet_node_config *c,
                        struct node_state *s) {
    for (uint16_t p = 0; p < c->num_neighbors; p++) {
        s->blocked[p] = false;
    }
}

/** Become the root of a depth-0 tree. Used at startup and on re-election. */
static void become_root(const struct mixnet_node_config *c,
                        struct node_state *s) {
    s->root = c->node_addr;
    s->path_len = 0;
    s->next_hop = INVALID_MIXADDR;
}

static bool state_init(const struct mixnet_node_config *c,
                       struct node_state *s) {

    s->neighbor_addr = malloc(sizeof(mixnet_address) * c->num_neighbors);
    s->blocked = malloc(sizeof(bool) * c->num_neighbors);

    // A node with no neighbors gets NULL from malloc(0); that is fine, but
    // a genuine allocation failure is not.
    if ((c->num_neighbors > 0) &&
        ((s->neighbor_addr == NULL) || (s->blocked == NULL))) {
        free(s->neighbor_addr);
        free(s->blocked);
        return false;
    }
    become_root(c, s);

    for (uint16_t p = 0; p < c->num_neighbors; p++) {
        s->neighbor_addr[p] = INVALID_MIXADDR;  // Learned from the first STP packet
        s->blocked[p] = false;                  // See the note in the CP1 plan
    }
    s->hello_start_ms = now_ms();
    s->reelection_start_ms = now_ms();

    // The topology starts empty: even our own row waits on STP to supply our
    // neighbors' addresses. See originate_lsa().
    s->topology.v = NULL;
    s->topology.count = 0;
    s->topology.capacity = 0;
    s->lsa_start_ms = now_ms();

    return true;
}

static void state_free(struct node_state *s) {
    free(s->neighbor_addr);
    free(s->blocked);
    s->neighbor_addr = NULL;
    s->blocked = NULL;

    for (uint16_t i = 0; i < s->topology.count; i++) {
        free(s->topology.v[i].links);
    }
    free(s->topology.v);
    s->topology.v = NULL;
    s->topology.count = 0;
    s->topology.capacity = 0;
}

/**
 * STP receive path. The branch chain decides how *our* state changes; the two
 * rules after it react to what the *sender* claims, and so are evaluated on
 * post-update state. The cases are mutually exclusive: a parent leaves
 * path_len one greater than the packet's, a sibling leaves them equal, so
 * neither can also satisfy the child test.
 */
static void handle_stp(void *const handle,
                       const struct mixnet_node_config *c,
                       struct node_state *s, const uint8_t port,
                       mixnet_packet *const packet) {

    const mixnet_packet_stp *stp =
        (const mixnet_packet_stp *) packet->payload;

    const mixnet_address pkt_root = stp->root_address;
    const uint16_t pkt_path_len = stp->path_length;
    const mixnet_address pkt_addr = stp->node_address;

    // Neighbor discovery: every STP packet identifies its sender
    s->neighbor_addr[port] = pkt_addr;

    // A better (numerically smaller) root supersedes everything
    if (s->root > pkt_root) {
        s->root = pkt_root;
        s->path_len = (uint16_t) (pkt_path_len + 1);
        s->next_hop = pkt_addr;
        unblock_all(c, s);
        broadcast_stp(handle, c, s, -1);
    }
    // Hello from our parent: adopt its distance, whether it shrank or grew,
    // then relay the wave on all *other* links
    else if ((pkt_root == s->root) && (pkt_addr == s->next_hop)) {
        s->path_len = (uint16_t) (pkt_path_len + 1);
        broadcast_stp(handle, c, s, (int) port);
    }
    // A better path to the same root through this neighbor. The second
    // disjunct is the equal-cost case, broken by smallest neighbor address.
    else if ((pkt_root == s->root) &&
             ((s->path_len > (pkt_path_len + 1)) ||
              ((s->path_len > pkt_path_len) && (s->next_hop > pkt_addr)))) {

        const int old_parent_port = port_of(c, s, s->next_hop);
        if (old_parent_port >= 0) {
            // No longer a tree edge from our side. Recoverable: if that
            // neighbor later re-parents onto us, the child rule below
            // reopens the port.
            s->blocked[old_parent_port] = true;
        }
        s->path_len = (uint16_t) (pkt_path_len + 1);
        s->blocked[port] = false;
        s->next_hop = pkt_addr;
        broadcast_stp(handle, c, s, -1);
    }
    // Same root, same distance: a sibling, so this link is not a tree edge
    else if ((pkt_root == s->root) && (s->path_len == pkt_path_len)) {
        s->blocked[port] = true;
    }

    // The sender is claiming to be our child; that link is a tree edge
    if ((pkt_root == s->root) && (pkt_path_len == (s->path_len + 1))) {
        s->blocked[port] = false;
    }
    // Evidence that our path to our root is alive. The root test matters: a
    // parent that has regressed to a worse root is evidence the path is
    // gone, and must not hold the timer open.
    if ((pkt_addr == s->next_hop) && (pkt_root == s->root)) {
        s->reelection_start_ms = now_ms();
    }
    free(packet);
}

/**
 * FLOOD forwarding. Handout 2.3.1: flood packets travel only on links
 * belonging to the spanning tree, and a node that receives one on a non-user
 * port also forwards it up to its user port.
 */
static void handle_flood(void *const handle,
                         const struct mixnet_node_config *c,
                         struct node_state *s, const uint8_t port,
                         mixnet_packet *const packet) {

    const uint8_t user_port = (uint8_t) c->num_neighbors;
    const bool from_user = (port == user_port);

    // Arrived over a link that is not part of the tree. Dropping it here is
    // what prevents broadcast storms on cyclic topologies, and it must not
    // reach the user either, or that node counts the flood twice.
    if (!from_user && s->blocked[port]) {
        DBG("[%u] FLOOD dropped: ingress port %u is blocked\n",
            (unsigned) c->node_addr, (unsigned) port);
        free(packet);
        return;
    }

    // Out over every other tree link. A flood injected by our own user
    // arrives on the user port, which is never a valid except_port, so it
    // correctly goes out over all of them.
    broadcast_on_tree(handle, c, s, (int) port, packet);

    // A flood from a neighbor is also delivered to this node's user; one
    // injected by our own user is not sent back to it.
    if (from_user) {
        free(packet);
    }
    else {
        DBG("[%u] FLOOD delivered to user\n", (unsigned) c->node_addr);
        send_packet(handle, user_port, packet);
    }
}

/**
 * LSA receive path. An advertisement is both consumed and re-flooded: the
 * consume half adds one row to our adjacency list, the re-flood half is what
 * carries every node's purely local knowledge to every other node. Neither
 * alone produces a global view.
 */
static void handle_lsa(void *const handle,
                       const struct mixnet_node_config *c,
                       struct node_state *s, const uint8_t port,
                       mixnet_packet *const packet) {

    // LSAs are control traffic: the user neither sends nor receives one
    if (port == (uint8_t) c->num_neighbors) {
        free(packet);
        return;
    }

    // Bounds-check before trusting neighbor_count, since the links array is
    // variable-size and a short packet would send us reading past it
    if ((packet->total_size < LSA_PACKET_SIZE(0)) ||
        (packet->total_size <
            LSA_PACKET_SIZE(((const mixnet_packet_lsa *)
                             packet->payload)->neighbor_count))) {

        DBG("[%u] LSA dropped: bad total_size %u\n",
            (unsigned) c->node_addr, (unsigned) packet->total_size);
        free(packet);
        return;
    }
    const mixnet_packet_lsa *lsa = (const mixnet_packet_lsa *) packet->payload;

    // Our own advertisement, come back to us. Impossible on a settled tree,
    // but the blocked sets can disagree briefly while STP converges. Our row
    // is authoritative from our own config, so neither install this nor put
    // it back on the wire.
    if (lsa->node_address == c->node_addr) {
        free(packet);
        return;
    }

    // Arrived over a non-tree link: the same rule that keeps FLOOD from
    // storming. The tree spans every node, so a copy still reaches us.
    if (s->blocked[port]) {
        DBG("[%u] LSA dropped: ingress port %u is blocked\n",
            (unsigned) c->node_addr, (unsigned) port);
        free(packet);
        return;
    }

    if (graph_update(&s->topology, lsa->node_address,
                     lsa->neighbor_count, lsa_links(lsa))) {

        DBG("[%u] LSA from %u: %u links, topology now %u nodes\n",
            (unsigned) c->node_addr, (unsigned) lsa->node_address,
            (unsigned) lsa->neighbor_count, (unsigned) s->topology.count);

        update_shortest_path(c, s);
    }

    // Re-flooded even when the row did not change, unlike the plan's first
    // sketch. Suppressing that would strand nodes further along the tree: a
    // neighbor that already holds this row would stop an advertisement whose
    // only remaining job is to reach the nodes behind it. Termination does
    // not depend on the suppression anyway -- the tree is acyclic, and we
    // never send back out the ingress port, so a flood dies at the leaves.
    broadcast_on_tree(handle, c, s, (int) port, packet);
    free(packet);
}

/**
 * Runs on every iteration of the main loop, not only when a packet arrives:
 * a node whose neighbors have gone silent still has to send hellos and still
 * has to time out.
 */
static void check_timers(void *const handle,
                         const struct mixnet_node_config *c,
                         struct node_state *s) {

    const uint64_t now = now_ms();

    // The root drives the tree with a periodic hello. It has no parent, so
    // it never refreshes reelection_start_ms and must not test it.
    if (s->root == c->node_addr) {
        if ((now - s->hello_start_ms) >= c->root_hello_interval_ms) {
            broadcast_stp(handle, c, s, -1);
            s->hello_start_ms = now;
        }
    }
    // No hello from our parent for too long: the path to the root is gone.
    // Discard the old root outright, otherwise we keep believing it and
    // reject the very packets that would repair the tree.
    else if ((now - s->reelection_start_ms) >= c->reelection_interval_ms) {
        DBG("[node] reelection: dropping root %u\n", (unsigned) s->root);

        become_root(c, s);
        unblock_all(c, s);
        broadcast_stp(handle, c, s, -1);

        s->hello_start_ms = now;
        s->reelection_start_ms = now;
    }

    // Re-advertise our own links, independently of our role in the tree.
    // See originate_lsa() for why this repeats rather than firing once.
    if ((now - s->lsa_start_ms) >= c->root_hello_interval_ms) {
        originate_lsa(handle, c, s);
        s->lsa_start_ms = now;
    }
}

void run_node(void *const handle,
              volatile bool *const keep_running,
              const struct mixnet_node_config c) {

    struct node_state s;
    if (!state_init(&c, &s)) { return; }

    DBG("[%u] start, %u neighbors\n",
        (unsigned) c.node_addr, (unsigned) c.num_neighbors);

    // Every node begins by claiming to be the root of a tree of depth 0
    broadcast_stp(handle, &c, &s, -1);

    while (*keep_running) {
        uint8_t port = 0;
        mixnet_packet *packet = NULL;

        // Non-blocking: returns 0 when nothing is waiting, which is what
        // lets one iteration of this loop double as the timer tick.
        if (mixnet_recv(handle, &port, &packet) > 0) {
            switch (packet->type) {
            case PACKET_TYPE_STP:
                handle_stp(handle, &c, &s, port, packet);
                break;

            case PACKET_TYPE_FLOOD:
                handle_flood(handle, &c, &s, port, packet);
                break;

            case PACKET_TYPE_LSA:
                handle_lsa(handle, &c, &s, port, packet);
                break;

            default:
                // CP2 §2 does not route DATA/PING yet; drop them
                free(packet);
                break;
            }
        }
        check_timers(handle, &c, &s);
    }
    DBG("[%u] exit: root=%u len=%u parent=%u topology=%u nodes\n",
        (unsigned) c.node_addr, (unsigned) s.root, (unsigned) s.path_len,
        (unsigned) s.next_hop, (unsigned) s.topology.count);

    state_free(&s);
}
