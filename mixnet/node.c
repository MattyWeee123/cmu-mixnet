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

/**
 * This node's spanning-tree state.
 *
 * Invariant: root == config.node_addr  <=>  path_len == 0
 *                                     <=>  next_hop == INVALID_MIXADDR
 */
struct stp_state {
    mixnet_address root;        // Believed root of the spanning tree
    uint16_t path_len;          // Hop count from this node to the root
    mixnet_address next_hop;    // Parent: neighbor on the path to the root

    mixnet_address *neighbor_addr;  // [num_neighbors] port -> neighbor address
    bool *blocked;                  // [num_neighbors] port -> FLOOD blocked?

    uint64_t hello_start_ms;        // Last hello broadcast (root only)
    uint64_t reelection_start_ms;   // Last hello heard from the parent
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
                   const struct stp_state *s,
                   const mixnet_address addr) {

    if (addr == INVALID_MIXADDR) { return -1; }
    for (uint16_t p = 0; p < c->num_neighbors; p++) {
        if (s->neighbor_addr[p] == addr) { return (int) p; }
    }
    return -1;
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
                                      const struct stp_state *s) {
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
                          const struct stp_state *s,
                          const int except_port) {

    for (uint16_t p = 0; p < c->num_neighbors; p++) {
        if ((int) p == except_port) { continue; }

        mixnet_packet *packet = make_stp_packet(c, s);
        if (packet == NULL) { continue; }
        send_packet(handle, (uint8_t) p, packet);
    }
}

/** Reopen every port. Blocks computed against a stale root are meaningless. */
static void unblock_all(const struct mixnet_node_config *c,
                        struct stp_state *s) {
    for (uint16_t p = 0; p < c->num_neighbors; p++) {
        s->blocked[p] = false;
    }
}

/** Become the root of a depth-0 tree. Used at startup and on re-election. */
static void become_root(const struct mixnet_node_config *c,
                        struct stp_state *s) {
    s->root = c->node_addr;
    s->path_len = 0;
    s->next_hop = INVALID_MIXADDR;
}

static bool state_init(const struct mixnet_node_config *c,
                       struct stp_state *s) {

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

    return true;
}

static void state_free(struct stp_state *s) {
    free(s->neighbor_addr);
    free(s->blocked);
    s->neighbor_addr = NULL;
    s->blocked = NULL;
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
                       struct stp_state *s, const uint8_t port,
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
                         struct stp_state *s, const uint8_t port,
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

    // Out over every other tree link
    for (uint16_t p = 0; p < c->num_neighbors; p++) {
        if ((p == (uint16_t) port) || s->blocked[p]) { continue; }

        mixnet_packet *copy = clone_packet(packet);
        if (copy == NULL) { continue; }
        send_packet(handle, (uint8_t) p, copy);
    }

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
 * Runs on every iteration of the main loop, not only when a packet arrives:
 * a node whose neighbors have gone silent still has to send hellos and still
 * has to time out.
 */
static void check_timers(void *const handle,
                         const struct mixnet_node_config *c,
                         struct stp_state *s) {

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
}

void run_node(void *const handle,
              volatile bool *const keep_running,
              const struct mixnet_node_config c) {

    struct stp_state s;
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

            default:
                // CP1 does not route LSA/DATA/PING; drop them
                free(packet);
                break;
            }
        }
        check_timers(handle, &c, &s);
    }
    DBG("[%u] exit: root=%u len=%u parent=%u\n", (unsigned) c.node_addr,
        (unsigned) s.root, (unsigned) s.path_len, (unsigned) s.next_hop);

    state_free(&s);
}
