# CP2 Plan - Link State Advertisement, Shortest Path Routing

## 1. Link State Advertisement

### Storing the global view of the graph
- To store the global view of the graph, we can make use of an adjacency list.
- The adjacency list will be an array of vertices. A vertex is one mixnet node.
- Each vertex should contain
    - Address of the node
    - Number of neighbors
    - Link weights to each of the neighbors
- Sizing: `MAX_MIXNET_ROUTE_LENGTH` is 256, so the network is at most ~258
  nodes, and the cp2 tests are 7-8 nodes. Linear scans are fine everywhere -
  no hash table for address lookup, no priority queue in Dijkstra.
- Reuse `mixnet_lsa_link_params` as the edge type. It is already
  `(neighbor_mixaddr, cost)`, so we can `memcpy` straight out of the LSA
  payload on receive, and our own row is byte-for-byte the payload we need
  when originating our own LSA.

```c
struct vertex {
    mixnet_address addr;
    bool advertised;                // Have we received this node's LSA?
    uint16_t num_links;
    mixnet_lsa_link_params *links;  // [num_links], (neighbor_mixaddr, cost)
                                    // NULL => mentioned in someone else's
                                    // LSA, own LSA not yet received
};

struct graph {
    struct vertex *v;   // [count], array index is the vertex id
    uint16_t count;
    uint16_t capacity;
};
```

- `advertised` is needed because a node that advertises *zero* links and a
  node merely named in someone else's neighbor list both leave `links == NULL`.
  Without the flag, a link-less node's first LSA is mistaken for a no-op, and
  "have we heard from this node yet?" becomes unanswerable - which §2 wants for
  a convergence check.
- The vertex set is *originators + every address named in any neighbor list*.
  A node can be named as a neighbor before its own LSA arrives, so
  `id_lookup()` is find-or-insert, not find: it appends a vertex with
  `links = NULL, num_links = 0` on first sight and returns its id. Otherwise
  we would hit a missing id in the middle of Dijkstra's relaxation loop.
- Vertex ids are stable because cp2 never removes a vertex (links never
  fail). Ids shift on append only, so index == vertex id holds for the life
  of the node, and `dist[]` / `prev[]` / FIB can all be arrays parallel to
  `graph.v`.
- Where this lives: rename `struct stp_state` to `struct node_state` and add
  `struct graph topology` plus the FIB to it. Every handler already threads
  `(c, s, port, packet)`, so this avoids adding a parameter everywhere. Split
  the existing doc comment, since the root/path_len invariant is STP-only.

### Originating our own LSA
- We never receive our own LSA, so nothing else will ever create our row. We
  build it ourselves from `c->link_costs[p]` paired with `s->neighbor_addr[p]`.
- Neighbor *addresses* come from STP neighbor discovery, so we cannot build a
  complete LSA until the neighbor table is full - `originate_lsa()` returns
  early until every entry of `s->neighbor_addr` is valid.
- Re-originate periodically (every `root_hello_interval_ms`, on the existing
  timer tick) rather than once. Our first advertisement can go out while the
  tree is still settling, and a flood across a changing tree may not reach
  every node; repeating repairs that without needing to detect tree changes.
- Re-origination is harmless: every receiver replaces our row wholesale, and an
  unchanged row costs them no recompute.

### Receiving a LSA packet
- When a node receives a LSA packet, it will carry out `handle_lsa()`
  (naming it to match `handle_stp` / `handle_flood`).
- A new LSA is a *complete replacement* of the advertising node's row, never a
  delta - the originator is the sole authority on its own links. Merging into
  the existing row would retain edges the originator no longer advertises.
- Two hazards:
    1. Interning the mentioned neighbor addresses can grow `g->v`, and
       `realloc` may move it. So intern everything *first*, then take the row
       pointer. A pointer taken before the inserts would dangle.
    2. Overwriting `row->links` without freeing the old array leaks it.
- Detect whether the row actually changed, and use it to skip the shortest-path
  recompute. During the initial flooding burst most arrivals are new, but every
  re-advertisement after convergence is byte-identical, so this keeps Dijkstra
  off the hot path.
- Do **not** also use it to suppress the re-flood (an earlier draft of this plan
  did). Suppressing strands nodes further along the tree: a neighbour that
  already holds the row would stop an advertisement whose only remaining job is
  to reach the nodes behind it, and periodic re-advertisement could then never
  repair the gap. Termination does not depend on the suppression anyway - see
  the flooding section.

```c
def handle_lsa(port, packet):
    origin = packet.node_address

    # Our own row is authoritative from config. If the tree is momentarily
    # inconsistent during STP convergence our own LSA can come back to us;
    # do not install it and do not re-flood it.
    if origin == config.node_addr:
        free(packet); return

    if graph_update(origin, packet.neighbor_count, packet.links):
        update_shortest_path()              # FIB is derived state

    broadcast_lsa(port, packet)             # unconditional; see above


# Returns True if the topology actually changed.
def graph_update(origin, num_links, links):
    # Intern before taking a row pointer - these inserts may realloc g->v
    for i in range(num_links):
        id_lookup(links[i].neighbor_mixaddr)
    row = &graph.v[id_lookup(origin)]       # safe: no further inserts past here

    bytes = sizeof(mixnet_lsa_link_params) * num_links
    if row.advertised and row.num_links == num_links \
       and (num_links == 0 or memcmp(row.links, links, bytes) == 0):
        return False                        # byte-identical, no state change

    links_copy = NULL
    if num_links > 0:                       # avoid malloc(0) / memcpy(NULL)
        links_copy = malloc(bytes)
        memcpy(links_copy, links, bytes)    # note: memcpy(dest, src, n)

    free(row.links)                         # NULL on a find-or-insert row
    row.links = links_copy
    row.num_links = num_links
    row.advertised = True
    return True
```

### Flooding a LSA
- LSAs flood along the spanning tree, same rule as FLOOD: tree links only
  (skip `s->blocked[p]`) and skip the ingress port.
- The exclusion is by **port**, not by vertex id. Ports index our own links
  (`0 .. num_neighbors-1`); vertex ids index the global topology. They are
  unrelated namespaces and must not be compared.
- Unlike FLOOD, an LSA is never sent out the user port - it is a control
  packet, and the user never injects one either, so there is no `from_user`
  case. Free the packet after re-flooding.
- The loop is now identical to the one in `handle_flood`, so factor it out
  into `broadcast_on_tree(handle, c, s, except_port, packet)` and call it from
  both.

```c
def broadcast_lsa(ingress_port, packet):
    for p in range(config.num_neighbors):   # p is a port, not a vertex id
        if p == ingress_port or s.blocked[p]:
            continue
        mixnet_send(handle, p, clone_packet(packet))
    free(packet)                            # not delivered to the user
```

- Flooding terminates without any duplicate suppression: the spanning tree is
  acyclic and we never send back out the ingress port, so a flood dies at the
  leaves. This is the same reason `handle_flood` needs no suppression.
- Bounded cost: one advertisement crosses each of the N-1 tree edges exactly
  once, so a full round of re-advertisement by all N nodes is N(N-1) packets
  per interval - 42 per 100ms for the 7-node ring.
- Bounds-check `total_size` against `LSA_PACKET_SIZE(neighbor_count)` before
  reading the links array, since it is variable-size and a short packet would
  have us reading past the allocation.
- No sequence numbers in cp2. Real OSPF needs them so a late stale LSA cannot
  overwrite fresh state, but here links never fail and each node advertises the
  same content every time, so there is no old-versus-new to adjudicate. This is
  the piece to add if we ever handle topology changes.

## 2. Shortest Path Routing
- TODO: Dijkstra over the adjacency list, FIB, source-routing the RH.
- Notes so far: `dist` must be `uint32_t` (255 hops x cost 65535 overflows 16
  bits); the equal-cost tie-break is on the *first hop out of the source*, not
  the predecessor, so carry a `first_hop[]` alongside `dist[]` / `prev[]`.
