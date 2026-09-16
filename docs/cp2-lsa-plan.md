# CP2 Plan - Link State Advertisement, Shortest Path Routing, Mixing

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

### FIB
- The FIB is Dijkstra's output, kept between runs: one `fib_entry` per vertex, parallel to `graph.v`, holding `reachable`, `route_len`, and the intermediate hops in forwarding order.
  That is exactly the form the routing header wants, so the source copies it in verbatim.
- It is derived state.
  `update_shortest_path()` rebuilds the whole table whenever `graph_update()` reports a change, and the data path only ever reads it.
  There is no per-destination caching: a cached path is only valid for the map it was computed on, and the event that changes the map is the same event that would have to invalidate it.
- `reachable` exists for the same reason `advertised` does.
  A direct neighbor and an unreachable node both have `route == NULL`.

### Dijkstra
- Linear scan for the next vertex to settle, no heap.
  The graph is at most a few hundred vertices, and the recompute runs a handful of times during the LSA burst and then stops, since byte-identical re-advertisements never reach it.
- Each vertex's advertised row is its outgoing edges, so the graph is directed and asymmetric costs need nothing special.
- Costs are `uint32_t`: 255 hops x 65535 overflows 16 bits.
- The equal-cost tie-break is on the first hop out of the source, per the handout, not on the predecessor.
  Each vertex therefore carries `first_hop` alongside `cost` and `prev`, inherited from the predecessor, or set to the neighbor itself when relaxing from us.
  A path is better if it is cheaper, or equal and through a smaller first hop.
- The same comparison decides the settling order, and that is required, not cosmetic.
  Over a zero-cost link a vertex can be reached at equal cost from two unsettled predecessors with different first hops.
  Settling by cost alone may settle it through the larger first hop before the smaller one has been examined, and a settled vertex is never revisited.
  Settling by (cost, first hop) guarantees that every equal-cost path with a smaller first hop has already been relaxed by then.
  `testcase_sp_zero_cost` is the regression test.
- Our own row must be in the graph before anything is reachable, since it is the only source of our outgoing edges.
  Until `originate_lsa()` installs it, the FIB is empty and user packets are dropped.

### Data path
- DATA and PING share one handler, `handle_routed()`, with three roles: source (arrived on the user port), destination (addressed to us), forwarder (everything else).
- Source: FIB lookup, memmove the DATA payload down by the route's size, copy the route in, hop index 0.
  User packets are allocated at `MAX_MIXNET_PACKET_SIZE`, so the move is safe as long as the result is a legal packet size, which is checked.
  A PING from the user carries no PING fields at all (`total_size` is 20); the source appends them and stamps `send_time` in monotonic milliseconds.
- Destination: up the user port.
  A PING request is also cloned into a reply: src and dst swapped, route reversed, hop index 0, `is_request` false.
  The reply follows the reversed route rather than a fresh FIB lookup, as the handout specifies.
- Forwarder: we must be `route[hop_index]`, else drop.
  Increment, then send to `route[hop_index]`, or to `dst` once the route is used up.
- Routed packets may use any link, blocked or not.
  The spanning tree constrains flooding only.
- Every routed packet leaves through `send_to_next_hop()`, which is the seam for mixing.
- Mixing is §3 and random routing is §4; both are implemented and sit
  behind this same seam.

## 3. Mixing

### The rule
- A node collects exactly `mixing_factor` packets before sending any of them out
  over the network, then releases the whole batch.
  Collect k, send k - not collect k and release one.
  Releasing one leaves a permanent backlog of k-1: the buffer refills to k on the
  next arrival and drains to k-1 again, so the last k-1 packets of a run are never
  delivered and `await_packet_propagation()` times out short.
  It would also be a pure delay line - output order equals input order, so an
  observer learns exactly what they would have learned without it.
  The batch release *is* the mixing.
- One budget per node, not one per port.
  The handout counts packets "received from the user layer, a neighbor, or both"
  against a single number, so there is a single buffer.
- No timeout flush. "Exact number" means exact; see liveness below.

### What gets mixed
- DATA and PING, and only on their way *out over the network*.
- Control packets bypass.
  STP and LSA leave through `send_packet()` and `broadcast_on_tree()` and never
  reach `send_to_next_hop()`, so they already sit outside the seam.
  Keep it that way: a node that mixed its own hellos would stop refreshing the
  tree while waiting on a batch that may never fill.
- FLOOD is the genuinely ambiguous case.
  `config.h` says "non-control", and the framework's user port accepts exactly
  `{FLOOD, DATA, PING}`, which argues for including it.
  Exclude it anyway: a FLOOD is replicated to every tree port, so "one packet" has
  no single meaning for the count, and the handout introduces mixing purely to
  hide *which pairs are communicating* - a question only source-routed traffic
  raises. Revisit if a mixing test turns out to send FLOODs.
- Packets addressed to us are never buffered; they go straight up the user port.
  The user port is not "the network", and buffering them would break
  `testcase_ping` outright - a destination receiving fewer than k packets would
  never deliver even one.
  So the count is just the number of network-bound packets we are holding.
- A PING reply is generated locally rather than received, but it is network-bound,
  so it enqueues like anything else.
  The request it answers still goes up to the user immediately, unbuffered.

### Buffer
- The buffer never exceeds `mixing_factor` (at most 16), because we flush the
  moment we reach it and a flush always drains to empty.
  So: one flat array sized at startup, plus a count. No ring buffer, no head/tail
  wraparound, no growth.

```c
struct mix_slot {
    uint8_t port;               // Egress port, resolved before enqueueing
    mixnet_packet *packet;      // Ours until it is flushed
};

// Added to struct node_state:
struct mix_slot *mix;           // [mixing_factor], oldest first
uint16_t mix_count;             // Held packets; always < mixing_factor between calls
```

- Resolve the egress port *before* enqueueing, not at flush time.
  A packet whose next hop is not a neighbor is dropped today; enqueueing first
  would let that drop silently eat a slot, leaving the node one short of a batch
  forever.
- `state_init()` allocates the array; `state_free()` frees the array *and* every
  packet still held in it.
  A node that ends a run mid-batch owns those packets and leaks them otherwise.

### The seam
- `send_to_next_hop()` is the only path from a routed packet to the wire, for all
  three roles (source, forwarder, PING reply), so mixing goes there and nowhere
  else.
- It, `source_route()` and `handle_routed()` currently take
  `const struct node_state *s`. The buffer is mutable state, so all three drop the
  `const`.

```c
def send_to_next_hop(packet):           # takes ownership
    rh = routing_header(packet)
    next_hop = rh.route[rh.hop_index] if rh.hop_index < rh.route_length \
                                      else rh.dst_address

    port = port_of(next_hop)
    if port < 0:
        free(packet); return            # dropped before it can take a slot

    if config.mixing_factor <= 1:       # 1 is the default
        send_packet(port, packet)       # degenerates to today's behavior
        return

    s.mix[s.mix_count] = (port, packet)
    s.mix_count += 1

    if s.mix_count >= config.mixing_factor:
        for (p, pkt) in s.mix[0 : s.mix_count]:
            send_packet(p, pkt)         # FIFO; the framework takes ownership
        s.mix_count = 0
```

- Test `>=`, not `==`, so a stray `mixing_factor` of 0 flushes immediately rather
  than never.
- Flush at enqueue time, inside this call, not on the `check_timers()` tick.
  The batch is complete the moment the k'th packet arrives; deferring the send to
  the next tick adds latency for nothing.
- Order within a batch is FIFO.
  The handout does not ask for a shuffle, and staying deterministic keeps routes
  checkable in `pcap`.
  The mixing comes from batching traffic from different links together, not from
  permuting it.

### Liveness
- A node left holding fewer than `mixing_factor` packets holds them until the run
  ends. That is the specified behavior, not a bug to paper over with a timer: do
  not add a timeout flush, and check the test's arithmetic before debugging a
  suspected hang here.
- Consequence for our own tests: every mixing node must see a multiple of its
  mixing factor.
  Count the packets that actually *cross* each node, not the flows sent - a
  forwarder that sits on two flows' shortest paths sees both.
- That count is necessary but not sufficient: the packets also have to be able
  to *reach* the node while it is waiting.
  Two mixers in series, each needing a packet the other is holding, deadlock
  even though both counts come out right.
  `10 --- [20, k=2] --- 30 --- [40, k=2] --- 50` with flows 10->50 and 50->10
  gives each mixer a count of 2 and delivers nothing: node 20 holds the
  rightbound packet waiting for the leftbound one, which is sitting at node 40
  waiting for the rightbound one. Running both flows in the same direction
  fixes it, since then each mixer's batch is filled by packets that have
  already got past every mixer upstream of it.
  `testcase_mix_chain` is the working version, and says so in its comment.

### Interaction with random routing
- Orthogonal.
  `do_random_routing` changes only which route `source_route()` writes into the
  header; every packet still leaves through the same seam.
  It does change *which* nodes see traffic, so the per-node counts above stop
  being predictable once it is on - worth keeping the two features' tests apart.

## 4. Random Routing

### The rule
- Only the source randomizes.
  `do_random_routing` is per-node config and changes exactly one thing: which
  route `source_route()` writes into the header. Forwarders follow the route
  they are handed and never look at the flag.
- The route is a detour through one random waypoint W, each leg a shortest
  path: `src -> ... -> W -> ... -> dest`.
- Revisiting a node is allowed and expected.

### Choosing the waypoint
- Draw W uniformly from the topology, excluding `src` and `dest`.

### Building the route
- The two legs come from different places.
  `fib_lookup(s, W)` answers the first, because the FIB is rooted at this node.
  It cannot answer the second: the FIB holds routes *from us*, so the W -> dest
  leg needs its own `run_dijkstra(g, id_of(W))` plus an `install_route()`-style
  walk of the predecessor chain to turn `struct sp_vertex *` into hops. That
  array is freshly allocated and we free it; the FIB's array is not ours.
- **W has to be spliced in between them.** Both legs exclude it.
  A `fib_entry` route is "hops strictly between us and the destination", and
  `install_route()` builds its array by walking `sp[dst].prev` back to `self`.
  So W - the destination of the first leg, the root of the second - is in
  neither. Concatenating the legs alone joins them at a node present in neither,
  leaving a seam between two nodes that are not adjacent.

```
def generate_random_route(src, dest):       # hops only, excluding src and dest
    eligible = [v for v in topology if v != src and v != dest]
    if eligible is empty:
        return fib_lookup(dest)             # 2-node topology, or barely converged

    W = eligible[random(len(eligible))]

    src_to_w = fib_lookup(W)                # strictly between src and W
    if src_to_w is None:
        return fib_lookup(dest)             # W not reachable yet

    w_to_dest = shortest_path_from(W, dest) # own Dijkstra; strictly between
    if w_to_dest is None:
        return fib_lookup(dest)             # dest not reachable from W

    route = src_to_w + [W] + w_to_dest      # the [W] is the whole trick
    if len(route) > MAX_MIXNET_ROUTE_LENGTH:
        return fib_lookup(dest)
    return route
```

### The seam
- `source_route()` is where this goes, and the only place.
  Inside source_route(), check the config to see if random routing is to be used. 
  If using random routing, use generate_random_route()

### Fallbacks
- Every failure falls back to the plain FIB route, the one
  `do_random_routing == false` would have produced: empty eligible set, W
  unreachable, dest unreachable from W, route over the cap.
- A source that cannot build a detour should still deliver. Dropping the packet
  instead would turn a converging topology into lost traffic, and the length
  guard exists in `install_route()` already - not repeating it here would be the
  inconsistency.
