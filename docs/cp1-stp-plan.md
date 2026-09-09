# CP1 Plan — STP + FLOOD

Transcribed from whiteboard, 2026-09-09. This is Jason's design; §1–§3 are a faithful
transcription. §4 is a list of open questions raised during transcription — nothing there
has been decided or applied.

Spec references: handout §2.2.1 (*neighbor discovery*, *enabling safe flooding*),
§2.3.1 (`PACKET_TYPE_STP`, `PACKET_TYPE_FLOOD`).

---

## 0. Node state

Implied by the pseudocode below:

| Field | Meaning |
|---|---|
| `node.addr` | This node's mixnet address (from config) |
| `node.root` | Address of the believed spanning-tree root |
| `node.pathLen` | Hop count from this node to the root |
| `node.nextHop` | Address of the neighbor on the path to the root (parent) |
| `Neighbor_Addr[port]` | Port index → neighbor mixnet address |
| `blockedState` | Per-port blocked/unblocked flags |
| `hello_start` | Timestamp of last hello broadcast (root only) |
| `reelection_start` | Timestamp of last hello heard from the parent |

`broadcast(root, pathLen)` = send an STP packet carrying
`(root_address=root, path_length=pathLen, node_address=node.addr)`.

---

## 1. Start logic

```
If start:
    node_init()
    broadcast(node.addr, 0)

def node_init():
    node.root = config.node_addr
    node.addr = config.node_addr
    node.pathLen = 0
    node.nextHop = INVALID_MIXADDR
    for port in 0 ... config.num_neighbors - 1:
        neighborAddr[port] = INVALID_MIXADDR
        blockedState[port] = false
    hello_start = time()
    reelection_start = time()
```

Every node begins by claiming to be the root of a tree of depth 0. Initialize reelection_start. 

```
while running:
    packetReceived = mixnet_rcv()
    if packetReceived:
        # check packet type
        if packet.type == STP:
            handle_STP()
        elif packet.type == FLOOD:
            handle_Flood()
```

Listen to all ports for packets when node is running. 

---

## 2. STP packet handling

### Neighbor refresh logic

```
Neighbor_Addr[port] = packet.addr
```

### `If PACKET_STP == packet.header`

#### STP update and block logic

```
# If there is a root with lower ID
If node.root > packet.root:
    node.root    = packet.root
    node.pathLen = packet.pathLen + 1
    node.nextHop = packet.sender
    blockedState.reset()
    broadcast(node.root, node.pathLen)

# Receiving packet from parent, same root as before
elif packet.root == node.root && packet.addr == node.nextHop:
    node.pathLen = packet.pathLen + 1
    broadcast(node.root, node.pathLen)

# If same root,
# There is a better path through the sender, 
# Or if there is equal path through sender and sender wins tiebreak,
# Send through sender
elif packet.root == node.root  && 
    (node.pathLen > packet.pathLen + 1) ||
     (node.pathLen > packet.pathLen && node.nextHop > packet.addr):
    node.pathLen = packet.pathLen + 1
    block(node.nextHop)
    unblock(packet.sender)
    node.nextHop = packet.sender
    broadcast(node.root, node.pathLen)

# Neighbor cannot be my child nor parent, block
elif packet.root == node.root && node.pathLen == packet.pathLen:
    block(packet.sender)

# Condition for hello
if packet.addr == node.nextHop && packet.root == node.root:
    reelection_start = time()

# The sender is now my parent, unblock
if packet.root == node.root && packet.pathLen == node.pathLen + 1:
    unblock(port)
```

#### STP health logic

```
If node.root == node.addr && time() - hello_start >= hello_interval:
    broadcast(node.root, node.pathLen)
    hello_start = time()

# Only check for non-root nodes
# Once exceed reelection_interval, trigger reelection with node as root
If node.root != node.addr && time() - reelection_start >= reelection_interval:
    node.root = node.addr
    node.pathLen = 0
    node.nextHop = node.addr
    blockedState.reset()
    broadcast(node.addr, 0)
    reelection_start = time()
```

---

## 3. FLOOD packet handling

```
If FLOOD_PKT == packet.header:
    broadcast_to_all_non_blocked_children(packet)
```

---