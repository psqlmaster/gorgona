### Technical Specification: Gorgona Self-Optimizing P2P Mesh

#### 1. General Overview
**Gorgona** is a decentralized management system for distributed infrastructure. This specification describes the transition from a classic client-server model to a **Symmetric Sidecar Mesh** architecture, where each cluster node runs a pair: a local daemon (`gorgonad`) and a local client (`gorgona`).

#### 2. Objectives
1.  **Topology Automation (PEX):** Implementation of a Peer Exchange mechanism for dynamic node discovery.
2.  **Intelligent Routing:** Peer selection based on real-world **Effective Throughput** (Bytes/sec) rather than simple latency.
3.  **Management Plane Security:** Encryption of service traffic between nodes based on the existing synchronization key.
4.  **Resilience Hardening:** Eliminating Single Points of Failure (SPOF) via "Happy Eyeballs" client connection logic.

#### 3. Architecture: Sidecar Mesh
*   **Local Connectivity:** The client on a node communicates exclusively with the local `gorgonad` instance at `127.0.0.1`.
*   **Backbone Connectivity:** Daemons form a full or partial P2P mesh network for alert replication.
*   **Autonomy:** In the event of external network loss, the node retains the ability to execute scheduled tasks from the daemon's local cache.

#### 4. Peer Exchange (PEX) and Discovery
*   **Seed Nodes:** Configuration in `gorgona.conf` / `gorgonad.conf` requires only one or several IP addresses of any active cluster nodes to "warm up" the network.
*   **`NODES` Protocol Command:**
    *   A service request to retrieve a list of known nodes.
    *   Response format: `NODES|IP:Port:Speed_Score,IP:Port:Speed_Score...`
*   **Pool Management:**
    *   **Active Pool:** Nodes with established active connections (limited by slots).
    *   **Passive List:** A database of all discovered addresses in the cluster.
    *   **Garbage Collection:** Automatic removal of nodes that fail to respond after a series of attempts with exponential backoff.

#### 5. Performance Metrics (Performance Routing)
*   **Metric:** Effective Throughput measured in Bytes per second.
*   **Measurement Algorithm:**
    *   Timestamping the start and end of data transfers using `clock_gettime`.
    *   Calculation: `Speed = Transferred_Bytes / Elapsed_Time`.
*   **Smoothing:** Application of a **Rolling Average**:
    `Speed_Avg = (Old_Avg * 0.7) + (Current_Speed * 0.3)`
*   **Peer Selection:** The server periodically rotates the slowest connection in the Active Pool, attempting to replace it with a random node from the Passive List (Darwinian selection).

#### 6. Management Plane Security
*   **Transport Key:** Utilization of `sync_psk` from the `[replication]` section of `gorgonad.conf`.
*   **Metadata Encryption:** All service packets (PEX, SYNC, NODES) are encapsulated using **AES-256-GCM**. The key is derived via `SHA-256(sync_psk)`.
*   **Handshake:** Implementation of a **Challenge-Response** mechanism using a Nonce (random number) to prevent Replay Attacks.
*   **Layer Isolation:**
    *   **Management Plane:** Encrypted with `sync_psk` (visible to daemons for routing/discovery).
    *   **Command Plane (E2EE):** Alerts (commands) remain encrypted with client-generated keys. Daemons cannot read or tamper with command content even with knowledge of `sync_psk`.

#### 7. Intelligent Client Logic
*   **Multi-Server Configuration:** Support for an array of server addresses in the client configuration.
*   **Failover Strategy:**
    1.  Attempt connection to `127.0.0.1`.
    2.  On failure: Initiate parallel non-blocking `connect()` calls to the **Top-3** fastest nodes from the `NODES` list.
    3.  Select the first node to complete the handshake for data transmission.

#### 8. Diagnostics and Observability
*   **`status` Command Expansion:** Displaying a peer table with "health" metrics: IP, RTT, effective throughput, and last synchronization time.
*   **Logging:** Detailed logging of PEX synchronization attempts and new node discovery events.

#### 9. Technical Constraints
*   **Language:** Pure C (C99/C11).
*   **Dependencies:** OpenSSL only (libcrypto).
*   **Networking:** Non-blocking sockets, `select()` (with architectural path to `epoll` for 1000+ nodes).
*   **Memory:** Minimal footprint, no leaks, `mmap`-backed alert storage.

---
**Gorgona: Transforming distributed infrastructure into a self-healing digital nervous system.**
