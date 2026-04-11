### Technical Specification: Gorgona Flexible P2P Mesh
---
#### 1. General Overview
**Gorgona** is a decentralized management system for distributed infrastructure. This specification describes a **Flexible Mesh Architecture**. The core consists of a P2P backbone of daemons (`gorgonad`) that store and replicate the alert database. Clients (`gorgona`) act as independent agents that can either run alongside a local daemon (Sidecar mode) for maximum autonomy or operate as standalone tools (Remote mode) to send commands or aggregate telemetry from the mesh.

#### 2. Objectives
1.  **Topology Automation (PEX):** Implementation of a Peer Exchange mechanism for dynamic node discovery.
2.  **Intelligent Routing:** Peer selection based on real-world **Effective Throughput** (Bytes/sec).
3.  **Management Plane Security:** Encryption of service traffic between nodes based on the existing synchronization key.
4.  **Resilience Hardening:** Eliminating Single Points of Failure (SPOF) via "Happy Eyeballs" client connection logic across multiple mesh nodes.

#### 3. Flexible Architecture
*   **P2P Backbone:** Daemons form a resilient mesh network. They are responsible for data persistence, consistency, and gossip-based discovery.
*   **Sidecar Deployment (Recommended for Segments):** Deploying both a client and a daemon on critical nodes (e.g., DB segments) to ensure task execution even during total network isolation.
*   **Standalone Deployment (For Consumers/Admins):** Clients running without a local daemon. For example, a Prometheus exporter node can pull data from any available `gorgonad` in the mesh without hosting its own database.
*   **Multi-Node Access:** Standalone clients can be configured with a list of multiple entry points to ensure connectivity if a specific mesh node goes down.

#### 4. Peer Exchange (PEX) and Discovery
*   **Seed Nodes:** Initial configuration requires only one or several "Seed" IP addresses.
*   **`NODES` Protocol Command:** A service request allowing both servers and standalone clients to retrieve the current cluster map.
*   **Pool Management:**
    *   **Active Pool:** Nodes with established active connections.
    *   **Passive List:** A background database of all discovered addresses in the cluster.
    *   **Garbage Collection:** Automatic removal of inactive nodes.

#### 5. Performance Metrics (Performance Routing)
*   **Metric:** Effective Throughput (Bytes per second).
*   **Measurement:** Calculating `Speed = Transferred_Bytes / Elapsed_Time` during real data synchronization.
*   **Smoothing:** Application of a **Rolling Average**: `Speed_Avg = (Old_Avg * 0.7) + (Current_Speed * 0.3)`.
*   **Peer Selection:** Clients and servers prioritize connections to nodes with the highest historical throughput.

#### 6. Management Plane Security
*   **Transport Key:** Utilization of `sync_psk` from the `[replication]` section.
*   **Metadata Encryption:** All service packets (PEX, SYNC, NODES) are encapsulated using **AES-256-GCM**, keyed by `SHA-256(sync_psk)`.
*   **Handshake:** A **Challenge-Response** mechanism using a Nonce to prevent Replay Attacks.
*   **E2EE Command Plane:** Regardless of the management layer, commands (alerts) remain encrypted with client-specific keys, ensuring daemons never see the raw content.

#### 7. Intelligent Client Logic
*   **Multi-Server Configuration:** Support for an array of entry points.
*   **Failover Strategy:**
    1.  Attempt connection to a preferred node (e.g., `127.0.0.1` if available).
    2.  On failure: Initiate parallel non-blocking `connect()` calls to the **Top-3** fastest known nodes.
    3.  Proceed with the first successful connection.

#### 8. Diagnostics and Observability
*   **`status` Command:** Real-time table of peers, their RTT, effective speed, and sync status.
*   **Logging:** Tracking PEX events and mesh topology changes.

#### 9. Technical Constraints
*   **Language:** Pure C (C99/C11).
*   **Dependencies:** OpenSSL only.
*   **Networking:** Non-blocking sockets, `select()` (scalable to `epoll`).
*   **Memory:** `mmap`-backed storage, minimal footprint.

---
##### **Gorgona: Resilient, decentralized, and flexible management for modern distributed "monsters".**
---

