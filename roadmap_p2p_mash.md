## Technical Specification: Gorgona Flexible P2P Mesh
---
#### 1. General Overview
**Gorgona** is a decentralized management system for distributed infrastructure. This specification describes a **Flexible Dual-Layer Mesh Architecture**. The system logically decouples data delivery from network management:

1.  **Command Plane (Data Layer):** A zero-trust layer for storing and replicating encrypted alerts/commands. Daemons act as "blind carriers"; only clients possess the cryptographic keys to decrypt and execute the content.
2.  **Management Plane (Administrative Layer):** A dedicated server-to-server layer used for P2P backbone synchronization, topology discovery (PEX), and performance monitoring.

#### 2. Objectives
1.  **Topology Automation (PEX):** Implementation of a Peer Exchange mechanism for dynamic node discovery.
2.  **Intelligent Routing:** Peer selection based on real-world **Effective Throughput** (Bytes/sec).
3.  **Management Plane Security:** Encryption of all administrative traffic based on a shared cluster secret (`sync_psk`).
4.  **Resilience Hardening:** Eliminating Single Points of Failure (SPOF) via "Happy Eyeballs" client connectivity.

#### 3. Flexible Deployment Models
*   **P2P Backbone:** A network of `gorgonad` daemons providing a resilient, distributed storage for encrypted payloads.
*   **Sidecar Mode (High Autonomy):** Client and daemon running on the same host. Recommended for critical infrastructure (e.g., DB segments) to ensure execution even during total network isolation.
*   **Remote/Standalone Mode (Telemetry/Admin):** Clients running without a local daemon. They connect to any available backbone node to inject commands or aggregate telemetry (e.g., for Prometheus export).

#### 4. Layer Isolation & Security

###### Layer 1: The Command Plane (End-to-End Encrypted)
*   **Role:** Storage and replication of encrypted alerts.
*   **Security:** Uses RSA-OAEP for key transport and AES-256-GCM for data.
*   **Blind Replication:** Daemons have no access to the decryption keys. They manage metadata (`unlock_at`, `expire_at`) but cannot read or modify the command payload.

###### Layer 2: The Management Plane (Administrative Mesh)
*   **Role:** Peer discovery, health checks, and metadata synchronization.
*   **Security:** All server-to-server communication is encapsulated in a secondary encryption layer using **AES-256-GCM**, keyed by `SHA-256(sync_psk)`.
*   **Authentication:** A **Challenge-Response** handshake with Nonce protection prevents unauthorized nodes from joining the mesh or sniffing the cluster topology.

#### 5. Peer Exchange (PEX) and Discovery
*   **Seed Nodes:** Initial connection requires only one or several known entry points.
*   **`NODES` Command:** A management-layer request allowing nodes to learn the full cluster map.
*   **Garbage Collection:** Automatic removal of inactive or unresponsive nodes from the Peer List.

#### 6. Performance Metrics (Performance Routing)
*   **Metric:** Effective Throughput (Bytes per second).
*   **Measurement:** `Speed = Transferred_Bytes / Elapsed_Time` calculated during real synchronization events.
*   **Smoothing:** **Rolling Average** (`Speed_Avg = (Old_Avg * 0.7) + (Current_Speed * 0.3)`) to prevent routing oscillation.
*   **Selection:** Priority is given to peers with the highest historical throughput to minimize transmission windows.

#### 7. Intelligent Client Logic
*   **Failover Strategy:** 
    1. Attempt local connection (`127.0.0.1`).
    2. On failure: Initiate parallel non-blocking `connect()` to the **Top-3** fastest known mesh nodes.
    3. Selection of the first node to complete the handshake.

#### 8. Technical Constraints
*   **Language:** Pure C (C99/C11).
*   **Dependencies:** OpenSSL (libcrypto).
*   **Networking:** Non-blocking sockets, `select()` (architecturally ready for `epoll`).
*   **Storage:** `mmap`-backed ring buffer for high-speed persistence.

---
#### *Gorgona: Decoupled, decentralized, and cryptographically secure management for distributed monsters.*
---
