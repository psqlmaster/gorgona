## Technical Specification: Gorgona Client Autonomy & Sovereignty

### 1. General Overview
This phase upgrades the **Gorgona CLI Client** from a simple terminal tool to an **Autonomous Intelligent Agent**. The client will no longer depend on a single hardcoded server address, but will instead leverage the Layer 2 Mesh metrics and a shared peer registry to ensure zero-latency command delivery and 100% execution integrity (Idempotency).

### 2. Core Objectives
1.  **Universal Peer Caching:** Enable the client to read and write to the shared `/var/lib/gorgona/peers.cache`.
2.  **Execution Guarantee (Idempotency):** Implement a tracking mechanism to ensure each unique Snowflake ID is executed exactly once.
3.  **Latency-Aware Probing (Happy Eyeballs):** Implement parallel non-blocking connection attempts to the top-N healthiest nodes.
4.  **Graceful Failover:** Automated transition between mesh nodes if the primary entry point degrades.

### 3. Implementation Details: Client Architecture

#### A. Shared Intelligence Protocol
*   **Path:** `/var/lib/gorgona/peers.cache` (Shared with `gorgonad`).
*   **Logic:**
    *   **Read-at-Startup:** Client loads all IPs from the cache before attempting any connection.
    *   **Live-Sync:** If the client receives a `PEX_LIST` or `PONG` (with metadata) during an active session, it updates the cache file.
    *   **Sidecar Synergy:** If a local daemon is running, the client prioritizes `127.0.0.1`, but instantly switches to remote peers from the shared cache if the local daemon is unresponsive.

#### B. The Idempotency Filter (History Tracker)
*   **Database:** `/var/lib/gorgona/history.log`.
*   **Identifier:** Each command is identified by its **64-bit Snowflake ID**.
*   **Verification:** 
    *   Upon receiving an alert via `LISTEN` or `SUBSCRIBE`, the client checks if the ID exists in the history log.
    *   If found: The alert is discarded without decryption or execution.
    *   If new: The command is executed, and the ID is persisted to the log with a timestamp.
*   **Auto-Pruning:** Since alerts have an `expire_at` field, IDs in the history log older than the max TTL (e.g., 24 hours) are automatically removed to keep the footprint small.

#### C. Connectivity Engine: Parallel Probing
*   **Mechanism:** Instead of `connect(peer[0]) -> wait -> fail -> connect(peer[1])`.
*   **Happy Eyeballs Logic:**
    1.  Pick the **Top 3** nodes based on historical Gorgona Score (from cache metadata or order).
    2.  Initiate 3 non-blocking `connect()` calls simultaneously.
    3.  The **first** node to complete the Handshake becomes the active provider.
    4.  All other pending connections are immediately closed.

### 4. Client Logic Flow
1.  **INIT:** Load PSK, Load Peer Cache.
2.  **DISCOVER:** Launch parallel probes to Top-3 peers.
3.  **CONNECT:** Establish encrypted L2 Handshake.
4.  **OPERATE:** 
    *   If `LISTEN`: Stream alerts $\rightarrow$ Filter via History Tracker $\rightarrow$ Execute $\rightarrow$ Update History Tracker.
    *   If session health drops (Server latency > threshold): Redo **DISCOVER** step without interrupting the local command loop.

### 5. Expected Outcome
*   **Resilience:** The client can reach the mesh as long as at least one node is alive in the global registry.
*   **Precision:** No command is ever executed twice, even if the client moves between different servers during a network split.
*   **Performance:** Client "felt speed" is always optimal as it is pinned to the most performant mesh entry point.

---

