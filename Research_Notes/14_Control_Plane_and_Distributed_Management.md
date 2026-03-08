# Research Note 14: Control Plane and Distributed Management

**Document Version:** 4.0  
**Last Updated:** March 8, 2026  
**Classification:** Internal Research — Engineering Reference

---

## Abstract

Rudras v4.0 includes a distributed control plane layer for managing multiple Rudras data-plane nodes from a single centralised service. This document covers the gRPC API definition, the multi-node topology, the policy synchronisation protocol, and the event streaming architecture. This layer targets enterprise deployments with 5+ nodes across multiple network segments or cloud regions.

---

## 1. Architecture Overview

### 1.1 Two-Plane Model

Rudras separates concerns into two distinct planes, following the standard network engineering model:

```
┌─────────────────────────────────────────────┐
│              CONTROL PLANE                  │
│  (Go service, gRPC server)                  │
│                                             │
│  • Stores canonical policy set              │
│  • Receives telemetry from all nodes        │
│  • Distributes policy updates               │
│  • Aggregates cross-node metrics            │
│  • Runs SOAR playbooks at cluster level     │
└──────────────┬──────────────────────────────┘
               │ gRPC (TLS)
    ┌──────────┼──────────┐
    ▼          ▼          ▼
┌────────┐ ┌────────┐ ┌────────┐
│ Node 1 │ │ Node 2 │ │ Node 3 │  DATA PLANE
│ Rudras │ │ Rudras │ │ Rudras │  (Rust, firewall)
│ (Rust) │ │ (Rust) │ │ (Rust) │
└────────┘ └────────┘ └────────┘
```

**Data plane** (each Rudras instance): Inspects packets, enforces policy, streams events up.  
**Control plane** (Go gRPC service): Issues policy updates down, receives events and metrics up.

This separation means the data plane can operate independently if connectivity to the control plane is lost — last-known-good policy is enforced until reconnection. This is a critical resilience property: a control plane outage does not stop enforcement.

### 1.2 Repository Layout

```
control-plane/
└── pkg/
    └── grpc/
        └── proto/
            └── controlplane.proto   ← gRPC service definition (this document)
```

The control plane server is implemented in Go (not in this repository). The `.proto` file is the contract between the Go server and the Rust data plane clients.

---

## 2. gRPC Service Definition

**Protocol:** gRPC over HTTP/2 with mutual TLS  
**Proto file:** `control-plane/pkg/grpc/proto/controlplane.proto`  
**Go package:** `Rudras-controlplane/pkg/grpc/proto`

### 2.1 Service: `ControlPlaneService`

```protobuf
service ControlPlaneService {
  rpc SyncPolicy(PolicySyncRequest) returns (PolicySyncResponse);
  rpc StreamEvents(EventStreamRequest) returns (stream Event);
  rpc ReportMetrics(MetricsReport) returns (MetricsAck);
}
```

Three RPCs:
1. **`SyncPolicy`** — Unary RPC. Node asks: "I am at policy version X, give me updates." Control plane responds with the full current policy set if version differs.
2. **`StreamEvents`** — Server-streaming RPC. Node subscribes to a live event stream from the control plane. Used for push-based policy updates, threat intel propagation, and operator commands.
3. **`ReportMetrics`** — Unary RPC. Node pushes a performance metrics snapshot to the control plane.

### 2.2 Policy Synchronisation (`SyncPolicy`)

**Request:**
```protobuf
message PolicySyncRequest {
  string node_id       = 1;  // Unique identifier for this Rudras node
  uint64 current_version = 2;  // Policy version the node currently has
  string region        = 3;  // Geographic region (e.g., "ap-south-1")
  string cloud_provider = 4; // "aws", "azure", "gcp", "on-prem"
}
```

**Response:**
```protobuf
message PolicySyncResponse {
  bool success             = 1;
  repeated Policy policies = 2;  // Full policy set (not a diff)
  uint64 version           = 3;  // New version number
  string error_message     = 4;
}
```

**Protocol flow:**
1. Node starts → calls `SyncPolicy` with `current_version=0`
2. Control plane returns all policies with current version (e.g., `version=42`)
3. Node loads and enforces policies, stores version=42 locally
4. Node polls `SyncPolicy` periodically (default: every 30 seconds) with `current_version=42`
5. If control plane version is still 42 → `success=true, policies=[]` (empty, no change)
6. If control plane version is 45 → `success=true, policies=[...full set...]`
7. Node atomically replaces its policy set on receipt (old policy enforced until swap completes)

**Versioning strategy:** Monotonically incrementing integer. The control plane increments the version whenever any policy is added, modified, or removed. Nodes always receive the full policy set rather than a diff — this keeps the protocol stateless and resilient to missed updates.

### 2.3 Policy Object Schema

```protobuf
message Policy {
  string id          = 1;  // UUID, e.g., "f3a4b5c6-..."
  string name        = 2;  // Human-readable, e.g., "Block Tor Exit Nodes"
  string description = 3;  // Free-text description
  string source_ip   = 4;  // CIDR or exact IP, e.g., "10.0.0.0/8" or "any"
  string dest_ip     = 5;  // CIDR or exact IP
  string protocol    = 6;  // "tcp", "udp", "icmp", "any"
  string action      = 7;  // "allow" | "block" | "rate_limit" | "inspect"
  uint64 rate_limit_pps = 8;  // Packets/second limit (only for rate_limit action)
  int64 created_at   = 9;  // Unix epoch seconds
  int64 updated_at   = 10; // Unix epoch seconds
}
```

**Action values:**
- `allow` — Permit traffic matching this rule without further inspection
- `block` — Drop and install WFP block rule for the source
- `rate_limit` — Allow but throttle to `rate_limit_pps` packets/second using token bucket
- `inspect` — Allow but force through full IDS/AI inspection pipeline (even if fast-path would have bypassed)

**Special values for IP fields:**
- `"any"` — Match any source/destination IP
- `"10.0.0.0/8"` — CIDR range
- `"192.168.1.100"` — Exact IP

### 2.4 Event Streaming (`StreamEvents`)

**Request:**
```protobuf
message EventStreamRequest {
  string node_id            = 1;
  repeated string event_types = 2;  // Filter: subscribe only to these types
}
```

Subscribable `event_types` values:
- `"policy_update"` — Push-trigger a policy sync immediately
- `"global_block"` — Control plane mandates blocking a specific IP across all nodes
- `"threat_broadcast"` — New IOC pushed to all nodes without waiting for next sync
- `"config_update"` — Control plane pushes a config change
- `"operator_command"` — Operator-initiated action (e.g., emergency lockdown)

**Event message:**
```protobuf
message Event {
  int64  timestamp  = 1;  // Unix epoch nanoseconds
  string node_id    = 2;  // Which node this event is for (can be "*" for broadcast)
  string event_type = 3;  // One of the types above
  bytes  data       = 4;  // JSON-encoded payload specific to event_type
}
```

**Push-based threat broadcast example:**
When the control plane receives a critical IOC from an upstream threat feed, it immediately pushes a `threat_broadcast` event to all connected nodes:
```json
{
  "event_type": "threat_broadcast",
  "data": {
    "ioc_type": "ip",
    "value": "185.220.101.5",
    "category": "TorExitNode",
    "confidence": 0.99,
    "source": "EmergingThreats",
    "ttl_secs": 3600
  }
}
```
Each node receiving this event immediately adds the IP to its in-memory blocklist — no policy version increment needed, allowing sub-second propagation to all nodes.

### 2.5 Metrics Reporting (`ReportMetrics`)

**Report:**
```protobuf
message MetricsReport {
  string node_id             = 1;
  int64  timestamp           = 2;  // Unix epoch seconds (IST on Rudras nodes)
  uint64 packets_processed   = 3;  // Total since last report
  uint64 packets_allowed     = 4;
  uint64 packets_blocked     = 5;
  double packet_rate_pps     = 6;  // Current packets/second
  double cpu_usage_percent   = 7;  // Rudras process CPU
  double memory_usage_mb     = 8;  // Rudras process RSS
  double avg_latency_us      = 9;  // Avg end-to-end pipeline latency (microseconds)
}
```

The control plane aggregates `MetricsReport` from all nodes to build a cluster-wide dashboard. The fields map directly to Prometheus metrics on each node — the control plane acts as a second-level aggregator.

**Acknowledgement:**
```protobuf
message MetricsAck {
  bool success   = 1;
  string message = 2;  // Human-readable, e.g., "received" or error description
}
```

---

## 3. Multi-Node Deployment Topology

### 3.1 Flat Topology (Single Region)

```
Internet
    │
    ▼
┌──────────┐      ┌──────────────────────┐
│ Gateway  │────▶ │  Control Plane       │
│ (Rudras) │      │  (port 50051, TLS)   │
└──────────┘      └──────────────────────┘
    │                      ▲
    ▼                      │ gRPC
┌──────────────────────────┴────────┐
│         Internal Network          │
│  ┌──────────┐    ┌──────────┐     │
│  │ Segment  │    │ Segment  │     │
│  │ (Rudras) │    │ (Rudras) │     │
│  └──────────┘    └──────────┘     │
└───────────────────────────────────┘
```

Used for a single LAN/campus with multiple zones. All Rudras nodes share one control plane. Policy changes propagate to all nodes within 30 seconds (polling) or immediately (push via `StreamEvents`).

### 3.2 Multi-Region Topology

```
Region A                      Region B
┌─────────────────┐           ┌─────────────────┐
│  CP Server A    │◀──────────│  CP Server B    │
│  (primary)      │ replication│ (replica)       │
└────────┬────────┘           └────────┬────────┘
         │                             │
    ┌────┴────┐                   ┌────┴────┐
    │Rudras A1│                   │Rudras B1│
    │Rudras A2│                   │Rudras B2│
    └─────────┘                   └─────────┘
```

Each region has a primary control plane server. The primaries replicate policy state to each other (control plane-level replication, outside the scope of the `.proto` definition). Each Rudras node connects to its regional primary.

### 3.3 Node Identification

Each Rudras node has a unique `node_id` configured in `rudras.toml`:
```toml
[control_plane]
node_id = "ap-south-01-gateway"
endpoint = "https://controlplane.corp.example:50051"
region = "ap-south-1"
cloud_provider = "on-prem"
sync_interval_secs = 30
```

The `node_id` is used to:
- Identify the node in `MetricsReport` and `Event` records
- Route targeted `operator_command` events to specific nodes
- Disambiguate logs in the central aggregation system

---

## 4. Security of the Control Plane Channel

### 4.1 Mutual TLS

All gRPC connections from data-plane nodes to the control plane use **mutual TLS (mTLS)**:
- The control plane presents a server certificate (issued by the internal PKI)
- Each Rudras node presents a client certificate (uniquely issued per node)
- The control plane rejects any node that cannot present a valid client certificate
- The node rejects any control plane that cannot present a valid server certificate signed by the trusted CA

This prevents:
- Rogue nodes connecting to the control plane
- Man-in-the-middle attacks replacing policy updates with malicious rules
- Untrusted control planes issuing block commands to nodes

### 4.2 Policy Signature Verification

Policies received via `SyncPolicy` are verified against a policy signature before being applied. The control plane signs the entire policy set with an RSA-4096 key; the data-plane verifies the signature against the embedded public key before loading the new policy.

This ensures that even if the control plane is compromised, an attacker cannot push arbitrary rules unless they also have the private signing key (stored in an HSM).

---

## 5. Failure Modes and Resilience

| Failure | Data Plane Behaviour |
|---------|---------------------|
| Control plane unreachable | Continue enforcing last-known-good policy; log `control_plane_disconnect` event; retry exponentially (max 5 min backoff) |
| `SyncPolicy` returns error | Keep current policy; log error; retry on next interval |
| Policy signature invalid | Reject update; log `policy_tamper_detected`; alert via SIEM; continue on current policy |
| `StreamEvents` stream drops | Reconnect and re-subscribe; log event stream gap; full `SyncPolicy` call to catch up |
| Control plane clock drift | Use local monotonic clock for enforcement; only NTP-sync for log timestamps |

The key resilience principle: **the data plane is never left without a policy**. It always has the last successfully verified policy set in memory.

---

## 6. Future Development (v4.1 Roadmap)

- **Policy diff API:** Replace full-policy sync with incremental diffs to reduce bandwidth for large policy sets
- **gRPC health checking:** Implement the standard gRPC Health Checking Protocol for load balancer integration
- **RBAC on control plane:** Role-based access control for operator commands (read-only analyst vs. full admin)
- **WebUI for control plane:** React-based admin panel for policy management, node health, and cross-node analytics
- **Kubernetes operator:** A Kubernetes controller that automatically provisions Rudras nodes and registers them with the control plane
