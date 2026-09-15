# System overview

## How it works

`security_pack.py` and `security_event_connector.py` normalize control observations or alerts. `GovernanceCore` owns the relational finding lifecycle. The HTTP adapter authenticates a human actor through the local identity store; agent ingestion uses HMAC-backed agent keys and persistent replay state. Reports, queues, and audit/evidence records are outputs of the workflow rather than sources of authority.

```mermaid
flowchart LR
    subgraph Inputs
        P["Posture and access-review JSON"]
        L["LogWatcher alert JSONL"]
        B["Read-only JML and Mini-SOAR bridges"]
    end

    subgraph TrustBoundaries["Validation and identity boundaries"]
        A["Agent HMAC and replay checks"]
        H["Human API key authentication"]
        N["Normalize controls and alerts"]
    end

    subgraph Governance["Governance core"]
        F["Stable finding upsert"]
        R["Risk and treatment"]
        G["Role-gated approval"]
        W["Action and evidence"]
        V["Independent verification and closure"]
    end

    subgraph Outputs
        Q["Remediation queue and SLA tickets"]
        E["Evidence metadata and hash-chained audit"]
        O["Executive report"]
    end

    P --> A --> N
    L --> N
    B --> N
    H --> G
    N --> F --> R --> G --> W --> V
    W --> Q
    W --> E
    V --> O
    V --> E
```

### Finding lifecycle

The lifecycle is enforced by `governance_core.py`. A risk owner cannot approve their own finding, and an implementer or evidence submitter cannot verify the same finding.

```mermaid
stateDiagram-v2
    [*] --> Open
    Open --> RiskAssessed: assess risk
    RiskAssessed --> PendingApproval: propose treatment
    PendingApproval --> Approved: approve mitigation
    PendingApproval --> Accepted: approve risk acceptance
    PendingApproval --> RiskAssessed: reject treatment
    Approved --> InProgress: start action
    InProgress --> PendingVerification: submit evidence
    PendingVerification --> Verified: independent verification passes
    PendingVerification --> InProgress: independent verification fails
    Verified --> Closed: authorised closure
    Accepted --> Closed: authorised closure
    Closed --> [*]
```

The normal remediation path is `Open` through `Closed`. A failed independent check returns the finding to `InProgress`; an approved risk-acceptance treatment takes the controlled `Accepted` path and still requires authorised closure. There is no transition that allows a finding to skip approval, evidence, or verification.

### Alert intake and idempotent replay

`connectors.py`, `security_event_connector.py`, and `GovernanceCore.upsert_finding()` separate a newly observed alert from a replay. The event identity includes its source, so two sources can use the same event identifier without being treated as the same event.

```mermaid
flowchart LR
    S["Security alert or control observation"] --> V["Validate schema and source"]
    V --> K["Derive source and stable identity"]
    K --> D{"Previously accepted"}
    D -->|"No"| C["Create finding"]
    D -->|"Yes"| R["Reassess existing finding"]
    C --> E["Record governance event"]
    R --> E
    E --> O["Return finding ID and outcome"]
```

The first LogWatcher concept run takes the **Create finding** path for three alerts. Replaying the same three alerts takes the **Reassess existing finding** path, so the database contains three findings rather than six.

### Authenticated agent ingestion

The HTTP ingestion path is intentionally separate from the human governance API. An agent must present a known key ID and a valid HMAC signature; nonce and payload state reject replay before a posture document is accepted for downstream processing.

```mermaid
flowchart LR
    A["Posture client"] --> H["Agent key ID and HMAC"]
    H --> V{"Signature and schema valid"}
    V -->|"No"| X["Reject request"]
    V -->|"Yes"| N{"Nonce and payload are new"}
    N -->|"No"| I["Return existing evidence ID"]
    N -->|"Yes"| S["Persist accepted payload state"]
    S --> B["Write posture document to inbox"]
    B --> Q["SQLite job queue"]
```

This flow is implemented for the local lab using per-agent key lifecycle and SQLite state. It is not a substitute for TLS, mTLS, a secret manager, or a shared production replay store.

### Background worker and recovery path

`scripts/pipeline_worker.py` keeps ingestion responsive by processing inbox files through `job_queue.py`. A worker owns a job only while its lease is valid; a stale worker cannot later mark a reclaimed job complete or failed.

```mermaid
flowchart LR
    I["Evidence inbox"] --> Q["Enqueue job"]
    Q --> C["Worker claims valid lease"]
    C --> P["Run deterministic pipeline"]
    P -->|"Success"| OK["Complete job and write outputs"]
    P -->|"Retryable error"| R["Release for retry"]
    R --> Q
    P -->|"Retry limit reached"| D["Dead-letter state for review"]
    C -->|"Lease expires"| Q
```

The queue provides local retry, lease, and dead-letter behaviour for a concept environment. It is not a managed message broker and should not be used as the production queue.

### Evidence and audit integrity

Every governance mutation records a deterministic event sequence. Evidence content is hashed before its metadata is recorded, and the event chain links each event to the hash of its predecessor.

```mermaid
flowchart LR
    M["Lifecycle mutation"] --> J["Canonical event details"]
    J --> P["Previous event hash"]
    P --> H["Compute event hash"]
    H --> L["Governance event sequence"]
    L --> Q["Transactional audit export record"]
    Q --> W["Fenced archive worker"]
    W --> B["Create-only local or Azure audit object"]
    B --> R["Read-back SHA-256 verification"]
    R --> A["Acknowledge or retry/dead-letter"]
    E["Evidence content"] --> S["SHA-256 evidence hash"]
    S --> G["Evidence metadata record"]
    G --> L
    L --> V["Verify per-finding chain"]
```

The governance event and its audit-export record commit in the same database
transaction. The worker preserves per-finding order, uses deterministic
server-generated object names, and acknowledges delivery only after reading the
object back and verifying its SHA-256. A failed archive remains visible for
retry or dead-letter review. The lab filesystem is not immutable; Azure
retention becomes enforceable only after the operator validates and locks the
container policy.

Governance events also create a transactional broker-outbox record. A separate
fenced worker publishes canonical `governance.event.v1` messages. Lab runs use
create-only local files; staging is configured for Azure Service Bus with a
user-assigned managed identity. The stable `outbox_id` is the broker
`MessageId`, and the finding ID is both the session and partition key. This
allows duplicate detection and preserves per-finding publish order without
making Service Bus authoritative for governance state.

### Connected portfolio boundaries

The repository has two narrow portfolio bridges. They feed SentinelGRC as evidence sources but do not import external code, operate external systems, or turn SentinelGRC into a response platform.

```mermaid
flowchart LR
    J["JML-Automation SQLite database"] -->|"Read-only closed and verified requests"| JB["JML bridge"]
    M["Mini-SOAR evidence bundle"] -->|"Closed verified synthetic-lab evidence"| MB["Mini-SOAR bridge"]
    JB --> G["SentinelGRC governance core"]
    MB --> G
    G --> F["Stable finding or reassessment"]
    G --> A["Audit and evidence records"]
```

The JML bridge requires a closed request and a passing verification record. The Mini-SOAR bridge accepts synthetic-lab evidence, requires passing verification by default, and requires the bundle manifest digest to be pinned through a trusted channel outside the evidence directory. Both boundaries are implemented and tested locally; neither is a live production integration.

### Connected systems map

This is the single map for the three connected portfolio systems. **LogWatcher** provides a validated synthetic alert fixture. **JML-Automation** is read through SQLite in read-only mode. **Mini-SOAR** provides only closed, independently verified `synthetic-lab` evidence. SentinelGRC is the common governance and evidence sink; none of these connections can change the source system.

```mermaid
flowchart LR
    subgraph Sources["Connected portfolio systems"]
        LW["LogWatcher"]
        JML["JML-Automation"]
        MS["Mini-SOAR"]
    end

    subgraph Boundaries["Accepted connector boundary"]
        LC["Staging alert connector"]
        JC["Read-only JML bridge"]
        MC["Verified synthetic-evidence bridge"]
    end

    subgraph Sentinel["SentinelGRC"]
        IN["Validate and normalize"]
        FI["Create or reassess stable finding"]
        GO["Governance lifecycle"]
        AU["Audit and evidence records"]
    end

    LW -->|"Alert JSONL fixture"| LC
    JML -->|"Closed verified request"| JC
    MS -->|"Closed verified synthetic evidence"| MC
    LC --> IN
    JC --> IN
    MC --> IN
    IN --> FI --> GO --> AU
```

The three paths differ in their trust condition, but converge only after validation and stable-identity handling. The LogWatcher path has tracked concept proof of first ingestion and replay. The JML and Mini-SOAR paths are covered by local bridge tests. All three remain portfolio integrations, not live production connectors.
