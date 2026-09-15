# Historical Mini-SOAR integration diagrams

Design reference only, not a SentinelGRC runtime feature or validated live integration.

### Mini-SOAR blueprint appendix

The next six diagrams are the remaining Mermaid diagrams from the Mini-SOAR design documents. They describe a **separate concept-only response layer** that can feed evidence back into SentinelGRC. They do not represent an implemented live response service in this repository: all action adapters and target stores below are synthetic or mock by design.

#### Mini-SOAR concept architecture

This diagram shows the proposed boundary from synthetic detections through approval, mock response actions, evidence, and re-verification. The SentinelGRC governance plane remains the system of record for the finding and its decision trail.

```mermaid
flowchart LR
    subgraph Sources["Synthetic detection sources"]
        L["LogWatcher alerts"]
        S["SOC Homelab alert fixture"]
    end

    subgraph Intake["Alert boundary"]
        N["Normalizer"]
        V["Schema HMAC and replay validation"]
        D["Stable alert identity"]
    end

    subgraph Governance["SentinelGRC governance plane"]
        F["Finding and risk context"]
        R["Risk treatment proposal"]
        A["Approval and separation of duties"]
        Q["Response job state lease and retry"]
        E["Evidence metadata and hashes"]
        I["Independent verification"]
    end

    subgraph Actions["Concept-only action plane"]
        P["Playbook registry"]
        M["Mock disable-account action"]
        H["Mock isolate-host action"]
        T["Mock ticket action"]
    end

    L --> N
    S --> N
    N --> V --> D --> F --> R --> A --> Q
    Q --> P
    P --> M
    P --> H
    P --> T
    Q --> E
    M --> E
    H --> E
    T --> E
    E --> I --> F
```

#### Mini-SOAR concise lifecycle

This is the short response-lifecycle view. It shows that an unsupported alert, rejected approval, failure, or insufficient verification is deliberately routed to review rather than allowing an unrestricted action.

```mermaid
stateDiagram-v2
    [*] --> Received
    Received --> Normalized: schema accepted
    Normalized --> Duplicate: same stable identity
    Duplicate --> [*]
    Normalized --> FindingCreated: new alert
    FindingCreated --> PlaybookMatched: supported alert
    FindingCreated --> ManualReview: no safe playbook
    PlaybookMatched --> ApprovalPending: action requires approval
    ApprovalPending --> Rejected: denied or expired
    ApprovalPending --> Approved: authorised approver
    Approved --> DryRun: concept default
    DryRun --> Executed: mock action succeeds
    DryRun --> Failed: mock action fails
    Approved --> Cancelled: operator cancels
    Executed --> EvidenceSubmitted
    Failed --> RetryPending: retryable failure
    RetryPending --> DryRun: retry within policy
    Failed --> ManualReview: retry limit reached
    EvidenceSubmitted --> Verified: independent verifier accepts
    EvidenceSubmitted --> VerificationFailed: evidence insufficient
    VerificationFailed --> ManualReview
    Verified --> Closed
    Rejected --> Closed
    ManualReview --> Closed: disposition recorded
    Closed --> [*]
```

#### Mini-SOAR enterprise context

This diagram adds the human roles and synthetic target stores around the proposed response plane. It is useful for explaining separation of duties, but the `Mock` stores are not Active Directory, EDR, a ticketing platform, or a real asset inventory.

```mermaid
flowchart TB
    AN["SOC analyst"]
    OW["Risk or asset owner"]
    AP["Security approver"]
    VE["Independent verifier"]
    AU["Auditor or security manager"]

    subgraph Detection["Synthetic detection sources"]
        LW["LogWatcher alerts"]
        SC["SOC Homelab alert fixture"]
    end

    subgraph SOAR["Mini-SOAR concept only"]
        API["Alert intake"]
        NO["Normalizer"]
        VA["Schema HMAC and replay validation"]
        FI["Finding and risk context"]
        PL["Playbook registry"]
        PO["Approval and policy engine"]
        RP["Response plan generator"]
        JW["Response job worker"]
        MA["Mock action adapters"]
        PV["Simulated post-condition verifier"]
        EV["Evidence package and audit chain"]
        RE["Incident and governance report"]
    end

    subgraph Mock["Synthetic target stores"]
        ID["Mock identity store"]
        AS["Mock asset store"]
        TI["Local mock ticket store"]
    end

    AN --> API
    OW --> PO
    AP --> PO
    VE --> PV
    AU --> RE
    LW --> API
    SC --> API
    API --> NO --> VA --> FI --> PL --> PO --> RP --> JW --> MA
    MA --> ID
    MA --> AS
    MA --> TI
    MA --> PV
    API --> EV
    PO --> EV
    JW --> EV
    PV --> EV --> RE
    RI["Real infrastructure is not connected"] -.-> MA
```

#### Mini-SOAR detailed sequence

This sequence expands the proposed action path. It is intentionally labelled `Mock Adapter` and `Mock Ticket Store`: it documents an evidence-producing lab scenario, not a command path to real systems.

```mermaid
sequenceDiagram
    participant D as Detection source
    participant API as Alert intake
    participant G as SentinelGRC
    participant P as Playbook engine
    participant A as Security approver
    participant W as Response worker
    participant M as Mock adapter
    participant V as Independent verifier
    participant T as Mock ticket store
    participant L as Evidence and audit log

    D->>API: Submit structured alert
    API->>API: Validate size schema and signature
    API->>L: Record alert received
    API->>G: Normalize and upsert finding
    G->>G: Derive stable finding identity
    G->>L: Record finding created or reassessed
    G->>P: Match alert and asset context
    P->>A: Request approval for exact action
    A->>G: Approve or reject
    G->>L: Record approval decision

    alt Approved
        G->>W: Submit response job
        W->>L: Record response started
        W->>M: Preview mock action
        M-->>W: Simulated planned effect
        W->>M: Execute mock action
        M-->>W: Simulated outcome and state
        W->>T: Create or update mock ticket
        W->>V: Submit result for verification
        V->>L: Record verification result
    else Rejected expired or unsupported
        G->>L: Record review or rejection
    end

    alt Verification passed
        V->>G: Mark evidence verified
        G->>L: Record finding closed
    else Verification failed
        V->>G: Return for manual review
        G->>L: Record verification failed
    end
```

#### Mini-SOAR detailed state machine

This version makes validation failure, approval expiry, planning, execution, retry, and manual review explicit. It is a design contract for the proposed Mini-SOAR workflow; it is not the SentinelGRC finding state machine shown earlier.

```mermaid
stateDiagram-v2
    [*] --> Received
    Received --> Rejected: invalid input
    Received --> Normalized
    Normalized --> Duplicate: replayed alert
    Duplicate --> [*]
    Normalized --> FindingCreated
    FindingCreated --> PlaybookMatched
    FindingCreated --> ManualReview: no supported playbook
    PlaybookMatched --> ApprovalPending
    ApprovalPending --> Rejected: denied
    ApprovalPending --> Expired: timeout
    ApprovalPending --> Approved
    Approved --> Planned
    Planned --> DryRun
    DryRun --> Executing
    Executing --> ActionFailed
    Executing --> PendingVerification
    ActionFailed --> RetryPending: retryable
    ActionFailed --> ManualReview: retry limit reached
    RetryPending --> DryRun
    PendingVerification --> VerificationFailed
    PendingVerification --> Verified
    VerificationFailed --> ManualReview
    Verified --> Closed
    ManualReview --> Closed: disposition recorded
    Rejected --> [*]
    Expired --> [*]
    Closed --> [*]
```

#### SentinelGRC and Mini-SOAR integration map

This final design diagram states the intended responsibilities: detection sources produce a canonical alert, SentinelGRC governs the finding and approval, and Mini-SOAR can only run a mock response plan before evidence is returned to SentinelGRC.

```mermaid
flowchart LR
    LW["LogWatcher"]
    SC["SOC Homelab"]
    AL["Canonical security alert"]
    SG["SentinelGRC governance"]
    FI["Governance finding"]
    AP["Role-gated approval"]
    SO["Mini-SOAR response plan"]
    MO["Mock action"]
    EV["Evidence and verification"]

    LW --> AL
    SC --> AL
    AL --> SG --> FI --> AP --> SO --> MO
    MO --> EV --> SG
```

In short: LogWatcher and SOC-Homelab are detection concepts, SentinelGRC is the governance and evidence sink, and Mini-SOAR remains a proposed mock-response concept. No diagram in this section authorises a real identity, endpoint, network, cloud, or ticketing action.
