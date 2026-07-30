# SentinelGRC

**A Python concept MVP that turns security-control observations into traceable findings, governed remediation decisions, evidence, verification, and closure.**

**Stack:** Python 3.12, SQLite for local labs, PostgreSQL for the canonical shared-state staging path, Gunicorn/WSGI, JSON and JSONL fixtures, PowerShell posture collectors, Docker, and GitHub Actions.

**Status:** Portfolio / concept MVP. It completes a bounded security-governance workflow end to end, but it is not production-ready.

## What it is

Security teams often receive posture failures and alerts without a consistent way to assign ownership, approve treatment, retain evidence, and prove that remediation was independently checked. SentinelGRC models that workflow in a small, inspectable Python codebase.

It accepts normalized control observations and security alerts, derives stable findings, records risk treatment decisions, and keeps evidence and audit records linked to each finding. The repository includes synthetic concept validation with LogWatcher alerts and read-only portfolio bridges for JML-Automation and Mini-SOAR.

This repository does **not** claim ISO certification, ISMS replacement, live SIEM or Elastic integration, a production Active Directory connection, or readiness for an organisation-wide deployment. It does not make automatic changes to Active Directory or endpoints.

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
    E["Evidence content"] --> S["SHA-256 evidence hash"]
    S --> G["Evidence metadata record"]
    G --> L
    L --> V["Verify per-finding chain"]
```

The hashes detect changes to recorded data in the local ledger. They do not make a local SQLite file immutable; immutable storage and retained exports are production requirements.

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

The JML bridge requires a closed request and a passing verification record. The Mini-SOAR bridge accepts synthetic-lab evidence and requires passing verification by default. Both boundaries are implemented and tested locally; neither is a live production integration.

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

## Commands used

The repository has no third-party Python package requirement for the concept workflow. Use a supported Python installation; GitHub Actions validates the code with Python 3.12.

### 1. Initialise a local runtime area

```powershell
git clone https://github.com/SuriyaBoon/SentinelGRC.git
cd SentinelGRC
python --version
New-Item -ItemType Directory -Force runtime | Out-Null
```

### 2. Evaluate the bundled posture fixture

```powershell
python -m scripts.governance assess `
  --posture sample_posture.json `
  --controls controls.json `
  --assets assets.json `
  --output runtime/control-assessment.json
```

### 3. Run the end-to-end control pipeline

```powershell
python -m scripts.pipeline run `
  --posture sample_posture.json `
  --controls controls.json `
  --assets assets.json `
  --access-review sample_ad_access_review.json `
  --ledger runtime/evidence-ledger.jsonl `
  --remediation runtime/remediation-queue.json `
  --tickets runtime/tickets.json `
  --report runtime/executive-report.json `
  --state-db runtime/sentinel-state.db `
  --audit-log runtime/audit-log.jsonl `
  --governance-db runtime/governance.db
```

### 4. Reproduce the LogWatcher concept validation

The tracked alert fixture is the sanitized output from the LogWatcher sample scenario.

```powershell
python -m scripts.staging_logwatcher `
  --events docs/evidence/concept-validation/alerts.jsonl `
  --input-kind alert `
  --governance-db runtime/concept-governance.db
```

Run the exact same command a second time against the same database to test replay idempotency.

### 5. Run tests and inspect generated evidence

```powershell
python -m unittest discover -v -p "test_*.py"

Get-Content runtime/executive-report.json
Get-Content runtime/remediation-queue.json
Get-Content runtime/evidence-ledger.jsonl
Get-Content docs/evidence/concept-validation/SHA256SUMS.txt
Get-FileHash docs/evidence/concept-validation/*.png, docs/evidence/concept-validation/*.json* -Algorithm SHA256
```

Runtime databases, reports, queues, and ledgers are intentionally ignored by Git. They may contain local machine metadata and should not be committed.

## Evidence that it works

### Automated verification

The current test command is:

```powershell
python -m unittest discover -v -p "test_*.py"
```

Current local regression result without an external database:

```text
Ran 118 tests
OK (skipped=5 PostgreSQL integration tests)
```

The PostgreSQL tests run when `SENTINEL_TEST_POSTGRES_URL` is set. The complete
suite was also validated against an isolated PostgreSQL 17 container:

```text
Ran 118 tests
OK
```

Those tests cover transactional migrations, checksum mismatch rejection,
human identity authentication, the full finding lifecycle, rollback,
idempotent concurrent reassessment, ordered event chains, and runtime
readiness. GitHub Actions runs the normal test discovery command, executes the
five PostgreSQL tests against an ephemeral database service, parses both
PowerShell collectors, builds the non-root image, and checks that runtime
artifacts are not tracked.

### Synthetic-lab integration proof

The tracked evidence package is in [`docs/evidence/concept-validation`](docs/evidence/concept-validation/).

| File | What it proves |
| --- | --- |
| [`01-logwatcher-report.png`](docs/evidence/concept-validation/01-logwatcher-report.png) | A sanitized LogWatcher run processed 20 Windows-style events and fired 3 alerts. |
| [`02-sentinel-replay.png`](docs/evidence/concept-validation/02-sentinel-replay.png) | First Sentinel ingestion created 3 findings; replay created 0 findings and reassessed 3. |
| [`alerts.jsonl`](docs/evidence/concept-validation/alerts.jsonl) | The three structured alert records submitted to the staging connector. |
| [`report.json`](docs/evidence/concept-validation/report.json) | Machine-readable totals for the source scenario, including 20 events and 3 alerts. |
| [`SHA256SUMS.txt`](docs/evidence/concept-validation/SHA256SUMS.txt) | SHA-256 checksums for the tracked screenshots and data files. |

![LogWatcher processed 20 sample events and generated 3 alerts](docs/evidence/concept-validation/01-logwatcher-report.png)

![SentinelGRC created three findings once and reassessed them on replay](docs/evidence/concept-validation/02-sentinel-replay.png)

The validated scenario is deliberately bounded:

```text
Source scenario: 20 sample events -> 3 alerts
First Sentinel run: 3 findings created, 0 reassessed, 0 errors
Replay of the same alerts: 0 findings created, 3 reassessed, 0 errors
```

This is evidence of synthetic-lab alert normalization and idempotent finding handling. It is not evidence of a live Windows fleet, Elastic, SIEM, or production environment.

## What problem it solves

The practical problem is the gap between a technical signal and an accountable outcome. A failed control, privileged-account concern, or detection alert can otherwise remain a spreadsheet entry or an isolated ticket with no reliable risk owner, approval record, evidence, or re-check.

SentinelGRC makes that path visible: normalize the observation, create or reassess one stable finding, assign a treatment decision, collect evidence, require independent verification, and preserve the resulting audit trail. This is useful as a portfolio demonstration of security governance and IT operations thinking, not as a replacement for an operational GRC programme.

## Safety model

The following guardrails are implemented in code and covered by tests:

- **Server-derived human actor:** `GovernanceApi` rejects actor fields in request bodies and resolves the actor through `HumanIdentityStore`.
- **Role-gated workflow:** only specified roles can assess, approve, verify, or close a finding; self-approval and self-verification are rejected in `GovernanceCore`.
- **Agent authentication and replay protection:** `scripts/ingestion_api.py`, `scripts/agent_keys.py`, and `state_store.py` validate HMAC-backed agent identity, nonces, and payload hashes.
- **Idempotent finding identity:** repeated LogWatcher alerts and bridged evidence reassess the same finding rather than creating duplicates.
- **Integrity records:** governance events are hash chained in a deterministic per-finding sequence; submitted evidence is SHA-256 hashed.
- **Bounded lab automation:** the repository collects and evaluates data. It does not automatically remediate endpoints or modify Active Directory.
- **Worker lease fencing:** a stale queue worker cannot complete or fail a job after its lease is no longer valid.

## Repository structure

```text
SentinelGRC/
├── governance_core.py          # Finding, risk, approval, evidence, verification, closure state machine
├── governance_api.py           # Transport-neutral authenticated workflow dispatcher
├── governance_http.py          # Minimal HTTP adapter and request limits
├── human_identity.py           # Human identity and hashed API-key store
├── persistence.py              # SQLite/PostgreSQL adapter and connection pool
├── runtime_app.py              # WSGI composition, readiness, and production gate
├── security_pack.py            # Control observation normalization
├── security_event_connector.py # Alert-to-finding mapping
├── connectors.py               # Connector event identity and replay state
├── state_store.py              # Nonce, payload, and pipeline-run persistence
├── job_queue.py                # SQLite queue leases, retry, and dead-letter state
├── audit_log.py                # Append-only hash-chained operational audit log
├── reporting.py                # Summary and KPI/KRI report generation
├── scripts/                    # CLI adapters, pipeline, worker, ingestion, and portfolio bridges
├── agent/                      # Read-only Windows posture and AD access-review collectors
├── migrations/                 # SQLite contracts and executable PostgreSQL schema
├── docs/evidence/              # Sanitized synthetic-lab proof package
├── ui/                         # Static workflow UI shell
└── test_*.py                   # Automated unit and integration-style concept tests
```

## Production boundary

This repository is **not** a production deployment. Before even a limited internal pilot, it would need at least:

- An Azure Database for PostgreSQL instance with private networking, managed credentials, backup/restore validation, capacity tests, and operational ownership. The canonical governance and identity adapters and migrations are implemented and container-tested; no Azure database has been provisioned by this repository.
- Real OIDC or SSO with MFA, short-lived tokens, role/group mapping, and lifecycle-managed service identities; local hashed API keys are only the current concept mechanism.
- A secrets manager, TLS termination, network policy, rate limiting, and a hardened WSGI or ASGI server around the HTTP adapter.
- Encrypted object storage with retention and immutable export for evidence; local JSON, JSONL, and SQLite files are not an evidence vault.
- A managed durable queue and supervised workers; the current queue is SQLite polling with lease and retry logic.
- Centralized logging, metrics, tracing, alerting, backup/restore tests, disaster-recovery procedures, and security assessment.
- A real connector test against an authorised Windows and SIEM environment, including failure recovery and access-control validation.

The PostgreSQL adapter is repository-tested for canonical governance and human
identity state. Connector replay state, the polling job queue, and legacy
pipeline stores remain SQLite-specific. OIDC, deployment, and observability
contracts are not proof that their external controls have been deployed.

## Planned integration

| Integration | Current status |
| --- | --- |
| LogWatcher | **Connected and validated at synthetic-lab level.** The tracked fixture demonstrates 20 source events, 3 alerts, and idempotent finding replay. |
| JML-Automation | **Implemented as a read-only portfolio bridge and covered by repository tests.** It requires closed requests with passing verification records. No live directory changes are made. |
| Mini-SOAR | **Implemented as a synthetic-evidence bridge and covered by repository tests.** It accepts `synthetic-lab` evidence and requires independent verification by default. |
| Windows, Elastic, SIEM, ITSM, object storage, and SSO | **Designed or documented, not validated as live integrations in this repository.** |

For the deployment outline and remaining infrastructure requirements, see [`docs/production-runbook.md`](docs/production-runbook.md) and [`docs/enterprise-deployment.md`](docs/enterprise-deployment.md).
