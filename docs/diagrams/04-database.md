# 04 — PostgreSQL ledger and permission model

Logical ER diagram derived from schema.sql and migrations 002–004. Selected fields only; see SQL for exact constraints.

[← Authority atlas](README.md) · [Customer visual atlas](https://github.com/VY-Groups/yarp-lb/tree/docs/visual-architecture-atlas/docs/diagrams)

> Authority baseline main: `78b3cbcceafbf08e70d1d319f9318e23665153be`. Candidate integration tests: `a915910a64adb3c6ccddcfa418118d2a38420422` (PR #6). All diagrams show logical software behavior, not production authorization. No real customer data, keys or credentials are shown.

## Entity relationship diagram
```mermaid
erDiagram
GC_CUSTOMERS ||--o{ GC_SUBSCRIPTIONS : owns
GC_SUBSCRIPTIONS ||--o{ GC_LICENSE_JOBS : requests
GC_SUBSCRIPTIONS ||--o| GC_ISSUER_AUTHORITY : current_signer
GC_SUBSCRIPTIONS ||--o{ GC_ISSUER_ALLOCATIONS : allocates
GC_LICENSE_JOBS ||--o| GC_ISSUER_RESULTS : completes
GC_SUBSCRIPTIONS ||--o{ GC_ISSUER_KEY_HISTORY : history
GC_LICENSE_JOBS ||--o{ GC_ISSUER_KEY_HISTORY : rotation_job
GC_SUBSCRIPTIONS ||--o{ GC_BILLING_INVOICES : billing
GC_LICENSE_JOBS o|--o{ GC_BILLING_INVOICES : optional_renewal
GC_CUSTOMERS ||--o| GC_EVALUATION_CLAIMS : consumes
GC_SUBSCRIPTIONS ||--o| GC_EVALUATION_CLAIMS : trial_contract
GC_CUSTOMERS {
 string id PK
 string name
}
GC_SUBSCRIPTIONS {
 string id PK
 string customer_id FK
 string deployment_id UK
 string edition
 int max_nodes
 int max_sites
 bigint terms_revision
 datetime expires_at
}
GC_LICENSE_JOBS {
 uuid id PK
 string subscription_id FK
 string kind
 bigint expected_terms_revision
 string request_id UK
 string requested_by
 string approved_by
 string state
}
GC_ISSUER_AUTHORITY {
 string subscription_id PK,FK
 string key_id
 string public_key_hash
}
GC_ISSUER_ALLOCATIONS {
 string subscription_id PK,FK
 string installation_hash PK,UK
 string allocation_id UK
 string site_id
 bigint revision
 string revocation_envelope
}
GC_ISSUER_RESULTS {
 uuid job_id PK,FK
 string envelope
 datetime completed_at
}
GC_ISSUER_KEY_HISTORY {
 string subscription_id PK,FK
 string key_id PK
 string public_key_hash
 uuid rotation_job FK
}
GC_BILLING_INVOICES {
 uuid id PK
 string subscription_id FK
 uuid renewal_job_id FK
 string terms_hash
 string currency
 bigint amount_minor
 string state
 string payment_reference UK
}
GC_EVALUATION_CLAIMS {
 string customer_id PK,FK
 string subscription_id FK,UK
 string installation_hash UK
 bigint expires_utc
}
GC_PORTAL_AUDIT {
 bigint id PK
 string actor
 string action
 string subject
 datetime occurred_at
}
```

Audit subjects are textual, not an inferred foreign key. The diagram omits many fields, triggers, CHECK constraints and indexes; SQL migrations are authoritative.

**Source:** [tools/LicensePortal/schema.sql](https://github.com/VY-Groups/gatewaycore-license-authority/blob/a915910a64adb3c6ccddcfa418118d2a38420422/tools/LicensePortal/schema.sql) · [tools/LicensePortal/migration-002-authority-rotation.sql](https://github.com/VY-Groups/gatewaycore-license-authority/blob/a915910a64adb3c6ccddcfa418118d2a38420422/tools/LicensePortal/migration-002-authority-rotation.sql) · [tools/LicensePortal/migration-003-billing.sql](https://github.com/VY-Groups/gatewaycore-license-authority/blob/a915910a64adb3c6ccddcfa418118d2a38420422/tools/LicensePortal/migration-003-billing.sql) · [tools/LicensePortal/migration-004-evaluation.sql](https://github.com/VY-Groups/gatewaycore-license-authority/blob/a915910a64adb3c6ccddcfa418118d2a38420422/tools/LicensePortal/migration-004-evaluation.sql)

## Role separation
```mermaid
flowchart LR
R["Requester role"] --> J["Create customer/subscription and pending jobs/invoices"]
V["Reviewer role"] --> A["Decide pending jobs and invoices"]
I["Issuer runtime"] --> W["Transactional signing ledger and results"]
K["Recovery reader"] --> D["Read-only repeatable-read checkpoint"]
M["Migration owner"] --> S["Schema / roles / grants"]
J --> P[("PostgreSQL")]
A --> P
W --> P
D --> P
S --> P
```

No runtime role is the schema owner. Requester and issuer cannot approve jobs; portal roles do not write issuer signing state. Recovery identity has no mutation privileges. A privileged DB owner can still change data, so external checkpoint protection matters.

**Source:** [tools/LicensePortal/runtime-grants.sql](https://github.com/VY-Groups/gatewaycore-license-authority/blob/a915910a64adb3c6ccddcfa418118d2a38420422/tools/LicensePortal/runtime-grants.sql) · [tools/AuthorityRecovery/recovery-grants.sql](https://github.com/VY-Groups/gatewaycore-license-authority/blob/a915910a64adb3c6ccddcfa418118d2a38420422/tools/AuthorityRecovery/recovery-grants.sql) · [tools/LicensePortal/README.md](https://github.com/VY-Groups/gatewaycore-license-authority/blob/a915910a64adb3c6ccddcfa418118d2a38420422/tools/LicensePortal/README.md)

## Concurrent issuance and idempotence
```mermaid
sequenceDiagram
participant W1 as Worker 1
participant W2 as Worker 2
participant D as Subscription row lock
participant L as Allocation and result ledger
W1->>D: SELECT FOR UPDATE
W2->>D: Same subscription, waits
W1->>L: Validate and commit allocation/result
W1-->>D: Release lock
D-->>W2: Acquire after commit
W2->>L: Read committed result / current seats
alt Same completed job
 L-->>W2: Exact committed envelope
else Different job with exhausted cap
 L-->>W2: Refuse allocation
end
```

Across different evaluation subscriptions, the unique customer claim serializes the first trial; database uniqueness also protects global installation binding.

**Source:** [tools/LicenseIssuerWorker/ApprovedJobExecutor.cs](https://github.com/VY-Groups/gatewaycore-license-authority/blob/a915910a64adb3c6ccddcfa418118d2a38420422/tools/LicenseIssuerWorker/ApprovedJobExecutor.cs) · [tests/PostgresAcceptance/Program.cs](https://github.com/VY-Groups/gatewaycore-license-authority/blob/a915910a64adb3c6ccddcfa418118d2a38420422/tests/PostgresAcceptance/Program.cs)

