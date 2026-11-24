# 02 — Issuance and license lifecycle

End-to-end offline activation and transactional issuance.

[← Authority atlas](README.md) · [Customer visual atlas](https://github.com/VY-Groups/yarp-lb/tree/docs/visual-architecture-atlas/docs/diagrams)

> Authority baseline main: `78b3cbcceafbf08e70d1d319f9318e23665153be`. Candidate integration tests: `a915910a64adb3c6ccddcfa418118d2a38420422` (PR #6). All diagrams show logical software behavior, not production authorization. No real customer data, keys or credentials are shown.

## Activation sequence
```mermaid
sequenceDiagram
actor C as Customer operator
participant G as Customer installation
participant P as Requester portal
participant R as Reviewer portal
participant D as PostgreSQL
participant W as Isolated issuer worker
C->>G: Provision installation identity
G-->>C: Signed GCR1 proof-of-possession request
C->>P: Transfer GCR1 and approved contract details offline
P->>D: Create customer/subscription, issue job and invoice if paid
R->>D: Independently approve job and confirm settlement
W->>D: Load approved job, lock subscription row
W->>W: Verify proof, terms, issuer key and seat/site limits
W->>D: Commit allocation and exact GCL1 result together
P->>D: Retrieve committed signed result
P-->>C: Offline license file
C->>G: Import GCL1 with pinned public trust
G-->>C: Local entitlement status
```

New PostgreSQL issuer GCL1 uses schema 2 with exact allocated site. Schema 1 remains compatible for standalone usage; fleet requires site-bound proof. No network call by the customer runtime.

**Source:** [tools/LicenseIssuerWorker/ApprovedJobExecutor.cs](https://github.com/VY-Groups/gatewaycore-license-authority/blob/a915910a64adb3c6ccddcfa418118d2a38420422/tools/LicenseIssuerWorker/ApprovedJobExecutor.cs) · [docs/PROTOCOL_BOUNDARY.md](https://github.com/VY-Groups/gatewaycore-license-authority/blob/a915910a64adb3c6ccddcfa418118d2a38420422/docs/PROTOCOL_BOUNDARY.md)

## Worker decision and transaction
```mermaid
flowchart TD
J["Job ID + isolated signer"] --> A{"Independently approved immutable job?"}
A -->|No| X["Reject"]
A -->|Yes| L["Lock subscription row"]
L --> I{"Committed result already exists?"}
I -->|Yes| R["Return exact previous output"]
I -->|No| T{"Expected terms revision current?"}
T -->|No| X
T -->|Yes| K{"Correct active issuer key?"}
K -->|No| X
K -->|Yes| Y{"Operation"}
Y -->|Issue| V["Check settlement or trial policy, GCR1 and seat/site constraints"]
Y -->|Renew terms| N["Check exact paid terms and allocation restrictions"]
Y -->|Revoke| Z["Bind existing allocation; sign irreversible GCV1"]
Y -->|Rotate| H["Verify staged trust and both keys"]
V --> S["Sign GCL1; persist allocation / revision"]
N --> S2["Update subscription terms"]
Z --> S3["Persist revocation"]
H --> S4["Update authority and key history"]
S --> C["Commit result in same transaction"]
S2 --> C
S3 --> C
S4 --> C
```

Failure rolls back the database transaction; do not return an uncommitted signature as a completed issuance. A committed job retry returns the recorded result, including a null envelope for terms/rotation operations where applicable.

**Source:** [tools/LicenseIssuerWorker/ApprovedJobExecutor.cs](https://github.com/VY-Groups/gatewaycore-license-authority/blob/a915910a64adb3c6ccddcfa418118d2a38420422/tools/LicenseIssuerWorker/ApprovedJobExecutor.cs)

## Node and site allocation
```mermaid
flowchart TD
A["Verified request and exact site"] --> G{"Installation hash globally unique or same allocation?"}
G -->|Different allocation| X["Reject"]
G -->|Same allocation| B{"Original site and nonrevoked?"}
B -->|No| X
B -->|Yes| R["Reissue with next monotonic allocation revision"]
G -->|New installation| N{"Seat count below maxNodes?"}
N -->|No| X
N -->|Yes| S{"Existing site or distinct sites below maxSites?"}
S -->|No| X
S -->|Yes| I["Create new allocation ID"]
R --> C["Atomic commit"]
I --> C
```

Revoked allocations retain their consumed seat; no automatic reassignment or site transfer. Commercial offline software cannot conclusively detect all privileged cloning of an installation.

**Source:** [tools/LicenseIssuerWorker/ApprovedJobExecutor.cs](https://github.com/VY-Groups/gatewaycore-license-authority/blob/a915910a64adb3c6ccddcfa418118d2a38420422/tools/LicenseIssuerWorker/ApprovedJobExecutor.cs) · [tools/LicensePortal/schema.sql](https://github.com/VY-Groups/gatewaycore-license-authority/blob/a915910a64adb3c6ccddcfa418118d2a38420422/tools/LicensePortal/schema.sql)

## License lifecycle
```mermaid
stateDiagram-v2
[*] --> Requested
Requested --> Approved: separate reviewer
Requested --> Rejected
Approved --> Issued: authorized worker transaction
Issued --> Issued: valid newer revision
Issued --> Expired: signed expiry at customer
Expired --> Issued: valid renewal and new signed envelope
Issued --> Revoked: approved GCV1 and local import
Revoked --> Revoked: allocation remains fenced
Rejected --> [*]
```

Authority revocation and customer revocation are distinct events: a signed GCV1 must actually reach and be imported by the offline installation. No immediate remote revocation promise.

**Source:** [docs/PROTOCOL_BOUNDARY.md](https://github.com/VY-Groups/gatewaycore-license-authority/blob/a915910a64adb3c6ccddcfa418118d2a38420422/docs/PROTOCOL_BOUNDARY.md) · [tools/LicensePortal/README.md](https://github.com/VY-Groups/gatewaycore-license-authority/blob/a915910a64adb3c6ccddcfa418118d2a38420422/tools/LicensePortal/README.md)

