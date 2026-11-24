# 01 — System and trust boundaries

Component and deployment architecture. Baseline contains the separate portal, issuer, recovery tool and manifest signer.

[← Authority atlas](README.md) · [Customer visual atlas](https://github.com/VY-Groups/yarp-lb/tree/docs/visual-architecture-atlas/docs/diagrams)

> Authority baseline main: `78b3cbcceafbf08e70d1d319f9318e23665153be`. Candidate integration tests: `a915910a64adb3c6ccddcfa418118d2a38420422` (PR #6). All diagrams show logical software behavior, not production authorization. No real customer data, keys or credentials are shown.

## Company deployment
```mermaid
flowchart TB
A["Requester: pinned client cert + independent password"] --> P["Requester HTTPS portal process"]
B["Reviewer: distinct pinned cert + independent password"] --> R["Reviewer HTTPS portal process"]
P -->|"gc_portal_requester"| DB[("PostgreSQL authority ledger")]
R -->|"gc_portal_reviewer"| DB
I["Isolated issuer service / operator"] -->|"gc_issuer_runtime"| DB
K["Encrypted PKCS8 entitlement key"] --> I
O["Independent recovery operator"] -->|"gc_recovery_reader"| DB
M["Migration administrator"] -. "schema and grants only" .-> DB
S["Release signing host"] --> F["Reviewed staging packages"]
```

Requester and reviewer are separate service identities, hostnames and protected configurations; neither process receives the other's DB credentials. Production host isolation must be tested. The legacy file-ledger CLI is a development alternative and must not issue against the same commercial subscriptions.

**Source:** [tools/LicensePortal/README.md](https://github.com/VY-Groups/gatewaycore-license-authority/blob/a915910a64adb3c6ccddcfa418118d2a38420422/tools/LicensePortal/README.md) · [tools/LicenseIssuerWorker/ApprovedJobExecutor.cs](https://github.com/VY-Groups/gatewaycore-license-authority/blob/a915910a64adb3c6ccddcfa418118d2a38420422/tools/LicenseIssuerWorker/ApprovedJobExecutor.cs)

## Operator authentication
```mermaid
sequenceDiagram
actor U as Operator
participant P as Role-specific portal
participant C as Protected operator config
participant D as Role-specific database
U->>P: HTTPS with client certificate
P->>C: Validate pinned identity and assigned role
U->>P: Independent password
P->>C: Verify password hash and throttling
alt Accepted
 P-->>U: Certificate-bound secure session cookie
 U->>P: Authorized role operation + CSRF
 P->>D: Execute allowed DB operation
else Rejected
 P-->>U: Deny access
end
```

Session lifetime is bounded and process-local; restart invalidates sessions. Actual identity independence, secret rotation and phishing-resistant policies are operational decisions.

**Source:** [tools/LicensePortal/README.md](https://github.com/VY-Groups/gatewaycore-license-authority/blob/a915910a64adb3c6ccddcfa418118d2a38420422/tools/LicensePortal/README.md) · [tools/LicensePortal/Program.cs](https://github.com/VY-Groups/gatewaycore-license-authority/blob/a915910a64adb3c6ccddcfa418118d2a38420422/tools/LicensePortal/Program.cs)

## Four distinct key roles
```mermaid
flowchart LR
E["Entitlement P-256 private key"] --> W["Issuer: GCL1 and GCV1"]
L["Local installation P-256 key"] --> R["Customer: GCR1 and GCP1"]
S["Separate release private key"] --> M["Company: GCM1"]
B["Independent recovery private key"] --> C["Recovery tool: GCB1"]
W --> P["Customer embeds entitlement PUBLIC trust"]
M --> Q["Customer embeds release PUBLIC trust"]
C --> T["Independent recovery PUBLIC trust"]
```

TLS transport credentials are additional, separate identities. No private signing material is transferred into customer packages or web portal processes.

**Source:** [docs/PROTOCOL_BOUNDARY.md](https://github.com/VY-Groups/gatewaycore-license-authority/blob/a915910a64adb3c6ccddcfa418118d2a38420422/docs/PROTOCOL_BOUNDARY.md) · [docs/AUTHORITY_RECOVERY.md](https://github.com/VY-Groups/gatewaycore-license-authority/blob/a915910a64adb3c6ccddcfa418118d2a38420422/docs/AUTHORITY_RECOVERY.md) · [tools/ReleaseManifestSigner/ReleaseManifestBuilder.cs](https://github.com/VY-Groups/gatewaycore-license-authority/blob/a915910a64adb3c6ccddcfa418118d2a38420422/tools/ReleaseManifestSigner/ReleaseManifestBuilder.cs)

