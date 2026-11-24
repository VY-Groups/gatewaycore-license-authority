# 06 — Release signing, interoperability and CI

Baseline manifest signer and candidate actual-binary integration tests.

[← Authority atlas](README.md) · [Customer visual atlas](https://github.com/VY-Groups/yarp-lb/tree/docs/visual-architecture-atlas/docs/diagrams)

> Authority baseline main: `78b3cbcceafbf08e70d1d319f9318e23665153be`. Candidate integration tests: `a915910a64adb3c6ccddcfa418118d2a38420422` (PR #6). All diagrams show logical software behavior, not production authorization. No real customer data, keys or credentials are shown.

## Independent release signing
```mermaid
sequenceDiagram
participant B as Customer build
participant S as Company release signer
participant P as Immutable staging package
participant G as Genuine customer executable
B->>P: Publish with public entitlement/release trust and source SHA
S->>P: Review exact inventory and reject unsafe files
S->>S: Separate P-256 release private key signs GCM1
S->>P: Create manifest once and verify complete inventory
P-->>G: Offline transfer of signed package
G->>G: Verify embedded trust, source SHA and exact file hashes
alt Invalid or unsigned
 G-->>G: Refuse startup
else Valid
 G->>G: Run local entitlement checks
end
```

No key or license is included in the release inventory. GCM1 is not an OS code signature or trusted timestamp; operator must keep staging private and immutable.

**Source:** [tools/ReleaseManifestSigner/ReleaseManifestBuilder.cs](https://github.com/VY-Groups/gatewaycore-license-authority/blob/a915910a64adb3c6ccddcfa418118d2a38420422/tools/ReleaseManifestSigner/ReleaseManifestBuilder.cs) · [README.md](https://github.com/VY-Groups/gatewaycore-license-authority/blob/a915910a64adb3c6ccddcfa418118d2a38420422/README.md)

## Integrated paid runtime acceptance — PR #6 candidate
```mermaid
flowchart TD
S["Checkout pinned customer source"] --> P["Publish five actual commercial packages"]
P --> M["Actual company manifest builder signs each package"]
M --> V["Verify actual executable; reject unsigned or extra files"]
V --> L["Real L4 executable exports GCR1"]
L --> DB["PostgreSQL job: independent approval and paid settlement"]
DB --> W["Real worker emits GCL1"]
W --> F["Import; actual TCP echo forwarding"]
F --> R["Approve and issue GCV1"]
R --> X["Import revocation; active stream terminates"]
X --> N["Restart refused while revoked"]
```

CI uses ephemeral signing keys and synthetic records. No artifact is promoted to a customer release. Other engines' runtime traffic acceptance is covered separately; this candidate specifically exercises paid runtime and revocation with L4.

**Source:** [docs/INTEGRATED_COMMERCIAL_CANDIDATE.md](https://github.com/VY-Groups/gatewaycore-license-authority/blob/a915910a64adb3c6ccddcfa418118d2a38420422/docs/INTEGRATED_COMMERCIAL_CANDIDATE.md) · [tests/CommercialCandidate/Program.cs](https://github.com/VY-Groups/gatewaycore-license-authority/blob/a915910a64adb3c6ccddcfa418118d2a38420422/tests/CommercialCandidate/Program.cs)

## Authority CI job graph
```mermaid
flowchart TD
T["Push main / allowed pull request"] --> W["build-test: Windows"]
T --> L["build-test: Ubuntu"]
T --> P["postgres-acceptance: Ubuntu"]
T --> C["customer-protocol-snapshot"]
T --> X["release-candidate-windows: candidate PR #6"]
W --> U["SDK / portal / worker / manifest tests"]
L --> U
P --> D["Postgres 16 + pinned customer checkout"]
D --> A["CustomerInterop + allocation/billing/recovery tests"]
A --> H["Two HTTPS portals; signer isolation"]
H --> I["Candidate actual paid runtime and signed packages"]
C --> E["Exact shared SDK snapshot diff"]
X --> V["Five Windows published package integrity tests"]
```

Baseline four jobs include matrix instances; candidate adds Windows package acceptance and expands PostgreSQL job. These are parallel independent jobs, not a sequential cross-job dependency. The candidate must be repinned to the final merged customer source before release.

**Source:** [.github/workflows/authority-ci.yml](https://github.com/VY-Groups/gatewaycore-license-authority/blob/a915910a64adb3c6ccddcfa418118d2a38420422/.github/workflows/authority-ci.yml)

## Commercial promotion gates
```mermaid
flowchart TD
A["Authority reviewed main + exact-head CI"] --> B["Customer reviewed main + exact-head CI"]
B --> C["Freeze and repin both repositories"]
C --> D{"Integrated acceptance passed?"}
D -->|No| X["Fix or hold"]
D -->|Yes| E["Owner-approved commercial policy and private authority"]
E --> F["Separate production key custody and release signing"]
F --> G["Controlled software candidate"]
G --> H["Customer physical and operational acceptance"]
```

No real billing, production signing, external provider, physical HA or legal certification is performed by diagram documentation.

**Source:** [docs/INTEGRATED_COMMERCIAL_CANDIDATE.md](https://github.com/VY-Groups/gatewaycore-license-authority/blob/a915910a64adb3c6ccddcfa418118d2a38420422/docs/INTEGRATED_COMMERCIAL_CANDIDATE.md) · [docs/AUTHORITY_RECOVERY.md](https://github.com/VY-Groups/gatewaycore-license-authority/blob/a915910a64adb3c6ccddcfa418118d2a38420422/docs/AUTHORITY_RECOVERY.md)

