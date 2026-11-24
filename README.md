# GatewayCore License Authority

**[Visual architecture and workflow atlas](docs/diagrams/README.md)** — licensing, PostgreSQL, billing, trust, recovery, signing and CI diagrams.

Company-side development repository; public temporarily, private before commercial operation. No production credentials, signing keys, operational customer data or issuer ledgers belong in Git, even after privatization. Previously public source cannot be made confidential retroactively.

## Components

- `tools/LicenseAuthority`: encrypted-key operator CLI and local prototype ledger.
- `tools/LicensePortal`: ASP.NET Core portal, PostgreSQL schema, distinct-person approval and customer/subscription administration.
- `tools/LicenseIssuerWorker`: independent approved-job database signing executable.
- `src/GatewayCore.Licensing`: pinned compatibility snapshot of the shared verification/activation library.
- `tests/OfflineLicensing`: ephemeral-key protocol, allocation, renewal, revocation and rollback tests.

Source baseline: [GatewayCore PR #546, 5a0d5f1470a5dd8b853113b1e96b48348cb52c38](https://github.com/VY-Groups/yarp-lb/tree/5a0d5f1470a5dd8b853113b1e96b48348cb52c38). Preserve historical licensing obligations; see PROJECT_LICENSE_STATUS.md. No new distribution license is asserted.

## Build/test

Install .NET 10 SDK. Run `dotnet run --project tests/OfflineLicensing/OfflineLicensing.csproj -c Release`, `dotnet build tools/LicensePortal/LicensePortal.csproj -c Release`, and `dotnet build tools/LicenseIssuerWorker/LicenseIssuerWorker.csproj -c Release`. Portal provisioning is documented in tools/LicensePortal/README.md.

## Acceptance

Development only. Pending: real PostgreSQL concurrent issuance/approval acceptance, least-privilege roles, MFA, key rotation and recovery, portal end-to-end HTTPS, immutable audit, customer compatibility and independent review. Do not provision real keys or use for commercial issuance yet.

## Independent commercial release signing
The customer release profile pins independent public release trust and exact source commit. Build and sign the five native platform packages with [`docs/COMMERCIAL_PACKAGE_RELEASE.md`](docs/COMMERCIAL_PACKAGE_RELEASE.md) on the isolated company signing host. Use a distinct release key from license entitlements, stored outside Git and outside all package directories. The tool refuses to overwrite existing manifests, rejects linked paths and obvious secret file types, signs the bounded full inventory, and re-verifies each package and archive with the customer-compatible SDK before returning success. Keep staging storage private and immutable during signing. This is not an external trusted timestamp, OS signing, or production release authorization.

## Required dual-control deployment
The portal is deployed twice, each instance using one operator role and one DB principal. See tools/LicensePortal/README.md and deploy/gc-license-portal@.service. Never deploy both portal secrets to a shared process or account.
