# Commercial package build and signing procedure

This procedure creates five independently verifiable commercial packages from an exact, clean GatewayCore customer commit: gateway, gateway agent, L4 proxy, authoritative DNS, and GSLB observer. It builds only for the native host architecture (`win-x64` on Windows or `linux-x64` on Linux), because runtime-native components must not be cross-built by this tool.

## Before release signing

- Use a private, access-controlled signing host and private staging volume. The authority repository is public at this time; do not put real private keys, production package artifacts, customer data, or release secrets in GitHub Actions or this repository.
- Use a release signing key that is separate from all entitlement keys. Keep its encrypted PKCS#8 PEM and passphrase in approved company custody, outside both repositories and all package/output directories.
- Pin the release key's public SPKI in the customer source's `GatewayCore.ReleaseTrust` file and pin entitlement public keys separately in `GatewayCore.CommercialTrust`. The tool checks that the release key ID exists and that the release and entitlement public keys have different fingerprints.
- Review and freeze the exact customer commit. The tool rejects a mismatched or dirty customer checkout.

## Build, sign, and verify

Install the .NET 10 SDK and PowerShell 7 on the signing host. Check out the exact customer commit into a clean directory. Provide two JSON trust files in the existing format: a JSON object mapping key IDs to Base64-encoded DER SubjectPublicKeyInfo bytes. Then run the script from the authority repository:

```powershell
pwsh -NoProfile -File .\ops\release\build-commercial-packages.ps1 `
  -CustomerRepository C:\release\customer-source `
  -SourceCommit <full-lowercase-40-character-commit> `
  -RuntimeIdentifier win-x64 `
  -ReleaseKeyId <pinned-release-key-id> `
  -EncryptedReleaseKey C:\secure\release-key.pem `
  -ReleasePublicTrust C:\secure\release-trust.json `
  -EntitlementPublicTrust C:\secure\entitlement-trust.json `
  -OutputDirectory C:\private-staging\gatewaycore-release
```

Use `linux-x64` on a native Linux signing host. The script publishes each component with the commercial and release-integrity profiles, confirms the unsigned package is rejected, invokes the interactive `ReleaseManifestSigner` for each package, and requires the actual customer binary to accept the resulting signature. It archives each signed package, extracts and verifies each archive again, and writes `SHA256SUMS.txt`, `SOURCE_COMMIT.txt`, and `RELEASE_KEY_ID.txt`. The signer requests the encrypted-key passphrase interactively and does not accept it as a command-line argument or environment variable.

Transfer only the resulting package archives and checksum file through the approved release process. Verify the archive checksums on the receiving host before extraction. Keep the signing host's access controls and package staging immutable during signing. Never upload signing keys or passphrases alongside the package.

## Scope and limits

The `gatewaycore.integrity` manifest proves the complete package file inventory against a source commit and a pinned release key. It is not Authenticode or OS package signing, does not provide a trusted timestamp, and does not protect an administrator who can replace both the verifier and its embedded trust. This script does not publish a GitHub Release or authorize a production deployment. CI's ephemeral-key tests verify protocol behavior only; they are not production package signatures. Production release authorization, real key custody and recovery, platform code signing, deployment acceptance, and physical #36 acceptance remain separate gates.
