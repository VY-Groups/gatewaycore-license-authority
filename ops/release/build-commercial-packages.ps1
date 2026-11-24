[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$CustomerRepository,
    [Parameter(Mandatory = $true)][string]$SourceCommit,
    [Parameter(Mandatory = $true)][ValidateSet('win-x64', 'linux-x64')][string]$RuntimeIdentifier,
    [Parameter(Mandatory = $true)][string]$ReleaseKeyId,
    [Parameter(Mandatory = $true)][string]$EncryptedReleaseKey,
    [Parameter(Mandatory = $true)][string]$ReleasePublicTrust,
    [Parameter(Mandatory = $true)][string]$EntitlementPublicTrust,
    [Parameter(Mandatory = $true)][string]$OutputDirectory
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function Resolve-ExistingFile([string]$Path, [string]$Label) {
    $resolved = (Resolve-Path -LiteralPath $Path -ErrorAction Stop).Path
    $item = Get-Item -LiteralPath $resolved -Force
    if ($item.PSIsContainer -or (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)) {
        throw "$Label must be a regular file, not a directory or link."
    }
    return $resolved
}

function Is-Within([string]$Path, [string]$Directory) {
    $fullPath = [IO.Path]::GetFullPath($Path).TrimEnd([IO.Path]::DirectorySeparatorChar, [IO.Path]::AltDirectorySeparatorChar)
    $fullDirectory = [IO.Path]::GetFullPath($Directory).TrimEnd([IO.Path]::DirectorySeparatorChar, [IO.Path]::AltDirectorySeparatorChar)
    return $fullPath.Equals($fullDirectory, [StringComparison]::OrdinalIgnoreCase) -or
        $fullPath.StartsWith($fullDirectory + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase) -or
        $fullPath.StartsWith($fullDirectory + [IO.Path]::AltDirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)
}

function Read-PublicTrust([string]$Path, [string]$Label) {
    if ((Get-Item -LiteralPath $Path).Length -gt 16384) { throw "$Label exceeds the 16 KiB embedded trust limit." }
    $document = [Text.Json.JsonDocument]::Parse([IO.File]::ReadAllText($Path))
    try {
        $properties = @($document.RootElement.EnumerateObject())
        if ($document.RootElement.ValueKind -ne [Text.Json.JsonValueKind]::Object -or
            $properties.Count -lt 1 -or $properties.Count -gt 16) {
            throw "$Label must be a JSON object containing between 1 and 16 public keys."
        }
        $keys = @{}
        foreach ($property in $document.RootElement.EnumerateObject()) {
            if ($property.Name -notmatch '^[A-Za-z0-9_-]{1,80}$' -or
                $property.Value.ValueKind -ne [Text.Json.JsonValueKind]::String) {
                throw "$Label contains an invalid key identifier or value."
            }
            if ($keys.ContainsKey($property.Name)) { throw "$Label contains a duplicate key identifier." }
            $spki = [Convert]::FromBase64String($property.Value.GetString())
            if ($spki.Length -lt 1 -or $spki.Length -gt 256) { throw "$Label contains an invalid public key size." }
            $key = [Security.Cryptography.ECDsa]::Create()
            try {
                $bytesRead = 0
                $key.ImportSubjectPublicKeyInfo($spki, [ref]$bytesRead)
                if ($bytesRead -ne $spki.Length -or $key.ExportParameters($false).Curve.Oid.Value -ne '1.2.840.10045.3.1.7') {
                    throw "$Label keys must be complete P-256 SubjectPublicKeyInfo values."
                }
                $fingerprint = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($key.ExportSubjectPublicKeyInfo()))
                $keys[$property.Name] = $fingerprint
            }
            finally { $key.Dispose() }
        }
        return $keys
    }
    finally { $document.Dispose() }
}

function Invoke-Checked([string]$Executable, [string[]]$Arguments, [string]$Label) {
    & $Executable @Arguments
    if ($LASTEXITCODE -ne 0) { throw "$Label failed with exit code $LASTEXITCODE." }
}

if ($SourceCommit -cnotmatch '^[0-9a-f]{40}$') { throw 'SourceCommit must be a full lowercase Git commit SHA.' }
if ($ReleaseKeyId -notmatch '^[A-Za-z0-9_-]{1,80}$') { throw 'ReleaseKeyId has an invalid format.' }
if (-not (Test-Path -LiteralPath $CustomerRepository -PathType Container)) { throw 'Customer repository does not exist.' }
$customerRoot = (Resolve-Path -LiteralPath $CustomerRepository).Path

$isWindowsHost = [Runtime.InteropServices.RuntimeInformation]::IsOSPlatform([Runtime.InteropServices.OSPlatform]::Windows)
$isLinuxHost = [Runtime.InteropServices.RuntimeInformation]::IsOSPlatform([Runtime.InteropServices.OSPlatform]::Linux)
if ([Runtime.InteropServices.RuntimeInformation]::ProcessArchitecture -ne [Runtime.InteropServices.Architecture]::X64 -or
    ($RuntimeIdentifier -eq 'win-x64') -ne $isWindowsHost -or ($RuntimeIdentifier -eq 'linux-x64') -ne $isLinuxHost) {
    throw "Run on a native $RuntimeIdentifier host; cross-OS signing builds are rejected."
}

$actualCommit = (& git -C $customerRoot rev-parse --verify HEAD 2>$null).Trim()
if ($LASTEXITCODE -ne 0 -or $actualCommit -cne $SourceCommit) { throw 'Customer checkout is not at SourceCommit.' }
$dirty = & git -C $customerRoot status --porcelain --untracked-files=all
if ($LASTEXITCODE -ne 0 -or $dirty) { throw 'Customer checkout must be clean before packaging.' }

$keyPath = Resolve-ExistingFile $EncryptedReleaseKey 'Encrypted release key'
$releaseTrustPath = Resolve-ExistingFile $ReleasePublicTrust 'Release public trust'
$entitlementTrustPath = Resolve-ExistingFile $EntitlementPublicTrust 'Entitlement public trust'
$keyInfo = Get-Item -LiteralPath $keyPath -Force
if ($keyInfo.Length -lt 1 -or $keyInfo.Length -gt 65536 -or
    ([IO.File]::ReadAllText($keyPath) -notmatch 'ENCRYPTED PRIVATE KEY')) {
    throw 'Release key must be an encrypted PKCS#8 PEM file no larger than 64 KiB.'
}
$releaseKeys = Read-PublicTrust $releaseTrustPath 'Release trust'
$entitlementKeys = Read-PublicTrust $entitlementTrustPath 'Entitlement trust'
if (-not $releaseKeys.ContainsKey($ReleaseKeyId)) { throw 'ReleaseKeyId is not present in the pinned release public trust.' }
if (@($releaseKeys.Values | Where-Object { $entitlementKeys.Values -contains $_ }).Count -gt 0) {
    throw 'Release and entitlement public keys must be cryptographically independent.'
}

$outputPath = [IO.Path]::GetFullPath($OutputDirectory)
if ((Is-Within $outputPath $customerRoot) -or (Is-Within $customerRoot $outputPath)) {
    throw 'OutputDirectory and the customer source checkout must be separate trees.'
}
foreach ($controlFile in @($keyPath, $releaseTrustPath, $entitlementTrustPath)) {
    if (Is-Within $controlFile $outputPath) { throw 'Signing keys and trust inputs must remain outside the package output tree.' }
}
if (Test-Path -LiteralPath $outputPath) {
    if ((Get-Item -LiteralPath $outputPath -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) {
        throw 'OutputDirectory cannot be a link or junction.'
    }
    if (-not (Get-ChildItem -LiteralPath $outputPath -Force | Select-Object -First 1)) {
        # An existing empty directory is acceptable.
    } else { throw 'OutputDirectory must be new or empty; existing package data is never overwritten.' }
} else {
    $outputParent = Split-Path -Parent $outputPath
    if (-not (Test-Path -LiteralPath $outputParent -PathType Container)) { throw 'OutputDirectory parent must already exist on the private staging volume.' }
    $parentItem = Get-Item -LiteralPath $outputParent -Force
    if (($parentItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'OutputDirectory parent cannot be a link or junction.' }
    [void][IO.Directory]::CreateDirectory($outputPath)
}

$projects = @(
    @{ Name = 'gateway'; Project = 'control-center/GatewayCoreYarp.csproj'; Dll = 'GatewayCoreYarp.dll' },
    @{ Name = 'agent'; Project = 'control-center/GatewayAgent/GatewayCoreGatewayAgent.csproj'; Dll = 'GatewayCoreGatewayAgent.dll' },
    @{ Name = 'l4'; Project = 'engines/L4/L4Proxy.csproj'; Dll = 'L4Proxy.dll' },
    @{ Name = 'authoritative-dns'; Project = 'engines/GslbDns/GslbDns.csproj'; Dll = 'GslbDns.dll' },
    @{ Name = 'gslb-observer'; Project = 'engines/GslbObserver/GslbObserver.csproj'; Dll = 'GslbObserver.dll' }
)
$authorityRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..'))
$signerProject = Join-Path $authorityRoot 'tools/ReleaseManifestSigner/ReleaseManifestSigner.csproj'
$sums = [Collections.Generic.List[string]]::new()

try {
    foreach ($component in $projects) {
        $projectPath = Join-Path $customerRoot $component.Project
        if (-not (Test-Path -LiteralPath $projectPath -PathType Leaf)) { throw "Missing customer project $($component.Project)." }
        $packagePath = Join-Path $outputPath $component.Name
        [void][IO.Directory]::CreateDirectory($packagePath)
        $publishArgs = @(
            'publish', $projectPath, '--configuration', 'Release', '--runtime', $RuntimeIdentifier,
            '--self-contained', 'false', '--output', $packagePath,
            "-p:GatewayCoreCommercial=true", "-p:GatewayCoreReleasePackage=true",
            "-p:GatewayCoreTrustFile=$entitlementTrustPath", "-p:GatewayCoreReleaseTrustFile=$releaseTrustPath",
            "-p:GatewayCoreReleaseSourceCommit=$SourceCommit"
        )
        Invoke-Checked 'dotnet' $publishArgs "Publish $($component.Name)"

        $binary = Join-Path $packagePath $component.Dll
        if (-not (Test-Path -LiteralPath $binary -PathType Leaf)) { throw "Publish did not produce $($component.Dll)." }
        $verifyArgs = @($binary, '--verify-release')
        & dotnet @verifyArgs
        if ($LASTEXITCODE -ne 78) { throw "Unsigned $($component.Name) package did not fail closed with exit code 78." }

        $signArgs = @('run', '--project', $signerProject, '--configuration', 'Release', '--',
            $packagePath, $SourceCommit, $ReleaseKeyId, $keyPath)
        Invoke-Checked 'dotnet' $signArgs "Sign $($component.Name)"

        $verification = & dotnet @verifyArgs 2>&1
        if ($LASTEXITCODE -ne 0 -or ($verification -join "`n") -notmatch [regex]::Escape("COMMERCIAL_RELEASE_INTEGRITY_PASS $SourceCommit")) {
            throw "Customer binary did not verify the signed $($component.Name) package."
        }

        $archiveName = "GatewayCore-$($component.Name)-$RuntimeIdentifier-$($SourceCommit.Substring(0, 12)).zip"
        $archivePath = Join-Path $outputPath $archiveName
        [IO.Compression.ZipFile]::CreateFromDirectory($packagePath, $archivePath, [IO.Compression.CompressionLevel]::Optimal, $false)

        $extractPath = Join-Path $outputPath ('.verify-' + [Guid]::NewGuid().ToString('N'))
        try {
            [IO.Compression.ZipFile]::ExtractToDirectory($archivePath, $extractPath)
            $extractedBinary = Join-Path $extractPath $component.Dll
            $archiveVerifyArgs = @($extractedBinary, '--verify-release')
            $archivedVerification = & dotnet @archiveVerifyArgs 2>&1
            if ($LASTEXITCODE -ne 0 -or ($archivedVerification -join "`n") -notmatch [regex]::Escape("COMMERCIAL_RELEASE_INTEGRITY_PASS $SourceCommit")) {
                throw "Archived $($component.Name) package failed signature verification after extraction."
            }
        }
        finally { if (Test-Path -LiteralPath $extractPath) { Remove-Item -LiteralPath $extractPath -Recurse -Force } }

        $hash = (Get-FileHash -LiteralPath $archivePath -Algorithm SHA256).Hash.ToLowerInvariant()
        $sums.Add("$hash  $archiveName")
        Write-Host "SIGNED_PACKAGE_PASS $($component.Name) $RuntimeIdentifier $SourceCommit $hash"
    }

    [IO.File]::WriteAllLines((Join-Path $outputPath 'SHA256SUMS.txt'), $sums, [Text.Encoding]::ASCII)
    [IO.File]::WriteAllText((Join-Path $outputPath 'SOURCE_COMMIT.txt'), "$SourceCommit`n", [Text.Encoding]::ASCII)
    [IO.File]::WriteAllText((Join-Path $outputPath 'RELEASE_KEY_ID.txt'), "$ReleaseKeyId`n", [Text.Encoding]::ASCII)
    Write-Host "COMMERCIAL_PACKAGE_SET_SIGNED $RuntimeIdentifier $SourceCommit"
}
catch {
    Write-Error "Commercial package release stopped: $($_.Exception.Message)"
    exit 1
}
