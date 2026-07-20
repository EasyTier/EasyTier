# Sign-Windows.ps1
# Signs Windows EasyTier executables and libraries with a Certum SimplySign cloud certificate.

param(
    [string]$TargetDirectory = "sign_binaries",
    [string]$CertificateSHA1 = $env:CERTUM_CERTIFICATE_SHA1,
    [string]$TimestampServer = "http://time.certum.pl"
)

function Get-LatestSignToolPath {
    $windowsKitsBin = Join-Path ${env:ProgramFiles(x86)} "Windows Kits\10\bin"
    if (Test-Path $windowsKitsBin) {
        $candidate = (
            Get-ChildItem -Path $windowsKitsBin -Recurse -File -Filter "signtool.exe" -ErrorAction SilentlyContinue |
                Where-Object { $_.FullName -match "\\x64\\signtool\.exe$" } |
                ForEach-Object {
                    $version = [version]"0.0"
                    if ($_.FullName -match "\\bin\\([^\\]+)\\x64\\signtool\.exe$") {
                        try {
                            $version = [version]$matches[1]
                        } catch {
                            $version = [version]"0.0"
                        }
                    }
                    [PSCustomObject]@{
                        Path = $_.FullName
                        Version = $version
                    }
                } |
                Sort-Object -Property Version -Descending |
                Select-Object -First 1
        )

        if ($candidate) {
            return $candidate.Path
        }
    }

    $cmd = Get-Command "signtool.exe" -ErrorAction SilentlyContinue
    if ($cmd) {
        return $cmd.Source
    }

    return $null
}

function Find-TargetCertificate {
    param([string]$Thumbprint)

    $all = Get-ChildItem -Path "Cert:\CurrentUser\My", "Cert:\LocalMachine\My" -ErrorAction SilentlyContinue
    # 对证书库中的 Thumbprint 同样做规范化（去除不可见字符、统一大写），避免 BOM 或格式差异导致匹配失败
    return @($all | Where-Object {
        $normalizedStoreThumprint = ($_.Thumbprint -replace "[^a-fA-F0-9]", "").ToUpperInvariant()
        $normalizedStoreThumprint -eq $Thumbprint
    })
}

function Show-PrivateKeyCertificateHints {
    $candidates = Get-ChildItem -Path "Cert:\CurrentUser\My", "Cert:\LocalMachine\My" -ErrorAction SilentlyContinue |
        Where-Object { $_.HasPrivateKey }

    if (($null -eq $candidates) -or ($candidates.Count -eq 0)) {
        Write-Host "No certificates with private keys were found in Personal stores"
        return
    }

    Write-Host "Certificates with private keys are present in Personal stores, but details are hidden for security"
}

Write-Host "=== WINDOWS BINARY SIGNING (CERTUM SIMPLYSIGN) ==="
Write-Host "Target directory: $TargetDirectory"

if (-not (Test-Path $TargetDirectory)) {
    Write-Host "ERROR: Target directory not found: $TargetDirectory"
    exit 1
}

if (-not $CertificateSHA1) {
    Write-Host "ERROR: CERTUM_CERTIFICATE_SHA1 environment variable not provided"
    exit 1
}

$normalizedSha1 = ($CertificateSHA1 -replace "[^a-fA-F0-9]", "").ToUpperInvariant()
if ($normalizedSha1.Length -ne 40) {
    Write-Host "ERROR: CERTUM_CERTIFICATE_SHA1 is invalid after normalization"
    Write-Host "Raw length: $($CertificateSHA1.Length), normalized length: $($normalizedSha1.Length)"
    exit 1
}

Write-Host "Expected signing certificate thumbprint has been received (masked)"

$targetCerts = Find-TargetCertificate -Thumbprint $normalizedSha1
if (($null -eq $targetCerts) -or ($targetCerts.Count -eq 0)) {
    Write-Host "ERROR: Target certificate not found in Cert:\CurrentUser\My or Cert:\LocalMachine\My"
    Write-Host "Authentication likely failed or CERTUM_CERTIFICATE_SHA1 is incorrect"
    Show-PrivateKeyCertificateHints
    exit 1
}

$targetWithPrivateKey = @($targetCerts | Where-Object { $_.HasPrivateKey })
if (($null -eq $targetWithPrivateKey) -or ($targetWithPrivateKey.Count -eq 0)) {
    Write-Host "ERROR: Target certificate exists but has no available private key"
    Write-Host "Signing cannot continue without private key access"
    Show-PrivateKeyCertificateHints
    exit 1
}

Write-Host "Locating signtool..."
$signTool = Get-LatestSignToolPath
if (-not $signTool) {
    Write-Host "ERROR: signtool.exe not found"
    exit 1
}

Write-Host "Found signtool: $signTool"

Write-Host "Scanning for Windows binaries to sign (.exe, .dll)..."
$filesToSign = Get-ChildItem -Path $TargetDirectory -Recurse -File |
    Where-Object { $_.Extension -iin @(".exe", ".dll") }

if (($null -eq $filesToSign) -or ($filesToSign.Count -eq 0)) {
    Write-Host "WARNING: No signable files (.exe, .dll) found to sign"
    exit 0
}

Write-Host "Found $($filesToSign.Count) files to sign"
$signedCount = 0
$failedCount = 0

foreach ($file in $filesToSign) {
    Write-Host "=== Signing: $($file.Name) ==="
    Write-Host "Path: $($file.FullName)"

    $attempts = @(
        @{ Name = "SHA1 thumbprint + /td SHA256"; Args = @("sign", "/sha1", $normalizedSha1, "/tr", $TimestampServer, "/td", "SHA256", "/fd", "SHA256", "/v", $file.FullName) },
        @{ Name = "SHA1 thumbprint in CurrentUser\\My"; Args = @("sign", "/sha1", $normalizedSha1, "/s", "My", "/tr", $TimestampServer, "/td", "SHA256", "/fd", "SHA256", "/v", $file.FullName) },
        @{ Name = "SHA1 thumbprint in LocalMachine\\My"; Args = @("sign", "/sha1", $normalizedSha1, "/sm", "/s", "My", "/tr", $TimestampServer, "/td", "SHA256", "/fd", "SHA256", "/v", $file.FullName) },
        @{ Name = "Auto-select cert (fallback)"; Args = @("sign", "/a", "/tr", $TimestampServer, "/td", "SHA256", "/fd", "SHA256", "/v", $file.FullName) }
    )

    $signed = $false
    foreach ($attempt in $attempts) {
        Write-Host "Attempt: $($attempt.Name)"
        $signOutput = & $signTool @($attempt.Args) 2>&1
        if ($LASTEXITCODE -eq 0) {
            Write-Host "SUCCESS: $($attempt.Name)"
            $signed = $true
            break
        }

        Write-Host "FAILED: $($attempt.Name)"
        Write-Host "signtool returned a non-zero exit code; detailed output is hidden for security"
    }

    if ($signed) {
        $signedCount++
        $verifyOutput = & $signTool verify /pa /v $file.FullName 2>&1
        if ($LASTEXITCODE -eq 0) {
            Write-Host "VERIFIED: Signature verification successful"
        } else {
            Write-Host "WARNING: Signature verification failed"
            Write-Host "Detailed verification output is hidden for security"
        }
    } else {
        $failedCount++
    }

    Write-Host ""
}

Write-Host "=== SIGNING SUMMARY ==="
Write-Host "Total files: $($filesToSign.Count)"
Write-Host "Successfully signed: $signedCount"
Write-Host "Failed to sign: $failedCount"

if ($failedCount -eq 0) {
    Write-Host "ALL WINDOWS BINARIES SIGNED SUCCESSFULLY"
    exit 0
}

Write-Host "SOME WINDOWS BINARIES FAILED TO SIGN"
exit 1