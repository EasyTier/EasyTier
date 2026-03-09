<#
.SYNOPSIS
    EasyTier Windows Installer

.DESCRIPTION
    Download EasyTier from GitHub Release and install it

.PARAMETER Version
    Target version: "latest", "stable", or a specific tag like "v2.5.0".
    Default: "latest"

.PARAMETER InstallDir
    Directory to install EasyTier binaries.
    Default: "$env:ProgramFiles\EasyTier"

.EXAMPLE
    .\install.ps1
    .\install.ps1 -Version v2.5.0
    .\install.ps1 -InstallDir "C:\EasyTier"

.NOTES
    Administrator privileges are required
#>
param(
    [Parameter(Position = 0)]
    [ValidatePattern('^(stable|latest|v?\d+\.\d+\.\d+(-[^\s]+)?)$')]
    [string]$Version = 'latest',

    [Parameter(Position = 1)]
    [string]$InstallDir = "$env:ProgramFiles\EasyTier"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
$GITHUB_REPO        = 'EasyTier/EasyTier'
$GITHUB_API         = "https://api.github.com/repos/$GITHUB_REPO"
$GITHUB_RELEASE_URL = "https://github.com/$GITHUB_REPO/releases"

# ---------------------------------------------------------------------------
# Administrator check
# ---------------------------------------------------------------------------
$currentPrincipal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error 'Please run this script as Administrator.'
    exit 1
}

# ---------------------------------------------------------------------------
# Architecture detection
# ---------------------------------------------------------------------------
switch ($env:PROCESSOR_ARCHITECTURE) {
    'AMD64' { $arch = 'x86_64' }
    'ARM64' { $arch = 'arm64'  }
    'x86'   { $arch = 'i686'   }
    default {
        Write-Error "Unsupported processor architecture: $env:PROCESSOR_ARCHITECTURE"
        exit 1
    }
}
$assetBaseName = "easytier-windows-$arch"

Write-Host ''
Write-Host '  ===============================================' -ForegroundColor Cyan
Write-Host '        EasyTier Windows Installer              ' -ForegroundColor Cyan
Write-Host '  ===============================================' -ForegroundColor Cyan
Write-Host ''
Write-Host "  Architecture : $arch" -ForegroundColor White
Write-Host ''

# ---------------------------------------------------------------------------
# Step 1 - Resolve release version
# ---------------------------------------------------------------------------
Write-Host '[1/4] Querying GitHub Release info...' -ForegroundColor Yellow

try {
    if ($Version -eq 'latest' -or $Version -eq 'stable') {
        $releaseInfo = Invoke-RestMethod `
            -Uri "$GITHUB_API/releases/latest" `
            -Headers @{ 'User-Agent' = 'EasyTier-Installer/1.0' } `
            -ErrorAction Stop
    }
    else {
        $tag = if ($Version -notmatch '^v') { "v$Version" } else { $Version }
        $releaseInfo = Invoke-RestMethod `
            -Uri "$GITHUB_API/releases/tags/$tag" `
            -Headers @{ 'User-Agent' = 'EasyTier-Installer/1.0' } `
            -ErrorAction Stop
    }
}
catch {
    Write-Error "Failed to fetch release info from GitHub: $_`nPlease check your network or visit $GITHUB_RELEASE_URL to download manually."
    exit 1
}

$releaseVersion = $releaseInfo.tag_name
$assetZipName   = "$assetBaseName-$releaseVersion.zip"

Write-Host "  Version : $releaseVersion" -ForegroundColor Green

$asset = $releaseInfo.assets |
    Where-Object { $_.name -eq $assetZipName } |
    Select-Object -First 1

if (-not $asset) {
    $availableAssets = ($releaseInfo.assets | Select-Object -ExpandProperty name) -join ', '
    Write-Error "Asset '$assetZipName' not found in release $releaseVersion.`nAvailable: $availableAssets`nVisit $GITHUB_RELEASE_URL to download manually."
    exit 1
}

$downloadUrl = $asset.browser_download_url
Write-Host "  URL     : $downloadUrl" -ForegroundColor DarkGray

# ---------------------------------------------------------------------------
# Step 2 - Download ZIP
# ---------------------------------------------------------------------------
Write-Host ''
Write-Host "[2/4] Downloading $assetZipName ..." -ForegroundColor Yellow

$tempDir = Join-Path $env:TEMP "easytier-install-$(Get-Random)"
$zipPath = Join-Path $tempDir $assetZipName

New-Item -ItemType Directory -Force -Path $tempDir | Out-Null

try {
    Invoke-WebRequest -Uri $downloadUrl -OutFile $zipPath -ErrorAction Stop
    $sizeMB = [math]::Round((Get-Item $zipPath).Length / 1MB, 2)
    Write-Host "  Download complete ($sizeMB MB)" -ForegroundColor Green
}
catch {
    Write-Error "Download failed: $_"
    Remove-Item -Recurse -Force $tempDir -ErrorAction SilentlyContinue
    exit 1
}

# ---------------------------------------------------------------------------
# Step 3 - Extract & copy to install directory
# ---------------------------------------------------------------------------
Write-Host ''
Write-Host '[3/4] Extracting and copying files...' -ForegroundColor Yellow

$extractDir = Join-Path $tempDir 'extracted'
New-Item -ItemType Directory -Force -Path $extractDir | Out-Null

try {
    Expand-Archive -Path $zipPath -DestinationPath $extractDir -Force -ErrorAction Stop
}
catch {
    Write-Error "Extraction failed: $_"
    Remove-Item -Recurse -Force $tempDir -ErrorAction SilentlyContinue
    exit 1
}

# ZIP may contain a sub-directory; find exe files recursively and flatten
$exeFiles = Get-ChildItem -Path $extractDir -Filter '*.exe' -Recurse
if (-not $exeFiles) {
    Remove-Item -Recurse -Force $tempDir -ErrorAction SilentlyContinue
    Write-Error 'No .exe files found after extraction. The ZIP may be malformed.'
    exit 1
}

$binSourceDir = $exeFiles[0].DirectoryName

try {
    New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
    Get-ChildItem -Path $binSourceDir | Copy-Item -Destination $InstallDir -Force
}
catch {
    Remove-Item -Recurse -Force $tempDir -ErrorAction SilentlyContinue
    Write-Error "Failed to copy files to install directory: $_"
    exit 1
}

Write-Host "  Installed to: $InstallDir" -ForegroundColor Green

# ---------------------------------------------------------------------------
# Step 4 - Update system PATH
# ---------------------------------------------------------------------------
Write-Host ''
Write-Host '[4/4] Updating system PATH...' -ForegroundColor Yellow

$systemPath = [Environment]::GetEnvironmentVariable('PATH', 'Machine')
if ($systemPath -notlike "*$InstallDir*") {
    [Environment]::SetEnvironmentVariable('PATH', "$systemPath;$InstallDir", 'Machine')
    $env:PATH = "$env:PATH;$InstallDir"
    Write-Host "  Added $InstallDir to system PATH" -ForegroundColor Green
}
else {
    Write-Host "  $InstallDir is already in PATH, skipping" -ForegroundColor DarkGray
}

# ---------------------------------------------------------------------------
# Cleanup
# ---------------------------------------------------------------------------
try {
    Remove-Item -Recurse -Force $tempDir -ErrorAction SilentlyContinue
}
catch {
    Write-Warning "Could not remove temp dir $tempDir : $_"
}

# ---------------------------------------------------------------------------
# Done
# ---------------------------------------------------------------------------
Write-Host ''
Write-Host "  [OK] EasyTier $releaseVersion installation complete!" -ForegroundColor Green
Write-Host ''
Write-Host "  Install dir : $InstallDir" -ForegroundColor White
Write-Host '  User guide  : https://easytier.cn/en/guide/network/decentralized-networking.html' -ForegroundColor DarkGray
Write-Host ''
Write-Host '  NOTE: If PATH was just updated, please restart your terminal.' -ForegroundColor DarkYellow
Write-Host ''
