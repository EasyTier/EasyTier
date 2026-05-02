# Connect-SimplySign-Enhanced.ps1
# Registry-Enhanced TOTP Authentication for SimplySign Desktop
# Uses registry pre-configuration + TOTP credential injection approach

param(
    [string]$OtpUri = $env:CERTUM_OTP_URI,
    [string]$UserId = $env:CERTUM_USERNAME,
    [string]$ExePath = $env:CERTUM_EXE_PATH
)

# Validate required parameters
if (-not $OtpUri) {
    Write-Host "ERROR: CERTUM_OTP_URI environment variable not provided"
    exit 1
}

if (-not $UserId) {
    Write-Host "ERROR: CERTUM_USERNAME environment variable not provided"
    exit 1
}

if (-not $ExePath) {
    $ExePath = "C:\Program Files\Certum\SimplySign Desktop\SimplySignDesktop.exe"
}

Write-Host "=== REGISTRY-ENHANCED TOTP AUTHENTICATION ==="
Write-Host "Using registry pre-configuration + credential injection"
Write-Host "OTP URI provided (length: $($OtpUri.Length))"
Write-Host "User ID: $UserId"
Write-Host "Executable: $ExePath"
Write-Host ""

# Verify SimplySign Desktop exists
if (-not (Test-Path $ExePath)) {
    Write-Host "ERROR: SimplySign Desktop not found at: $ExePath"
    exit 1
}

# Parse the otpauth:// URI
$uri = [Uri]$OtpUri

# Parse query parameters (compatible with both PowerShell 5.1 and 7+)
try {
    $q = [System.Web.HttpUtility]::ParseQueryString($uri.Query)
} catch {
    $q = @{}
    foreach ($part in $uri.Query.TrimStart('?') -split '&') {
        $kv = $part -split '=', 2
        if ($kv.Count -eq 2) { 
            $q[$kv[0]] = [Uri]::UnescapeDataString($kv[1]) 
        }
    }
}

$Base32 = $q['secret']
$Digits = if ($q['digits']) { [int]$q['digits'] } else { 6 }
$Period = if ($q['period']) { [int]$q['period'] } else { 30 }
$Algorithm = if ($q['algorithm']) { $q['algorithm'].ToUpper() } else { 'SHA256' }

# Validate supported algorithms
$SupportedAlgorithms = @('SHA1', 'SHA256', 'SHA512')
if ($Algorithm -notin $SupportedAlgorithms) {
    Write-Host "ERROR: Unsupported algorithm: $Algorithm. Supported: $($SupportedAlgorithms -join ', ')"
    exit 1
}

# TOTP Generator (inline C# implementation)
Add-Type -Language CSharp @"
using System;
using System.Security.Cryptography;

public static class Totp
{
    private const string B32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

    private static byte[] Base32Decode(string s)
    {
        s = s.TrimEnd('=').ToUpperInvariant();
        int byteCount = s.Length * 5 / 8;
        byte[] bytes = new byte[byteCount];

        int bitBuffer = 0, bitsLeft = 0, idx = 0;
        foreach (char c in s)
        {
            int val = B32.IndexOf(c);
            if (val < 0) throw new ArgumentException("Invalid Base32 char: " + c);

            bitBuffer = (bitBuffer << 5) | val;
            bitsLeft += 5;

            if (bitsLeft >= 8)
            {
                bytes[idx++] = (byte)(bitBuffer >> (bitsLeft - 8));
                bitsLeft -= 8;
            }
        }
        return bytes;
    }

    private static HMAC GetHmacAlgorithm(string algorithm, byte[] key)
    {
        switch (algorithm.ToUpper())
        {
            case "SHA1":
                return new HMACSHA1(key);
            case "SHA256":
                return new HMACSHA256(key);
            case "SHA512":
                return new HMACSHA512(key);
            default:
                throw new ArgumentException("Unsupported algorithm: " + algorithm);
        }
    }

    public static string Now(string secret, int digits, int period, string algorithm = "SHA256")
    {
        byte[] key = Base32Decode(secret);
        long counter = DateTimeOffset.UtcNow.ToUnixTimeSeconds() / period;

        byte[] cnt = BitConverter.GetBytes(counter);
        if (BitConverter.IsLittleEndian) Array.Reverse(cnt);

        byte[] hash;
        using (var hmac = GetHmacAlgorithm(algorithm, key))
        {
            hash = hmac.ComputeHash(cnt);
        }

        int offset = hash[hash.Length - 1] & 0x0F;
        int binary =
            ((hash[offset] & 0x7F) << 24) |
            ((hash[offset + 1] & 0xFF) << 16) |
            ((hash[offset + 2] & 0xFF) << 8) |
            (hash[offset + 3] & 0xFF);

        int otp = binary % (int)Math.Pow(10, digits);
        return otp.ToString(new string('0', digits));
    }
}
"@

function Get-TotpCode {
    param([string]$Secret, [int]$Digits = 6, [int]$Period = 30, [string]$Algorithm = 'SHA256')
    [Totp]::Now($Secret, $Digits, $Period, $Algorithm)
}

# Generate current TOTP code
$otp = Get-TotpCode -Secret $Base32 -Digits $Digits -Period $Period -Algorithm $Algorithm
Write-Host "Generated TOTP: $otp (using $Algorithm algorithm)"
Write-Host ""

# Launch SimplySign Desktop (registry should auto-open login dialog)
Write-Host "Launching SimplySign Desktop..."
Write-Host "Registry pre-configuration should auto-open login dialog"
$proc = Start-Process -FilePath $ExePath -PassThru
Write-Host "Process started with ID: $($proc.Id)"
Write-Host ""

# Wait for the application to initialize
Write-Host "Waiting for SimplySign Desktop to initialize..."
Start-Sleep -Seconds 3

# Create WScript.Shell for window interaction
$wshell = New-Object -ComObject WScript.Shell

# Try to focus the SimplySign Desktop window
Write-Host "Attempting to focus SimplySign Desktop window..."
$focused = $false

# Method 1: Focus by process ID (most reliable)
$focused = $wshell.AppActivate($proc.Id)

# Method 2: Focus by window title (fallback)
if (-not $focused) {
    $focused = $wshell.AppActivate('SimplySign Desktop')
}

# Method 3: Multiple attempts with slight delays
for ($i = 0; (-not $focused) -and ($i -lt 10); $i++) {
    Start-Sleep -Milliseconds 500
    $focused = $wshell.AppActivate($proc.Id) -or $wshell.AppActivate('SimplySign Desktop')
    Write-Host "Focus attempt $($i + 1): $focused"
}

if (-not $focused) {
    Write-Host "ERROR: Could not bring SimplySign Desktop to foreground"
    Write-Host "Login dialog may not be visible for credential injection"
    exit 1
}

Write-Host "Successfully focused SimplySign Desktop window"
Write-Host ""

# Small delay to ensure window is ready for input
Start-Sleep -Milliseconds 400

# Inject credentials: Username + TAB + TOTP + ENTER
Write-Host "Injecting credentials into login dialog..."
Write-Host "Sending: Username -> TAB -> TOTP -> ENTER"

# Send the credential sequence
$wshell.SendKeys($UserId)
Start-Sleep -Milliseconds 200
$wshell.SendKeys("{TAB}")
Start-Sleep -Milliseconds 200
$wshell.SendKeys($otp)
Start-Sleep -Milliseconds 200
$wshell.SendKeys("{ENTER}")

Write-Host "Credentials injected successfully"
Write-Host ""

# Wait for authentication to process
Write-Host "Waiting for authentication to complete..."
Start-Sleep -Seconds 5

# Verify SimplySign Desktop is still running
$stillRunning = Get-Process -Id $proc.Id -ErrorAction SilentlyContinue
if ($stillRunning) {
    Write-Host "SUCCESS: SimplySign Desktop is running"
    Write-Host "Authentication should be complete"
    Write-Host "Cloud certificate should now be available"
} else {
    Write-Host "WARNING: SimplySign Desktop process has exited"
    Write-Host "This may indicate authentication failure"
}

Write-Host ""
Write-Host "=== TOTP AUTHENTICATION COMPLETE ==="
Write-Host "Registry pre-configuration + credential injection finished"
