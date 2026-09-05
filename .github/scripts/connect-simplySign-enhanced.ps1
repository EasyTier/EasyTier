# Connect-SimplySign-Enhanced.ps1
# Registry-Enhanced TOTP Authentication for SimplySign Desktop
# Uses registry pre-configuration + TOTP credential injection approach

param(
    [string]$OtpUri = $env:CERTUM_OTP_URI,
    [string]$UserId = $env:CERTUM_USERNAME,
    [string]$ExePath = $env:CERTUM_EXE_PATH,
    [string]$ExpectedCertificateSHA1 = $env:CERTUM_CERTIFICATE_SHA1
)

function Normalize-Sha1 {
    param([string]$InputSha1)
    if (-not $InputSha1) {
        return $null
    }
    return ($InputSha1 -replace "[^a-fA-F0-9]", "").ToUpperInvariant()
}

function Find-CertificateByThumbprint {
    param([string]$Thumbprint)

    if (-not $Thumbprint) {
        return @()
    }

    $all = Get-ChildItem -Path "Cert:\CurrentUser\My", "Cert:\LocalMachine\My" -ErrorAction SilentlyContinue
    # 对证书库中的 Thumbprint 同样做规范化（去除不可见字符、统一大写），避免 BOM 或格式差异导致匹配失败
    return @($all | Where-Object {
        $normalizedStoreThumbprint = ($_.Thumbprint -replace "[^a-fA-F0-9]", "").ToUpperInvariant()
        $normalizedStoreThumbprint -eq $Thumbprint
    })
}

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

# Add Win32 API for force foreground window
Add-Type @"
using System;
using System.Runtime.InteropServices;

public static class Win32 {
    [DllImport("user32.dll")]
    public static extern bool SetForegroundWindow(IntPtr hWnd);

    [DllImport("user32.dll")]
    public static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);

    [DllImport("user32.dll")]
    public static extern IntPtr FindWindow(string lpClassName, string lpWindowName);

    [DllImport("user32.dll")]
    public static extern bool AllowSetForegroundWindow(int dwProcessId);

    public const int SW_RESTORE = 9;
    public const int SW_SHOW = 5;
}
"@

# 预先验证证书 SHA1
$normalizedExpectedSha1 = Normalize-Sha1 -InputSha1 $ExpectedCertificateSHA1
if ($normalizedExpectedSha1) {
    if ($normalizedExpectedSha1.Length -ne 40) {
        Write-Host "ERROR: CERTUM_CERTIFICATE_SHA1 is invalid after normalization"
        Write-Host "Raw length: $($ExpectedCertificateSHA1.Length), normalized length: $($normalizedExpectedSha1.Length)"
        exit 1
    }
}

# === 认证重试循环（最多 10 次） ===
$maxAttempts = 10
$authSuccess = $false

for ($attempt = 1; $attempt -le $maxAttempts; $attempt++) {
    Write-Host ""
    Write-Host "=========================================="
    Write-Host "=== AUTHENTICATION ATTEMPT $attempt / $maxAttempts ==="
    Write-Host "=========================================="
    Write-Host ""

    # 每次重试都重新生成 TOTP（确保验证码有效）
    $otp = Get-TotpCode -Secret $Base32 -Digits $Digits -Period $Period -Algorithm $Algorithm
    Write-Host "Generated TOTP code successfully (masked) using $Algorithm algorithm"
    Write-Host ""

    # 终止之前可能残留的 SimplySign Desktop 进程
    Get-Process -Name "SimplySignDesktop" -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 2

    # 启动 SimplySign Desktop
    Write-Host "Launching SimplySign Desktop..."
    Write-Host "Registry pre-configuration should auto-open login dialog"
    $proc = Start-Process -FilePath $ExePath -PassThru
    Write-Host "Process started with ID: $($proc.Id)"
    Write-Host ""

    # 等待应用初始化
    Write-Host "Waiting for SimplySign Desktop to initialize..."
    Start-Sleep -Seconds 10

    # Allow our process to set foreground window
    [Win32]::AllowSetForegroundWindow($proc.Id) | Out-Null

    # Create WScript.Shell for window interaction
    $wshell = New-Object -ComObject WScript.Shell

    # 尝试聚焦 SimplySign Desktop 窗口
    Write-Host "Attempting to focus SimplySign Desktop window..."
    $focused = $false

    # Method 1: Use Win32 API to find and activate window
    $mainWindowHandle = $proc.MainWindowHandle
    if ($mainWindowHandle -ne $null -and $mainWindowHandle -ne [IntPtr]::Zero) {
        [Win32]::ShowWindow($mainWindowHandle, [Win32]::SW_RESTORE) | Out-Null
        [Win32]::SetForegroundWindow($mainWindowHandle) | Out-Null
        $focused = $true
        Write-Host "Focused via MainWindowHandle"
    } else {
        Write-Host "MainWindowHandle not available yet, will try other methods..."
    }

    # Method 2: Find window by title
    if (-not $focused) {
        $hwnd = [Win32]::FindWindow($null, "SimplySign Desktop")
        if ($hwnd -ne [IntPtr]::Zero) {
            [Win32]::ShowWindow($hwnd, [Win32]::SW_RESTORE) | Out-Null
            [Win32]::SetForegroundWindow($hwnd) | Out-Null
            $focused = $true
            Write-Host "Focused via FindWindow"
        }
    }

    # Method 3: AppActivate with extended retries
    for ($i = 0; (-not $focused) -and ($i -lt 20); $i++) {
        Start-Sleep -Milliseconds 1000

        # Refresh process handle
        $proc.Refresh()
        $mainWindowHandle = $proc.MainWindowHandle
        if ($mainWindowHandle -ne [IntPtr]::Zero) {
            [Win32]::ShowWindow($mainWindowHandle, [Win32]::SW_RESTORE) | Out-Null
            [Win32]::SetForegroundWindow($mainWindowHandle) | Out-Null
            $focused = $true
            Write-Host "Focused via MainWindowHandle (attempt $($i + 1))"
            break
        }

        $focused = $wshell.AppActivate($proc.Id)
        if (-not $focused) {
            $focused = $wshell.AppActivate('SimplySign Desktop')
        }
        if (-not $focused) {
            $focused = $wshell.AppActivate('SimplySign')
        }
        Write-Host "Focus attempt $($i + 1): $focused"
    }

    if (-not $focused) {
        Write-Host "WARNING: Could not bring SimplySign Desktop to foreground via window handle"
        Write-Host "SimplySign Desktop may be running as a background/tray process - proceeding with credential injection anyway"
    }

    Write-Host ""

    # Small delay to ensure window is ready for input
    Start-Sleep -Milliseconds 400

    # 注入凭据: Username + TAB + TOTP + ENTER
    Write-Host "Injecting credentials into login dialog..."
    Write-Host "Sending: Username -> TAB -> TOTP -> ENTER"

    $wshell.SendKeys($UserId)
    Start-Sleep -Milliseconds 200
    $wshell.SendKeys("{TAB}")
    Start-Sleep -Milliseconds 200
    $wshell.SendKeys($otp)
    Start-Sleep -Milliseconds 200
    $wshell.SendKeys("{ENTER}")

    Write-Host "Credentials injected successfully"
    Write-Host ""

    # 等待认证处理
    Write-Host "Waiting for authentication to complete..."
    Start-Sleep -Seconds 5

    # 验证证书是否可用
    if ($normalizedExpectedSha1) {
        Write-Host "Validating certificate availability for expected signing certificate"
        $ready = $false
        $withPrivateKey = $false

        for ($i = 0; $i -lt 15; $i++) {
            $matched = Find-CertificateByThumbprint -Thumbprint $normalizedExpectedSha1
            if ($matched.Count -gt 0) {
                $ready = $true
                $withPrivateKey = ($matched | Where-Object { $_.HasPrivateKey }).Count -gt 0
                if ($withPrivateKey) {
                    Write-Host "Certificate is available and has private key"
                    break
                }
            }
            Start-Sleep -Seconds 2
        }

        if ($ready -and $withPrivateKey) {
            $authSuccess = $true
            Write-Host "SUCCESS: Authentication verified - certificate with private key is available"
            break
        }

        # 认证失败，准备重试
        if (-not $ready) {
            Write-Host "WARNING: Target certificate was not found after attempt $attempt"
        } elseif (-not $withPrivateKey) {
            Write-Host "WARNING: Target certificate found but no private key available after attempt $attempt"
        }
    } else {
        # 没有指定证书 SHA1，无法验证，假设成功
        $authSuccess = $true
        break
    }

    # 如果不是最后一次尝试，等待后重试
    if ($attempt -lt $maxAttempts) {
        Write-Host "Authentication attempt $attempt failed, will retry in 5 seconds..."
        # 终止当前 SimplySign Desktop 进程
        $stillRunning = Get-Process -Id $proc.Id -ErrorAction SilentlyContinue
        if ($stillRunning) {
            Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue
        }
        Start-Sleep -Seconds 5
    }
}

if (-not $authSuccess) {
    Write-Host ""
    Write-Host "ERROR: Authentication failed after $maxAttempts attempts"
    Write-Host "All TOTP injection attempts were unsuccessful"
    exit 1
}

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
