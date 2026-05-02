param(
    [switch]$DebugMode = $false,
    [switch]$VerifyOnly = $false
)

# SimplySign Desktop Registry Configuration Script
# Pre-configures optimal registry settings for automated login dialog display

Write-Host "=== SimplySign Desktop Registry Configuration ==="

if ($DebugMode) {
    Write-Host "Debug mode enabled - verbose logging active"
}

# Registry path for SimplySign Desktop settings
$RegistryPath = "HKCU:\Software\Certum\SimplySign"

# Optimal configuration values for automation
$OptimalSettings = @{
    "ShowLoginDialogOnStart" = 1
    "ShowLoginDialogOnAppRequest" = 1
    "RememberLastUserName" = 1
    "Autostart" = 0
    "UnregisterCertificatesOnDisconnect" = 0
    "RememberPINinCSP" = 1
    "ForgetPINinCSPonDisconnect" = 1
    "LangID" = 9
}

# Function to check if registry path exists
function Test-RegistryPath {
    param([string]$Path)
    
    try {
        $null = Get-Item -Path $Path -ErrorAction Stop
        return $true
    } catch {
        return $false
    }
}

# Function to get current registry value
function Get-RegistryValue {
    param(
        [string]$Path,
        [string]$Name
    )
    
    try {
        $value = Get-ItemProperty -Path $Path -Name $Name -ErrorAction Stop
        return $value.$Name
    } catch {
        return $null
    }
}

# Function to set registry value safely
function Set-RegistryValue {
    param(
        [string]$Path,
        [string]$Name,
        [int]$Value
    )
    
    try {
        Set-ItemProperty -Path $Path -Name $Name -Value $Value -Type DWord -ErrorAction Stop
        if ($DebugMode) {
            Write-Host "  Set $Name = $Value"
        }
        return $true
    } catch {
        Write-Host "  ERROR: Failed to set $Name = $Value - $($_.Exception.Message)"
        return $false
    }
}

# Function to display current settings
function Show-CurrentSettings {
    Write-Host "Current SimplySign Desktop registry settings:"
    Write-Host "============================================="
    
    if (-not (Test-RegistryPath $RegistryPath)) {
        Write-Host "Registry path does not exist: $RegistryPath"
        return
    }
    
    foreach ($setting in $OptimalSettings.Keys) {
        $currentValue = Get-RegistryValue -Path $RegistryPath -Name $setting
        if ($null -eq $currentValue) {
            Write-Host "  $setting : NOT SET"
        } else {
            Write-Host "  $setting : $currentValue"
        }
    }
    Write-Host ""
}

# Function to create registry structure
function Initialize-RegistryStructure {
    Write-Host "Initializing registry structure..."
    
    # Create parent keys if they don't exist
    $ParentPaths = @(
        "HKCU:\Software\Certum",
        $RegistryPath
    )
    
    $allCreated = $true
    foreach ($path in $ParentPaths) {
        if (-not (Test-RegistryPath $path)) {
            try {
                New-Item -Path $path -Force -ErrorAction Stop | Out-Null
                if ($DebugMode) {
                    Write-Host "  Created registry path: $path"
                }
            } catch {
                Write-Host "  ERROR: Failed to create registry path: $path - $($_.Exception.Message)"
                $allCreated = $false
            }
        } else {
            if ($DebugMode) {
                Write-Host "  Registry path exists: $path"
            }
        }
    }
    
    return $allCreated
}

# Function to apply optimal configuration
function Set-OptimalConfiguration {
    Write-Host "Applying optimal configuration for automation..."
    
    $successCount = 0
    $totalSettings = $OptimalSettings.Count
    
    foreach ($setting in $OptimalSettings.Keys) {
        $value = $OptimalSettings[$setting]
        if (Set-RegistryValue -Path $RegistryPath -Name $setting -Value $value) {
            $successCount++
        }
    }
    
    Write-Host "Applied $successCount of $totalSettings settings successfully"
    return ($successCount -eq $totalSettings)
}

# Function to verify configuration
function Test-Configuration {
    Write-Host "Verifying configuration..."
    
    $verificationResults = @{}
    $allCorrect = $true
    
    foreach ($setting in $OptimalSettings.Keys) {
        $expectedValue = $OptimalSettings[$setting]
        $actualValue = Get-RegistryValue -Path $RegistryPath -Name $setting
        
        $isCorrect = ($actualValue -eq $expectedValue)
        $verificationResults[$setting] = @{
            Expected = $expectedValue
            Actual = $actualValue
            Correct = $isCorrect
        }
        
        if (-not $isCorrect) {
            $allCorrect = $false
        }
        
        if ($DebugMode -or -not $isCorrect) {
            $status = if ($isCorrect) { "OK" } else { "MISMATCH" }
            Write-Host "  $setting : Expected=$expectedValue, Actual=$actualValue [$status]"
        }
    }
    
    return $verificationResults, $allCorrect
}

# Main execution
try {
    Write-Host "Starting registry configuration process..."
    Write-Host ""
    
    # Show current state
    Write-Host "BEFORE CONFIGURATION:"
    Show-CurrentSettings
    
    if ($VerifyOnly) {
        Write-Host "Verification-only mode - no changes will be made"
        $verificationResults, $allCorrect = Test-Configuration
        
        if ($allCorrect) {
            Write-Host "SUCCESS: All settings are correctly configured"
            exit 0
        } else {
            Write-Host "CONFIGURATION NEEDED: Some settings require adjustment"
            exit 1
        }
    }
    
    # Initialize registry structure
    if (-not (Initialize-RegistryStructure)) {
        Write-Host "FATAL ERROR: Failed to initialize registry structure"
        exit 1
    }
    
    # Apply optimal configuration
    if (-not (Set-OptimalConfiguration)) {
        Write-Host "ERROR: Failed to apply complete configuration"
        exit 1
    }
    
    Write-Host ""
    Write-Host "AFTER CONFIGURATION:"
    Show-CurrentSettings
    
    # Verify the configuration was applied correctly
    $verificationResults, $allCorrect = Test-Configuration
    
    if ($allCorrect) {
        Write-Host "SUCCESS: Registry configuration completed successfully"
        Write-Host ""
        Write-Host "Key automation settings enabled:"
        Write-Host "  ShowLoginDialogOnStart = 1 (Login dialog will appear automatically)"
        Write-Host "  ShowLoginDialogOnAppRequest = 1 (Dialog appears when apps request access)"
        Write-Host "  RememberLastUserName = 1 (Username persistence for efficiency)"
        Write-Host ""
        Write-Host "Next steps:"
        Write-Host "1. Launch SimplySign Desktop"
        Write-Host "2. Login dialog should appear automatically"
        Write-Host "3. Complete authentication process"
        
        # Create a status file for the workflow to check
        "REGISTRY_CONFIGURATION_SUCCESS" | Out-File -FilePath "registry_config_status.log" -Encoding UTF8
        
        exit 0
    } else {
        Write-Host "ERROR: Configuration verification failed"
        Write-Host "Some settings were not applied correctly"
        
        "REGISTRY_CONFIGURATION_PARTIAL" | Out-File -FilePath "registry_config_status.log" -Encoding UTF8
        
        exit 1
    }
    
} catch {
    Write-Host "FATAL ERROR: Registry configuration failed - $($_.Exception.Message)"
    
    "REGISTRY_CONFIGURATION_FAILED" | Out-File -FilePath "registry_config_status.log" -Encoding UTF8
    
    exit 1
}
