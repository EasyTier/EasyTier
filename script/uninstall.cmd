::BATCH_START
@ECHO off
SETLOCAL EnableDelayedExpansion
TITLE Initializing Script...
CD /d %~dp0   
SET ScriptPath=\^"%~f0\^"
SET ScriptRoot=%~dp0
SET ScriptRoot=\^"!ScriptRoot:~0,-1!\^"
SET Args=%*
IF DEFINED Args (SET Args=!Args:"=\"!)
<NUL SET /p="Checking PowerShell ... "
WHERE /q PowerShell 
IF !ERRORLEVEL! NEQ 0 (ECHO PowerShell is not installed. & PAUSE & EXIT)
PowerShell -Command "if ($PSVersionTable.PSVersion.Major -lt 3) { exit 1 }"
IF !ERRORLEVEL! NEQ 0 (ECHO Requires PowerShell 3 or later. & PAUSE & EXIT)
ECHO OK
<NUL SET /p="Checking execute permissions ... "
PowerShell -Command "if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { exit 1 }"
IF !ERRORLEVEL! NEQ 0 (CLS & ECHO Restart with administrator privileges ... & PowerShell -Command "Start-Process cmd.exe -Verb RunAs -ArgumentList '/k CD /d !ScriptRoot! && !ScriptPath! !Args!'" & EXIT)
ECHO OK
<NUL SET /p="Extract embedded script ... "
PowerShell -Command "$content = (Get-Content -Path '%~f0' -Encoding UTF8 | Out-String) -replace '(?s)' + [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('OjpCQVRDSF9TVEFSVA==')) + '.*?' + [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('OjpCQVRDSF9FTkQ=')); Set-Content -Path '%~f0.ps1' -Value $content.Trim() -Encoding UTF8"
IF !ERRORLEVEL! NEQ 0 (ECHO Embedded script section not found. & PAUSE & EXIT)
ECHO OK
<NUL SET /p="Execute script ... "
PowerShell -NoProfile -ExecutionPolicy Bypass -File "%~f0.ps1" %*
ECHO OK
<NUL SET /p="Delete script ... "
DEL /f /q "%~f0.ps1"
ECHO OK
EXIT
::BATCH_END
param(
    [Parameter(Mandatory = $false)]
    [string]$ServiceName = "EasyTierService",
    [Parameter(Mandatory = $false)]
    [ValidateSet("all")]
    [string]$Action,
    [Parameter(Mandatory = $false)]
    [switch]$Force
)
[System.Threading.Thread]::CurrentThread.CurrentCulture = [System.Globalization.CultureInfo]::GetCultureInfo("zh-CN")
[System.Threading.Thread]::CurrentThread.CurrentUICulture = [System.Globalization.CultureInfo]::GetCultureInfo("zh-CN")
function Show-Pause {
    [CmdletBinding()]
    param(
        [Parameter(Position = 0)]
        [string]$Text = "按任意键继续...",
        [string]$Color = "Cyan"
    )
    Write-Host "$Text" -ForegroundColor $Color
    [System.Console]::ReadKey($true) > $null
}
function Show-YesNoPrompt {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, Position = 0)]
        [ValidateNotNullOrEmpty()]
        [string]$Message,
        [string]$Title = "",
        [ValidateRange(0, 1)]
        [int]$DefaultIndex = 0,
        [string[]]$Labels = @("&Yes", "&No"),
        [string[]]$Helps = @("是", "否")
    )
    
    if ($Labels.Count -ne $Helps.Count) {
        throw "Labels 和 Helps 的数量必须相同。"
    }
    
    $choices = for ($i = 0; $i -lt $Labels.Count; $i++) {
        [System.Management.Automation.Host.ChoiceDescription]::new($Labels[$i], $Helps[$i])
    }
    
    try {
        return $Host.UI.PromptForChoice($Title, $Message, $choices, $DefaultIndex) -eq 0
    }
    catch {
        Write-Error "显示选择提示时出错: $_"
        return $false
    }
}
function Remove-ServiceName {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$FilePath,

        [Parameter(Mandatory = $true)]
        [string]$ServiceName
    )
    if (Test-ServiceNameExists -FilePath $FilePath -ServiceName $ServiceName) {
        $uniqueLines = Get-Content -Path $FilePath | Where-Object { $_ -ne $ServiceName } | Sort-Object -Unique
        Set-Content -Path $FilePath -Value ($uniqueLines -join [Environment]::NewLine) -Encoding UTF8 -Force
    }
}
function Test-ServiceNameExists {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$FilePath,

        [Parameter(Mandatory = $true)]
        [string]$ServiceName
    )

    if (-Not (Test-Path $FilePath)) {
        Set-Content -Path $FilePath -Value "" -Encoding UTF8 -Force
        return $false
    }
    $uniqueLines = Get-Content -Path $FilePath | Sort-Object -Unique
    return $uniqueLines -contains $ServiceName
}

$host.ui.rawui.WindowTitle = "卸载EasyTier服务"
Clear-Host
$ScriptRoot = (Get-Location).Path
$ServicesPath = Join-Path $ScriptRoot "services"

# 必要文件检查
$RequiredFiles = @("nssm.exe")
foreach ($file in $RequiredFiles) {
    if (-not (Test-Path (Join-Path $ScriptRoot $file))) {
        Write-Host "缺少必要文件: $file" -ForegroundColor Red
        Show-Pause -Text "按任意键退出..."
        exit 1
    }
}
if (-not (Test-ServiceNameExists -FilePath $ServicesPath -ServiceName $ServiceName)) {
    Write-Host "服务未安装" -ForegroundColor Red
    if (Show-YesNoPrompt -Message "是否强制卸载？" -DefaultIndex 1) {
        $Force = $true
        $Action = "all"
    }
    else {
        Show-Pause -Text "按任意键退出..."    
        exit 1
    }
}

# 参数处理
if ($Action -eq "all") {
    if (-not $Force) {
        if (-not (Show-YesNoPrompt -Message "确定要完全卸载所有服务吗？" -DefaultIndex 1)) {
            Write-Host "已取消卸载操作" -ForegroundColor Yellow
            Show-Pause -Text "按任意键退出..."
            exit 0
        }
    }
    Write-Host "`n正在卸载所有服务..." -ForegroundColor Cyan
    
    # 读取所有服务名
    $services = Get-Content $ServicesPath | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
    if (-not $services) {
        $services = @($ServiceName)
    }
}
else {
    $services = @($ServiceName)
}

# 服务卸载部分
try {
    $nssm = Join-Path $ScriptRoot "nssm.exe"
    
    foreach ($service in $services) {
        # 停止服务
        Write-Host "正在停止服务 $service ..."
        & $nssm stop $service

        # 删除服务（自动确认）
        Write-Host "正在移除服务 $service ..."
        & $nssm remove $service confirm

        Remove-ServiceName -FilePath $ServicesPath -ServiceName $service
        Write-Host "服务 $service 已卸载" -ForegroundColor Green
    }

    # 如果是完全卸载，删除服务记录文件
    if ($Action -eq "all") {
        Remove-Item $ServicesPath -Force
        Write-Host "`n已删除服务列表文件" -ForegroundColor Green
    }
}
catch {
    Write-Host "`n卸载过程中发生错误: $_" -ForegroundColor Red
    Show-Pause -Text "按任意键退出..."
    exit 1
}

Show-Pause -Text "按任意键退出..."
exit
