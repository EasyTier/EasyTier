::BATCH_START
@ECHO off
SETLOCAL EnableDelayedExpansion
TITLE Initializing Script...
CD /d %~dp0
<NUL SET /p="Checking PowerShell ... "
WHERE /q PowerShell 
IF !ERRORLEVEL! NEQ 0 (
    ECHO PowerShell is not installed. & PAUSE & EXIT
)
ECHO OK
<NUL SET /p="Checking PowerShell version ... "
PowerShell -Command "if ($PSVersionTable.PSVersion.Major -lt 3) { exit 1 }"
IF !ERRORLEVEL! NEQ 0 (
    ECHO Requires PowerShell 3 or later. & PAUSE & EXIT
)
ECHO OK
<NUL SET /p="Checking execute permissions ... "
PowerShell -Command "if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { exit 1 }"
IF !ERRORLEVEL! NEQ 0 (
    ECHO Fail
    ECHO Restart with administrator privileges ... 
    SET args=%*
    IF DEFINED args (
        SET args=!args:'=''!
        SET args=!args:"=\"!
    )
    PowerShell -NoProfile -Command "Start-Process 'cmd.exe' -Verb RunAs -WorkingDirectory '%~dp0' -ArgumentList '/d /s /k \"\"%~f0\" !args!\"'"
    EXIT
)
ECHO OK
<NUL SET /p="Extract embedded script ... "
PowerShell -Command "$content = (Get-Content -Path '%~f0' -Encoding UTF8 | Out-String) -replace '(?s)' + [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('OjpCQVRDSF9TVEFSVA==')) + '.*?' + [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('OjpCQVRDSF9FTkQ=')); Set-Content -Path '%~f0.ps1' -Value $content -Encoding UTF8"
IF !ERRORLEVEL! NEQ 0 (
    ECHO Embedded script section not found. & PAUSE & EXIT
)
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
    [Alias("H", "?")]
    [switch]$Help,

    [Parameter(Mandatory = $false)]
    [Alias("UP")]
    [switch]$Update,

    [Parameter(Mandatory = $false)]
    [Alias("UN")]
    [switch]$Uninstall,

    [Parameter(Mandatory = $false)]
    [Alias("CT", "ConfType")]
    [string]$ConfigType,

    [Parameter(Mandatory = $false)]
    [Alias("SN", "SvcName")]
    [string]$ServiceName = "EasyTierService",

    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$ServiceArgs
)
$culture = [System.Globalization.CultureInfo]::CurrentCulture
[System.Threading.Thread]::CurrentThread.CurrentCulture = $culture
[System.Threading.Thread]::CurrentThread.CurrentUICulture = $culture
function Show-Pause {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [string]$Text = "请按任意键继续...",
        [Parameter(Mandatory = $false)]
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
function Get-InputWithNoNullOrWhiteSpace {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, Position = 0)]
        [ValidateNotNullOrEmpty()]
        [string]$Prompt
    )
    while ($true) {
        try {
            $response = Read-Host "请输入${Prompt}(必填)"
            if ([string]::IsNullOrWhiteSpace($response)) {
                Write-Host "${Prompt}不能为空！" -ForegroundColor Red
                continue
            }
            return $response.Trim()
        }
        catch {
            Write-Error "读取输入时出错: $_"
            continue
        }
    }
}
function Get-InputWithFileValidation {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, Position = 0)]
        [ValidateNotNullOrEmpty()]
        [string]$Prompt
    )
    while ($true) {
        try {         
            $filePath = (Get-InputWithNoNullOrWhiteSpace -Prompt $Prompt).Trim()  
            if (-not (Test-Path $filePath)) {
                Write-Host "文件不存在: $filePath" -ForegroundColor Red
                continue
            }
            return $filePath
        }
        catch {
            Write-Error "读取输入时出错: $_"
            continue
        }
    }
}
function Get-InputWithDefault {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, Position = 0)]
        [ValidateNotNullOrEmpty()]
        [string]$Prompt,
        [Parameter(Mandatory = $true, Position = 1)]
        [string]$DefaultValue
    )
    try {
        $response = Read-Host "${Prompt}(默认: ${DefaultValue})"
        if ([string]::IsNullOrWhiteSpace($response)) {
            return $DefaultValue
        }
        if ($response -match '^(?!").*(?<!")(?=.*\s).*$') {
            $response = "`"$response`""
        }
        return $response.Trim()
    }
    catch {
        Write-Error "读取输入时出错: $_"
        return $DefaultValue
    }
}
function Save-ServiceName {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$FilePath,

        [Parameter(Mandatory = $true)]
        [string]$ServiceName
    )
    if (-not (Test-ServiceNameExists -FilePath $FilePath -ServiceName $ServiceName)) {
        $uniqueLines = Get-Content -Path $FilePath | Sort-Object -Unique
        $uniqueLines += $ServiceName
        Set-Content -Path $FilePath -Value ($uniqueLines -join [Environment]::NewLine) -Encoding UTF8
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
        Set-Content -Path $FilePath -Value ($uniqueLines -join [Environment]::NewLine) -Encoding UTF8
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
        Set-Content $FilePath -Value "" -Encoding UTF8
        return $false
    }
    $uniqueLines = Get-Content -Path $FilePath | Sort-Object -Unique
    return $uniqueLines -contains $ServiceName
}
$HelpText = @"
EasyTier 安装脚本使用说明
=========================

【基本用法】
-------------
直接 双击运行 或 在命令行中执行：

    Install.cmd [参数]

脚本会自动调用嵌入的 PowerShell 脚本进行安装配置。

【可用参数】
-------------
    -H / -? / -Help
        显示此帮助信息并退出。

    -UP / -Update
        更新EasyTier

    -UN / -Uninstall
        卸载EasyTier服务

    -CT / -ConfType / -ConfigType <类型>
        指定配置模式，可选值：
        * File   本地配置文件
        * Remote 远程服务器集中管理
        * CLI    使用命令行直接传参

    -SN / -SvcName / -ServiceName <名称>
        指定安装的服务名称
        默认: EasyTierService

    <其他参数...>
        当选择 CLI 模式时，用于传递自定义参数，例如：
        Install.cmd -CT CLI -w udp://x.x.x.x:22020/admin

【运行要求】
-------------
    * 已安装 PowerShell 3.0 或更高版本。
    * 管理员权限(自动检测并可请求提升)。

【配置模式说明】
-----------------
    1. File 模式：
        从指定的本地配置文件加载运行参数。
        脚本会提示输入配置文件路径(可拖入文件)。

    2. Remote 模式：
        从服务器集中管理配置，可输入自定义管理服务器地址
        (例如: udp://x.x.x.x:22020/admin)。

    3. CLI 模式：
        直接通过命令行参数传递任意配置。

【示例】
-------------
    1. 使用本地配置文件安装：
        Install.cmd -CT File

    2. 使用远程服务器并设定服务名称：
        Install.cmd -CT Remote -SN EasyTierService

    3. 使用命令行传参：
        Install.cmd -CT CLI --ipv4 x.x.x.x --network-name xxx --network-secret yyy --peers tcp://peer_host:11010

    4. 卸载服务：
        Install.cmd -U
"@
$WatchDogTemplate = @"
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Date>$((Get-Date).ToString("s"))</Date>
    <URI>\EasyTierWatchDog</URI>
  </RegistrationInfo>
  <Triggers>
    <EventTrigger>
      <Enabled>true</Enabled>
      <Subscription>&lt;QueryList&gt;&lt;Query Id="0" Path="System"&gt;&lt;Select Path="System"&gt;*[System[Provider[@Name='Microsoft-Windows-Kernel-Power'] and EventID=107]]&lt;/Select&gt;&lt;/Query&gt;&lt;/QueryList&gt;</Subscription>
    </EventTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <UserId>SYSTEM</UserId>
      <RunLevel>HighestAvailable</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <AllowHardTerminate>true</AllowHardTerminate>
    <StartWhenAvailable>true</StartWhenAvailable>
    <Enabled>true</Enabled>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>cmd.exe</Command>
      <Arguments>/c "net stop $ServiceName &amp;&amp; net start $ServiceName"</Arguments>
    </Exec>
  </Actions>
</Task>
"@
function Get-SystemArchitecture {
    if ($PSVersionTable.PSEdition -eq 'Core') {
        $platform = [System.Environment]::OSVersion.Platform
        if ($platform -eq 'Unix') {
            if (uname -s 2>$null | Select-String -Pattern 'Darwin') {
                $os = 'macos'
            }
            else {
                $os = 'linux'
            }
        }
        else {
            $os = 'windows'
        }
    }
    else {
        $os = 'windows'
    }
    if ($os -eq 'windows') {
        if ($env:PROCESSOR_ARCHITEW6432) { $arch = $env:PROCESSOR_ARCHITEW6432 } else { $arch = $env:PROCESSOR_ARCHITECTURE }
        switch ($arch) {
            "AMD64" { return "$os-x86_64" }
            "ARM64" { return "$os-arm64" }
            "x86"   { return "$os-i686" }
            default { throw "Unsupported architecture: $os-$arch" }
        }
    }
    else {
        throw "Unsupported architecture: $os";
    }
}
function Get-LocalVersion {
    param([string]$CorePath)

    if (-not (Test-Path $CorePath)) {
        Write-Host "未检测到 core 二进制文件: $CorePath" -ForegroundColor Red
        return $null
    }

    try {
        $versionOutput = & $CorePath --version 2>$null
        if ($versionOutput -match "easytier-core\s+([0-9]+\.[0-9]+\.[0-9]+)") {
            return $matches[1]
        }
    }
    catch {
        Write-Host "执行 $CorePath --version 获取版本失败。" -ForegroundColor Yellow
    }

    return $null
}
function Get-RemoteVersion {
    param([PSCustomObject]$response)
    try {
        return $response.tag_name.TrimStart("v")
    }
    catch {
        Write-Host "无法从 GitHub 获取最新版本信息。" -ForegroundColor Red
        return $null
    }
}
function Get-EasyTier {
    $tempDirectory = New-Item -ItemType Directory -Path ([System.IO.Path]::GetTempPath()) -Name "easytier_update_$([System.Guid]::NewGuid())"
    try {
        $Arch = Get-SystemArchitecture
        Write-Host "检测系统架构: $Arch"
        $localVersion = Get-LocalVersion($EasyTierPath)
        Write-Host "检查最新版本..." -ForegroundColor Green
        try {
            $response = Invoke-RestMethod -Uri "https://api.github.com/repos/EasyTier/EasyTier/releases/latest" -UseBasicParsing
            $latestVersion = Get-RemoteVersion($response)
        }
        catch {
            throw "获取最新版本失败。请检查网络连接。"
        }
        $vLocal = [System.Version]$localVersion
        $vRemote = [System.Version]$latestVersion
        Write-Host "本地版本: $vLocal"
        Write-Host "最新版本: $vRemote"
        if ($vLocal -ge $vRemote) {
            Write-Host "EasyTier 已是最新版本 ($localVersion)。无需更新。" -ForegroundColor Green
            return
        }
        $asset = $response.assets | Where-Object { $_.name -like "easytier-$Arch*.zip" } | Select-Object -First 1
        if ($asset) {
            $downloadUrl = $asset.browser_download_url
            Write-Output "找到更新，下载链接：$downloadUrl"
        }
        else {
            throw "未适配当前平台"
        }
       
        $updateFile = Join-Path $tempDirectory $asset.name
        $updateDirectory = Join-Path $tempDirectory "easytier-$Arch"
        try {
            Invoke-WebRequest -Uri $downloadUrl -OutFile $updateFile
        }
        catch {
            throw "下载失败!"
        }
        Expand-Archive -Path $updateFile -DestinationPath $tempDirectory -Force
        Write-Host "准备就绪，开始更新..." -ForegroundColor Green
        $activeServices = Get-Service -Name $ServiceName | Where-Object { $_.Status -eq "Running" }
        if ($activeServices) {
            Write-Host "`n发现正在运行的服务: $($ServiceName)`n" -ForegroundColor Yellow
            Write-Host "停止 EasyTier 服务..." -ForegroundColor Yellow
            $activeServices | Stop-Service -Force
        }
        Write-Host "更新文件..."
        Copy-Item -Path $updateDirectory -Destination $ScriptRoot -Recurse -Force
        try {
            if ($activeServices) {
                Write-Host "启动服务..." -ForegroundColor Green
                $activeServices | Start-Service
            }
        }
        catch {
            throw "服务启动失败!"
        }
        Write-Host "EasyTier 已成功更新到版本 $latestVersion" -ForegroundColor Green
    }
    finally {
        Remove-Item -Recurse -Force $tempDirectory
    }
}

$host.ui.rawui.WindowTitle = "安装/卸载/更新 EasyTier 服务"
Clear-Host
$ScriptRoot = (Get-Location).Path
$EasyTierPath = Join-Path $ScriptRoot "easytier-core.exe"
$ServicesPath = Join-Path $ScriptRoot "services"
$OPTIONS = @()
$ErrorActionPreference = "Stop"
try {
    if ($Help) {
        Write-Host $HelpText
        Show-Pause -Text "按任意键退出..."
        exit 0
    }
    if ($Uninstall) {
        if (-not (Test-ServiceNameExists -FilePath $ServicesPath -ServiceName $ServiceName)) {
            Write-Host "服务未安装" -ForegroundColor Red
            if (Show-YesNoPrompt -Message "是否强制卸载？" -DefaultIndex 1) {
                Write-Host "正在停止服务 $service ..."
                Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue | Out-Null
                Write-Host "正在移除服务 $service ..."
                sc.exe delete "$ServiceName" >$null 2>&1
                Remove-ServiceName -FilePath $ServicesPath -ServiceName $service
                Write-Host "服务 $service 已卸载" -ForegroundColor Green
            }
        }
        else {
            $services = Get-Content $ServicesPath | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
            if (-not $services) {
                $services = @($ServiceName)
            }
            foreach ($service in $services) {
                if (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue) {
                    Write-Host "正在停止服务 $service ..."
                    Stop-Service -Name $ServiceName -Force -ErrorAction Stop | Out-Null
                    Write-Host "正在移除服务 $service ..."
                    sc.exe delete "$ServiceName" >$null 2>&1
                    Remove-ServiceName -FilePath $ServicesPath -ServiceName $service
                }
                Write-Host "服务 $service 已卸载" -ForegroundColor Green
            }
        }
        Show-Pause -Text "按任意键退出..."
        Unregister-ScheduledTask -TaskName "EasyTierWatchDog" -Confirm:$false -ErrorAction SilentlyContinue | Out-Null
        exit 0
    }
    if ($Update) {
        Get-EasyTier
        Show-Pause -Text "按任意键退出..."
        exit 0
    }
    if (-not (Test-Path $EasyTierPath)) {
        Get-EasyTier
    }
    if (-not $ConfigType) {
        $choices = @(
            [System.Management.Automation.Host.ChoiceDescription]::new("&File", "本地配置文件"),
            [System.Management.Automation.Host.ChoiceDescription]::new("&Remote", "服务器集中管理"),
            [System.Management.Automation.Host.ChoiceDescription]::new("&CLI", "命令行传参")
        )
        $selected = $Host.UI.PromptForChoice("您准备如何配置EasyTier?", "请选择：", $choices, 0)
        $ConfigType = @("File", "Remote", "CLI")[$selected]
    }
    switch ($ConfigType) {
        "File" {
            $OPTIONS += "--config-file $(Get-InputWithFileValidation -Prompt "配置文件路径(或将文件拖动到此处)")"
        }
        "Remote" {
            if (Show-YesNoPrompt -Message "是否使用自定义管理服务器？" -DefaultIndex 1) {
                $configServer = Get-InputWithNoNullOrWhiteSpace -Prompt "自定义管理服务器(格式：协议://IP:端口/用户)" 
            }
            else {
                $configServer = Get-InputWithNoNullOrWhiteSpace -Prompt "官方服务器用户名"
            }
            $OPTIONS += "--config-server $configServer"
        } 
        "CLI" {
            if (-not $ServiceArgs -or $ServiceArgs.Count -eq 0) {
                $OPTIONS += Get-InputWithNoNullOrWhiteSpace -Prompt "自定义启动参数" 
            }
            else {
                $OPTIONS += $ServiceArgs
            }
        }
        default {
            throw "未知配置类型：$ConfigType"
        }
    }
    $BinaryPath = "`"$EasyTierPath`" $($OPTIONS -join ' ')" 
    Write-Host "`n生成的配置参数如下：" -ForegroundColor Yellow
    Write-Host ($OPTIONS -join " ") -ForegroundColor DarkGray
    if (Show-YesNoPrompt -Message "确认安装配置？" -DefaultIndex 1) {
        if (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue) {
            Stop-Service -Name $ServiceName -Force -ErrorAction Stop | Out-Null
            sc.exe delete "$ServiceName" >$null 2>&1
        }
        New-Service -Name $ServiceName -DisplayName "EasyTier" `
            -Description "EasyTier 核心服务" `
            -StartupType Automatic `
            -BinaryPathName $BinaryPath `
            -ErrorAction Stop | Out-Null
        Start-Service -Name $ServiceName -ErrorAction Stop | Out-Null

        Register-ScheduledTask -TaskName "EasyTierWatchDog" -User "SYSTEM" -Xml $WatchDogTemplate -Force -ErrorAction Stop | Out-Null
        Save-ServiceName -FilePath $ServicesPath -ServiceName $ServiceName
        Clear-Host
        Write-Host "安装完成。" -ForegroundColor Green
    }
    else {
        Write-Host "安装已取消。" -ForegroundColor Yellow
    }
    Show-Pause -Text "按任意键退出..."
}
catch {
    Write-Host "`n发生错误: $_" -ForegroundColor Red
    Show-Pause -Text "按任意键退出..."
    Unregister-ScheduledTask -TaskName "EasyTierWatchDog" -Confirm:$false -ErrorAction SilentlyContinue
    exit 1
}
