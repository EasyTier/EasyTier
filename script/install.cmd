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
    [Alias("h", "?")]
    [switch]$Help,

    [Parameter(Mandatory = $false)]
    [Alias("u")]
    [switch]$Update,

    [Parameter(Mandatory = $false)]
    [Alias("x")]
    [switch]$Uninstall,
    
    [Parameter(Mandatory = $false)]
    [Alias("ughp")]
    [switch]$UseGitHubProxy = $false,

    [Parameter(Mandatory = $false)]
    [Alias("ghp")]
    [string]$GitHubProxy = "https://ghfast.top/",

    [Parameter(Mandatory = $false)]
    [Alias("up")]
    [switch]$UseProxy = $false,

    [Parameter(Mandatory = $false)]
    [Alias("p")]
    [string]$Proxy = "http://127.0.0.1:7890",

    [Parameter(Mandatory = $false)]
    [Alias("c")]
    [string]$ConfigType,

    [Parameter(Mandatory = $false)]
    [Alias("n")]
    [string]$ServiceName = "EasyTierService",

    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$ServiceArgs
)

try {
    $culture = [System.Globalization.CultureInfo]::CurrentCulture
    [System.Threading.Thread]::CurrentThread.CurrentCulture = $culture
    [System.Threading.Thread]::CurrentThread.CurrentUICulture = $culture
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
}
catch {
    throw "环境初始化未成功，若运行正常请无视此消息`n$_"
}
function Invoke-WebRequestCompatible {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Uri,
        [Parameter(Mandatory = $false)]
        [string]$OutFile
    )

    if ($PSVersionTable.PSVersion.Major -lt 5) {
        try {
            $client = New-Object System.Net.WebClient
            if ($UseProxy) {
                $client.Proxy = New-Object System.Net.WebProxy($Proxy)
            }
            if ($OutFile) {
                $client.DownloadFile($Uri, $OutFile)
                return $null
            }
            else {
                $response = $client.DownloadString($Uri)
                return $response
            }
        }
        catch {
            throw "[兼容模式]Invoke-WebRequest`n$_"
        }
    }
    else {
        $params = @{
            Uri             = $Uri
            UseBasicParsing = $true
        }
        if ($UseProxy) {
            $params.Proxy = $Proxy
        }
        if ($OutFile) {
            $params.OutFile = $OutFile
            Invoke-WebRequest @params
        }
        else {
            Invoke-WebRequest @params
        }
    }
}
function Invoke-RestMethodCompatible {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Uri
    )

    if ($PSVersionTable.PSVersion.Major -lt 5) {
        $rawJson = Invoke-WebRequestCompatible -Uri $Uri
        try {
            return $rawJson | ConvertFrom-Json
        }
        catch {
            throw "[兼容模式]Invoke-RestMethod`n$_"
        }
    }
    else {
        $params = @{
            Uri             = $Uri
            UseBasicParsing = $true
        }
        if ($UseProxy) {
            $params.Proxy = $Proxy
        }
        return Invoke-RestMethod @params
    }
}
function Expand-ZipFile {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ZipPath,
        [Parameter(Mandatory = $true)]
        [string]$DestinationPath
    )

    if ($PSVersionTable.PSVersion.Major -lt 5) {
        try {
            Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction SilentlyContinue
            [System.IO.Compression.ZipFile]::ExtractToDirectory($ZipPath, $DestinationPath)
        }
        catch {
            throw "[兼容模式]Expand-Archive`n$_"
        }
    }
    else {
        Expand-Archive -Path $ZipPath -DestinationPath $DestinationPath -Force
    }
}
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
                Write-Host "${Prompt}不能为空!" -ForegroundColor Red
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
function Initialize-RegistryEntryExists {
    if (-not (Test-Path $RegistryPath)) {
        New-Item -Path $RegistryPath -Force | Out-Null
    }
    try {
        $null = Get-ItemProperty -Path $RegistryPath -Name $RegistryName -ErrorAction Stop
    }
    catch {
        New-ItemProperty -Path $RegistryPath -Name $RegistryName -Value @() -PropertyType MultiString -Force | Out-Null
    }
}
function Get-ServiceNames {
    Initialize-RegistryEntryExists
    try {
        $value = (Get-ItemProperty -Path $RegistryPath -Name $RegistryName).$RegistryName
    }
    catch {
        return @()
    }
    if ($null -eq $value -or $value.Count -eq 0) {
        return @()
    }
    return $value
}
function Save-ServiceName {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$Name
    )
    $existing = Get-ServiceNames
    if ($existing -notcontains $Name) {
        $existing += $Name
        Set-ItemProperty -Path $RegistryPath -Name $RegistryName -Value $existing -Force
    }
}
function Remove-ServiceName {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$Name
    )
    $existing = Get-ServiceNames
    if ($existing -contains $Name) {
        $updated = $existing | Where-Object { $_ -ne $Name }
        Set-ItemProperty -Path $RegistryPath -Name $RegistryName -Value $updated -Force
    }
}
function Test-ServiceNameExists {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$Name
    )
    $existing = Get-ServiceNames
    return $existing -contains $Name
}
function Remove-ServiceCompatible {
    param (
        [Parameter(Mandatory = $true)]
        [string]$Name
    )
    if (Get-Command -Name Remove-Service -ErrorAction SilentlyContinue) {
        Remove-Service -Name $Name -Force
    }
    else {
        sc.exe delete "$Name" > $null 2>&1
    }
}
function Get-SystemArchitecture {
    try {
        $platform = [System.Environment]::OSVersion.Platform
        if ($platform -ne [System.PlatformID]::Win32NT) {
            throw "Unsupported OS: Non-Windows platform detected ($platform)"
        }
    }
    catch {
        throw "Unsupported OS: Unable to determine platform."
    }
    if ($env:PROCESSOR_ARCHITEW6432) {
        $arch = $env:PROCESSOR_ARCHITEW6432
    }
    else {
        $arch = $env:PROCESSOR_ARCHITECTURE
    }
    switch ($arch) {
        "AMD64" { return "windows-x86_64" }
        "ARM64" { return "windows-arm64" }
        "x86" { return "windows-i686" }
        default { throw "Unsupported architecture: windows-$arch" }
    }
}
function Get-LocalVersion {
    param([string]$CorePath)
    if (-not (Test-Path $CorePath)) {
        Write-Host "未找到本地程序!" -ForegroundColor Yellow
        return [System.Version]"0.0.0"
    }
    try {
        $versionOutput = & $CorePath --version 2>$null
        if ($versionOutput -match "easytier-core\s+([0-9]+\.[0-9]+\.[0-9]+)") {
            return [System.Version]$matches[1]
        }
        else {
            throw "无法解析返回值: $versionOutput"
        }
    }
    catch {
        throw "获取本地版本失败`n$_"
    }
}
function Get-RemoteVersion {
    param([PSCustomObject]$response)
    try {
        return [System.Version]$response.tag_name.TrimStart("v")
    }
    catch {
        throw "无法从 GitHub 获取最新版本信息`n$response"
    }
}
function Get-EasyTier {
    $Arch = Get-SystemArchitecture

    $tempDirectory = Join-Path $ScriptRoot "easytier_update"

    try {
        if (-not (Test-Path $tempDirectory)) {
            New-Item -ItemType Directory -Path $tempDirectory | Out-Null
        }
    }
    catch {
        throw "无法创建文件夹 $tempDirectory`n$_"
    }

    try {
        Write-Host "检查最新版本..." -ForegroundColor Green
        $response = Invoke-RestMethodCompatible -Uri "https://api.github.com/repos/EasyTier/EasyTier/releases/latest"
        $latestVersion = Get-RemoteVersion($response)
    }
    catch {
        throw "获取最新版本失败。请检查网络连接或API请求达到上限`n$_"
    }

    $localVersion = Get-LocalVersion($EasyTierPath)
    if ($localVersion -ge $latestVersion) {
        Write-Host "EasyTier 已是最新版本 $localVersion" -ForegroundColor Green
        return
    }

    $asset = $response.assets | Where-Object { $_.name -like "easytier-$Arch*.zip" } | Select-Object -First 1
    if ($asset) {
        Write-Output "发现新版本 $latestVersion"
        $downloadUrl = $asset.browser_download_url
        if ($UseGitHubProxy) {
            $downloadUrl = "$GitHubProxy$downloadUrl"
        }
    }
    else {
        throw "未适配当前平台!"
    }

    $updateFile = Join-Path $tempDirectory $asset.name

    try {
        Write-Output "开始下载: $downloadUrl"
        Invoke-WebRequestCompatible -Uri $downloadUrl -OutFile $updateFile
    }
    catch {
        throw "下载失败!`n$_"
    }

    try {
        Expand-ZipFile -ZipPath $updateFile -DestinationPath $tempDirectory
        $extractedRoot = Get-ChildItem -Path $tempDirectory -Directory | Select-Object -First 1
        $updateFileDirectory = $extractedRoot.FullName
    }
    catch {
        throw "解压失败!`n$_"
    }

    Write-Host "准备就绪，开始更新..." -ForegroundColor Green
            
    $activeServices = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq "Running" }
    if ($activeServices) {
        try {
            Write-Host "发现正在运行的服务: $ServiceName" -ForegroundColor Yellow
            Write-Host "停止 EasyTier 服务..." -ForegroundColor Yellow
            $activeServices | Stop-Service -Force
        }
        catch {
            throw "停止服务失败!`n$_"
        }
    }

    try {
        Write-Host "更新文件..."
        Get-ChildItem -Path $updateFileDirectory | Copy-Item -Destination $ScriptRoot -Recurse -Force
    }
    catch {
        throw "更新文件失败!`n$_"
    }

    $localVersion = Get-LocalVersion($EasyTierPath)
    if ($localVersion -ge $latestVersion) {
        if ($activeServices) {
            try {
                Write-Host "启动服务..." -ForegroundColor Green
                $activeServices | Start-Service
            }
            catch {
                throw "服务启动失败!`n$_"
            }
        }
        Write-Host "EasyTier 已成功更新到版本 $latestVersion" -ForegroundColor Green
    }
    else {
        throw "更新文件失败! 请检查脚本是否过时或者文件/文件夹是否被其他程序占用"
    }
    Remove-Item -Recurse -Force $tempDirectory
}

$HelpText = @"
EasyTier 服务管理脚本

【使用方式】
直接双击运行或在命令行中执行:

    install.cmd [参数]

【可用参数】

    -H / -? / -Help
        显示此帮助信息并退出。

    -U / -Update
        更新 EasyTier 到最新版本

    -X / -Uninstall
        卸载 EasyTier 服务

    -UGHP / -UseGitHubProxy
        使用 GitHub 镜像代理下载 (默认: $false)

    -GHP / -GitHubProxy <代理地址>
        指定 GitHub 镜像代理地址 (默认: https://ghfast.top/)

    -UP / -UseProxy
        使用自定义代理 (默认: $false)

    -P / -Proxy <代理地址>
        指定自定义代理地址 (默认: http://127.0.0.1:7890)

    -C / -ConfigType <类型>
        指定配置模式，可选值: 
        * File   本地配置文件
        * Remote 远程服务器集中管理
        * CLI    使用命令行直接传参

    -N / -ServiceName <名称>
        指定安装的服务名称 (默认: EasyTierService)

    <其他参数...>
        当选择 CLI 模式时，用于传递自定义参数

【运行要求】
    * 已安装 PowerShell 3.0 或更高版本
    * 管理员权限 (自动检测并可请求提升)

【配置模式说明】
    1. File 模式: 
        从指定的本地配置文件加载运行参数
        脚本会提示输入配置文件路径 (可拖入文件)

    2. Remote 模式: 
        从服务器集中管理配置，可输入自定义管理服务器地址
        (例如: udp://x.x.x.x:22020/admin)

    3. CLI 模式: 
        直接通过命令行参数传递任意配置

【代理设置说明】
    * UseGitHubProxy 和 UseProxy 参数不能同时使用
    * 使用 GitHub 镜像代理可加速下载

【示例】
    1. 使用本地配置文件安装: 
        install.cmd -ConfigType File

    2. 使用远程服务器并设定服务名称: 
        install.cmd -ConfigType Remote -ServiceName EasyTierService

    3. 使用命令行传参: 
        install.cmd -ConfigType CLI --ipv4 x.x.x.x --network-name xxx --network-secret yyy --peers tcp://peer_host:11010

    4. 使用 GitHub 镜像代理更新: 
        install.cmd -Update -UseGitHubProxy

    5. 使用系统代理安装: 
        install.cmd -UseProxy -Proxy http://127.0.0.1:8080

    6. 卸载服务: 
        install.cmd -Uninstall

    7. 显示帮助信息: 
        install.cmd -Help
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
    <EventTrigger>
      <Enabled>true</Enabled>
      <Subscription>&lt;QueryList&gt;&lt;Query Id="0" Path="Microsoft-Windows-WLAN-AutoConfig/Operational"&gt;&lt;Select Path="Microsoft-Windows-WLAN-AutoConfig/Operational"&gt;*[System[Provider[@Name='Microsoft-Windows-WLAN-AutoConfig'] and EventID=8001]]&lt;/Select&gt;&lt;/Query&gt;&lt;/QueryList&gt;</Subscription>
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
      <Arguments>/c "net stop %#ServiceName#% &amp; net start %#ServiceName#%"</Arguments>
    </Exec>
  </Actions>
</Task>
"@

$host.ui.rawui.WindowTitle = "安装/卸载/更新 EasyTier 服务"
Clear-Host
$ScriptRoot = (Get-Location).Path
$RegistryPath = "HKLM:\SOFTWARE\EasyTierServiceManage"
$RegistryName = "Services"
$EasyTierPath = Join-Path $ScriptRoot "easytier-core.exe"
$OPTIONS = @()

$ErrorActionPreference = "Stop"
try {
    if ($Help) {
        Write-Host $HelpText
        Show-Pause -Text "按任意键退出..."
        exit 0
    }
    if ($UseProxy -and $UseGitHubProxy) {
        throw "UseProxy 和 UseGitHubProxy 参数不能同时使用，请选择其中一种代理方式。"
    }
    if ($Uninstall) {
        $services = Get-ServiceNames
        if ($services.Count -lt 1 -and (-not (Test-ServiceNameExists -Name $ServiceName))) {
            Write-Host "服务未安装" -ForegroundColor Red
            if (Show-YesNoPrompt -Message "是否尝试强制卸载？" -DefaultIndex 1) {
                Write-Host "正在停止服务 $ServiceName ..."
                Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
                Write-Host "正在移除服务 $ServiceName ..."
                Remove-ServiceCompatible -Name "$ServiceName" -ErrorAction SilentlyContinue
                Remove-ServiceName -Name $ServiceName -ErrorAction SilentlyContinue
                Write-Host "服务 $ServiceName 已卸载" -ForegroundColor Green
            }
        }
        else {
            foreach ($service in $services) {
                if (Get-Service -Name $service -ErrorAction SilentlyContinue) {
                    Write-Host "正在停止服务 $service ..."
                    Stop-Service -Name $service -Force
                    Write-Host "正在移除服务 $service ..."
                    Remove-ServiceCompatible -Name "$service"
                    Remove-ServiceName -Name $service
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
        $selected = $Host.UI.PromptForChoice("您准备如何配置EasyTier?", "请选择: ", $choices, 0)
        $ConfigType = @("File", "Remote", "CLI")[$selected]
    }
    switch ($ConfigType) {
        "File" {
            $OPTIONS += "--config-file $(Get-InputWithFileValidation -Prompt "配置文件路径(或将文件拖动到此处)")"
        }
        "Remote" {
            if (Show-YesNoPrompt -Message "是否使用自定义管理服务器？" -DefaultIndex 1) {
                $configServer = Get-InputWithNoNullOrWhiteSpace -Prompt "自定义管理服务器(格式: 协议://IP:端口/用户)" 
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
            throw "未知配置类型: $ConfigType"
        }
    }
    $BinaryPath = "`"$EasyTierPath`" $($OPTIONS -join ' ')" 
    Write-Host "生成的配置参数如下: " -ForegroundColor Yellow
    Write-Host ($OPTIONS -join " ") -ForegroundColor DarkGray
    if (Show-YesNoPrompt -Message "确认安装配置？" -DefaultIndex 1) {
        if (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue) {
            Stop-Service -Name $ServiceName -Force | Out-Null
            Remove-ServiceCompatible -Name $ServiceName
        }
        New-Service -Name $ServiceName -DisplayName "EasyTier" `
            -Description "EasyTier 核心服务" `
            -StartupType Automatic `
            -BinaryPathName $BinaryPath | Out-Null
        Start-Service -Name $ServiceName | Out-Null

        Register-ScheduledTask -TaskName "EasyTierWatchDog" -User "SYSTEM" -Xml $WatchDogTemplate.Replace("%#ServiceName#%", $ServiceName) -Force | Out-Null
        Save-ServiceName -Name $ServiceName
        Write-Host "安装完成。" -ForegroundColor Green
    }
    else {
        Write-Host "安装已取消。" -ForegroundColor Yellow
    }
    Show-Pause -Text "按任意键退出..."
}
catch {
    Write-Host "发生错误: $_" -ForegroundColor Red
    Show-Pause -Text "按任意键退出..."
    Unregister-ScheduledTask -TaskName "EasyTierWatchDog" -Confirm:$false -ErrorAction SilentlyContinue
    exit 1
}

