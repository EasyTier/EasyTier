<# : batch
@ECHO off
SETLOCAL EnableDelayedExpansion
TITLE Initializing Script...
CD /d %~dp0
<NUL SET /p="Checking PowerShell ... "
WHERE /q PowerShell 
IF !ERRORLEVEL! NEQ 0 ( ECHO PowerShell is not installed. & PAUSE & EXIT )
ECHO OK
<NUL SET /p="Checking PowerShell version ... "
PowerShell -C "if ($PSVersionTable.PSVersion.Major -lt 3) { exit 1 }"
IF !ERRORLEVEL! NEQ 0 ( ECHO Requires PowerShell 3 or later. & PAUSE & EXIT )
ECHO OK
<NUL SET /p="Checking execute permissions ... "
PowerShell -C "if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { exit 1 }"
IF !ERRORLEVEL! NEQ 0 (
    ECHO Fail
    ECHO Restart with administrator privileges ... 
    SET args=%*
    IF DEFINED args (
        SET args=!args:'=''!
        SET args=!args:"=\"!
    )
    PowerShell -NoP -C "Start-Process 'cmd.exe' -Verb RunAs -WorkingDirectory '%~dp0' -ArgumentList '/d /s /k \"\"%~f0\" !args!\"'"
    EXIT
)
ECHO OK
<NUL SET /p="Extract embedded script ... "
powershell -NoP -C "$c=gc '%~f0' -Raw -En UTF8;if(($s=$c.IndexOf('<'+'# : '+'batch'))-ge 0 -and ($e=$c.IndexOf(':: '+'#'+'>',$s))-ge 0){$c.Substring($e+6)|sc '%~n0.ps1' -En UTF8}else{exit 1}"
IF !ERRORLEVEL! NEQ 0 ( ECHO Embedded script section not found. & PAUSE & EXIT )
ECHO OK
PowerShell -NoP -EP Bypass -File "%~n0.ps1" %*
EXIT
:: #>
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
    [Alias("t")]
    [string]$Tag = "latest",

    [Parameter(Mandatory = $false)]
    [Alias("n")]
    [string]$ServiceName = "EasyTierService",

    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$ServiceArgs
)
$I18N = @{
    "zh-CN" = @{
        PressAnyKey                  = "按任意键继续..."
        Error                        = "发生错误: {0}"
        InitFail                     = "环境初始化未成功`n{0}"
        InputRequired                = "请输入{0}(必填)"
        InputEmpty                   = "{0}不能为空!"
        FileNotExist                 = "文件不存在: {0}"
        ServiceNotInstalled          = "服务未安装"
        ServiceStopping              = "正在停止服务 {0} ..."
        ServiceRemoving              = "正在移除服务 {0} ..."
        ServiceRemoved               = "服务 {0} 已卸载"
        ServiceRunningFound          = "发现正在运行的服务: {0}"
        DownloadStart                = "开始下载: {0}"
        ExtractStart                 = "开始解压: {0}"
        CleanTemp                    = "清理临时目录..."
        InstallDone                  = "EasyTier {0} 已安装完成!"
        UpdateDone                   = "EasyTier 已成功更新到版本 {0}"
        FetchLatest                  = "检查最新版本..."
        FetchTag                     = "获取指定版本: {0}"
        FetchFail                    = "获取最新版本失败`n{0}"
        FetchTagFail                 = "获取版本 {0} 失败`n{1}"
        ConfigUnknown                = "未知配置类型: {0}"
        ConfigConfirm                = "确认安装配置？"
        ConfigCancel                 = "安装已取消。"
        ConfigDone                   = "安装完成。"
        ProxyConflict                = "UseProxy 和 UseGitHubProxy 不能同时使用"
        VersionParseFail             = "无法解析返回值: {0}"
        LocalVersionFail             = "获取本地版本失败`n{0}"
        AlreadyLatest                = "已经是最新版本 ({0})"
        UnsupportedOS                = "不支持的操作系统"
        UnsupportedArch              = "不支持的架构: {0}"
        StopService                  = "停止 EasyTier 服务..."
        UpdateFile                   = "更新文件..."
        StartService                 = "启动服务..."
        DownloadFail                 = "下载失败!`n{0}"
        ExtractFail                  = "解压失败!`n{0}"
        UpdateFail                   = "更新失败!`n{0}"
        CreateDirFail                = "无法创建目录: {0}`n{1}"
        CleanFail                    = "清理临时目录失败!`n{0}"
        ConfirmForceRemove           = "是否尝试强制卸载？"
        ConfirmCustomServer          = "是否使用自定义管理服务器？"
        InputConfigFile              = "配置文件路径(或拖入)"
        InputServer                  = "自定义管理服务器"
        InputUser                    = "官方服务器用户名"
        InputCLI                     = "自定义启动参数"
        GeneratedArgs                = "生成的配置参数如下:"
        ChooseConfig                 = "您准备如何配置EasyTier?"
        ChooseAction                 = "EasyTier服务管理"
        InstallHelp                  = "安装服务"
        UninstallHelp                = "卸载服务"
        UpdateHelp                   = "更新EasyTier"
        SelectPrompt                 = "请选择:"
        LabelsHelpsCountMismatch     = "Labels 和 Helps 的数量必须相同。"
        ShowChoiceError              = "显示选择提示时出错: {0}"
        ReadInputError               = "读取输入时出错: {0}"
        CompatibleWebRequestError    = "[兼容模式]Invoke-WebRequest`n{0}"
        CompatibleRestMethodError    = "[兼容模式]Invoke-RestMethod`n{0}"
        CompatibleExpandArchiveError = "[兼容模式]Expand-Archive`n{0}"
        UnsupportedOSDetailed        = "不支持的操作系统: 非Windows环境 ({0})"
        UnsupportedOSUnable          = "不支持的操作系统: 无法确定平台"
        UnsupportedArchDetailed      = "不支持的CPU架构: windows-{0}"
        LocalProgramNotFound         = "未找到本地程序!"
        FetchLatestFailDetailed      = "获取最新版本失败。请检查网络连接或API请求达到上限`n{0}"
        FetchTagFailDetailed         = "获取版本 {0} 失败。请检查网络连接或该版本是否存在`n{1}"
        VersionConsistent            = "本地版本与{0}版本一致, 无需重复获取。"
        PlatformNotAdapted           = "未适配当前平台!"
        CreateFolderFail             = "无法创建文件夹 {0}`n{1}"
        StopServiceFail              = "停止服务失败!`n{0}"
        UpdateFileFail               = "更新文件失败!`n{0}"
        ServiceStartFail             = "服务启动失败!`n{0}"
        UpdateFileFailDetailed       = "更新文件失败! 请检查脚本是否过时或者文件/文件夹是否被其他程序占用"
        UseProxyConflictDetailed     = "UseProxy 和 UseGitHubProxy 参数不能同时使用，请选择其中一种代理方式。"
        WindowTitle                  = "安装/卸载/更新 EasyTier 服务"
        ExitPrompt                   = "按任意键退出..."
        LatestVersion                = "最新"
        SpecifiedVersion             = "指定({0})"
        FileModeHelp                 = "本地配置文件"
        RemoteModeHelp               = "服务器集中管理"
        CLIModeHelp                  = "命令行传参"
        Default                      = "默认"
    }
    "en-US" = @{
        PressAnyKey                  = "Press any key to continue..."
        Error                        = "Error: {0}"
        InitFail                     = "Initialization failed`n{0}"
        InputRequired                = "Enter {0} (required)"
        InputEmpty                   = "{0} cannot be empty!"
        FileNotExist                 = "File not found: {0}"
        ServiceNotInstalled          = "Service not installed"
        ServiceStopping              = "Stopping service {0} ..."
        ServiceRemoving              = "Removing service {0} ..."
        ServiceRemoved               = "Service {0} removed"
        ServiceRunningFound          = "Running service found: {0}"
        DownloadStart                = "Downloading: {0}"
        ExtractStart                 = "Extracting: {0}"
        CleanTemp                    = "Cleaning temp directory..."
        InstallDone                  = "Installed EasyTier {0}"
        UpdateDone                   = "Updated to version {0}"
        FetchLatest                  = "Checking latest version..."
        FetchTag                     = "Fetching version: {0}"
        FetchFail                    = "Failed to fetch latest`n{0}"
        FetchTagFail                 = "Failed to fetch {0}`n{1}"
        ConfigUnknown                = "Unknown config type: {0}"
        ConfigConfirm                = "Confirm install?"
        ConfigCancel                 = "Cancelled"
        ConfigDone                   = "Done"
        ProxyConflict                = "UseProxy and UseGitHubProxy conflict"
        VersionParseFail             = "Cannot parse version: {0}"
        LocalVersionFail             = "Failed to get local version`n{0}"
        AlreadyLatest                = "Already latest ({0})"
        UnsupportedOS                = "Unsupported OS"
        UnsupportedArch              = "Unsupported architecture: {0}"
        StopService                  = "Stopping service..."
        UpdateFile                   = "Updating files..."
        StartService                 = "Starting service..."
        DownloadFail                 = "Download failed`n{0}"
        ExtractFail                  = "Extract failed`n{0}"
        UpdateFail                   = "Update failed`n{0}"
        CreateDirFail                = "Cannot create dir {0}`n{1}"
        CleanFail                    = "Clean failed`n{0}"
        ConfirmForceRemove           = "Force uninstall?"
        ConfirmCustomServer          = "Use custom server?"
        InputConfigFile              = "Config file path"
        InputServer                  = "Custom server"
        InputUser                    = "Username"
        InputCLI                     = "CLI args"
        GeneratedArgs                = "Generated args:"
        ChooseConfig                 = "Select config mode"
        ChooseAction                 = "EasyTier service manage"
        InstallHelp                  = "Install service"
        UninstallHelp                = "Uninstall service"
        UpdateHelp                   = "Update EasyTier"
        SelectPrompt                 = "Choose:"
        LabelsHelpsCountMismatch     = "Labels and Helps count must match."
        ShowChoiceError              = "Error showing choice prompt: {0}"
        ReadInputError               = "Error reading input: {0}"
        CompatibleWebRequestError    = "[Compatible]Invoke-WebRequest`n{0}"
        CompatibleRestMethodError    = "[Compatible]Invoke-RestMethod`n{0}"
        CompatibleExpandArchiveError = "[Compatible]Expand-Archive`n{0}"
        UnsupportedOSDetailed        = "Unsupported OS: Non-Windows platform detected ({0})"
        UnsupportedOSUnable          = "Unsupported OS: Unable to determine platform."
        UnsupportedArchDetailed      = "Unsupported architecture: windows-{0}"
        LocalProgramNotFound         = "Local program not found!"
        FetchLatestFailDetailed      = "Failed to fetch latest version. Check network or API limit`n{0}"
        FetchTagFailDetailed         = "Failed to fetch version {0}. Check network or version existence`n{1}"
        VersionConsistent            = "Local version is consistent with {0} version, no need to fetch again."
        PlatformNotAdapted           = "Platform not adapted!"
        CreateFolderFail             = "Cannot create folder {0}`n{1}"
        StopServiceFail              = "Failed to stop service!`n{0}"
        UpdateFileFail               = "Failed to update files!`n{0}"
        ServiceStartFail             = "Failed to start service!`n{0}"
        UpdateFileFailDetailed       = "Failed to update files! Check if script is outdated or files/folders are occupied"
        UseProxyConflictDetailed     = "UseProxy and UseGitHubProxy cannot be used together, choose one proxy method."
        WindowTitle                  = "Install/Uninstall/Update EasyTier Service"
        ExitPrompt                   = "Press any key to exit..."
        LatestVersion                = "latest"
        SpecifiedVersion             = "specified({0})"
        FileModeHelp                 = "Local configuration file"
        RemoteModeHelp               = "Remote server centralized management"
        CLIModeHelp                  = "Command line arguments"
        Default                      = "default"
    }
}

$culture = [System.Globalization.CultureInfo]::CurrentCulture
[System.Threading.Thread]::CurrentThread.CurrentCulture = $culture
[System.Threading.Thread]::CurrentThread.CurrentUICulture = $culture
$script:Lang = (Get-UICulture).Name
if (-not $I18N.ContainsKey($Lang)) { $script:Lang = "en-US" }
function T {
    param($Key, [Parameter(ValueFromRemainingArguments = $true)]$Args)
    $text = $I18N[$script:Lang][$Key]
    if (-not $text) { $text = $I18N["en-US"][$Key] }
    if ($Args) {
        $stringArgs = @()
        foreach ($arg in $Args) {
            $stringArgs += [string]$arg
        }
        return [string]::Format($text, $stringArgs)
    }
    return $text
}
try {
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
}
catch {
    throw (T "InitFail" $_)
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
            throw (T "CompatibleWebRequestError" $_)
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
            throw (T "CompatibleRestMethodError" $_)
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
            throw (T "CompatibleExpandArchiveError" $_)
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
        [string]$Text = (T "PressAnyKey"),
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
        [string[]]$Helps = @("Yes", "No")
    )
    if ($Labels.Count -ne $Helps.Count) {
        throw (T "LabelsHelpsCountMismatch")
    }
    $choices = for ($i = 0; $i -lt $Labels.Count; $i++) {
        [System.Management.Automation.Host.ChoiceDescription]::new($Labels[$i], $Helps[$i])
    }
    try {
        return $Host.UI.PromptForChoice($Title, $Message, $choices, $DefaultIndex) -eq 0
    }
    catch {
        Write-Error (T "ShowChoiceError" $_)
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
            $response = Read-Host (T "InputRequired" $Prompt)
            if ([string]::IsNullOrWhiteSpace($response)) {
                Write-Host (T "InputEmpty" $Prompt) -ForegroundColor Red
                continue
            }
            return $response.Trim()
        }
        catch {
            Write-Error (T "ReadInputError" $_)
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
                Write-Host (T "FileNotExist" $filePath) -ForegroundColor Red
                continue
            }
            return $filePath
        }
        catch {
            Write-Error (T "ReadInputError" $_)
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
        $response = Read-Host "$Prompt($(T "Default"): $DefaultValue)"
        if ([string]::IsNullOrWhiteSpace($response)) {
            return $DefaultValue
        }
        if ($response -match '^(?!").*(?<!")(?=.*\s).*$') {
            $response = "`"$response`""
        }
        return $response.Trim()
    }
    catch {
        Write-Error (T "ReadInputError" $_)
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
            throw (T "UnsupportedOSDetailed" $platform)
        }
    }
    catch {
        throw (T "UnsupportedOSUnable")
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
        default { throw (T "UnsupportedArchDetailed" $arch) }
    }
}
function Get-LocalVersion {
    param([string]$CorePath)
    if (-not (Test-Path $CorePath)) {
        Write-Host (T "LocalProgramNotFound") -ForegroundColor Yellow
        return [System.Version]"0.0.0"
    }
    try {
        $versionOutput = & $CorePath --version 2>$null
        if ($versionOutput -match "easytier-core\s+([0-9]+\.[0-9]+\.[0-9]+)") {
            return [System.Version]$matches[1]
        }
        else {
            throw (T "VersionParseFail" $versionOutput)
        }
    }
    catch {
        throw (T "LocalVersionFail" $_)
    }
}
function Get-RemoteVersion {
    param([PSCustomObject]$response)
    try {
        return [System.Version]$response.tag_name.TrimStart("v")
    }
    catch {
        throw (T "FetchFail" $response)
    }
}
function Get-EasyTier {
    $Arch = Get-SystemArchitecture
    if ($Tag -eq "latest") {
        try {
            Write-Host (T "FetchLatest") -ForegroundColor Green
            $response = Invoke-RestMethodCompatible -Uri "https://api.github.com/repos/EasyTier/EasyTier/releases/latest"
        }
        catch {
            throw (T "FetchLatestFailDetailed" $_)
        }
    }
    else {
        try {
            Write-Host (T "FetchTag" $Tag) -ForegroundColor Green
            $response = Invoke-RestMethodCompatible -Uri "https://api.github.com/repos/EasyTier/EasyTier/releases/tags/$Tag"
        }
        catch {
            throw (T "FetchTagFailDetailed" $Tag $_)
        }
    }
    $remoteVersion = Get-RemoteVersion($response)
    $localVersion = Get-LocalVersion($EasyTierPath)
    if ($localVersion -ge $remoteVersion) { 
        $versionType = if ($Tag -eq 'latest') { (T "LatestVersion") } else { (T "SpecifiedVersion" $Tag) }
        throw (T "VersionConsistent" $versionType)
    }
    $asset = $response.assets | Where-Object { $_.name -like "easytier-$Arch*.zip" } | Select-Object -First 1
    if ($asset) {
        $downloadUrl = $asset.browser_download_url
        if ($UseGitHubProxy) {
            $downloadUrl = "$GitHubProxy$downloadUrl"
        }
        
        return [PSCustomObject]@{
            DownloadUrl   = $downloadUrl
            AssetName     = $asset.name
            TargetVersion = $remoteVersion
        }
    }
    else {
        throw (T "PlatformNotAdapted")
    }
}
function Install-EasyTier {
    param (
        [Parameter(ValueFromPipelineByPropertyName = $true)]
        [string]$DownloadUrl,

        [Parameter(ValueFromPipelineByPropertyName = $true)]
        [string]$AssetName,

        [Parameter(ValueFromPipelineByPropertyName = $true)]
        [System.Version]$TargetVersion
    )
    $tempDirectory = Join-Path $ScriptRoot "easytier_update"
    try {
        if (-not (Test-Path $tempDirectory)) {
            New-Item -ItemType Directory -Path $tempDirectory | Out-Null
        }
    }
    catch {
        throw (T "CreateFolderFail" $tempDirectory $_)
    }
    $updateFile = Join-Path $tempDirectory $AssetName
    try {
        Write-Output (T "DownloadStart" $AssetName)
        Invoke-WebRequestCompatible -Uri $DownloadUrl -OutFile $updateFile
    }
    catch {
        throw (T "DownloadFail" $_)
    }
    try {
        Write-Output (T "ExtractStart" $AssetName)
        Expand-ZipFile -ZipPath $updateFile -DestinationPath $tempDirectory
        $extractedRoot = Get-ChildItem -Path $tempDirectory -Directory | Select-Object -First 1
        Get-ChildItem -Path $extractedRoot.FullName | Copy-Item -Destination $ScriptRoot -Recurse -Force
    }
    catch {
        throw (T "ExtractFail" $_)
    }
    try {
        Write-Host (T "CleanTemp") -ForegroundColor Green
        Remove-Item -Recurse -Force $tempDirectory
    }
    catch {
        throw (T "CleanFail" $_)
    }
    Write-Host (T "InstallDone" $TargetVersion) -ForegroundColor Green
}
function Update-EasyTier {
    param (
        [Parameter(ValueFromPipelineByPropertyName = $true)]
        [string]$DownloadUrl,

        [Parameter(ValueFromPipelineByPropertyName = $true)]
        [string]$AssetName,

        [Parameter(ValueFromPipelineByPropertyName = $true)]
        [System.Version]$TargetVersion
    )
    $tempDirectory = Join-Path $ScriptRoot "easytier_update"
    try {
        if (-not (Test-Path $tempDirectory)) {
            New-Item -ItemType Directory -Path $tempDirectory | Out-Null
        }
    }
    catch {
        throw (T "CreateFolderFail" $tempDirectory $_)
    }
    $updateFile = Join-Path $tempDirectory $AssetName
    try {
        Write-Output (T "DownloadStart" $AssetName)
        Invoke-WebRequestCompatible -Uri $DownloadUrl -OutFile $updateFile
    }
    catch {
        throw (T "DownloadFail" $_)
    }
    try {
        Write-Output (T "ExtractStart" $AssetName)
        Expand-ZipFile -ZipPath $updateFile -DestinationPath $tempDirectory
        $extractedRoot = Get-ChildItem -Path $tempDirectory -Directory | Select-Object -First 1
    }
    catch {
        throw (T "ExtractFail" $_)
    }
    $activeServices = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq "Running" }
    if ($activeServices) {
        try {
            Write-Host (T "ServiceRunningFound" $ServiceName) -ForegroundColor Yellow
            Write-Host (T "StopService") -ForegroundColor Yellow
            $activeServices | Stop-Service -Force
        }
        catch {
            throw (T "StopServiceFail" $_)
        }
    }
    try {
        Write-Host (T "UpdateFile")
        Get-ChildItem -Path $extractedRoot.FullName | Copy-Item -Destination $ScriptRoot -Recurse -Force
    }
    catch {
        throw (T "UpdateFileFail" $_)
    }
    $localVersion = Get-LocalVersion($EasyTierPath)
    if ($localVersion -ge $TargetVersion) {
        if ($activeServices) {
            try {
                Write-Host (T "StartService") -ForegroundColor Green
                $activeServices | Start-Service
            }
            catch {
                throw (T "ServiceStartFail" $_)
            }
        }
    }
    else {
        throw (T "UpdateFileFailDetailed")
    }
    Write-Host (T "UpdateDone" $localVersion) -ForegroundColor Green
    try {
        Write-Host (T "CleanTemp") -ForegroundColor Green
        Remove-Item -Recurse -Force $tempDirectory
    }
    catch {
        throw (T "CleanFail" $_)
    }
}
function Uninstall-EasyTier {
    $services = Get-ServiceNames
    if ($services.Count -lt 1 -and (-not (Test-ServiceNameExists -Name $ServiceName))) {
        Write-Host (T "ServiceNotInstalled") -ForegroundColor Red
        if (Show-YesNoPrompt -Message (T "ConfirmForceRemove") -DefaultIndex 1) {
            Write-Host (T "ServiceStopping" $ServiceName)
            Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
            Write-Host (T "ServiceRemoving" $ServiceName)
            Remove-ServiceCompatible -Name "$ServiceName" -ErrorAction SilentlyContinue
            Remove-ServiceName -Name $ServiceName -ErrorAction SilentlyContinue
            Write-Host (T "ServiceRemoved" $ServiceName) -ForegroundColor Green
        }
    }
    else {
        foreach ($service in $services) {
            if (Get-Service -Name $service -ErrorAction SilentlyContinue) {
                Write-Host (T "ServiceStopping" $service)
                Stop-Service -Name $service -Force
                Write-Host (T "ServiceRemoving" $service)
                Remove-ServiceCompatible -Name "$service"
                Remove-ServiceName -Name $service
            }
            Write-Host (T "ServiceRemoved" $service) -ForegroundColor Green
        }
    }
    Unregister-ScheduledTask -TaskName "EasyTierWatchDog" -Confirm:$false -ErrorAction SilentlyContinue | Out-Null
}

function Set-EasyTier {
    switch ($ConfigType) {
        "File" {
            $OPTIONS += "--config-file $(Get-InputWithFileValidation -Prompt (T "InputConfigFile"))"
        }
        "Remote" {
            if (Show-YesNoPrompt -Message (T "ConfirmCustomServer") -DefaultIndex 1) {
                $configServer = Get-InputWithNoNullOrWhiteSpace -Prompt (T "InputServer") 
            }
            else {
                $configServer = Get-InputWithNoNullOrWhiteSpace -Prompt (T "InputUser")
            }
            $OPTIONS += "--config-server $configServer"
        } 
        "CLI" {
            if (-not $ServiceArgs -or $ServiceArgs.Count -eq 0) {
                $OPTIONS += Get-InputWithNoNullOrWhiteSpace -Prompt (T "InputCLI") 
            }
            else {
                $OPTIONS += $ServiceArgs
            }
        }
        default {
            throw (T "ConfigUnknown" $ConfigType)
        }
    }
    $BinaryPath = "`"$EasyTierPath`" $($OPTIONS -join ' ')" 
    Write-Host (T "GeneratedArgs") -ForegroundColor Yellow
    Write-Host ($OPTIONS -join " ") -ForegroundColor DarkGray
    if (Show-YesNoPrompt -Message (T "ConfigConfirm") -DefaultIndex 1) {
        if (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue) {
            Stop-Service -Name $ServiceName -Force | Out-Null
            Remove-ServiceCompatible -Name $ServiceName
        }
        New-Service -Name $ServiceName -DisplayName "EasyTier" `
            -Description "EasyTier Core Service" `
            -StartupType Automatic `
            -BinaryPathName $BinaryPath | Out-Null
        Start-Service -Name $ServiceName | Out-Null

        Save-ServiceName -Name $ServiceName
        Write-Host (T "ConfigDone") -ForegroundColor Green
    }
    else {
        Write-Host (T "ConfigCancel") -ForegroundColor Yellow
    }
}
$HelpText = @"
EasyTier Service Management Script

【Usage】
Run by double-clicking or execute in command line:

    install.cmd [parameters]

【Available Parameters】

    -H / -? / -Help
        Show this help message and exit.

    -U / -Update
        Update EasyTier to the latest version

    -T / -Tag
        Specify EasyTier version to install or update (default: latest [e.g., v2.4.5])

    -X / -Uninstall
        Uninstall EasyTier service

    -UGHP / -UseGitHubProxy
        Use GitHub mirror proxy for download (default: $false)

    -GHP / -GitHubProxy <proxy_address>
        Specify GitHub mirror proxy address (default: https://ghfast.top/)

    -UP / -UseProxy
        Use custom proxy (default: $false)

    -P / -Proxy <proxy_address>
        Specify custom proxy address (default: http://127.0.0.1:7890)

    -C / -ConfigType <type>
        Specify configuration mode, options: 
        * File   Local configuration file
        * Remote Remote server centralized management
        * CLI    Use command line arguments directly

    -N / -ServiceName <name>
        Specify service name to install (default: EasyTierService)

    <other arguments...>
        Used to pass custom arguments when CLI mode is selected

【Requirements】
    * PowerShell 3.0 or higher installed
    * Administrator privileges (automatically detected and can request elevation)

【Configuration Mode Description】
    1. File mode: 
        Load runtime parameters from specified local configuration file
        Script will prompt for configuration file path (can drag and drop file)

    2. Remote mode: 
        Centralized management from server, can input custom management server address
        (e.g., udp://x.x.x.x:22020/admin)

    3. CLI mode: 
        Pass any configuration directly through command line arguments

【Proxy Settings Description】
    * UseGitHubProxy and UseProxy cannot be used together
    * Using GitHub mirror proxy can speed up downloads

【Examples】
    1. Install using local configuration file: 
        install.cmd -ConfigType File

    2. Use remote server and set service name: 
        install.cmd -ConfigType Remote -ServiceName EasyTierService

    3. Use command line arguments: 
        install.cmd -ConfigType CLI --ipv4 x.x.x.x --network-name xxx --network-secret yyy --peers tcp://peer_host:11010

    4. Update using GitHub mirror proxy: 
        install.cmd -Update -UseGitHubProxy

    5. Install using system proxy: 
        install.cmd -UseProxy -Proxy http://127.0.0.1:8080
    
    6. Update EasyTier to version 2.4.5: 
        install.cmd -Update -Tag v2.4.5

    7. Uninstall service: 
        install.cmd -Uninstall

    8. Show help information: 
        install.cmd -Help
"@

$host.ui.rawui.WindowTitle = (T "WindowTitle")
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
        Show-Pause -Text (T "ExitPrompt")
        exit 0
    }
    if ($UseProxy -and $UseGitHubProxy) {
        throw (T "UseProxyConflictDetailed")
    }
    if ($Update) {
        Get-EasyTier | Update-EasyTier
        Show-Pause -Text (T "ExitPrompt")
        exit 0
    }
    if ($Uninstall) {
        Uninstall-EasyTier
        Show-Pause -Text (T "ExitPrompt")
        exit 0
    }
    if (-not (Test-Path $EasyTierPath)) {
        Get-EasyTier | Install-EasyTier
    }
    if (-not $ConfigType) {
        $choices = @(
            New-Object System.Management.Automation.Host.ChoiceDescription "&Install", (T "InstallHelp")
            New-Object System.Management.Automation.Host.ChoiceDescription "U&ninstall", (T "UninstallHelp")
            New-Object System.Management.Automation.Host.ChoiceDescription "&Update", (T "UpdateHelp")
        )
        $selected = $Host.UI.PromptForChoice(
            (T "ChooseAction"),
            (T "SelectPrompt"),
            $choices,
            0
        )
        switch ($selected) {
            0 {
                $ConfigType = @("File", "Remote", "CLI")[$Host.UI.PromptForChoice(
                    (T "ChooseConfig"),
                    (T "SelectPrompt"),
                    @(
                        New-Object System.Management.Automation.Host.ChoiceDescription "&File", (T "FileModeHelp")
                        New-Object System.Management.Automation.Host.ChoiceDescription "&Remote", (T "RemoteModeHelp")
                        New-Object System.Management.Automation.Host.ChoiceDescription "&CLI", (T "CLIModeHelp")
                    ),
                    0
                )]
            } 
            1 {
                Uninstall-EasyTier
                Show-Pause -Text (T "ExitPrompt")
                exit 0
            }
            2 {
                Get-EasyTier | Update-EasyTier
                Show-Pause -Text (T "ExitPrompt")
                exit 0
            }
        }
    }
    Set-EasyTier
    Show-Pause -Text (T "ExitPrompt")
    exit 0
}
catch {
    Unregister-ScheduledTask -TaskName "EasyTierWatchDog" -Confirm:$false -ErrorAction SilentlyContinue
    Write-Host (T "Error" $_) -ForegroundColor Red
    Show-Pause -Text (T "ExitPrompt")
    exit 1
}