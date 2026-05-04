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
        ConfirmSpecifyVersion        = "是否指定特定版本？"
        InputTag                     = "版本标签(如 v2.4.5)"
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
        FileOccupiedScan             = "扫描被占用的文件..."
        FileOccupiedStopService      = "停止占用文件的旧服务 {0}..."
        RestoringBackup              = "正在从备份恢复原文件..."
        Default                      = "默认"
        ServiceDiscoveringSCM        = "正在扫描 Windows 服务管理器..."
        ServiceFoundInSCM            = "在 SCM 中发现 {0} 个 EasyTier 相关服务"
        ServiceNotFoundInSCM         = "SCM 中未发现 EasyTier 相关服务"
        ServiceWaitStop              = "等待服务 {0} 停止..."
        ServiceWaitStopTimeout       = "等待服务 {0} 停止超时，尝试强制终止..."
        ServiceForceStop             = "正在强制终止服务 {0}..."
        ServiceStopRetry             = "服务 {0} 停止失败，正在进行第 {1} 次重试..."
        ServiceRemoveRetry           = "服务 {0} 移除失败，正在进行第 {1} 次重试..."
        ServiceForceRemove           = "尝试强制删除服务 {0}..."
        ServiceForceRemoveFail       = "强制删除服务 {0} 失败: {1}"
        ServiceConflictFound         = "发现冲突服务: {0} (路径: {1})"
        ServiceConflictResolve       = "正在处理冲突服务 {0}..."
        ServiceSyncRegistry          = "正在同步注册表记录..."
        ServiceRegistrySynced        = "注册表记录已同步"
        ServiceStoppingTimeout       = "停止服务 {0} 超时（{1}秒）"
        ServiceRemoveFail            = "移除服务 {0} 失败: {1}"
        ServiceNotStopped            = "服务 {0} 未能停止，跳过移除"
        DiscoveredServiceSummary     = "发现服务: {0} (状态: {1}, 路径: {2})"
        ServiceNotFound              = "未找到服务: {0}"
        ServiceExternalDetected      = "检测到外部安装的服务（无注册表记录）: {0}"
        ExtractFailAlternative       = "所有解压方法均失败: {0}"
        DownloadValidateFail         = "下载文件验证失败: 文件大小为 {0} 字节，不是有效的 ZIP 文件"
        DownloadValidateRetry        = "文件不完整或损坏，正在重新下载..."
        ExtractMethodFallback        = "[解压] 尝试方案: {0}"
        ExtractMethodWarn            = "  [警告] 方案 {0} 失败: {1}"
        TagNotFound                  = "版本 {0} 不存在！请检查版本标签是否正确（例如 v2.4.5）"
        RetryFetch                   = "拉取失败，正在进行第 {0} 次重试..."
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
        ConfirmSpecifyVersion        = "Specify a specific version?"
        InputTag                     = "Version tag (e.g., v2.4.5)"
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
        FileOccupiedScan             = "Scanning for occupied files..."
        FileOccupiedStopService      = "Stopping old service {0} that occupies files..."
        RestoringBackup              = "Restoring original files from backup..."
        Default                      = "default"
        ServiceDiscoveringSCM        = "Scanning Windows SCM..."
        ServiceFoundInSCM            = "Found {0} EasyTier-related services in SCM"
        ServiceNotFoundInSCM         = "No EasyTier-related services found in SCM"
        ServiceWaitStop              = "Waiting for service {0} to stop..."
        ServiceWaitStopTimeout       = "Timeout waiting for service {0} to stop, forcing termination..."
        ServiceForceStop             = "Forcefully terminating service {0}..."
        ServiceStopRetry             = "Failed to stop service {0}, retry {1}..."
        ServiceRemoveRetry           = "Failed to remove service {0}, retry {1}..."
        ServiceForceRemove           = "Attempting force removal of service {0}..."
        ServiceForceRemoveFail       = "Force removal of service {0} failed: {1}"
        ServiceConflictFound         = "Conflict service found: {0} (path: {1})"
        ServiceConflictResolve       = "Resolving conflict service {0}..."
        ServiceSyncRegistry          = "Syncing registry records..."
        ServiceRegistrySynced        = "Registry records synced"
        ServiceStoppingTimeout       = "Service {0} stop timeout ({1}s)"
        ServiceRemoveFail            = "Failed to remove service {0}: {1}"
        ServiceNotStopped            = "Service {0} not stopped, skipping removal"
        DiscoveredServiceSummary     = "Discovered service: {0} (status: {1}, path: {2})"
        ServiceNotFound              = "Service not found: {0}"
        ServiceExternalDetected      = "Externally installed service detected (no registry record): {0}"
        ExtractFailAlternative       = "All extraction methods failed: {0}"
        DownloadValidateFail         = "Download validation failed: file size {0} bytes, not a valid ZIP file"
        DownloadValidateRetry        = "File is incomplete or corrupted, re-downloading..."
        ExtractMethodFallback        = "[Extract] Try Method: {0}"
        ExtractMethodWarn            = "  [WARN] Method {0} failed: {1}"
        TagNotFound                  = "Version {0} does not exist! Check the version tag (e.g., v2.4.5)"
        RetryFetch                   = "Fetch failed, retry {0}..."
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
    $maxRetries = 2
    $lastError = $null
    for ($attempt = 1; $attempt -le $maxRetries; $attempt++) {
        try {
            if ($PSVersionTable.PSVersion.Major -lt 5) {
                $rawJson = Invoke-WebRequestCompatible -Uri $Uri
                $result = $rawJson | ConvertFrom-Json
                if ($result.message -and $result.message -eq "Not Found" -and $Uri -match "releases/tags/") {
                    throw "HTTP 404"
                }
                return $result
            }
            else {
                $params = @{
                    Uri             = $Uri
                    UseBasicParsing = $true
                    ErrorAction     = "Stop"
                }
                if ($UseProxy) {
                    $params.Proxy = $Proxy
                }
                return Invoke-RestMethod @params
            }
        }
        catch {
            $lastError = $_
            if ($_.Exception -is [System.Net.WebException]) {
                $response = $_.Exception.Response
                if ($response -and [int]$response.StatusCode -eq 404) {
                    throw $_
                }
            }
            if ($_ -match "HTTP 404") {
                throw (T "CompatibleRestMethodError" "HTTP 404 (Not Found)")
            }
            if ($attempt -lt $maxRetries) {
                Write-Host (T "RetryFetch" $attempt) -ForegroundColor Yellow
                Start-Sleep -Seconds 2
            }
        }
    }
    throw $lastError
}
function Invoke-DownloadWithValidation {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Url,

        [Parameter(Mandatory = $true)]
        [string]$OutFile,

        [Parameter(Mandatory = $false)]
        [int]$MaxRetries = 2,

        [Parameter(Mandatory = $false)]
        [long]$MinSizeBytes = 1024
    )
    $attempt = 0
    do {
        $attempt++
        try {
            Write-Output (T "DownloadStart" (Split-Path $OutFile -Leaf))
            if ($attempt -gt 1) {
                Write-Host (T "DownloadValidateRetry") -ForegroundColor Yellow
            }
            Invoke-WebRequestCompatible -Uri $Url -OutFile $OutFile
        }
        catch {
            throw (T "DownloadFail" $_)
        }
        if (-not (Test-DownloadValid -Path $OutFile -MinSizeBytes $MinSizeBytes)) {
            $fileInfo = Get-Item -Path $OutFile -ErrorAction SilentlyContinue
            $fileSize = if ($fileInfo) { $fileInfo.Length } else { 0 }
            Write-Host (T "DownloadValidateFail" $fileSize) -ForegroundColor Red
            if ($attempt -ge $MaxRetries) {
                throw (T "DownloadValidateFail" $fileSize)
            }
            Write-Host (T "DownloadValidateRetry") -ForegroundColor Yellow
            Remove-Item -Path $OutFile -Force -ErrorAction SilentlyContinue
        }
    } while ((-not (Test-DownloadValid -Path $OutFile -MinSizeBytes $MinSizeBytes)) -and ($attempt -lt $MaxRetries))
}
function Test-DownloadValid {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,
        [Parameter(Mandatory = $false)]
        [long]$MinSizeBytes = 1024
    )
    if (-not (Test-Path $Path)) { return $false }
    $item = Get-Item -Path $Path -ErrorAction SilentlyContinue
    if (-not $item -or $item.Length -lt $MinSizeBytes) { return $false }
    try {
        $stream = [System.IO.File]::OpenRead($Path)
        try {
            $header = New-Object byte[] 4
            $stream.Read($header, 0, 4) | Out-Null
            return ($header[0] -eq 0x50 -and $header[1] -eq 0x4B -and $header[2] -eq 0x03 -and $header[3] -eq 0x04)
        }
        finally {
            $stream.Close()
        }
    }
    catch {
        return $false
    }
}
function Expand-ArchiveViaDotNet {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ZipPath,
        [Parameter(Mandatory = $true)]
        [string]$DestinationPath
    )
    try {
        [System.IO.Compression.ZipArchive]::new | Out-Null
    }
    catch {
        Add-Type -AssemblyName System.IO.Compression -ErrorAction SilentlyContinue
    }
    Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction SilentlyContinue
    if (-not ([System.Management.Automation.PSTypeName]'System.IO.Compression.ZipFile').Type) {
        throw "Assembly System.IO.Compression.FileSystem not available"
    }
    $readStream = [System.IO.File]::OpenRead($ZipPath)
    try {
        $archive = [System.IO.Compression.ZipArchive]::new($readStream, [System.IO.Compression.ZipArchiveMode]::Read)
        try {
            if ($archive.Entries.Count -eq 0) { throw "ZIP archive contains 0 entries" }
        }
        finally {
            $archive.Dispose()
        }
    }
    finally {
        $readStream.Close()
    }
    [System.IO.Compression.ZipFile]::ExtractToDirectory($ZipPath, $DestinationPath)
    return $true
}
function Expand-ArchiveViaManualZip {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ZipPath,
        [Parameter(Mandatory = $true)]
        [string]$DestinationPath
    )
    try {
        [System.IO.Compression.ZipArchive]::new | Out-Null
    }
    catch {
        Add-Type -AssemblyName System.IO.Compression -ErrorAction SilentlyContinue
    }
    if (-not (Test-Path $DestinationPath)) {
        New-Item -ItemType Directory -Path $DestinationPath -Force | Out-Null
    }
    $readStream = [System.IO.File]::OpenRead($ZipPath)
    try {
        $archive = [System.IO.Compression.ZipArchive]::new($readStream, [System.IO.Compression.ZipArchiveMode]::Read)
        try {
            if ($archive.Entries.Count -eq 0) { throw "ZIP archive contains 0 entries" }
            foreach ($entry in $archive.Entries) {
                $entryPath = Join-Path $DestinationPath $entry.FullName
                if ($entry.FullName.EndsWith("/") -or $entry.FullName.EndsWith("\")) {
                    $null = New-Item -ItemType Directory -Path $entryPath -Force -ErrorAction SilentlyContinue
                    continue
                }
                $parentDir = Split-Path $entryPath -Parent
                if (-not (Test-Path $parentDir)) {
                    $null = New-Item -ItemType Directory -Path $parentDir -Force -ErrorAction SilentlyContinue
                }
                $entryStream = $entry.Open()
                try {
                    $fileStream = [System.IO.File]::Create($entryPath)
                    try {
                        $entryStream.CopyTo($fileStream)
                    }
                    finally {
                        $fileStream.Close()
                    }
                }
                finally {
                    $entryStream.Close()
                }
            }
            return $true
        }
        finally {
            $archive.Dispose()
        }
    }
    finally {
        $readStream.Close()
    }
}
function Expand-ArchiveViaShellApp {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ZipPath,
        [Parameter(Mandatory = $true)]
        [string]$DestinationPath
    )
    $shell = New-Object -ComObject Shell.Application -ErrorAction Stop
    $zipFolder = $shell.NameSpace($ZipPath)
    if (-not $zipFolder) { throw "Cannot open ZIP via Shell.Application" }
    if (-not (Test-Path $DestinationPath)) {
        New-Item -ItemType Directory -Path $DestinationPath -Force | Out-Null
    }
    $destFolder = $shell.NameSpace($DestinationPath)
    if (-not $destFolder) { throw "Cannot open destination via Shell.Application" }
    $destFolder.CopyHere($zipFolder.Items(), 20)  # 20 = 4(NoProgress) + 16(NoConfirmation)
    Start-Sleep -Milliseconds 1000
    if ((Get-ChildItem -Path $DestinationPath | Measure-Object).Count -eq 0) {
        throw "Shell.Application extraction produced 0 files"
    }
    return $true
}
function Expand-ArchiveCompatible {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ZipPath,
        [Parameter(Mandatory = $true)]
        [string]$DestinationPath
    )
    $methods = @(
        @{ Name = "PowerShell Expand-Archive"; Script = {
                param($ZipPath, $DestinationPath)
                if (-not (Test-Path $DestinationPath)) {
                    New-Item -ItemType Directory -Path $DestinationPath -Force | Out-Null
                }
                Expand-Archive -Path $ZipPath -DestinationPath $DestinationPath -Force
            }
        },
        @{ Name = ".NET ZipFile.ExtractToDirectory"; Script = ${function:Expand-ArchiveViaDotNet} },
        @{ Name = ".NET ZipArchive ManualExtract"; Script = ${function:Expand-ArchiveViaManualZip} },
        @{ Name = "Shell.Application COM"; Script = ${function:Expand-ArchiveViaShellApp} }
    )
    $errors = @()
    $succeeded = $false
    foreach ($method in $methods) {
        if ($succeeded) { break }
        try {
            Write-Host (T "ExtractMethodFallback" $method.Name) -ForegroundColor DarkGray
            & $method.Script -ZipPath $ZipPath -DestinationPath $DestinationPath
            $succeeded = $true
        }
        catch {
            Write-Host (T "ExtractMethodWarn" $method.Name $_.Exception.Message) -ForegroundColor DarkGray
            $errors += "[$($method.Name)] $($_.Exception.Message)"
        }
    }
    if (-not $succeeded) {
        throw (T "ExtractFailAlternative" $($errors -join " | "))
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
function Unregister-ScheduledTaskCompatible {
    param (
        [Parameter(Mandatory = $true)]
        [string]$TaskName
    )
    if (Get-Command -Name Unregister-ScheduledTask -ErrorAction SilentlyContinue) {
        Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue | Out-Null
    }
    else {
        schtasks.exe /Delete /TN "$TaskName" /F > $null 2>&1
    }
}
function Find-EasyTierService {
    [CmdletBinding()]
    param()
    Write-Host (T "ServiceDiscoveringSCM") -ForegroundColor Green
    $discovered = [System.Collections.ArrayList]@()
    try {
        $allServices = Get-WmiObject -Class Win32_Service -ErrorAction Stop
    }
    catch {
        try {
            $allServices = Get-CimInstance -ClassName Win32_Service -ErrorAction Stop
        }
        catch {
            Write-Host (T "ServiceDiscoveringSCM") -ForegroundColor Red
            return $discovered
        }
    }
    $easyTierExe = [System.IO.Path]::GetFileName($EasyTierPath)
    $scriptRootLower = $ScriptRoot.ToLowerInvariant()
    foreach ($svc in $allServices) {
        $pathName = if ($svc.PathName) { $svc.PathName } else { "" }
        if ($pathName -match [regex]::Escape($easyTierExe) -or
            $pathName.ToLowerInvariant() -like "*$scriptRootLower*" -or
            $pathName -match "easytier") {
            [void]$discovered.Add([PSCustomObject]@{
                    Name        = $svc.Name
                    State       = $svc.State
                    PathName    = $pathName
                    DisplayName = if ($svc.DisplayName) { $svc.DisplayName } else { "" }
                })
        }
    }
    return $discovered
}
function Get-ServiceInfo {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name
    )
    try {
        $svc = Get-WmiObject -Class Win32_Service -Filter "Name='$Name'" -ErrorAction Stop
        if ($svc) {
            return [PSCustomObject]@{
                Name        = $svc.Name
                State       = $svc.State
                PathName    = if ($svc.PathName) { $svc.PathName } else { "" }
                DisplayName = if ($svc.DisplayName) { $svc.DisplayName } else { "" }
            }
        }
    }
    catch {
        try {
            $svc = Get-CimInstance -ClassName Win32_Service -Filter "Name='$Name'" -ErrorAction Stop
            if ($svc) {
                return [PSCustomObject]@{
                    Name        = $svc.Name
                    State       = $svc.State
                    PathName    = if ($svc.PathName) { $svc.PathName } else { "" }
                    DisplayName = if ($svc.DisplayName) { $svc.DisplayName } else { "" }
                }
            }
        }
        catch { }
    }
    return $null
}
function Stop-ServiceForce {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name,
        [int]$MaxRetries = 3,
        [int]$WaitTimeoutSeconds = 30,
        [int]$RetryDelaySeconds = 2
    )
    $svc = Get-Service -Name $Name -ErrorAction SilentlyContinue
    if (-not $svc) {
        return $false
    }
    $wasRunning = $svc.Status -eq "Running"
    if (-not $wasRunning) {
        return $false
    }
    Write-Host (T "ServiceRunningFound" $Name) -ForegroundColor Yellow
    Write-Host (T "StopService") -ForegroundColor Yellow
    $stopped = $false
    for ($attempt = 1; $attempt -le $MaxRetries; $attempt++) {
        try {
            if ($attempt -gt 1) {
                Write-Host (T "ServiceStopRetry" $Name $attempt) -ForegroundColor Yellow
                Start-Sleep -Seconds $RetryDelaySeconds
            }
            Stop-Service -Name $Name -Force -ErrorAction Stop
            Write-Host (T "ServiceWaitStop" $Name) -ForegroundColor Yellow
            try {
                $svc.WaitForStatus("Stopped", [System.TimeSpan]::FromSeconds($WaitTimeoutSeconds))
                $stopped = $true
            }
            catch {
                Write-Host (T "ServiceWaitStopTimeout" $Name) -ForegroundColor Yellow
            }
            if ($stopped) { break }
            $svc.Refresh()
            if ($svc.Status -eq "Stopped") {
                $stopped = $true
                break
            }
        }
        catch {
            if ($attempt -ge $MaxRetries) {
                throw (T "StopServiceFail" $_)
            }
        }
    }
    if (-not $stopped) {
        Write-Host (T "ServiceForceStop" $Name) -ForegroundColor Red
        try {
            $processId = (Get-WmiObject -Class Win32_Service -Filter "Name='$Name'" -ErrorAction SilentlyContinue).ProcessId
            if ($processId -and $processId -gt 0) {
                Stop-Process -Id $processId -Force -ErrorAction SilentlyContinue
                Start-Sleep -Seconds 2
                $svc.Refresh()
                if ($svc.Status -ne "Stopped") {
                    sc.exe stop "$Name" > $null 2>&1
                    Start-Sleep -Seconds 3
                }
            }
        }
        catch {
            throw (T "ServiceStoppingTimeout" $Name $WaitTimeoutSeconds)
        }
    }
    return $true
}
function Remove-ServiceForce {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name,
        [int]$MaxRetries = 3
    )
    $svc = Get-Service -Name $Name -ErrorAction SilentlyContinue
    if (-not $svc) {
        Remove-ServiceName -Name $Name
        return $true
    }
    if ($svc.Status -ne "Stopped") {
        try {
            Stop-ServiceForce -Name $Name
        }
        catch {
            Write-Host (T "ServiceNotStopped" $Name) -ForegroundColor Yellow
        }
    }
    $svc.Refresh()
    if ($svc.Status -ne "Stopped") {
        Write-Host (T "ServiceNotStopped" $Name) -ForegroundColor Yellow
    }
    $removed = $false
    for ($attempt = 1; $attempt -le $MaxRetries; $attempt++) {
        try {
            if ($attempt -gt 1) {
                Write-Host (T "ServiceRemoveRetry" $Name $attempt) -ForegroundColor Yellow
                Start-Sleep -Seconds 2
            }
            Remove-ServiceCompatible -Name $Name
            $removed = $true
            break
        }
        catch {
            if ($attempt -ge $MaxRetries) {
                Write-Host (T "ServiceForceRemove" $Name) -ForegroundColor Yellow
                sc.exe delete "$Name" > $null 2>&1
                Start-Sleep -Seconds 1
                if (Get-Service -Name $Name -ErrorAction SilentlyContinue) {
                    $output = sc.exe delete "$Name" 2>&1
                    if ($LASTEXITCODE -ne 0) {
                        Write-Host (T "ServiceForceRemoveFail" $Name $output) -ForegroundColor Red
                        return $false
                    }
                }
                $removed = $true
            }
        }
    }
    Remove-ServiceName -Name $Name
    return $removed
}
function Update-RegistryServiceList {
    [CmdletBinding()]
    param()
    Write-Host (T "ServiceSyncRegistry") -ForegroundColor Green
    $discovered = Find-EasyTierService
    $existing = Get-ServiceNames
    $newList = @()
    foreach ($svc in $discovered) {
        if ($existing -notcontains $svc.Name) {
            Write-Host (T "ServiceExternalDetected" $svc.Name) -ForegroundColor Yellow
        }
        $newList += $svc.Name
    }
    foreach ($oldName in $existing) {
        $info = Get-ServiceInfo -Name $oldName
        if ($info) {
            if ($newList -notcontains $oldName) {
                $newList += $oldName
            }
        }
    }
    Initialize-RegistryEntryExists
    Set-ItemProperty -Path $RegistryPath -Name $RegistryName -Value $newList -Force
    Write-Host (T "ServiceRegistrySynced") -ForegroundColor Green
}
function Stop-RunningService {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name
    )
    return Stop-ServiceForce -Name $Name
}
function Start-ServiceIfWasRunning {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name,
        [Parameter(Mandatory = $true)]
        [bool]$WasRunning,
        [int]$MaxRetries = 3
    )
    if ($WasRunning) {
        for ($attempt = 1; $attempt -le $MaxRetries; $attempt++) {
            try {
                if ($attempt -gt 1) {
                    Start-Sleep -Seconds 2
                }
                Write-Host (T "StartService") -ForegroundColor Green
                Start-Service -Name $Name -ErrorAction Stop
                return
            }
            catch {
                if ($attempt -ge $MaxRetries) {
                    throw (T "ServiceStartFail" $_)
                }
            }
        }
    }
}
function Stop-LockingProcesses {
    Write-Host (T "FileOccupiedScan") -ForegroundColor Yellow
    $lockedFiles = @()
    $scriptFiles = Get-ChildItem -Path $ScriptRoot -File -Recurse -ErrorAction SilentlyContinue
    foreach ($file in $scriptFiles) {
        try {
            $stream = $file.Open([System.IO.FileMode]::Open, [System.IO.FileAccess]::ReadWrite, [System.IO.FileShare]::None)
            $stream.Close()
        }
        catch {
            $lockedFiles += $file.FullName
        }
    }
    $killedServices = [System.Collections.ArrayList]@()
    if ($lockedFiles.Count -gt 0) {
        try {
            $processes = Get-CimInstance -ClassName Win32_Process -ErrorAction SilentlyContinue
        }
        catch {
            $processes = Get-WmiObject -Class Win32_Process -ErrorAction SilentlyContinue
        }
        foreach ($lockedFile in $lockedFiles) {
            foreach ($proc in $processes) {
                if ($proc.CommandLine -and $proc.CommandLine -like "*$ScriptRoot*") {
                    try {
                        $svcName = $null
                        if ($proc.Name -eq "easytier-core.exe") {
                            try {
                                $svc = Get-CimInstance -ClassName Win32_Service -Filter "ProcessId = $($proc.ProcessId)" -ErrorAction SilentlyContinue
                                if ($svc) { $svcName = $svc.Name }
                            }
                            catch {
                                $svc = Get-WmiObject -Class Win32_Service -Filter "ProcessId = $($proc.ProcessId)" -ErrorAction SilentlyContinue
                                if ($svc) { $svcName = $svc.Name }
                            }
                            if (-not $svcName) { $svcName = "$ServiceName(unknown)" }
                        }
                        else {
                            $svcName = $proc.ProcessName
                        }
                        Write-Host (T "FileOccupiedStopService" $svcName) -ForegroundColor Yellow
                        Stop-Process -Id $proc.ProcessId -Force -ErrorAction SilentlyContinue
                        [void]$killedServices.Add($svcName)
                    }
                    catch {
                        Write-Host (T "StopServiceFail" $_) -ForegroundColor Red
                    }
                }
            }
        }
    }
    return , $killedServices
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
        if (-not $response -or -not $response.tag_name) {
            throw "tag_name_missing"
        }
        return [System.Version]$response.tag_name.TrimStart("v")
    }
    catch {
        if ($_.Exception.Message -eq "tag_name_missing") {
            throw (T "TagNotFound" $Tag)
        }
        if ($_.Exception.Message -match "Cannot bind argument to parameter 'response'") {
            throw (T "TagNotFound" $Tag)
        }
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
            if ($_.Exception.Message -match "404" -or $_ -match "404") {
                throw (T "TagNotFound" $Tag)
            }
            throw (T "FetchLatestFailDetailed" $_)
        }
    }
    else {
        try {
            Write-Host (T "FetchTag" $Tag) -ForegroundColor Green
            $response = Invoke-RestMethodCompatible -Uri "https://api.github.com/repos/EasyTier/EasyTier/releases/tags/$Tag"
        }
        catch {
            if ($_.Exception.Message -match "404" -or $_ -match "404") {
                throw (T "TagNotFound" $Tag)
            }
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
    Invoke-DownloadWithValidation -Url $DownloadUrl -OutFile $updateFile
    try {
        Write-Output (T "ExtractStart" $AssetName)
        Expand-ArchiveCompatible -ZipPath $updateFile -DestinationPath $tempDirectory
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
    Invoke-DownloadWithValidation -Url $DownloadUrl -OutFile $updateFile
    try {
        Write-Output (T "ExtractStart" $AssetName)
        Expand-ArchiveCompatible -ZipPath $updateFile -DestinationPath $tempDirectory
        $extractedRoot = Get-ChildItem -Path $tempDirectory -Directory | Select-Object -First 1
    }
    catch {
        throw (T "ExtractFail" $_)
    }
    $wasRunning = Stop-RunningService -Name $ServiceName
    $killedServices = Stop-LockingProcesses
    if (-not $wasRunning -and $killedServices.Count -gt 0) {
        $normalizedSvcName = $ServiceName.ToLowerInvariant()
        foreach ($ks in $killedServices) {
            if ($ks.ToLowerInvariant() -eq $normalizedSvcName) {
                $wasRunning = $true
                break
            }
        }
    }
    if (-not $wasRunning) {
        $svcInfo = Get-ServiceInfo -Name $ServiceName
        if ($svcInfo -and $svcInfo.State -eq "Running") {
            $wasRunning = $true
        }
    }
    $copySucceeded = $false
    $backupPath = Join-Path $tempDirectory "easytier_backup"
    try {
        New-Item -ItemType Directory -Path $backupPath -Force | Out-Null
        Get-ChildItem -Path $extractedRoot.FullName | ForEach-Object {
            $target = Join-Path $ScriptRoot $_.Name
            if (Test-Path $target) {
                Copy-Item -Path $target -Destination (Join-Path $backupPath $_.Name) -Force
            }
        }
        Write-Host (T "UpdateFile")
        Get-ChildItem -Path $extractedRoot.FullName | Copy-Item -Destination $ScriptRoot -Recurse -Force
        $copySucceeded = $true
        $localVersion = Get-LocalVersion($EasyTierPath)
    }
    catch {
        Write-Host (T "UpdateFileFail" $_) -ForegroundColor Red
    }
    if (-not $copySucceeded) {
        if (Test-Path $backupPath) {
            Write-Host (T "RestoringBackup") -ForegroundColor Yellow
            Get-ChildItem -Path $backupPath | Copy-Item -Destination $ScriptRoot -Recurse -Force
        }
    }
    if ($wasRunning) {
        try {
            Start-ServiceIfWasRunning -Name $ServiceName -WasRunning $true
        }
        catch {
            Write-Host (T "ServiceStartFail" $_) -ForegroundColor Red
        }
    }
    foreach ($ks in $killedServices) {
        $normalizedKs = $ks.ToLowerInvariant()
        if ($normalizedKs -eq $ServiceName.ToLowerInvariant()) { continue }
        if ($ks -match "\(unknown\)$") { continue }
        $svcInfo = Get-ServiceInfo -Name $ks
        if ($svcInfo) {
            Save-ServiceName -Name $ks
            try {
                Start-ServiceIfWasRunning -Name $ks -WasRunning $true
            }
            catch {
                Write-Host (T "ServiceStartFail" $_) -ForegroundColor Red
            }
        }
    }
    if (-not $copySucceeded) {
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
    Update-RegistryServiceList
    $services = Get-ServiceNames
    $discovered = Find-EasyTierService
    $allTargets = @{}
    foreach ($svc in $discovered) {
        if (-not $allTargets.ContainsKey($svc.Name)) {
            $allTargets[$svc.Name] = $svc
        }
    }
    foreach ($name in $services) {
        if (-not $allTargets.ContainsKey($name)) {
            $allTargets[$name] = $null
        }
    }
    if ($allTargets.Count -lt 1) {
        Write-Host (T "ServiceNotInstalled") -ForegroundColor Red
        if (Show-YesNoPrompt -Message (T "ConfirmForceRemove") -DefaultIndex 1) {
            Write-Host (T "ServiceStopping" $ServiceName) -ForegroundColor Yellow
            Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
            Write-Host (T "ServiceRemoving" $ServiceName) -ForegroundColor Yellow
            Remove-ServiceCompatible -Name "$ServiceName" -ErrorAction SilentlyContinue
            Remove-ServiceName -Name $ServiceName -ErrorAction SilentlyContinue
            Write-Host (T "ServiceRemoved" $ServiceName) -ForegroundColor Green
        }
    }
    else {
        Write-Host (T "ServiceFoundInSCM" $allTargets.Count) -ForegroundColor Yellow
        foreach ($name in $allTargets.Keys) {
            $info = $allTargets[$name]
            if ($info) {
                Write-Host (T "DiscoveredServiceSummary" $info.Name $info.State $info.PathName) -ForegroundColor DarkGray
            }
            Write-Host (T "ServiceStopping" $name) -ForegroundColor Yellow
            try {
                Stop-ServiceForce -Name $name
            }
            catch {
                Write-Host (T "ServiceNotStopped" $name) -ForegroundColor Yellow
            }
            Write-Host (T "ServiceRemoving" $name) -ForegroundColor Yellow
            if (Remove-ServiceForce -Name $name) {
                Write-Host (T "ServiceRemoved" $name) -ForegroundColor Green
            }
            else {
                Write-Host (T "ServiceRemoveFail" $name "unknown") -ForegroundColor Red
            }
        }
    }
    Unregister-ScheduledTaskCompatible -TaskName "EasyTierWatchDog"
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
        Update-RegistryServiceList
        $discovered = Find-EasyTierService
        $resolvedConflicts = $false
        foreach ($svc in $discovered) {
            if ($svc.PathName -match [regex]::Escape($EasyTierPath) -or
                $svc.PathName.ToLowerInvariant() -like "*$($ScriptRoot.ToLowerInvariant())*") {
                if ($svc.Name -ne $ServiceName) {
                    Write-Host (T "ServiceConflictFound" $svc.Name $svc.PathName) -ForegroundColor Yellow
                    if (Show-YesNoPrompt -Message (T "ServiceConflictResolve" $svc.Name) -DefaultIndex 0) {
                        Write-Host (T "ServiceStopping" $svc.Name) -ForegroundColor Yellow
                        try { Stop-ServiceForce -Name $svc.Name } catch {}
                        Write-Host (T "ServiceRemoving" $svc.Name) -ForegroundColor Yellow
                        Remove-ServiceForce -Name $svc.Name
                        $resolvedConflicts = $true
                    }
                }
            }
        }
        if ($resolvedConflicts) {
            Start-Sleep -Seconds 1
        }
        if (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue) {
            Write-Host (T "ServiceConflictResolve" $ServiceName) -ForegroundColor Yellow
            try { Stop-ServiceForce -Name $ServiceName } catch {}
            Remove-ServiceForce -Name $ServiceName
        }
        try {
            New-Service -Name $ServiceName -DisplayName "EasyTier" `
                -Description "EasyTier Core Service" `
                -StartupType Automatic `
                -BinaryPathName $BinaryPath -ErrorAction Stop | Out-Null
        }
        catch {
            throw (T "CreateDirFail" "Service($ServiceName)" $_)
        }
        try {
            Write-Host (T "StartService") -ForegroundColor Green
            Start-Service -Name $ServiceName -ErrorAction Stop
        }
        catch {
            throw (T "ServiceStartFail" $_)
        }

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
                if (Show-YesNoPrompt -Message (T "ConfirmSpecifyVersion") -DefaultIndex 1) {
                    $Tag = Get-InputWithNoNullOrWhiteSpace -Prompt (T "InputTag") 
                }
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
    Unregister-ScheduledTaskCompatible -TaskName "EasyTierWatchDog"
    Write-Host (T "Error" $_) -ForegroundColor Red
    Show-Pause -Text (T "ExitPrompt")
    exit 1
}