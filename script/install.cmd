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
    [string]$ServiceName = "EasyTierService"
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

function Show-MultipleChoicePrompt {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, Position = 0)]
        [ValidateNotNullOrEmpty()]
        [string]$Message,
        [Parameter(Mandatory = $true, Position = 1)]
        [ValidateNotNullOrEmpty()]
        [string[]]$Options,
        [string[]]$Helps = @(),
        [string]$Title = "",
        [int]$DefaultIndex = 0
    )
    
    if ($Helps.Count -eq 0) {
        $Helps = @("")
        for ($i = 1; $i -lt $Options.Count; $i++) {
            $Helps += ""
        }
    }
    
    if ($Options.Count -ne $Helps.Count) {
        throw "Options 和 Helps 的数量必须相同。"
    }
    
    if ($DefaultIndex -ge $Options.Count) {
        $DefaultIndex = $Options.Count - 1
    }
    $currentSelection = $DefaultIndex
    
    function Show-Menu {
        param(
            [int]$highlightIndex,
            [string]$title,
            [string]$message,
            [string[]]$options,
            [string[]]$helps,
            [int]$prevIndex = -1
        )
        
        try {
            # 首次显示时绘制完整菜单
            if ($prevIndex -eq -1) {
                Clear-Host
                if (-not [string]::IsNullOrEmpty($title)) {
                    Write-Host "$title`n" -ForegroundColor Blue
                }
                Write-Host "$message" -ForegroundColor Yellow
                
                # 保存初始光标位置
                $script:menuTop = [Console]::CursorTop
                
                # 首次绘制所有选项
                for ($i = 0; $i -lt $options.Count; $i++) {
                    $prefix = if ($i -eq $highlightIndex) { "[>]" } else { "[ ]" }
                    $color = if ($i -eq $highlightIndex) { "Green" } else { "Gray" }
                    Write-Host "$prefix $($options[$i])" -ForegroundColor $color -NoNewline
                    Write-Host $(if (-not [string]::IsNullOrEmpty($helps[$i])) { " - $($helps[$i])" } else { "" }) -ForegroundColor DarkGray
                }
            }

            # 只更新变化的选项
            if ($prevIndex -ne -1) {
                $safePrevPos = [Math]::Min([Console]::WindowHeight - 1, $menuTop + $prevIndex)
                [Console]::SetCursorPosition(0, $safePrevPos)
                Write-Host "[ ] $($options[$prevIndex])" -ForegroundColor Gray -NoNewline
                Write-Host $(if (-not [string]::IsNullOrEmpty($helps[$prevIndex])) { " - $($helps[$prevIndex])" } else { "" }) -ForegroundColor DarkGray
            }

            $safeHighlightPos = [Math]::Min([Console]::WindowHeight - 1, $menuTop + $highlightIndex)
            [Console]::SetCursorPosition(0, $safeHighlightPos)
            Write-Host "[>] $($options[$highlightIndex])" -ForegroundColor Green -NoNewline
            Write-Host $(if (-not [string]::IsNullOrEmpty($helps[$highlightIndex])) { " - $($helps[$highlightIndex])" } else { "" }) -ForegroundColor DarkGray

            # 首次显示时绘制操作提示
            if ($prevIndex -eq -1) {
                $safePos = [Math]::Min([Console]::WindowHeight - 2, $menuTop + $options.Count)
                [Console]::SetCursorPosition(0, $safePos)
                Write-Host "操作: 使用 ↑ / ↓ 移动 | Enter - 确认"
            }
        }
        finally {
            # 将光标移动到操作提示下方等待位置
            $waitPos = [Math]::Min([Console]::WindowHeight - 1, $menuTop + $options.Count + 1)
            [Console]::SetCursorPosition(0, $waitPos)
        }
    }
    
    $prevSelection = -1
    while ($true) {
        Show-Menu -highlightIndex $currentSelection -title $Title -message $Message -options $Options -helps $Helps -prevIndex $prevSelection
        $prevSelection = $currentSelection
        
        $key = [System.Console]::ReadKey($true)
        switch ($key.Key) {
            { $_ -eq [ConsoleKey]::UpArrow } {
                $currentSelection = [Math]::Max(0, $currentSelection - 1)
            }
            { $_ -eq [ConsoleKey]::DownArrow } {
                $currentSelection = [Math]::Min($Options.Count - 1, $currentSelection + 1)
            }
            { $_ -eq [ConsoleKey]::Enter } {
                Clear-Host
                return $currentSelection
            }
        }
    }
}

function Show-MultiSelectPrompt {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, Position = 0)]
        [ValidateNotNullOrEmpty()]
        [string]$Message,
        [Parameter(Mandatory = $true, Position = 1)]
        [ValidateNotNullOrEmpty()]
        [string[]]$Options,
        [string[]]$Helps = @(),
        [string]$Title = "",
        [int[]]$DefaultSelections = @()
    )
    
    if ($Helps.Count -eq 0) {
        $Helps = @("")
        for ($i = 1; $i -lt $Options.Count; $i++) {
            $Helps += ""
        }
    }
    
    if ($Options.Count -ne $Helps.Count) {
        throw "Options 和 Helps 的数量必须相同。"
    }
    
    $selectedIndices = [System.Collections.Generic.List[int]]::new($DefaultSelections)
    $currentSelection = 0
    
    function Show-Menu {
        param(
            [int]$highlightIndex,
            [System.Collections.Generic.List[int]]$selectedItems,
            [int]$prevIndex = -1,
            [int]$prevHighlight = -1
        )
        
        try {
            # 首次显示时绘制完整菜单
            if ($prevIndex -eq -1) {
                Clear-Host
                if (-not [string]::IsNullOrEmpty($Title)) {
                    Write-Host "$Title`n" -ForegroundColor Blue
                }
                Write-Host "$Message" -ForegroundColor Yellow
                
                # 保存初始光标位置
                $script:menuTop = [Console]::CursorTop
                
                # 首次绘制所有选项
                for ($i = 0; $i -lt $Options.Count; $i++) {
                    $isSelected = $selectedItems -contains $i
                    $prefix = if ($isSelected) { "[#]" } else { "[ ]" }
                    $color = if ($i -eq $highlightIndex) { "Green" } elseif ($isSelected) { "Cyan" } else { "Gray" }
                    Write-Host "$prefix $($Options[$i])" -ForegroundColor $color -NoNewline
                    Write-Host $(if (-not [string]::IsNullOrEmpty($Helps[$i])) { " - $($Helps[$i])" } else { "" }) -ForegroundColor DarkGray
                }
            }

            # 只更新变化的选项
            if ($prevIndex -ne -1) {
                $safePrevPos = [Math]::Min([Console]::WindowHeight - 1, $menuTop + $prevIndex)
                [Console]::SetCursorPosition(0, $safePrevPos)
                $isPrevSelected = $selectedItems -contains $prevIndex
                $prefix = if ($isPrevSelected) { "[#]" } else { "[ ]" }
                Write-Host "$prefix $($Options[$prevIndex])" -ForegroundColor $(if ($isPrevSelected) { "Cyan" } else { "Gray" }) -NoNewline
                Write-Host $(if (-not [string]::IsNullOrEmpty($Helps[$prevIndex])) { " - $($Helps[$prevIndex])" } else { "" }) -ForegroundColor DarkGray
            }

            if ($prevHighlight -ne -1 -and $prevHighlight -ne $highlightIndex) {
                $safePrevHighlightPos = [Math]::Min([Console]::WindowHeight - 1, $menuTop + $prevHighlight)
                [Console]::SetCursorPosition(0, $safePrevHighlightPos)
                $isPrevHighlightSelected = $selectedItems -contains $prevHighlight
                $prefix = if ($isPrevHighlightSelected) { "[#]" } else { "[ ]" }
                Write-Host "$prefix $($Options[$prevHighlight])" -ForegroundColor $(if ($isPrevHighlightSelected) { "Cyan" } else { "Gray" }) -NoNewline
                Write-Host $(if (-not [string]::IsNullOrEmpty($Helps[$prevHighlight])) { " - $($Helps[$prevHighlight])" } else { "" }) -ForegroundColor DarkGray
            }

            $safeHighlightPos = [Math]::Min([Console]::WindowHeight - 1, $menuTop + $highlightIndex)
            [Console]::SetCursorPosition(0, $safeHighlightPos)
            $isSelected = $selectedItems -contains $highlightIndex
            $prefix = if ($isSelected) { "[#]" } else { "[ ]" }
            Write-Host "$prefix $($Options[$highlightIndex])" -ForegroundColor "Green" -NoNewline
            Write-Host $(if (-not [string]::IsNullOrEmpty($Helps[$highlightIndex])) { " - $($Helps[$highlightIndex])" } else { "" }) -ForegroundColor DarkGray

            # 首次显示时绘制操作提示
            if ($prevIndex -eq -1) {
                $safePos = [Math]::Min([Console]::WindowHeight - 2, $menuTop + $Options.Count)
                [Console]::SetCursorPosition(0, $safePos)
                Write-Host "操作: 使用 ↑ / ↓ 移动 | Space - 选中/取消 | Enter - 确认"
            }
        }
        finally {
            # 将光标移动到操作提示下方等待位置
            $waitPos = [Math]::Min([Console]::WindowHeight - 1, $menuTop + $Options.Count + 1)
            [Console]::SetCursorPosition(0, $waitPos)
        }
    }
    
    $prevSelection = -1
    $prevHighlight = -1
    while ($true) {
        Show-Menu -highlightIndex $currentSelection -selectedItems $selectedIndices -prevIndex $prevSelection -prevHighlight $prevHighlight
        $prevHighlight = $currentSelection
        
        $key = [System.Console]::ReadKey($true)
        switch ($key.Key) {
            { $_ -eq [ConsoleKey]::UpArrow } {
                $prevSelection = $currentSelection
                $currentSelection = [Math]::Max(0, $currentSelection - 1)
            }
            { $_ -eq [ConsoleKey]::DownArrow } {
                $prevSelection = $currentSelection
                $currentSelection = [Math]::Min($Options.Count - 1, $currentSelection + 1)
            }
            { $_ -eq [ConsoleKey]::Spacebar } {
                $prevSelection = $currentSelection
                if ($selectedIndices.Contains($currentSelection)) {
                    $selectedIndices.Remove($currentSelection)
                }
                else {
                    $selectedIndices.Add($currentSelection)
                }
            }
            { $_ -eq [ConsoleKey]::Enter } {
                Clear-Host
                return $selectedIndices
            }
        }
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
            if ($response -match '^(?!").*(?<!")(?=.*\s).*$') {
                $response = "`"$response`""
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

function Get-BasicNetworkConfig {
    [CmdletBinding()]
    param()
    
    $options = @()
    $options += "--network-name $(Get-InputWithNoNullOrWhiteSpace -Prompt "网络名称")"
    $options += "--network-secret $(Get-InputWithNoNullOrWhiteSpace -Prompt "网络密钥")"
    
    if (Show-YesNoPrompt -Message "是否指定当前设备名称？" -DefaultIndex 1) {
        $options += "--hostname $(Get-InputWithNoNullOrWhiteSpace -Prompt "设备名称")"
    }
    
    if (Show-YesNoPrompt -Message "是否使用公共共享节点来发现对等节点？") {
        $options += "--external-node $(Get-InputWithDefault -Prompt "公共节点地址(格式:协议://IP:端口)" -DefaultValue "tcp://public.easytier.cn:11010")"
    }
    
    if (Show-YesNoPrompt -Message "是否添加对等节点？") {
        $peers = @()
        do {
            $peers += Get-InputWithDefault -Prompt "对等节点地址" -DefaultValue "tcp://public.easytier.cn:11010"
        } while (Show-YesNoPrompt -Message "是否继续添加对等节点？" -DefaultIndex 1)
        
        if ($peers.Count -gt 0) {
            $options += ($peers | ForEach-Object { "--peers $($_.Trim())" }) -join ' '
        }
    }
    
    $ipChoice = Show-MultipleChoicePrompt -Message "请选择IP分配方式" `
        -Options @("手动指定IPv4", "自动DHCP", "不设置IP") `
        -Helps @("自定义此节点的IPv4地址，如果为空则仅转发数据包", "由Easytier自动确定并设置IP地址", "将仅转发数据包，不会创建TUN设备") `
        -DefaultIndex 1
    
    switch ($ipChoice) {
        0 { $options += "--ipv4 $(Get-InputWithNoNullOrWhiteSpace -Prompt "IPv4地址")" }
        1 { $options += "--dhcp" }
        2 { break }
    }
    
    return $options
}

function Get-AdvancedConfig {
    [CmdletBinding()]
    param()
    
    $options = @()

    # 设备配置
    if (Show-YesNoPrompt -Message "是否指定TUN接口名称？" -DefaultIndex 1) {
        $options += "--dev-name $(Get-InputWithNoNullOrWhiteSpace -Prompt "TUN接口名称(可选)")"
    }
        
    # 网络白名单
    if (Show-YesNoPrompt -Message "是否设置转发网络白名单？" -DefaultIndex 1) {
        $whitelist = Get-InputWithDefault -Prompt "白名单网络(空格分隔,*=所有,def*=以def开头的网络)" -DefaultValue "*"
        $options += "--relay-network-whitelist $whitelist"
    }

    # 监听器配置
    if (Show-YesNoPrompt -Message "是否启用端口监听？" -DefaultIndex 1) {
        $listeners = @()
        do {
            $listener = Get-InputWithNoNullOrWhiteSpace -Prompt "监听器地址（格式：协议://IP:端口）"
            $listeners += $listener
        } while (Show-YesNoPrompt -Message "是否添加更多监听器？" -DefaultIndex 1)
        
        $options += "--listeners $($listeners -join ' ')"

        if (Show-YesNoPrompt -Message "是否手动指定公网映射地址？") {
            $mapped = Get-InputWithNoNullOrWhiteSpace -Prompt "公网地址（格式：协议://IP:端口）"
            $options += "--mapped-listeners $mapped"
        }
    }
    else {
        $options += "--no-listener"
    }
    
    # 性能选项
    $performanceOptions = @(
        "启用多线程运行",
        "启用延迟优先模式",
        "通过系统内核转发",
        "启用KCP代理"
    )
    
    $performanceHelps = @(
        "使用多线程运行时(默认为单线程)",
        "延迟优先模式(默认使用最短路径)",
        "通过系统内核转发子网代理数据包(禁用内置NAT)",
        "使用KCP代理TCP流(提高UDP丢包网络性能)"
    )
    
    $selectedPerformance = Show-MultiSelectPrompt -Message "请选择性能选项:" -Options $performanceOptions -Helps $performanceHelps
    
    # 处理选中的性能选项
    foreach ($index in $selectedPerformance) {
        switch ($index) {
            0 { $options += "--multi-thread" }
            1 { $options += "--latency-first" }
            2 { $options += "--proxy-forward-by-system" }
            3 { $options += "--enable-kcp-proxy" }
        }
    }
    return $options
}

function Get-EasyTierConfig {
    [CmdletBinding()]
    param()
    $options = @()
    $configChoice = Show-MultipleChoicePrompt -Message "请选择配置方案:" `
        -Options @("命令行", "配置文件", "配置服务器") `
        -Helps @("使用命令行参数进行配置", "使用本地配置文件", "使用服务器集中管理") `
        -DefaultIndex 0
    switch ($configChoice) {
        0 {
            # 基本网络配置
            $options += Get-BasicNetworkConfig
    
            # 高级配置
            $options += Get-AdvancedConfig
    
            # 专家选项
            if (Show-YesNoPrompt -Message "是否调整专家选项？" -DefaultIndex 1) {
                $options += Get-ExtraAdvancedOptions
            }
        }
        1 {
            $options += "--config-file $(Get-InputWithFileValidation -Prompt "配置文件路径(或将文件拖动到此处)")"
        }
        2 {
            if (Show-YesNoPrompt -Message "是否使用自定义管理服务器？" -DefaultIndex 1) {
                $configServer = Get-InputWithNoNullOrWhiteSpace -Prompt "自定义管理服务器（格式：协议://IP:端口/用户）" 
            }
            else {
                $configServer = Get-InputWithNoNullOrWhiteSpace -Prompt "官方服务器用户名"
            }
            $options += "--config-server $configServer"
        }
    }
    return $options
}

function Get-ExtraAdvancedOptions {
    [CmdletBinding()]
    param()
    
    $options = @()

    # 检查并添加缺失的--no-tun参数
    if (Show-YesNoPrompt -Message "是否不创建TUN设备？" -DefaultIndex 1) {
        $options += "--no-tun"
    }

    # 检查并添加缺失的--mtu参数
    if (Show-YesNoPrompt -Message "是否自定义TUN设备MTU？" -DefaultIndex 1) {
        $mtu = Get-InputWithDefault -Prompt "MTU值(默认:加密1360/非加密1380)" -DefaultValue ""
        if (-not [string]::IsNullOrEmpty($mtu)) {
            $options += "--mtu $mtu"
        }
    }

    # 日志配置
    if (Show-YesNoPrompt -Message "是否配置日志选项？" -DefaultIndex 1) {
        $logLevels = @("trace", "debug", "info", "warn", "error", "critical")
        $consoleLog = Show-MultipleChoicePrompt -Message "选择控制台日志级别" -Options $logLevels -DefaultIndex 2
        $fileLog = Show-MultipleChoicePrompt -Message "选择文件日志级别" -Options $logLevels -DefaultIndex 2
        $options += "--console-log-level $($logLevels[$consoleLog])"
        $options += "--file-log-level $($logLevels[$fileLog])"
        
        if (Show-YesNoPrompt -Message "是否指定日志目录？" -DefaultIndex 1) {
            $logDir = Get-InputWithDefault -Prompt "日志目录路径" -DefaultValue "$env:ProgramData\EasyTier\logs"
            $options += "--file-log-dir `"$logDir`""
        }
    }

    # 实例配置
    if (Show-YesNoPrompt -Message "是否指定实例名称？" -DefaultIndex 1) {
        $options += "--instance-name $(Get-InputWithNoNullOrWhiteSpace -Prompt "实例名称")"
    }

    # 网络高级选项
    $networkOptions = @(
        "禁用IPv6",
        "禁用加密",
        "禁用P2P通信",
        "禁用UDP打洞",
        "启用私有模式",
        "转发所有对等节点RPC"
    )
    
    $networkHelps = @(
        "不使用IPv6",
        "禁用对等节点通信的加密",
        "只通过--peers指定的节点转发数据包",
        "禁用UDP打洞功能",
        "不允许不同网络的节点通过本节点中转",
        "转发所有对等节点的RPC数据包"
    )
    
    $selectedNetwork = Show-MultiSelectPrompt -Message "请选择网络高级选项:" -Options $networkOptions -Helps $networkHelps
    
    foreach ($index in $selectedNetwork) {
        switch ($index) {
            0 { $options += "--disable-ipv6" }
            1 { $options += "--disable-encryption" }
            2 { $options += "--disable-p2p" }
            3 { $options += "--disable-udp-hole-punching" }
            4 { $options += "--private-mode" }
            5 { $options += "--relay-all-peer-rpc" }
        }
    }

    # 端口转发
    if (Show-YesNoPrompt -Message "是否设置端口转发？" -DefaultIndex 1) {
        $forwards = @()
        do {
            Write-Host "`n格式示例: udp://0.0.0.0:12345/10.126.126.1:23456" -ForegroundColor DarkGray
            $forward = Get-InputWithNoNullOrWhiteSpace -Prompt "端口转发(格式:协议://本地IP:端口/虚拟IP:端口)"
            $forwards += $forward
        } while (Show-YesNoPrompt -Message "是否添加更多端口转发？" -DefaultIndex 1)
        
        $options += "--port-forward $($forwards -join ' ')"
    }

    # SOCKS5代理
    if (Show-YesNoPrompt -Message "是否启用SOCKS5代理？" -DefaultIndex 1) {
        $port = Get-InputWithDefault -Prompt "SOCKS5端口号" -DefaultValue "1080"
        $options += "--socks5 $port"
    }

    # 其他选项
    if (Show-YesNoPrompt -Message "是否配置其他高级选项？" -DefaultIndex 1) {
        $otherOptions = @(
            "使用smoltcp堆栈",
            "启用魔法DNS", 
            "绑定物理设备",
            "启用KCP代理",
            "禁用KCP输入",
            "设置VPN门户",
            "设置默认协议",
            "设置压缩算法",
            "手动分配路由CIDR",
            "启用出口节点"
        )
        
        $otherHelps = @(
            "为子网代理和KCP代理启用smoltcp堆栈",
            "启用魔法DNS(hostname.et.net)",
            "将套接字绑定到物理设备避免路由问题",
            "使用KCP代理TCP流提高UDP网络性能",
            "不允许其他节点使用KCP代理到此节点",
            "定义VPN门户URL(wg://IP:端口/网络)",
            "设置连接对等节点的默认协议",
            "设置压缩算法(none/zstd)",
            "手动分配路由CIDR(将禁用子网代理和wireguard路由)",
            "允许此节点成为出口节点"
        )
        
        $selectedOther = Show-MultiSelectPrompt -Message "请选择其他高级选项:" -Options $otherOptions -Helps $otherHelps
        
        foreach ($index in $selectedOther) {
            switch ($index) {
                0 { $options += "--use-smoltcp" }
                1 { $options += "--accept-dns" }
                2 { $options += "--bind-device" }
                3 { $options += "--enable-kcp-proxy" }
                4 { $options += "--disable-kcp-input" }
                5 { 
                    Write-Host "`n格式示例: wg://0.0.0.0:11010/10.14.14.0/24" -ForegroundColor DarkGray
                    $vpnPortal = Get-InputWithNoNullOrWhiteSpace -Prompt "VPN门户URL(格式:wg://IP:端口/网络)"
                    $options += "--vpn-portal `"$vpnPortal`"" 
                }
                6 {
                    $protocols = @("tcp", "udp", "ws", "wss", "wg", "ring")
                    $protoIndex = Show-MultipleChoicePrompt -Message "选择默认协议" -Options $protocols
                    $options += "--default-protocol $($protocols[$protoIndex])"
                }
                7 {
                    $algorithms = @("none", "zstd")
                    $algoIndex = Show-MultipleChoicePrompt -Message "选择压缩算法" -Options $algorithms
                    $options += "--compression $($algorithms[$algoIndex])"
                }
                8 {
                    $routes = @()
                    do {
                        $route = Get-InputWithNoNullOrWhiteSpace -Prompt "手动路由CIDR(如192.168.0.0/16)"
                        $routes += $route
                    } while (Show-YesNoPrompt -Message "是否添加更多手动路由？" -DefaultIndex 1)
                    $options += "--manual-routes $($routes -join ' ')"
                }
                9 {
                    $options += "--enable-exit-node"
                    if (Show-YesNoPrompt -Message "是否指定出口节点？" -DefaultIndex 1) {
                        $exitNodes = @()
                        do {
                            $exitNode = Get-InputWithNoNullOrWhiteSpace -Prompt "出口节点虚拟IPv4地址"
                            $exitNodes += $exitNode
                        } while (Show-YesNoPrompt -Message "是否添加更多出口节点？" -DefaultIndex 1)
                        $options += "--exit-nodes $($exitNodes -join ' ')"
                    }
                }
            }
        }
    }

    return $options
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
        $uniqueLines = @()
        $uniqueLines += Get-Content -Path $FilePath 
        $uniqueLines += $ServiceName | Sort-Object -Unique
        Set-Content -Path $FilePath -Value ($uniqueLines -join [Environment]::NewLine) -Encoding UTF8 -Force
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

$host.ui.rawui.WindowTitle = "安装EasyTier服务"
Clear-Host
$ScriptRoot = (Get-Location).Path
$ServicesPath = Join-Path $ScriptRoot "services"

$RequiredFiles = @("easytier-core.exe", "easytier-cli.exe", "nssm.exe", "Packet.dll", "wintun.dll")
foreach ($file in $RequiredFiles) {
    if (-not (Test-Path (Join-Path $ScriptRoot $file))) {
        Write-Host "缺少必要文件: ${file}" -ForegroundColor Red
        Show-Pause -Text "按任意键退出..."
        exit 1
    }
}

try {
    
    $OPTIONS = Get-EasyTierConfig
    $nssm = Join-Path $ScriptRoot "nssm.exe"
    $arguments = $OPTIONS -join ' '
    Write-Host "`n生成的配置参数如下：" -ForegroundColor Yellow
    Write-Host ($OPTIONS -join " ") -ForegroundColor DarkGray
    
    if (Show-YesNoPrompt -Message "`n确认安装配置？" -DefaultIndex 1) {

        & $nssm install $ServiceName (Join-Path $ScriptRoot "easytier-core.exe")
        & $nssm set $ServiceName AppParameters $arguments
        & $nssm set $ServiceName Description "EasyTier 核心服务"
        & $nssm set $ServiceName AppDirectory $ScriptRoot
        & $nssm set $ServiceName Start SERVICE_AUTO_START
        & $nssm start $ServiceName
        
        Save-ServiceName -FilePath $ServicesPath -ServiceName $ServiceName
        Write-Host "`n服务安装完成。" -ForegroundColor Green
    }
    else {
        Write-Host "安装已取消。" -ForegroundColor Yellow
    }
}
catch {
    Write-Host "`n安装过程中发生错误: $_" -ForegroundColor Red
    exit 1
}

Show-Pause -Text "按任意键退出..."
exit
