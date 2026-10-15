# Run with Windows PowerShell as administrator on a machine without an
# installed easytier-gui service. All processes and files are test fixtures.
# Use -GuiOnly from an unelevated shell to test the path that needs no UAC.
param([switch]$GuiOnly)

$ErrorActionPreference = 'Stop'
$helperScript = Join-Path $PSScriptRoot 'installer-processes.ps1'
$testDir = Join-Path $env:TEMP ("EasyTier installer test " + [guid]::NewGuid())
$appDir = Join-Path $testDir 'app'
$otherDir = Join-Path $testDir 'other'
$exe = Join-Path $appDir 'easytier-gui.exe'
$helper = $null
$gui = $null
$other = $null
$parent = $null
$createdService = $false

function Assert($condition, [string]$message) {
    if (!$condition) { throw $message }
}

function Prepare([int]$parentPid = $PID, [int]$restore = 1) {
    $output = & "$PSHOME\powershell.exe" -NoProfile -ExecutionPolicy Bypass `
        -File $helperScript -InstallDir $appDir -InstallerPid $parentPid -RestoreService $restore
    Assert ($LASTEXITCODE -eq 0) "Prepare failed: $output"
    $helperPid = [int]($output | Select-Object -Last 1)
    if ($helperPid) {
        $process = [Diagnostics.Process]::GetProcessById($helperPid)
        $null = $process.Handle
        return $process
    }
}

function Finish($process) {
    if (!$process) { return }
    $finish = [Threading.EventWaitHandle]::OpenExisting("Local\EasyTierInstaller-$PID-finish")
    $done = [Threading.EventWaitHandle]::OpenExisting("Local\EasyTierInstaller-$PID-done")
    $failed = [Threading.EventWaitHandle]::OpenExisting("Local\EasyTierInstaller-$PID-failed")
    try {
        [void]$finish.Set()
        Assert ($done.WaitOne(65000)) 'The helper did not signal completion.'
        Assert (!$failed.WaitOne(0)) 'The helper reported a failure.'
    }
    finally {
        $finish.Dispose()
        $done.Dispose()
        $failed.Dispose()
    }
    Assert ($process.WaitForExit(5000)) 'The helper did not finish.'
    Assert ($process.ExitCode -eq 0) "The helper failed: $($process.ExitCode)"
    $process.Dispose()
}

function Start-TestService {
    Start-Service easytier-gui
    (Get-Service easytier-gui).WaitForStatus('Running', [TimeSpan]::FromSeconds(10))
}

if (Get-Service easytier-gui -ErrorAction SilentlyContinue) {
    throw 'An easytier-gui service already exists; refusing to touch it.'
}
try {
    [void](New-Item -ItemType Directory -Path $appDir, $otherDir)
    Add-Type -ReferencedAssemblies System.ServiceProcess -OutputAssembly $exe -OutputType ConsoleApplication @'
using System;
using System.ServiceProcess;
using System.Threading;

class FixtureService : ServiceBase
{
    public FixtureService() { ServiceName = "easytier-gui"; }
    static void Main(string[] args)
    {
        if (args.Length > 0) ServiceBase.Run(new FixtureService());
        else Thread.Sleep(Timeout.Infinite);
    }
}
'@
    Copy-Item $exe (Join-Path $otherDir 'easytier-gui.exe')

    $helper = Prepare
    Assert (!$helper) 'An idle installation must not start a helper.'
    Write-Host 'PASS: no running process or service'

    $gui = Start-Process $exe -PassThru
    $other = Start-Process (Join-Path $otherDir 'easytier-gui.exe') -PassThru
    $helper = Prepare
    Assert $gui.HasExited 'The GUI was not stopped.'
    Assert (!$other.HasExited) 'A GUI from a different installation was stopped.'
    Finish $helper
    $helper = $null
    Write-Host 'PASS: close GUI, preserve a different installation'
    if ($GuiOnly) { return }

    New-Service -Name easytier-gui -BinaryPathName "`"$exe`" --service" -StartupType Manual | Out-Null
    $createdService = $true
    Start-TestService
    $gui = Start-Process $exe -PassThru
    $helper = Prepare
    Assert ((Get-Service easytier-gui).Status -eq 'Stopped') 'The service was not stopped.'
    Assert $gui.HasExited 'The GUI alongside the service was not stopped.'
    Move-Item $exe "$exe.old"
    Copy-Item "$exe.old" $exe
    Finish $helper
    $helper = $null
    Assert ((Get-Service easytier-gui).Status -eq 'Running') 'The running service was not restored.'
    Write-Host 'PASS: stop GUI and service, replace executable, restore service'

    Stop-Service easytier-gui
    (Get-Service easytier-gui).WaitForStatus('Stopped', [TimeSpan]::FromSeconds(10))
    $helper = Prepare
    Assert (!$helper) 'A stopped service must not start a helper.'
    $gui = Start-Process $exe -PassThru
    $helper = Prepare
    Finish $helper
    $helper = $null
    Assert ((Get-Service easytier-gui).Status -eq 'Stopped') 'A previously stopped service was started.'
    Write-Host 'PASS: preserve stopped service state'

    Start-TestService
    $parent = Start-Process "$PSHOME\powershell.exe" -ArgumentList '-NoProfile -Command Start-Sleep 300' -WindowStyle Hidden -PassThru
    $helper = Prepare $parent.Id
    Assert ((Get-Service easytier-gui).Status -eq 'Stopped') 'The service was not stopped before cancellation.'
    $parent.Kill()
    Assert ($helper.WaitForExit(35000)) 'The helper did not handle installer exit.'
    Assert ($helper.ExitCode -eq 0) 'The helper failed while handling installer exit.'
    $helper.Dispose()
    $helper = $null
    Assert ((Get-Service easytier-gui).Status -eq 'Running') 'Cancellation did not restore the service.'
    Write-Host 'PASS: restore service when the installer exits'

    $helper = Prepare $PID 0
    Finish $helper
    $helper = $null
    Assert ((Get-Service easytier-gui).Status -eq 'Stopped') 'Uninstallation restarted the service.'
    Write-Host 'PASS: do not restart the service after uninstall'
}
finally {
    if ($helper -and !$helper.HasExited) { Finish $helper }
    if ($createdService) {
        Stop-Service easytier-gui -ErrorAction SilentlyContinue
        & "$env:SystemRoot\System32\sc.exe" delete easytier-gui | Out-Null
    }
    foreach ($process in @($gui, $other, $parent)) {
        if ($process -and !$process.HasExited) { $process.Kill(); $process.WaitForExit() }
        if ($process) { $process.Dispose() }
    }
    Remove-Item -LiteralPath $testDir -Recurse -Force
}
