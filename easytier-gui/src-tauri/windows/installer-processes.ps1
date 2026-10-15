param(
    [ValidateSet('Prepare', 'Run')]
    [string]$Action = 'Prepare',
    [Parameter(Mandatory = $true)]
    [string]$InstallDir,
    [Parameter(Mandatory = $true)]
    [int]$InstallerPid,
    [int]$RestoreService = 1
)

$ErrorActionPreference = 'Stop'
$eventName = "Local\EasyTierInstaller-$InstallerPid"
$exePath = [IO.Path]::GetFullPath((Join-Path $InstallDir 'easytier-gui.exe')).Replace('\\?\', '')
Add-Type -AssemblyName System.ServiceProcess

# Process.MainModule and WMI cannot reliably read an elevated GUI's path from
# the unelevated installer. Limited query access works across that boundary.
Add-Type @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text;

public static class EasyTierInstallerProcess
{
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr OpenProcess(uint access, bool inherit, int pid);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    static extern bool QueryFullProcessImageName(IntPtr process, uint flags,
        StringBuilder path, ref int size);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool TerminateProcess(IntPtr process, uint exitCode);
    [DllImport("kernel32.dll")]
    static extern uint WaitForSingleObject(IntPtr handle, uint milliseconds);
    [DllImport("kernel32.dll")]
    public static extern bool CloseHandle(IntPtr handle);

    public static string Path(IntPtr process)
    {
        var path = new StringBuilder(32768);
        int size = path.Capacity;
        if (!QueryFullProcessImageName(process, 0, path, ref size))
        {
            int error = Marshal.GetLastWin32Error();
            if (WaitForSingleObject(process, 0) == 0) return null;
            throw new Win32Exception(error);
        }
        return path.ToString().Replace(@"\\?\", "");
    }

    public static bool Matches(int pid, string path, bool terminate)
    {
        // Keep the same handle for path verification, termination and waiting,
        // so a recycled PID cannot cause us to terminate a different process.
        IntPtr process = OpenProcess(terminate ? 0x101001u : 0x101000u, false, pid);
        if (process == IntPtr.Zero)
        {
            int error = Marshal.GetLastWin32Error();
            if (error == 87) return false; // The process has already exited.
            throw new Win32Exception(error);
        }
        try
        {
            if (!String.Equals(Path(process), path, StringComparison.OrdinalIgnoreCase))
                return false;
            if (terminate)
            {
                if (!TerminateProcess(process, 0) && WaitForSingleObject(process, 0) != 0)
                    throw new Win32Exception();
                if (WaitForSingleObject(process, 30000) != 0)
                    throw new TimeoutException("EasyTier did not exit within 30 seconds.");
            }
            return true;
        }
        finally { CloseHandle(process); }
    }
}
'@

function Get-AppProcesses {
    foreach ($process in @(Get-Process -Name easytier-gui -ErrorAction SilentlyContinue)) {
        if ([EasyTierInstallerProcess]::Matches($process.Id, $exePath, $false)) {
            $process
        }
    }
}

function Get-AppService {
    $service = Get-WmiObject -Class Win32_Service -Filter "Name='easytier-gui'"
    if ($service) {
        $path = [regex]::Match($service.PathName, '^(?:"([^"]+)"|(\S+))')
        $binary = ($path.Groups[1].Value + $path.Groups[2].Value).Replace('\\?\', '')
        if ($binary -eq $exePath) { $service }
    }
}

function New-InstallerEvent([string]$name) {
    $security = New-Object Security.AccessControl.EventWaitHandleSecurity
    # RunAs may use another administrator account. The installer keeps its
    # original identity; only these completion signals cross the boundary.
    foreach ($sid in @(
        [Security.Principal.WindowsIdentity]::GetCurrent().User,
        (New-Object Security.Principal.SecurityIdentifier 'S-1-5-32-544')
    )) {
        $rule = New-Object Security.AccessControl.EventWaitHandleAccessRule(
            $sid, 'FullControl', 'Allow')
        $security.AddAccessRule($rule)
    }
    $created = $false
    New-Object Threading.EventWaitHandle(
        $false, [Threading.EventResetMode]::ManualReset, $name, [ref]$created, $security)
}

try {
    if ($Action -eq 'Prepare') {
        $service = Get-AppService
        $runningService = $service -and $service.State -ne 'Stopped'
        $needsElevation = $runningService
        $processes = @()
        try {
            $processes = @(Get-AppProcesses)
            foreach ($process in $processes) {
                $handle = [EasyTierInstallerProcess]::OpenProcess(0x101001, $false, $process.Id)
                if ($handle -eq [IntPtr]::Zero) { $needsElevation = $true }
                else { [void][EasyTierInstallerProcess]::CloseHandle($handle) }
            }
        }
        catch {
            if ($_.Exception.GetBaseException().NativeErrorCode -ne 5) { throw }
            $needsElevation = $true
        }
        if (!$runningService -and !$processes.Count -and !$needsElevation) {
            Write-Output 0
            exit 0
        }

        $ready = New-InstallerEvent "$eventName-ready"
        $finish = New-InstallerEvent "$eventName-finish"
        $done = New-InstallerEvent "$eventName-done"
        $failed = New-InstallerEvent "$eventName-failed"
        try {
            $arguments = '-NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass ' +
                "-File `"$PSCommandPath`" -Action Run -InstallDir `"$InstallDir`" " +
                "-InstallerPid $InstallerPid -RestoreService $RestoreService"
            $start = @{
                FilePath = "$PSHOME\powershell.exe"
                ArgumentList = $arguments
                WindowStyle = 'Hidden'
                PassThru = $true
            }
            $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
            $principal = New-Object Security.Principal.WindowsPrincipal($identity)
            if ($needsElevation -and !$principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
                $start.Verb = 'RunAs'
            }
            $helper = Start-Process @start
            while (!$ready.WaitOne(100)) {
                if ($helper.HasExited) {
                    throw 'Could not stop EasyTier.'
                }
            }
            if ($failed.WaitOne(0)) { throw 'Could not stop EasyTier.' }
            Write-Output $helper.Id
        }
        finally {
            $ready.Dispose()
            $finish.Dispose()
            $done.Dispose()
            $failed.Dispose()
        }
    }
    else {
        $ready = [Threading.EventWaitHandle]::OpenExisting("$eventName-ready")
        $finish = [Threading.EventWaitHandle]::OpenExisting("$eventName-finish")
        $done = [Threading.EventWaitHandle]::OpenExisting("$eventName-done")
        $failed = [Threading.EventWaitHandle]::OpenExisting("$eventName-failed")
        $installer = [Diagnostics.Process]::GetProcessById($InstallerPid)
        $installerExit = New-Object Threading.ManualResetEvent($false)
        $installerExit.SafeWaitHandle = New-Object Microsoft.Win32.SafeHandles.SafeWaitHandle(
            $installer.Handle, $false)
        $restart = $false
        $controller = $null
        $serviceProcess = $null
        try {
            $service = Get-AppService
            if ($service -and $service.State -ne 'Stopped') {
                $controller = New-Object ServiceProcess.ServiceController('easytier-gui')
                $restart = $RestoreService -ne 0 -and $service.State -ne 'Stop Pending'
                if ($service.ProcessId) {
                    $serviceProcess = [Diagnostics.Process]::GetProcessById($service.ProcessId)
                    # Acquire the handle before stopping, while the PID still exists.
                    $null = $serviceProcess.Handle
                }
                if ($controller.Status -eq 'StartPending') {
                    $controller.WaitForStatus('Running', [TimeSpan]::FromSeconds(30))
                }
                if ($controller.Status -ne 'StopPending') { $controller.Stop() }
                $controller.WaitForStatus('Stopped', [TimeSpan]::FromSeconds(30))
                if ($serviceProcess -and !$serviceProcess.WaitForExit(30000)) {
                    throw 'The EasyTier service process did not exit within 30 seconds.'
                }
            }
            foreach ($process in @(Get-AppProcesses)) {
                [void][EasyTierInstallerProcess]::Matches($process.Id, $exePath, $true)
            }
            [void]$ready.Set()
            [void][Threading.WaitHandle]::WaitAny(@($finish, $installerExit))
        }
        finally {
            # Also restore after cancellation/failure, provided the executable
            # still exists. A completed uninstall must not restart the service.
            try {
                if ($restart -and (Test-Path -LiteralPath $exePath)) {
                    $controller.Refresh()
                    if ($controller.Status -eq 'StopPending') {
                        $controller.WaitForStatus('Stopped', [TimeSpan]::FromSeconds(30))
                    }
                    if ($controller.Status -eq 'Stopped') {
                        $controller.Start()
                        $controller.WaitForStatus('Running', [TimeSpan]::FromSeconds(30))
                    }
                }
            }
            finally {
                if ($controller) { $controller.Dispose() }
                if ($serviceProcess) { $serviceProcess.Dispose() }
                $installerExit.Dispose()
                $installer.Dispose()
            }
        }
    }
}
catch {
    if ($Action -eq 'Run' -and $failed) { [void]$failed.Set() }
    Write-Error $_ -ErrorAction Continue
    exit 1
}
finally {
    if ($Action -eq 'Run' -and $done) {
        # Completion events remain accessible to the original user even when
        # UAC ran the helper under a different administrator account.
        [void]$done.Set()
        [void]$ready.Set()
        $ready.Dispose()
        $finish.Dispose()
        $done.Dispose()
        $failed.Dispose()
    }
}
