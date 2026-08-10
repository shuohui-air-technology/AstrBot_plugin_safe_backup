Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Remove-NonRootTrailingSeparators {
    param([Parameter(Mandatory)][string]$Path)
    $root = [IO.Path]::GetPathRoot($Path)
    if ($Path -eq $root) { return $Path }
    return $Path.TrimEnd([char[]]@('\', '/'))
}

function Get-AbsolutePath {
    param([Parameter(Mandatory)][string]$Value, [Parameter(Mandatory)][string]$Label)
    if ([string]::IsNullOrWhiteSpace($Value)) { throw "$Label is required." }
    $expanded = [Environment]::ExpandEnvironmentVariables($Value)
    if (-not [IO.Path]::IsPathRooted($expanded)) { throw "$Label must be absolute." }
    if ($expanded.StartsWith('\\')) { throw "$Label must be local." }
    return Remove-NonRootTrailingSeparators ([IO.Path]::GetFullPath($expanded))
}

function Quote-TaskArgument {
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Value)
    $builder = [Text.StringBuilder]::new()
    [void]$builder.Append('"')
    $slashes = 0
    foreach ($ch in $Value.ToCharArray()) {
        if ($ch -eq '\') { $slashes++; continue }
        if ($ch -eq '"') {
            [void]$builder.Append('\', ($slashes * 2) + 1)
            [void]$builder.Append('"')
            $slashes = 0
            continue
        }
        if ($slashes -gt 0) { [void]$builder.Append('\', $slashes); $slashes = 0 }
        [void]$builder.Append($ch)
    }
    if ($slashes -gt 0) { [void]$builder.Append('\', $slashes * 2) }
    [void]$builder.Append('"')
    return $builder.ToString()
}

function New-ProcessArgumentString {
    param([Parameter(Mandatory)][string[]]$Arguments)
    return (($Arguments | ForEach-Object { Quote-TaskArgument ([string]$_) }) -join ' ')
}

function Get-SafeBackupLinkCount {
    param([Parameter(Mandatory)][IO.FileStream]$Stream)
    if ($null -eq ('SafeBackup.ScriptIdentity' -as [type])) {
        Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
namespace SafeBackup {
    public static class ScriptIdentity {
        [StructLayout(LayoutKind.Sequential)]
        private struct BY_HANDLE_FILE_INFORMATION {
            public uint FileAttributes;
            public System.Runtime.InteropServices.ComTypes.FILETIME CreationTime;
            public System.Runtime.InteropServices.ComTypes.FILETIME LastAccessTime;
            public System.Runtime.InteropServices.ComTypes.FILETIME LastWriteTime;
            public uint VolumeSerialNumber;
            public uint FileSizeHigh;
            public uint FileSizeLow;
            public uint NumberOfLinks;
            public uint FileIndexHigh;
            public uint FileIndexLow;
        }
        [DllImport("kernel32.dll", SetLastError=true)]
        private static extern bool GetFileInformationByHandle(IntPtr handle, out BY_HANDLE_FILE_INFORMATION info);
        public static uint LinkCount(SafeFileHandle handle) {
            BY_HANDLE_FILE_INFORMATION info;
            if (!GetFileInformationByHandle(handle.DangerousGetHandle(), out info)) {
                throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
            }
            return info.NumberOfLinks;
        }
    }
}
'@
    }
    return [SafeBackup.ScriptIdentity]::LinkCount($Stream.SafeFileHandle)
}

function Assert-TrustedPluginFile {
    param(
        [Parameter(Mandatory)][string]$Candidate,
        [Parameter(Mandatory)][string]$Expected
    )
    $actual = Get-AbsolutePath $Candidate 'Plugin script'
    $wanted = Get-AbsolutePath $Expected 'Plugin script'
    if (-not [string]::Equals($actual, $wanted, [StringComparison]::OrdinalIgnoreCase)) {
        throw 'Plugin script path mismatch.'
    }
    $current = $actual
    $leaf = $true
    while ($true) {
        $item = Get-Item -LiteralPath $current -Force -ErrorAction Stop
        if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw 'Plugin script path is a reparse point.'
        }
        if ($leaf -and $item.PSIsContainer) { throw 'Plugin script is not a regular file.' }
        if (-not $leaf -and -not $item.PSIsContainer) { throw 'Plugin script parent is not a directory.' }
        $parent = [IO.Directory]::GetParent($current)
        if ($null -eq $parent) { break }
        $current = $parent.FullName
        $leaf = $false
    }
    $stream = [IO.File]::Open($actual, [IO.FileMode]::Open, [IO.FileAccess]::Read, ([IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete))
    try {
        if ((Get-SafeBackupLinkCount $stream) -ne 1) { throw 'Plugin script has multiple hard links.' }
    }
    finally { $stream.Dispose() }
    return $actual
}

function Assert-BackupLauncherArguments {
    param([Parameter(Mandatory)][string[]]$Arguments)
    if ($Arguments.Count -notin @(15, 17)) { throw 'Invalid launcher arguments.' }
    $required = @('--astrbot-root', '--destination', '--python-path', '--keep', '--week-start', '--schedule-time')
    for ($i = 0; $i -lt $required.Count; $i++) {
        if ($Arguments[$i * 2] -cne $required[$i]) { throw 'Invalid launcher arguments.' }
    }
    if ($Arguments[-1] -cne '--scheduled' -or $Arguments[-3] -cne '--artifact-digest' -or $Arguments[-2] -notmatch '^[0-9a-f]{64}$' -or $Arguments[-2] -eq ('0' * 64) -or ($Arguments.Count -eq 17 -and $Arguments[-5] -cne '--napcat-root')) {
        throw 'Invalid launcher arguments.'
    }
    foreach ($index in @(1, 3, 5)) { [void](Get-AbsolutePath $Arguments[$index] 'LauncherArgument') }
    if ($Arguments.Count -eq 17) { [void](Get-AbsolutePath $Arguments[13] 'LauncherArgument') }
    if ($Arguments[7] -notmatch '^(?:[1-9]|[12][0-9]|30)$' -or $Arguments[9] -notmatch '^[0-6]$' -or $Arguments[11] -notmatch '^(?:[01]\d|2[0-3]):[0-5]\d$') {
        throw 'Invalid launcher arguments.'
    }
    $engineArguments = [Collections.Generic.List[string]]::new()
    for ($i = 0; $i -lt $Arguments.Count; $i++) {
        if ($i -in @(4, 5)) { continue }
        [void]$engineArguments.Add($Arguments[$i])
    }
    return [pscustomobject]@{ PythonPath=$Arguments[5]; ArtifactDigest=$Arguments[-2]; EngineArguments=@($engineArguments.ToArray()) }
}

function Get-SafeBackupArtifactDigest {
    $files = [ordered]@{
        'console_runner.py'=(Join-Path $PSScriptRoot '..\safe_backup\console_runner.py')
        'engine.py'=(Join-Path $PSScriptRoot '..\safe_backup\engine.py')
        'progress.py'=(Join-Path $PSScriptRoot '..\safe_backup\progress.py')
        'run_backup_visible.ps1'=(Join-Path $PSScriptRoot 'run_backup_visible.ps1')
        'task_common.ps1'=(Join-Path $PSScriptRoot 'task_common.ps1')
        'task_launcher.ps1'=(Join-Path $PSScriptRoot 'task_launcher.ps1')
    }
    $parts = [Collections.Generic.List[string]]::new()
    foreach ($name in $files.Keys) {
        $trusted = Assert-TrustedPluginFile $files[$name] $files[$name]
        $stream = [IO.File]::Open($trusted, [IO.FileMode]::Open, [IO.FileAccess]::Read, ([IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete))
        try { $hash = ([Security.Cryptography.SHA256]::Create().ComputeHash($stream) | ForEach-Object { $_.ToString('x2') }) -join '' }
        finally { $stream.Dispose() }
        [void]$parts.Add('"' + $name + '":{"sha256":"' + $hash + '"}')
    }
    $json = '{' + ($parts -join ',') + '}'
    $bytes = [Text.Encoding]::UTF8.GetBytes($json)
    return ([Security.Cryptography.SHA256]::Create().ComputeHash($bytes) | ForEach-Object { $_.ToString('x2') }) -join ''
}

function ConvertFrom-TaskArgumentString {
    param([Parameter(Mandatory)][string]$Value)
    $result = [Collections.Generic.List[string]]::new()
    $index = 0
    while ($index -lt $Value.Length) {
        while ($index -lt $Value.Length -and [char]::IsWhiteSpace($Value[$index])) { $index++ }
        if ($index -ge $Value.Length) { break }
        $part = [Text.StringBuilder]::new()
        $quoted = $false
        while ($index -lt $Value.Length) {
            $ch = $Value[$index]
            if ($ch -eq '\') {
                $start = $index
                while ($index -lt $Value.Length -and $Value[$index] -eq '\') { $index++ }
                $count = $index - $start
                if ($index -lt $Value.Length -and $Value[$index] -eq '"') {
                    [void]$part.Append('\', [int]($count / 2))
                    if (($count % 2) -eq 0) { $quoted = -not $quoted } else { [void]$part.Append('"') }
                    $index++
                } else { [void]$part.Append('\', $count) }
                continue
            }
            if ($ch -eq '"') { $quoted = -not $quoted; $index++; continue }
            if (-not $quoted -and [char]::IsWhiteSpace($ch)) { break }
            [void]$part.Append($ch)
            $index++
        }
        if ($quoted) { throw 'Invalid task argument string.' }
        [void]$result.Add($part.ToString())
    }
    return $result.ToArray()
}

function Get-WindowsPowerShellPath {
    if ($null -eq ('SafeBackup.TaskNative' -as [type])) {
        Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
namespace SafeBackup {
    public static class TaskNative {
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern uint GetSystemDirectory(char[] buffer, uint size);
    }
}
'@
    }
    $buffer = New-Object char[] 32768
    $length = [SafeBackup.TaskNative]::GetSystemDirectory($buffer, [uint32]$buffer.Length)
    if ($length -eq 0 -or $length -ge $buffer.Length) { throw 'Unable to resolve Windows PowerShell path.' }
    $systemDirectory = [string]::new($buffer, 0, [int]$length)
    $candidate = [IO.Path]::GetFullPath((Join-Path $systemDirectory 'WindowsPowerShell\v1.0\powershell.exe'))
    if (-not (Test-Path -LiteralPath $candidate -PathType Leaf)) { throw 'Unable to resolve Windows PowerShell path.' }
    return $candidate
}

function Get-TaskIdentity {
    param([Parameter(Mandatory)][string]$Fingerprint)
    if ($Fingerprint -notmatch '^[0-9a-f]{12}$') { throw 'Invalid task fingerprint.' }
    return [pscustomobject]@{
        Fingerprint = $Fingerprint
        Name = "AstrBot Safe Backup $Fingerprint"
        Description = "AstrBotSafeBackup:v1:$Fingerprint"
    }
}

function Get-LauncherScheduleTime {
    param([Parameter(Mandatory)][string[]]$LauncherArguments)
    $matches = @()
    for ($i = 0; $i -lt $LauncherArguments.Count; $i++) {
        if ($LauncherArguments[$i] -eq '--schedule-time') {
            if ($i + 1 -ge $LauncherArguments.Count) { throw 'Invalid launcher arguments.' }
            $matches += $LauncherArguments[$i + 1]
            $i++
        }
    }
    if ($matches.Count -ne 1 -or $matches[0] -notmatch '^(?:[01]\d|2[0-3]):[0-5]\d$') {
        throw 'Invalid launcher arguments.'
    }
    return $matches[0]
}

function Resolve-TaskInputs {
    param(
        [Parameter(Mandatory)][string]$TaskName,
        [Parameter(Mandatory)][string]$Description,
        [Parameter(Mandatory)][string]$TaskFingerprint,
        [Parameter(Mandatory)][string]$LauncherPath,
        [Parameter(Mandatory)][string]$LauncherArgumentsJson
    )
    $identity = Get-TaskIdentity $TaskFingerprint
    if ($TaskName -ne $identity.Name -or $Description -ne $identity.Description) {
        throw 'Task identity mismatch.'
    }
    $expectedLauncher = Get-AbsolutePath (Join-Path $PSScriptRoot 'task_launcher.ps1') 'LauncherPath'
    $launcher = Assert-TrustedPluginFile $LauncherPath $expectedLauncher
    [void](Assert-TrustedPluginFile (Join-Path $PSScriptRoot 'run_backup_visible.ps1') (Join-Path $PSScriptRoot 'run_backup_visible.ps1'))
    try { $arguments = ConvertFrom-Json -InputObject $LauncherArgumentsJson -ErrorAction Stop }
    catch { throw 'Invalid launcher arguments.' }
    if ($arguments -isnot [Array] -or $arguments.Count -eq 0) { throw 'Invalid launcher arguments.' }
    $stringArguments = @($arguments | ForEach-Object {
        if ($_ -isnot [string]) { throw 'Invalid launcher arguments.' }
        $_
    })
    [void](Assert-BackupLauncherArguments $stringArguments)
    $scheduleTime = $stringArguments[11]
    return [pscustomobject]@{
        Identity = $identity
        LauncherPath = $launcher
        LauncherArguments = $stringArguments
        ScheduleTime = $scheduleTime
    }
}

function New-LauncherArgumentString {
    param([Parameter(Mandatory)][string]$LauncherPath, [Parameter(Mandatory)][string[]]$LauncherArguments)
    $parts = @('-NoProfile', '-NonInteractive', '-WindowStyle', 'Hidden', '-File', $LauncherPath) + $LauncherArguments
    return (($parts | ForEach-Object { Quote-TaskArgument ([string]$_) }) -join ' ')
}

function New-HiddenLauncherAction {
    param([Parameter(Mandatory)]$Resolved)
    return New-ScheduledTaskAction -Execute (Get-WindowsPowerShellPath) -Argument (New-LauncherArgumentString $Resolved.LauncherPath $Resolved.LauncherArguments)
}

function New-TaskTrigger {
    param([Parameter(Mandatory)]$Resolved)
    return New-ScheduledTaskTrigger -Daily -At ([datetime]::ParseExact($Resolved.ScheduleTime, 'HH:mm', [Globalization.CultureInfo]::InvariantCulture))
}

function Test-TaskArguments {
    param([Parameter(Mandatory)][string]$Actual, [Parameter(Mandatory)]$Resolved)
    try { $actualParts = @(ConvertFrom-TaskArgumentString $Actual) }
    catch { return $false }
    $expectedParts = @('-NoProfile', '-NonInteractive', '-WindowStyle', 'Hidden', '-File', $Resolved.LauncherPath) + @($Resolved.LauncherArguments)
    if ($actualParts.Count -ne $expectedParts.Count) { return $false }
    for ($i = 0; $i -lt $expectedParts.Count; $i++) {
        if ($actualParts[$i] -cne [string]$expectedParts[$i]) { return $false }
    }
    return $true
}

function Test-DailyTaskTrigger {
    param([Parameter(Mandatory)]$Trigger, [Parameter(Mandatory)][string]$ScheduleTime)
    $kind = if ($null -ne $Trigger.PSObject.Properties['Type']) { [string]$Trigger.Type } elseif ($null -ne $Trigger.CimClass) { [string]$Trigger.CimClass.CimClassName } else { '' }
    if ($kind -ne 'Daily' -and $kind -ne 'MSFT_TaskDailyTrigger') { return $false }
    if ($null -ne $Trigger.PSObject.Properties['DaysInterval'] -and [int]$Trigger.DaysInterval -ne 1) { return $false }
    try { return ([datetime]$Trigger.StartBoundary).ToString('HH:mm') -eq $ScheduleTime }
    catch { return $false }
}

function Test-ZeroExecutionTimeLimit {
    param([Parameter(Mandatory)]$Value)
    return ([string]$Value -eq 'PT0S' -or [string]$Value -eq '00:00:00' -or [string]$Value -eq '0')
}

function Test-CurrentUserIdentity {
    param([Parameter(Mandatory)][string]$UserId)
    try {
        $actual = (New-Object Security.Principal.NTAccount($UserId)).Translate([Security.Principal.SecurityIdentifier]).Value
        $current = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
        return [string]::Equals($actual, $current, [StringComparison]::OrdinalIgnoreCase)
    }
    catch { return $false }
}

function Test-OwnedTask {
    param([Parameter(Mandatory)]$Task, [Parameter(Mandatory)]$Resolved)
    if ($Task.TaskName -cne $Resolved.Identity.Name -or $Task.Description -cne $Resolved.Identity.Description) { return $false }
    $principal = $Task.Principal
    if ($null -eq $principal -or -not (Test-CurrentUserIdentity ([string]$principal.UserId))) { return $false }
    if ([string]$principal.RunLevel -ne 'Limited' -or [string]$principal.LogonType -ne 'Interactive') { return $false }
    $actions = @($Task.Actions)
    if ($actions.Count -ne 1 -or -not [string]::Equals([string]$actions[0].Execute, (Get-WindowsPowerShellPath), [StringComparison]::OrdinalIgnoreCase)) { return $false }
    if (-not (Test-TaskArguments $actions[0].Arguments $Resolved)) { return $false }
    $triggers = @($Task.Triggers)
    if ($triggers.Count -ne 1 -or -not (Test-DailyTaskTrigger $triggers[0] $Resolved.ScheduleTime)) { return $false }
    $settings = $Task.Settings
    if ($null -eq $settings -or [string]$settings.MultipleInstances -ne 'IgnoreNew' -or -not [bool]$settings.StartWhenAvailable -or [bool]$settings.WakeToRun) { return $false }
    return Test-ZeroExecutionTimeLimit $settings.ExecutionTimeLimit
}

function Test-TaskInvariant {
    param([Parameter(Mandatory)]$Task, [Parameter(Mandatory)]$Identity)
    if ($Task.TaskName -cne $Identity.Name -or $Task.Description -cne $Identity.Description) { return $false }
    $principal = $Task.Principal
    if ($null -eq $principal -or -not (Test-CurrentUserIdentity ([string]$principal.UserId))) { return $false }
    if ([string]$principal.RunLevel -ne 'Limited' -or [string]$principal.LogonType -ne 'Interactive') { return $false }
    $actions = @($Task.Actions)
    if ($actions.Count -ne 1 -or -not [string]::Equals([string]$actions[0].Execute, (Get-WindowsPowerShellPath), [StringComparison]::OrdinalIgnoreCase)) { return $false }
    try { $parts = @(ConvertFrom-TaskArgumentString ([string]$actions[0].Arguments)) }
    catch { return $false }
    $expectedLauncher = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot 'task_launcher.ps1'))
    return ($parts.Count -ge 7 -and $parts[0] -ceq '-NoProfile' -and $parts[1] -ceq '-NonInteractive' -and $parts[2] -ceq '-WindowStyle' -and $parts[3] -ceq 'Hidden' -and $parts[4] -ceq '-File' -and [string]::Equals([string]$parts[5], $expectedLauncher, [StringComparison]::OrdinalIgnoreCase))
}

function New-TaskPrincipalForCurrentUser {
    return New-ScheduledTaskPrincipal -UserId ([Security.Principal.WindowsIdentity]::GetCurrent().Name) -LogonType Interactive -RunLevel Limited
}

function New-TaskSettings {
    return New-ScheduledTaskSettingsSet -MultipleInstances IgnoreNew -StartWhenAvailable -WakeToRun:$false -ExecutionTimeLimit ([TimeSpan]::Zero)
}

function Write-TaskResult {
    param([Parameter(Mandatory)][string]$Operation, [Parameter(Mandatory)][string]$Fingerprint, [Parameter(Mandatory)][string]$Status, [Parameter(Mandatory)][int]$Code)
    [ordered]@{ operation=$Operation; fingerprint=$Fingerprint; status=$Status; code=$Code } | ConvertTo-Json -Compress
}
