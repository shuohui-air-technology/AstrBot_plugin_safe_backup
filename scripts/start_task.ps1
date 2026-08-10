[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$TaskName,
    [Parameter(Mandatory)][string]$Description,
    [Parameter(Mandatory)][string]$TaskFingerprint,
    [Parameter(Mandatory)][string]$LauncherPath,
    [Parameter(Mandatory)][string]$LauncherArgumentsJson,
    [switch]$OutputJson
)

# This is deliberately an internal helper, not a public task-management
# command.  It never creates, changes, removes, enables, or disables a task.
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'task_common.ps1')
$fingerprint = if ($TaskFingerprint -match '^[0-9a-f]{12}$') { $TaskFingerprint } else { 'unknown' }
try {
    $resolved = Resolve-TaskInputs -TaskName $TaskName -Description $Description -TaskFingerprint $TaskFingerprint -LauncherPath $LauncherPath -LauncherArgumentsJson $LauncherArgumentsJson
    if ((Get-SafeBackupArtifactDigest) -cne $resolved.LauncherArguments[-2]) { throw 'Plugin artifact digest mismatch.' }
    $task = Get-ScheduledTask -TaskName $resolved.Identity.Name -ErrorAction SilentlyContinue
    if ($null -eq $task -or -not (Test-OwnedTask $task $resolved)) { throw 'Task ownership mismatch.' }
    Start-ScheduledTask -TaskName $resolved.Identity.Name
    $after = Get-ScheduledTask -TaskName $resolved.Identity.Name -ErrorAction SilentlyContinue
    if ($null -eq $after -or -not (Test-OwnedTask $after $resolved)) { throw 'Task postcondition mismatch.' }
    Write-TaskResult 'trigger' $resolved.Identity.Fingerprint 'triggered' 0
}
catch { Write-TaskResult 'trigger' $fingerprint 'failed' 1; exit 1 }
