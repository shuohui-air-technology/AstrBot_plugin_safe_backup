[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$TaskName,
    [Parameter(Mandatory)][string]$Description,
    [Parameter(Mandatory)][string]$TaskFingerprint,
    [Parameter(Mandatory)][string]$LauncherPath,
    [Parameter(Mandatory)][string]$LauncherArgumentsJson,
    [switch]$ValidateOnly,
    [switch]$OutputJson
)

. (Join-Path $PSScriptRoot 'task_common.ps1')
$fingerprint = if ($TaskFingerprint -match '^[0-9a-f]{12}$') { $TaskFingerprint } else { 'unknown' }
try {
    $resolved = Resolve-TaskInputs -TaskName $TaskName -Description $Description -TaskFingerprint $TaskFingerprint -LauncherPath $LauncherPath -LauncherArgumentsJson $LauncherArgumentsJson
    $task = Get-ScheduledTask -TaskName $resolved.Identity.Name -ErrorAction SilentlyContinue
    if ($null -eq $task -or -not (Test-OwnedTask $task $resolved)) { throw 'Task ownership mismatch.' }
    if ($ValidateOnly) { Write-TaskResult 'remove' $resolved.Identity.Fingerprint 'validated' 0; exit 0 }
    Unregister-ScheduledTask -TaskName $resolved.Identity.Name -Confirm:$false
    Write-TaskResult 'remove' $resolved.Identity.Fingerprint 'removed' 0
}
catch { Write-TaskResult 'remove' $fingerprint 'failed' 1; exit 1 }
