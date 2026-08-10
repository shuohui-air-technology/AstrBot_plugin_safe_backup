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
    if ((Get-SafeBackupArtifactDigest) -cne $resolved.LauncherArguments[-2]) { throw 'Plugin artifact digest mismatch.' }
    if ($null -ne (Get-ScheduledTask -TaskName $resolved.Identity.Name -ErrorAction SilentlyContinue)) { throw 'Task already exists; refusing to overwrite.' }
    if ($ValidateOnly) { Write-TaskResult 'install' $resolved.Identity.Fingerprint 'validated' 0; exit 0 }
    Register-ScheduledTask -TaskName $resolved.Identity.Name -Description $resolved.Identity.Description -Action (New-HiddenLauncherAction $resolved) -Trigger (New-TaskTrigger $resolved) -Principal (New-TaskPrincipalForCurrentUser) -Settings (New-TaskSettings) | Out-Null
    Write-TaskResult 'install' $resolved.Identity.Fingerprint 'installed' 0
}
catch { Write-TaskResult 'install' $fingerprint 'failed' 1; exit 1 }
