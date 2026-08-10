[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$TaskName,
    [Parameter(Mandatory)][AllowEmptyString()][string]$Description,
    [Parameter(Mandatory)][string]$TaskFingerprint,
    [string]$ExpectedLauncherPath,
    [string]$ExpectedLauncherArgumentsJson,
    [string]$LauncherPath,
    [string]$LauncherArgumentsJson,
    [switch]$ValidateOnly,
    [switch]$Discover,
    [switch]$OutputJson,
    [ValidateSet('update','inspect')][string]$Operation = 'update'
)

. (Join-Path $PSScriptRoot 'task_common.ps1')
$fingerprint = if ($TaskFingerprint -match '^[0-9a-f]{12}$') { $TaskFingerprint } else { 'unknown' }
try {
    if ($Discover) {
        $identity = Get-TaskIdentity $TaskFingerprint
        if ($TaskName -ne $identity.Name -or $Description -ne $identity.Description) { throw 'Task identity mismatch.' }
        $task = Get-ScheduledTask -TaskName $identity.Name -ErrorAction SilentlyContinue
        if ($null -eq $task) {
            [ordered]@{ operation='discover'; fingerprint=$identity.Fingerprint; status='missing'; code=0 } | ConvertTo-Json -Compress
            exit 0
        }
        $parts = @()
        try { $parts = @(ConvertFrom-TaskArgumentString ([string]$task.Actions[0].Arguments)) }
        catch { [ordered]@{ operation='discover'; fingerprint=$identity.Fingerprint; status='foreign'; code=3 } | ConvertTo-Json -Compress; exit 3 }
        if ($parts.Count -lt 7 -or $parts[4] -cne '-File') {
            [ordered]@{ operation='discover'; fingerprint=$identity.Fingerprint; status='foreign'; code=3 } | ConvertTo-Json -Compress; exit 3
        }
        $arguments = @($parts[6..($parts.Count - 1)])
        $resolved = Resolve-TaskInputs -TaskName $TaskName -Description $Description -TaskFingerprint $TaskFingerprint -LauncherPath $parts[5] -LauncherArgumentsJson ($arguments | ConvertTo-Json -Compress)
        if (-not (Test-OwnedTask $task $resolved)) {
            [ordered]@{ operation='discover'; fingerprint=$identity.Fingerprint; status='foreign'; code=3 } | ConvertTo-Json -Compress
            exit 3
        }
        [ordered]@{ operation='discover'; fingerprint=$identity.Fingerprint; status='exact'; code=0; arguments=@($resolved.LauncherArguments) } | ConvertTo-Json -Compress
        exit 0
    }
    $resolved = Resolve-TaskInputs -TaskName $TaskName -Description $Description -TaskFingerprint $TaskFingerprint -LauncherPath $LauncherPath -LauncherArgumentsJson $LauncherArgumentsJson
    if ($Operation -ne 'inspect' -and (Get-SafeBackupArtifactDigest) -cne $resolved.LauncherArguments[-2]) { throw 'Plugin artifact digest mismatch.' }
    $expected = if ($ExpectedLauncherPath) {
        Resolve-TaskInputs -TaskName $TaskName -Description $Description -TaskFingerprint $TaskFingerprint -LauncherPath $ExpectedLauncherPath -LauncherArgumentsJson $ExpectedLauncherArgumentsJson
    } else { $resolved }
    $task = Get-ScheduledTask -TaskName $resolved.Identity.Name -ErrorAction SilentlyContinue
    if ($null -eq $task -or -not (Test-OwnedTask $task $expected)) { throw 'Task ownership mismatch.' }
    if ($ValidateOnly -or $Operation -eq 'inspect') {
        if (-not (Test-OwnedTask $task $resolved)) { throw 'Task specification mismatch.' }
        $status = if ($Operation -eq 'inspect') { 'inspected' } else { 'validated' }
        Write-TaskResult $Operation $resolved.Identity.Fingerprint $status 0
        exit 0
    }
    $priorState = [string]$task.State
    if ($priorState -notin @('Ready', 'Disabled')) { throw 'Task state is unsafe for update.' }
    Set-ScheduledTask -TaskName $resolved.Identity.Name -Action (New-HiddenLauncherAction $resolved) -Trigger (New-TaskTrigger $resolved) -Principal (New-TaskPrincipalForCurrentUser) -Settings (New-TaskSettings) | Out-Null
    if ($priorState -eq 'Disabled') {
        Disable-ScheduledTask -TaskName $resolved.Identity.Name | Out-Null
    }
    $after = Get-ScheduledTask -TaskName $resolved.Identity.Name -ErrorAction SilentlyContinue
    $stateMatches = $null -ne $after -and [string]$after.State -ceq $priorState
    if ($null -eq $after -or -not (Test-OwnedTask $after $resolved) -or -not $stateMatches) { throw 'Task postcondition mismatch.' }
    Write-TaskResult 'update' $resolved.Identity.Fingerprint 'updated' 0
}
catch { Write-TaskResult $Operation $fingerprint 'failed' 1; exit 1 }
