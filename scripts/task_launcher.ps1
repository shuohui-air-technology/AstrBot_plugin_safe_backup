[CmdletBinding()]
param(
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$EngineArguments
)

# The scheduled task starts this script hidden.  It makes only the inexpensive
# target-side decision.  A due or unsafe decision is deliberately transferred
# to one ordinary visible PowerShell process, then waited for so IgnoreNew
# remains an effective second concurrency gate.
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'task_common.ps1')

try {
    $launcherPath = Assert-TrustedPluginFile $PSCommandPath (Join-Path $PSScriptRoot 'task_launcher.ps1')
    $runnerPath = Assert-TrustedPluginFile (Join-Path $PSScriptRoot 'run_backup_visible.ps1') (Join-Path $PSScriptRoot 'run_backup_visible.ps1')
    $enginePath = Assert-TrustedPluginFile (Join-Path $PSScriptRoot '..\safe_backup\engine.py') (Join-Path $PSScriptRoot '..\safe_backup\engine.py')
    $parts = Assert-BackupLauncherArguments $EngineArguments
    if ((Get-SafeBackupArtifactDigest) -cne $parts.ArtifactDigest) { throw 'Plugin artifact digest mismatch.' }
    $pythonPath = $parts.PythonPath
    $normalArguments = @($parts.EngineArguments)
    $probeArguments = @($normalArguments) + '--scheduled-probe'
    try {
        & $pythonPath '-B' $enginePath @probeArguments *> $null
        $probeExit = [int]$LASTEXITCODE
    }
    catch {
        $probeExit = 3
    }
    if ($probeExit -eq 0) { exit 0 }
    if ($probeExit -notin @(10, 3)) { $probeExit = 3 }
    $runnerArguments = @(
        '-NoProfile', '-NonInteractive', '-File', $runnerPath,
        '-PythonPath', $pythonPath, '-EnginePath', $enginePath,
        '-ProbeCode', [string]$probeExit
    ) + $normalArguments
    $process = Start-Process -Wait -PassThru -FilePath (Get-WindowsPowerShellPath) -ArgumentList (New-ProcessArgumentString $runnerArguments) -WindowStyle Normal
    if ($null -eq $process -or $null -eq $process.ExitCode) { exit 3 }
    exit [int]$process.ExitCode
}
catch {
    exit 3
}
