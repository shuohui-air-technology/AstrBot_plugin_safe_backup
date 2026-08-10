[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$PythonPath,
    [Parameter(Mandatory)][string]$EnginePath,
    [Parameter(Mandatory)][ValidateSet('3', '10')][string]$ProbeCode,
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$EngineArguments
)

# Task 6 adds sanitized progress rendering.  This thin runner already provides
# the important behavior: every actual attempt owns a visible terminal and its
# exact exit status is returned to Task Scheduler.
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'task_common.ps1')

try {
    $runnerPath = Assert-TrustedPluginFile $PSCommandPath (Join-Path $PSScriptRoot 'run_backup_visible.ps1')
    $trustedEngine = Assert-TrustedPluginFile $EnginePath (Join-Path $PSScriptRoot '..\safe_backup\engine.py')
    $consoleRunner = Assert-TrustedPluginFile (Join-Path $PSScriptRoot '..\safe_backup\console_runner.py') (Join-Path $PSScriptRoot '..\safe_backup\console_runner.py')
    $parts = Assert-BackupLauncherArguments $EngineArguments
    if ((Get-SafeBackupArtifactDigest) -cne $parts.ArtifactDigest) { throw 'Plugin artifact digest mismatch.' }
    if (-not [string]::Equals($parts.PythonPath, $PythonPath, [StringComparison]::OrdinalIgnoreCase)) {
        throw 'Runner argument mismatch.'
    }
    [Console]::OutputEncoding = [Text.UTF8Encoding]::new($false)
    & $PythonPath '-B' $consoleRunner @($parts.EngineArguments)
    if ($null -eq $LASTEXITCODE) { exit 3 }
    exit [int]$LASTEXITCODE
}
catch {
    exit 3
}
