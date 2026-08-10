[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$SourceDirectory,
    [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$OutputDirectory,
    [switch]$ValidateOnly,
    [string]$PythonPath = 'python'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
try {
    $helper = Join-Path $PSScriptRoot 'release_packager.py'
    if (-not (Test-Path -LiteralPath $helper -PathType Leaf)) { throw 'Release helper missing.' }
    $arguments = @($helper, '--source', $SourceDirectory, '--output', $OutputDirectory)
    if ($ValidateOnly) { $arguments += '--validate-only' }
    & $PythonPath @arguments
    if ($LASTEXITCODE -ne 0) { exit 1 }
    exit 0
}
catch {
    Write-Error 'Release package was not created.'
    exit 1
}
