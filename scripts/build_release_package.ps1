[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$SourceDirectory,
    [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$OutputDirectory,
    [switch]$ValidateOnly,
    [string]$PythonPath = 'python'
)

# This release-authoring wrapper creates astrbot_plugin_safe_backup-v0.1.0-beta.zip
# plus its .sha256 sidecar only in its explicit output directory; it makes no changes to AstrBot. The Python helper
# applies the exact allowlist and object-identity gates before it writes only
# the explicit output directory.
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
