[CmdletBinding()]
param(
    [ValidateSet('Menu', 'Status', 'Run', 'SetDestination', 'ClearDestination')]
    [string]$Action = 'Menu',
    [string]$Destination,
    [string]$TaskName,
    [switch]$NoPause
)

# This is a local, visible operator tool.  It never changes a Scheduled Task,
# never deletes an archive, and never starts AstrBot.  A saved destination is
# only a manual-run preference; the scheduled task keeps its own target until
# the administrator explicitly changes the plugin configuration and runs the
# normal task-update command.
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

. (Join-Path $PSScriptRoot 'task_common.ps1')

function Write-Ui {
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Text,
          [ConsoleColor]$Color = [ConsoleColor]::Gray)
    try { Write-Host $Text -ForegroundColor $Color }
    catch { Write-Output $Text }
}

function Get-FileSha256 {
    param([Parameter(Mandatory)][string]$Path)
    $stream = [IO.File]::Open($Path, [IO.FileMode]::Open, [IO.FileAccess]::Read,
        ([IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete))
    try {
        $hash = [Security.Cryptography.SHA256]::Create().ComputeHash($stream)
        return (($hash | ForEach-Object { $_.ToString('x2') }) -join '')
    }
    finally { $stream.Dispose() }
}

function Get-StringSha256 {
    param([Parameter(Mandatory)][string]$Value)
    $bytes = [Text.Encoding]::UTF8.GetBytes($Value)
    $hash = [Security.Cryptography.SHA256]::Create().ComputeHash($bytes)
    return (($hash | ForEach-Object { $_.ToString('x2') }) -join '')
}

function Format-Bytes {
    param([long]$Bytes)
    if ($Bytes -lt 1KB) { return "${Bytes} B" }
    if ($Bytes -lt 1MB) { return ('{0:N1} KiB' -f ($Bytes / 1KB)) }
    if ($Bytes -lt 1GB) { return ('{0:N2} MiB' -f ($Bytes / 1MB)) }
    return ('{0:N2} GiB' -f ($Bytes / 1GB))
}

function Get-TaskFingerprintFromName {
    param([Parameter(Mandatory)][string]$TaskName)
    if ($TaskName -notmatch '^AstrBot Safe Backup ([0-9a-f]{12})$') {
        throw '未找到唯一的受管 AstrBot Safe Backup 任务。'
    }
    return $Matches[1]
}

function Get-BackupTaskContext {
    $pluginRoot = [IO.DirectoryInfo]$PSScriptRoot
    $astrbotRoot = $pluginRoot.Parent.Parent.Parent.Parent
    if ($null -eq $astrbotRoot -or $astrbotRoot.Name -eq '') { throw '无法从插件位置确定 AstrBot 根目录。' }
    $rootKey = [IO.Path]::GetFullPath($astrbotRoot.FullName).TrimEnd('\').ToLowerInvariant()
    $fingerprint = (Get-StringSha256 $rootKey).Substring(0, 12)
    $identity = Get-TaskIdentity $fingerprint
    if (-not [string]::IsNullOrWhiteSpace($TaskName) -and $TaskName -cne $identity.Name) {
        throw '指定任务名与当前插件实例不匹配。'
    }
    $task = Get-ScheduledTask -TaskPath '\' -TaskName $identity.Name -ErrorAction SilentlyContinue
    if ($null -eq $task) { throw "未找到受管任务：$($identity.Name)" }
    $actions = @($task.Actions)
    if ($actions.Count -ne 1) { throw '任务动作数量不符合受管规格。' }
    $expectedPowerShell = Get-WindowsPowerShellPath
    if (-not [string]::Equals([string]$actions[0].Execute, $expectedPowerShell, [StringComparison]::OrdinalIgnoreCase)) {
        throw '任务动作不是受信任的 Windows PowerShell。'
    }
    $parts = @(ConvertFrom-TaskArgumentString ([string]$actions[0].Arguments))
    if ($parts.Count -lt 7 -or $parts[0] -cne '-NoProfile' -or $parts[1] -cne '-NonInteractive' -or $parts[2] -cne '-WindowStyle' -or $parts[3] -cne 'Hidden' -or $parts[4] -cne '-File') {
        throw '任务动作参数不是受管格式。'
    }
    $expectedLauncher = Get-AbsolutePath (Join-Path $PSScriptRoot 'task_launcher.ps1') 'LauncherPath'
    $launcher = Assert-TrustedPluginFile $parts[5] $expectedLauncher
    $launcherArgs = @($parts | Select-Object -Skip 6)
    $parsed = Assert-BackupLauncherArguments $launcherArgs
    $resolved = Resolve-TaskInputs -TaskName $task.TaskName -Description ([string]$task.Description) -TaskFingerprint $fingerprint -LauncherPath $launcher -LauncherArgumentsJson ($launcherArgs | ConvertTo-Json -Compress)
    $owned = Test-OwnedTask $task $resolved
    $info = Get-ScheduledTaskInfo -TaskName $task.TaskName -TaskPath '\' -ErrorAction SilentlyContinue
    $destinationArg = $null
    for ($i = 0; $i -lt $parsed.EngineArguments.Count; $i++) {
        if ($parsed.EngineArguments[$i] -ceq '--destination' -and $i + 1 -lt $parsed.EngineArguments.Count) {
            $destinationArg = [string]$parsed.EngineArguments[$i + 1]
        }
    }
    if ([string]::IsNullOrWhiteSpace($destinationArg)) { throw '任务没有可用的备份目标。' }
    return [pscustomobject]@{
        Task = $task
        Info = $info
        Fingerprint = $fingerprint
        Owned = $owned
        Launcher = $launcher
        LauncherArguments = $launcherArgs
        Parsed = $parsed
        ScheduledDestination = [IO.DirectoryInfo](Get-AbsolutePath $destinationArg 'ScheduledDestination')
        ConsoleRunner = Assert-TrustedPluginFile (Join-Path $PSScriptRoot '..\safe_backup\console_runner.py') (Join-Path $PSScriptRoot '..\safe_backup\console_runner.py')
    }
}

function Get-ManualPreferencePath {
    $base = [Environment]::GetFolderPath('LocalApplicationData')
    if ([string]::IsNullOrWhiteSpace($base)) { throw '无法确定本机应用数据目录。' }
    return Join-Path $base 'AstrBotSafeBackup\manual-target.json'
}

function Get-EngineArgumentValue {
    param([Parameter(Mandatory)]$Arguments, [Parameter(Mandatory)][string]$Name)
    for ($i = 0; $i -lt $Arguments.Count; $i++) {
        if ([string]$Arguments[$i] -ceq $Name -and $i + 1 -lt $Arguments.Count) {
            return [string]$Arguments[$i + 1]
        }
    }
    throw "任务动作缺少参数：$Name"
}

function Get-ManualPreference {
    param([Parameter(Mandatory)]$Context)
    $path = Get-ManualPreferencePath
    if (-not [IO.File]::Exists($path)) { return $null }
    try {
        $value = Get-Content -LiteralPath $path -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
        if ([string]$value.task_fingerprint -cne $Context.Fingerprint) { return $null }
        if ([string]::IsNullOrWhiteSpace([string]$value.destination)) { return $null }
        [IO.DirectoryInfo]$candidate = Get-AbsolutePath ([string]$value.destination) 'ManualDestination'
        Assert-ManualDestination $candidate $Context | Out-Null
        return $candidate
    }
    catch { return $null }
}

function Assert-ManualDestination {
    param([Parameter(Mandatory)][IO.DirectoryInfo]$Candidate,
          [Parameter(Mandatory)]$Context)
    $candidateText = $Candidate.FullName
    $source = [string]$Context.Parsed.EngineArguments[1]
    $napcat = $null
    for ($i = 0; $i -lt $Context.Parsed.EngineArguments.Count; $i++) {
        if ($Context.Parsed.EngineArguments[$i] -ceq '--napcat-root' -and $i + 1 -lt $Context.Parsed.EngineArguments.Count) {
            $napcat = [string]$Context.Parsed.EngineArguments[$i + 1]
        }
    }
    $sourcePath = Get-AbsolutePath $source 'AstrBotRoot'
    $sourceKey = [IO.Path]::GetFullPath([string]$sourcePath).TrimEnd('\').ToLowerInvariant()
    $candidateKey = [IO.Path]::GetFullPath($candidateText).TrimEnd('\').ToLowerInvariant()
    if ($candidateKey -eq $sourceKey -or $candidateKey.StartsWith($sourceKey + '\')) {
        throw '手动目标不能位于 AstrBot 源目录内。'
    }
    if ($null -ne $napcat) {
        $napcatPath = Get-AbsolutePath $napcat 'NapCatRoot'
        $napcatKey = [IO.Path]::GetFullPath([string]$napcatPath).TrimEnd('\').ToLowerInvariant()
        if ($candidateKey -eq $napcatKey -or $candidateKey.StartsWith($napcatKey + '\')) {
            throw '手动目标不能位于 NapCat 源目录内。'
        }
    }
    if ([IO.Path]::GetPathRoot($candidateText).TrimEnd('\') -eq $candidateText.TrimEnd('\')) {
        throw '手动目标不能是卷根目录。'
    }
    if ([IO.File]::Exists($candidateText)) { throw '手动目标已是文件。' }
    if ([IO.Directory]::Exists($candidateText)) {
        $item = Get-Item -LiteralPath $candidateText -Force
        if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw '手动目标不能是重解析点。' }
        $children = @(Get-ChildItem -LiteralPath $candidateText -Force -ErrorAction Stop)
        $scheduledKey = [IO.Path]::GetFullPath($Context.ScheduledDestination.FullName).TrimEnd('\').ToLowerInvariant()
        if ($candidateKey -ne $scheduledKey -and $children.Count -gt 0) {
            throw '新的手动目标必须不存在或为空目录；不会接管已有内容。'
        }
    }
    else {
        $parentItem = [IO.Directory]::GetParent($candidateText)
        if ($null -eq $parentItem -or -not $parentItem.Exists) {
            throw '新的手动目标父目录必须已存在；脚本不会递归创建未知路径。'
        }
        if (($parentItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw '手动目标父目录不能是重解析点。' }
    }
    return $true
}

function Set-ManualPreference {
    param([Parameter(Mandatory)]$Context, [Parameter(Mandatory)][string]$Value)
    [IO.DirectoryInfo]$candidate = Get-AbsolutePath $Value 'ManualDestination'
    Assert-ManualDestination $candidate $Context | Out-Null
    $path = Get-ManualPreferencePath
    $parentItem = [IO.Directory]::GetParent($path)
    if ($null -eq $parentItem) { throw '无法确定手动目标设置目录。' }
    if (-not $parentItem.Exists) { [IO.Directory]::CreateDirectory($parentItem.FullName) | Out-Null }
    $payload = [ordered]@{
        schema = 1
        task_fingerprint = $Context.Fingerprint
        destination = $candidate.FullName
        saved_at = [DateTimeOffset]::Now.ToString('o')
    } | ConvertTo-Json -Compress
    $temporary = Join-Path $parentItem.FullName ('.manual-target-' + [Guid]::NewGuid().ToString('N') + '.tmp')
    Set-Content -LiteralPath $temporary -Value $payload -Encoding UTF8 -NoNewline
    Move-Item -LiteralPath $temporary -Destination $path -Force
    return $candidate
}

function Remove-ManualPreference {
    $path = Get-ManualPreferencePath
    if ([IO.File]::Exists($path)) { Remove-Item -LiteralPath $path -Force -ErrorAction Stop }
}

function Get-StateObject {
    param([Parameter(Mandatory)][IO.DirectoryInfo]$Destination)
    $statePath = Join-Path $Destination.FullName 'state.json'
    if (-not [IO.File]::Exists($statePath)) { return $null }
    try { return (Get-Content -LiteralPath $statePath -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop) }
    catch { return $null }
}

function Get-JsonValue {
    param([Parameter(Mandatory)]$Object, [Parameter(Mandatory)][string]$Name,
          [AllowEmptyString()][string]$Fallback = '未知')
    $property = $Object.PSObject.Properties[$Name]
    if ($null -eq $property -or $null -eq $property.Value) { return $Fallback }
    return [string]$property.Value
}

function Test-ManagedArchiveName {
    param([Parameter(Mandatory)][string]$Name)
    return $Name -match '^astrbot-safe-backup-[0-9]{8}-[0-9]{6}-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\.zip$'
}

function Show-Status {
    param([Parameter(Mandatory)]$Context)
    $scheduled = $Context.ScheduledDestination
    $manual = Get-ManualPreference $Context
    $target = if ($null -ne $manual) { $manual } else { $scheduled }
    $state = Get-StateObject $target
    $archiveDir = $null
    $archives = @()
    $partialArchives = @()
    $unknownZipCount = 0
    $totalBytes = 0L
    $latest = $null
    $latestSha = '未知'
    $shaMatch = '未知'
    if ($null -ne $state -and [string]$state.owner_uuid -match '^[0-9a-fA-F-]{36}$') {
        $archiveDir = Join-Path $target.FullName ('managed\' + [string]$state.owner_uuid)
        if ([IO.Directory]::Exists($archiveDir)) {
            $allZipEntries = @(Get-ChildItem -LiteralPath $archiveDir -Filter '*.zip' -File -Force -ErrorAction SilentlyContinue)
            $archives = @($allZipEntries | Where-Object { Test-ManagedArchiveName $_.Name })
            $partialArchives = @($allZipEntries | Where-Object { $_.Name -like '*.partial.zip' })
            $unknownZipCount = $allZipEntries.Count - $archives.Count
            foreach ($archive in $archives) { $totalBytes += [long]$archive.Length }
            if (-not [string]::IsNullOrWhiteSpace([string]$state.last_successful_archive)) {
                $latest = $archives | Where-Object { $_.Name -ceq [string]$state.last_successful_archive } | Select-Object -First 1
                if ($null -ne $latest) {
                    try {
                        $latestSha = Get-FileSha256 $latest.FullName
                        $shaMatch = if ($latestSha -ieq [string]$state.last_successful_archive_sha256) { '匹配' } else { '不匹配' }
                    } catch { $shaMatch = '无法读取' }
                }
            }
        }
    }
    $staging = @(if ([IO.Directory]::Exists((Join-Path $target.FullName 'staging'))) { Get-ChildItem -LiteralPath (Join-Path $target.FullName 'staging') -Force -ErrorAction SilentlyContinue })
    $logs = @(if ([IO.Directory]::Exists((Join-Path $target.FullName 'logs'))) { Get-ChildItem -LiteralPath (Join-Path $target.FullName 'logs') -File -Force -ErrorAction SilentlyContinue })
    $diagnostics = @(if ([IO.Directory]::Exists((Join-Path $target.FullName 'diagnostics'))) { Get-ChildItem -LiteralPath (Join-Path $target.FullName 'diagnostics') -File -Force -ErrorAction SilentlyContinue })
    $free = '未知'
    try { $free = Format-Bytes ([IO.DriveInfo]::new([IO.Path]::GetPathRoot($target.FullName)).AvailableFreeSpace) } catch { }
    $next = if ($null -ne $Context.Info) { Get-JsonValue $Context.Info 'NextRunTime' '未知' } else { '未知' }
    $last = if ($null -ne $Context.Info) { Get-JsonValue $Context.Info 'LastRunTime' '未知' } else { '未知' }
    $lastResult = if ($null -ne $Context.Info) { Get-JsonValue $Context.Info 'LastTaskResult' '未知' } else { '未知' }
    Write-Ui ''
    Write-Ui '========== AstrBot 安全备份 · 手动控制台 ==========' ([ConsoleColor]::Cyan)
    Write-Ui ("计划任务：{0}  | 状态：{1}  | 身份：{2}" -f $Context.Task.TaskName, $Context.Task.State, ($(if ($Context.Owned) { '已验证' } else { '不可信/停止操作' })))
    Write-Ui ("下一次计划尝试：{0}" -f $next)
    Write-Ui ("上次任务结果：{0}  | 上次运行：{1}" -f $lastResult, $last)
    Write-Ui ("计划任务目标：{0}" -f $scheduled.FullName)
    Write-Ui ("手动执行目标：{0}" -f $target.FullName)
    Write-Ui '提示：手动快照不计入自动备份周期，也不触发自动保留清理。' ([ConsoleColor]::Yellow)
    if ($null -ne $manual -and $manual.FullName -ine $scheduled.FullName) { Write-Ui '提示：手动目标已切换；不会改动计划任务目标。' ([ConsoleColor]::Yellow) }
    Write-Ui ("正式归档 ZIP：{0} 个，合计 {1}；部分/未知 ZIP：{2}/{3}；暂存项：{4}；日志：{5}；诊断：{6}" -f $archives.Count, (Format-Bytes $totalBytes), $partialArchives.Count, $unknownZipCount, $staging.Count, $logs.Count, $diagnostics.Count)
    Write-Ui ("最近成功归档：{0}" -f ($(if ($null -ne $latest) { $latest.Name } else { '无' })))
    Write-Ui ("最近归档 SHA-256：{0}（状态绑定：{1}）" -f $latestSha, $shaMatch)
    if ($null -ne $state) {
        $retentionValues = @()
        $retentionProperty = $state.PSObject.Properties['retention_candidates']
        if ($null -ne $retentionProperty -and $null -ne $retentionProperty.Value) { $retentionValues = @($retentionProperty.Value) }
        Write-Ui ("状态：{0}  | 修订：{1}  | 最近成功周期：{2}" -f (Get-JsonValue $state 'last_result'), (Get-JsonValue $state 'state_revision'), (Get-JsonValue $state 'last_successful_cycle' '无'))
        $keep = Get-EngineArgumentValue $Context.Parsed.EngineArguments '--keep'
        Write-Ui ("保留候选：{0} 个（按配置上限 {1}；不会接管无法证明归属的 ZIP）" -f $retentionValues.Count, $keep)
    }
    else { Write-Ui '状态：尚未在当前手动目标建立可信账本。' ([ConsoleColor]::Yellow) }
    Write-Ui ("目标卷可用空间：{0}  | 模式：Windows 冷备份；AstrBot 必须先正常退出" -f $free)
    Write-Ui '====================================================' ([ConsoleColor]::Cyan)
}

function Invoke-ManualBackup {
    param([Parameter(Mandatory)]$Context, [string]$OverrideDestination)
    $target = if (-not [string]::IsNullOrWhiteSpace($OverrideDestination)) {
        [IO.DirectoryInfo]$candidate = Get-AbsolutePath $OverrideDestination 'ManualDestination'
        Assert-ManualDestination $candidate $Context | Out-Null
        $candidate
    } else {
        $saved = Get-ManualPreference $Context
        if ($null -ne $saved) { $saved } else { $Context.ScheduledDestination }
    }
    if (-not $Context.Owned) { throw '计划任务身份未验证，拒绝手动执行。' }
    if ((Get-SafeBackupArtifactDigest) -cne $Context.Parsed.ArtifactDigest) { throw '插件运行文件摘要不匹配，拒绝手动执行。' }
    $arguments = [Collections.Generic.List[string]]::new()
    for ($i = 0; $i -lt $Context.Parsed.EngineArguments.Count; $i++) {
        $value = [string]$Context.Parsed.EngineArguments[$i]
        if ($value -ceq '--scheduled') { continue }
        if ($value -ceq '--destination' -and $i + 1 -lt $Context.Parsed.EngineArguments.Count) {
            [void]$arguments.Add('--destination'); [void]$arguments.Add($target.FullName); $i++; continue
        }
        [void]$arguments.Add($value)
    }
    [void]$arguments.Add('--force')
    [void]$arguments.Add('--manual')
    Write-Ui ''
    Write-Ui '即将开始一次可视化手动冷备份。' ([ConsoleColor]::Yellow)
    Write-Ui '本次会读取源目录；请先正常退出 AstrBot。不会终止、暂停或强杀进程。' ([ConsoleColor]::Yellow)
    Write-Ui ("本次目标：{0}" -f $target.FullName)
    Write-Ui '开始后将显示七阶段进度；不要关闭窗口。' ([ConsoleColor]::Cyan)
    [Console]::OutputEncoding = [Text.UTF8Encoding]::new($false)
    & $Context.Parsed.PythonPath '-B' $Context.ConsoleRunner @($arguments.ToArray())
    $exitCode = if ($null -eq $LASTEXITCODE) { 3 } else { [int]$LASTEXITCODE }
    Write-Ui ("可视化备份进程退出码：{0}" -f $exitCode) ($(if ($exitCode -eq 0) { [ConsoleColor]::Green } else { [ConsoleColor]::Red }))
    return $exitCode
}

function Run-Menu {
    while ($true) {
        $context = Get-BackupTaskContext
        Show-Status $context
        Write-Ui '操作：1=立即备份  2=更换本次手动目标  3=清除手动目标  4=刷新  Q=退出' ([ConsoleColor]::White)
        $choice = (Read-Host '请选择').Trim().ToUpperInvariant()
        if ($choice -eq 'Q') { return 0 }
        try {
            if ($choice -eq '1') { [void](Invoke-ManualBackup $context); if (-not $NoPause) { [void](Read-Host '按 Enter 返回状态面板') } }
            elseif ($choice -eq '2') { $value = Read-Host '输入新的本次手动目标绝对路径'; $saved = Set-ManualPreference $context $value; Write-Ui ("已保存手动目标：{0}" -f $saved.FullName) ([ConsoleColor]::Green); if (-not $NoPause) { [void](Read-Host '按 Enter 继续') } }
            elseif ($choice -eq '3') { Remove-ManualPreference; Write-Ui '已清除手动目标，将恢复使用计划任务目标。' ([ConsoleColor]::Green); if (-not $NoPause) { [void](Read-Host '按 Enter 继续') } }
            elseif ($choice -eq '4') { continue }
            else { Write-Ui '无效选择。' ([ConsoleColor]::Yellow) }
        }
        catch { Write-Ui ("操作未执行：{0}" -f $_.Exception.Message) ([ConsoleColor]::Red); if (-not $NoPause) { [void](Read-Host '按 Enter 返回') } }
    }
}

$exitCode = 0
try {
    $context = Get-BackupTaskContext
    switch ($Action) {
        'Status' { Show-Status $context }
        'Run' { $exitCode = Invoke-ManualBackup $context $Destination }
        'SetDestination' { if ([string]::IsNullOrWhiteSpace($Destination)) { throw '-Destination 必须填写。' }; $saved = Set-ManualPreference $context $Destination; Write-Ui ("已保存手动目标：{0}" -f $saved.FullName) ([ConsoleColor]::Green) }
        'ClearDestination' { Remove-ManualPreference; Write-Ui '已清除手动目标，将恢复使用计划任务目标。' ([ConsoleColor]::Green) }
        default { $exitCode = Run-Menu }
    }
}
catch {
    $exitCode = 3
    Write-Ui ("无法安全执行：{0}" -f $_.Exception.Message) ([ConsoleColor]::Red)
}
finally {
    if (-not $NoPause -and $Action -ne 'Menu') { [void](Read-Host '按 Enter 关闭窗口') }
}
exit $exitCode
