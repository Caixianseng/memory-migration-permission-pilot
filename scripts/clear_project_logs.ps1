<#
.SYNOPSIS
Inventory or clear this project's console/debug log files without deleting results.
.DESCRIPTION
Only root-level *.log / *.log.* files, files under results/, and four explicitly
known local runtime logs are candidates. Reparse points are never followed.
Report JSON, request transports, auth events, datasets, code, models and Git
history are preserved. A failed delete may fall back to truncating that file;
services are never stopped. No log contents enter the receipt.
#>
[CmdletBinding()]
param(
    [ValidateSet('Inventory', 'Clear')]
    [string]$Mode = 'Inventory',
    [string]$ProjectRoot,
    [string]$ReceiptPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Get-NormalPath([string]$Path) {
    return [System.IO.Path]::GetFullPath($Path).TrimEnd([char[]]@('\', '/'))
}

function Test-InBoundary([string]$Path, [string]$Boundary) {
    return $Path.Equals($Boundary, [StringComparison]::OrdinalIgnoreCase) -or
        $Path.StartsWith($Boundary + [System.IO.Path]::DirectorySeparatorChar,
            [StringComparison]::OrdinalIgnoreCase)
}

function Assert-NoReparseAncestor([string]$Path, [string]$Boundary) {
    if (-not (Test-InBoundary $Path $Boundary)) {
        throw 'Resolved path leaves the permitted project boundary.'
    }
    $cursor = $Path
    while ($true) {
        if (Test-Path -LiteralPath $cursor) {
            $item = Get-Item -LiteralPath $cursor -Force
            if (($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw 'Reparse-point paths are outside the cleanup scope.'
            }
        }
        if ($cursor.Equals($Boundary, [StringComparison]::OrdinalIgnoreCase)) { break }
        $parent = [System.IO.Path]::GetDirectoryName($cursor)
        if ([string]::IsNullOrEmpty($parent) -or $parent -eq $cursor) {
            throw 'Could not verify the cleanup path boundary.'
        }
        $cursor = $parent
    }
}

function Get-RelativeProjectPath([string]$Path) {
    return $Path.Substring($root.Length + 1).Replace('\', '/')
}

function Test-LogName([string]$Name) {
    return $Name -match '(?i)\.log(?:\..+)?$'
}

$repository = Get-NormalPath (Join-Path $PSScriptRoot '..')
if ([string]::IsNullOrWhiteSpace($ProjectRoot)) { $ProjectRoot = $repository }
$requestedRoot = Get-NormalPath $ProjectRoot
if (-not (Test-InBoundary $requestedRoot $repository)) {
    throw 'ProjectRoot must be this repository or one of its internal subdirectories.'
}
Assert-NoReparseAncestor $requestedRoot $repository
$rootItem = Get-Item -LiteralPath $requestedRoot -Force
if (-not $rootItem.PSIsContainer) { throw 'ProjectRoot must be an existing directory.' }
$root = Get-NormalPath $rootItem.FullName

$relativeReceipt = if ($Mode -eq 'Clear') {
    'results/log_cleanup_20261025/cleanup_receipt.json'
} else {
    'results/log_cleanup_20261025/inventory_receipt.json'
}
if ([string]::IsNullOrWhiteSpace($ReceiptPath)) {
    $receipt = Get-NormalPath (Join-Path $root $relativeReceipt)
} elseif ([System.IO.Path]::IsPathRooted($ReceiptPath)) {
    $receipt = Get-NormalPath $ReceiptPath
} else {
    $receipt = Get-NormalPath (Join-Path $root $ReceiptPath)
}
$resultsRoot = Get-NormalPath (Join-Path $root 'results')
if (-not (Test-InBoundary $receipt $resultsRoot) -or
    [System.IO.Path]::GetExtension($receipt) -ne '.json') {
    throw 'ReceiptPath must be a JSON file inside ProjectRoot/results/.'
}
Assert-NoReparseAncestor $receipt $root

$candidateMap = @{}
$skippedReparse = [System.Collections.Generic.List[string]]::new()
$protectedDirectoryNames = @('.git', '.runtime', '.venv', '.venv-native-webui', 'venv',
    'node_modules', 'site-packages', 'datasets', 'fixtures', 'tests', 'testdata',
    'test_data', '__pycache__')
function Add-Candidate($Item) {
    if ($Item.PSIsContainer -or -not (Test-LogName $Item.Name)) { return }
    $path = Get-NormalPath $Item.FullName
    Assert-NoReparseAncestor $path $root
    $candidateMap[$path] = [pscustomobject]@{
        path = $path
        relative_path = Get-RelativeProjectPath $path
        bytes_before = [long]$Item.Length
    }
}

foreach ($item in @(Get-ChildItem -LiteralPath $root -Force)) {
    if (($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
        $skippedReparse.Add((Get-RelativeProjectPath (Get-NormalPath $item.FullName)))
        continue
    }
    if (-not $item.PSIsContainer) { Add-Candidate $item }
}

if (Test-Path -LiteralPath $resultsRoot) {
    $resultsItem = Get-Item -LiteralPath $resultsRoot -Force
    if (($resultsItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
        $skippedReparse.Add('results')
    } elseif (-not $resultsItem.PSIsContainer) {
        throw 'The results path must be a directory.'
    } else {
        $pending = [System.Collections.Generic.Stack[string]]::new()
        $pending.Push($resultsRoot)
        while ($pending.Count -gt 0) {
            $directory = $pending.Pop()
            Assert-NoReparseAncestor $directory $root
            foreach ($item in @(Get-ChildItem -LiteralPath $directory -Force)) {
                $path = Get-NormalPath $item.FullName
                if (($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
                    $skippedReparse.Add((Get-RelativeProjectPath $path))
                } elseif ($item.PSIsContainer) {
                    if ($item.Name -notin $protectedDirectoryNames) { $pending.Push($path) }
                } else {
                    Add-Candidate $item
                }
            }
        }
    }
}

$knownRuntimeLogs = @(
    '.runtime/privacy_agent/download_progress.log',
    '.runtime/privacy_agent/server.stderr.log',
    '.runtime/privacy_agent/server.stdout.log',
    '.runtime/native_mem0_sdk_v1/pip-install.log'
)
foreach ($relative in $knownRuntimeLogs) {
    $path = Get-NormalPath (Join-Path $root $relative)
    if (Test-Path -LiteralPath $path) {
        Assert-NoReparseAncestor $path $root
        Add-Candidate (Get-Item -LiteralPath $path -Force)
    }
}

$candidates = @($candidateMap.Values | Sort-Object relative_path)
$rows = [System.Collections.Generic.List[object]]::new()
foreach ($candidate in $candidates) {
    $action = 'inventory'
    $failure = $null
    $deleteError = $null
    $after = [long]$candidate.bytes_before
    if ($Mode -eq 'Clear') {
        try {
            Assert-NoReparseAncestor $candidate.path $root
            if (-not (Test-Path -LiteralPath $candidate.path)) {
                $action = 'already_absent'
                $after = 0
            } else {
                $current = Get-Item -LiteralPath $candidate.path -Force
                if ($current.PSIsContainer) { throw 'A log path became a directory.' }
                try {
                    Remove-Item -LiteralPath $candidate.path -Force -ErrorAction Stop
                    $action = 'deleted'
                    $after = 0
                } catch {
                    $deleteError = $_.Exception.GetType().Name
                    # Recheck immediately before the only fallback write.
                    Assert-NoReparseAncestor $candidate.path $root
                    $current = Get-Item -LiteralPath $candidate.path -Force
                    if ($current.PSIsContainer) { throw 'A log path became a directory.' }
                    $stream = $null
                    try {
                        $sharing = [System.IO.FileShare]::ReadWrite -bor [System.IO.FileShare]::Delete
                        $stream = [System.IO.File]::Open($candidate.path,
                            [System.IO.FileMode]::Open, [System.IO.FileAccess]::Write, $sharing)
                        $stream.SetLength(0)
                        $stream.Flush()
                    } finally {
                        if ($null -ne $stream) { $stream.Dispose() }
                    }
                    $after = [long](Get-Item -LiteralPath $candidate.path -Force).Length
                    if ($after -ne 0) { throw 'The log remained nonempty after truncation.' }
                    $action = 'truncated'
                }
                if ($action -eq 'deleted' -and (Test-Path -LiteralPath $candidate.path)) {
                    $after = [long](Get-Item -LiteralPath $candidate.path -Force).Length
                    throw 'The log was recreated during verification.'
                }
            }
        } catch {
            $action = 'failed'
            $failure = $_.Exception.GetType().Name
            if (Test-Path -LiteralPath $candidate.path -PathType Leaf) {
                $after = [long](Get-Item -LiteralPath $candidate.path -Force).Length
            }
        }
    }
    $rows.Add([pscustomobject]@{
        relative_path = $candidate.relative_path
        bytes_before = $candidate.bytes_before
        bytes_after = $after
        action = $action
        delete_error_type = $deleteError
        failure_type = $failure
    })
}

$failed = @($rows | Where-Object action -eq 'failed').Count
$beforeBytes = [long]0
$afterBytes = [long]0
foreach ($row in $rows) {
    $beforeBytes += [long]$row.bytes_before
    $afterBytes += [long]$row.bytes_after
}
$receiptObject = [ordered]@{
    version = 'bounded_project_log_cleanup_v1'
    mode = $Mode
    status = if ($failed -eq 0) { 'passed' } else { 'partial_failure' }
    timestamp_utc = [DateTime]::UtcNow.ToString('o')
    project_root = $root
    candidate_count = $candidates.Count
    deleted_count = @($rows | Where-Object action -eq 'deleted').Count
    truncated_count = @($rows | Where-Object action -eq 'truncated').Count
    already_absent_count = @($rows | Where-Object action -eq 'already_absent').Count
    failed_count = $failed
    bytes_before = $beforeBytes
    bytes_after = $afterBytes
    skipped_reparse_points = @($skippedReparse.ToArray())
    scope = @('Root-level and results/ .log/.log.* files; four explicit runtime log paths.',
        'No directory deletion, no service termination, no log contents in receipts.',
        'Result JSON, request transports, authorization events, billing, data, code and Git history preserved.',
        'A running service may write new log bytes after the point-in-time check.')
    files = @($rows.ToArray())
}
Assert-NoReparseAncestor $receipt $root
$receiptDirectory = [System.IO.Path]::GetDirectoryName($receipt)
[System.IO.Directory]::CreateDirectory($receiptDirectory) | Out-Null
Assert-NoReparseAncestor $receipt $root
[System.IO.File]::WriteAllText($receipt,
    ($receiptObject | ConvertTo-Json -Depth 8), [System.Text.UTF8Encoding]::new($false))
[pscustomobject]@{
    mode = $Mode; status = $receiptObject.status; candidate_count = $candidates.Count
    deleted_count = $receiptObject.deleted_count; truncated_count = $receiptObject.truncated_count
    failed_count = $failed; bytes_before = $beforeBytes; bytes_after = $afterBytes
    receipt = Get-RelativeProjectPath $receipt
} | ConvertTo-Json -Depth 3
if ($failed -gt 0) { exit 1 }
