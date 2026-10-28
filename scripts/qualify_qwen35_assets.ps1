param([switch]$PlanOnly, [switch]$ReuseOwnedService,
      [ValidateRange(60,1500)][int]$DownloadTimeoutSeconds=900,
      [ValidatePattern('^qwen35_assets_20261028_run0[1-9]$')]
      [string]$RunName='qwen35_assets_20261028_run01')
$ErrorActionPreference = 'Stop'
$projectRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$oldRoot = Join-Path $projectRoot '.runtime/privacy_agent'
$runtimeRoot = Join-Path $projectRoot '.runtime/privacy_qwen35'
$runRoot = Join-Path $projectRoot ('results/' + $RunName)
$binaryPath = Join-Path $oldRoot 'ollama/ollama.exe'
$modelRoot = Join-Path $runtimeRoot 'models'
$modelName = 'qwen3.5:4b-q4_K_M'
$endpoint = 'http://127.0.0.1:11435'
if ($DownloadTimeoutSeconds -ne 900 -and $RunName -ne 'qwen35_assets_20261028_run04') { throw 'Only the final documented recovery window may change its timeout.' }
$oldReceipt = Get-Content -LiteralPath (Join-Path $oldRoot 'runtime_receipt.json') -Raw | ConvertFrom-Json
if ((Get-FileHash -LiteralPath $binaryPath -Algorithm SHA256).Hash.ToLowerInvariant() -ne $oldReceipt.executable_sha256) { throw 'Runtime executable hash mismatch.' }
if ($oldReceipt.version -ne '0.40.8') { throw 'Unexpected existing runtime receipt.' }
if ((Get-PSDrive -Name ([IO.Path]::GetPathRoot($projectRoot).Substring(0,1))).Free -lt 12GB) { throw 'Require 12GiB available space.' }
$listeners = @(Get-NetTCPConnection -LocalPort 11435 -State Listen -ErrorAction SilentlyContinue)
$existingServerPid = $null
if ($ReuseOwnedService) {
    $previousOwnership = Get-Content -LiteralPath (Join-Path $projectRoot 'results/qwen35_assets_20261028_run02/ownership.json') -Raw | ConvertFrom-Json
    $ownedProcess = Get-Process -Id $previousOwnership.pid -ErrorAction Stop
    # PowerShell 7 may deserialize ISO timestamps to DateTime already. Parsing
    # its display string would discard UTC kind and introduce the local offset.
    $ownershipStarted = if ($previousOwnership.started_utc -is [DateTime]) { $previousOwnership.started_utc.ToUniversalTime() } else { [DateTimeOffset]::Parse($previousOwnership.started_utc).UtcDateTime }
    $startedGap = [Math]::Abs(($ownedProcess.StartTime.ToUniversalTime() - $ownershipStarted).TotalSeconds)
    if ($ownedProcess.Path -ne $binaryPath -or $previousOwnership.model_root -ne $modelRoot -or $startedGap -gt 15 -or $listeners.Count -ne 1 -or $listeners[0].LocalAddress -ne '127.0.0.1' -or $listeners[0].OwningProcess -ne $ownedProcess.Id) { throw 'Owned service identity mismatch.' }
    $existingServerPid = $ownedProcess.Id
} elseif ($listeners.Count -gt 0) { throw 'Port occupied: refuse to reuse or stop an unowned service.' }
if ($PlanOnly) {
    [ordered]@{model=$modelName; endpoint=$endpoint; runtime=$binaryPath; runtime_version='0.40.8'; model_root=$modelRoot; run_root=$runRoot; minimum_free_bytes=12GB; download_timeout_seconds=$DownloadTimeoutSeconds; generation_calls=0} | ConvertTo-Json
    exit 0
}
if (Test-Path -LiteralPath $runRoot) { throw 'Exclusive asset run already exists; inspect its live process/receipt before any continuation.' }
New-Item -ItemType Directory -Path $runRoot | Out-Null
New-Item -ItemType Directory -Force -Path $runtimeRoot,$modelRoot,(Join-Path $runtimeRoot 'profile') | Out-Null
$utf8 = New-Object Text.UTF8Encoding($false)
function Save-Receipt($name,$value) { [IO.File]::WriteAllText((Join-Path $runRoot $name),($value | ConvertTo-Json -Depth 20),$utf8) }
$environment = @{
    OLLAMA_HOST='127.0.0.1:11435'; OLLAMA_MODELS=$modelRoot; OLLAMA_NO_CLOUD='1';
    OLLAMA_NUM_PARALLEL='1'; OLLAMA_MAX_LOADED_MODELS='1'; OLLAMA_DEBUG='0';
    OLLAMA_DEBUG_LOG_REQUESTS='0'; OLLAMA_CONTEXT_LENGTH='4096'; OLLAMA_KEEP_ALIVE='30m';
    USERPROFILE=(Join-Path $runtimeRoot 'profile')
}
$prior = @{}
$serverPid = $null
$pull = $null
$started = [DateTime]::UtcNow
foreach ($entry in $environment.GetEnumerator()) {
    $prior[$entry.Key] = [Environment]::GetEnvironmentVariable($entry.Key,'Process')
    [Environment]::SetEnvironmentVariable($entry.Key,$entry.Value,'Process')
}
try {
    if ($existingServerPid) { $serverPid = $existingServerPid }
    else {
        $server = Start-Process -FilePath $binaryPath -ArgumentList 'serve' -WorkingDirectory $runtimeRoot -WindowStyle Hidden -PassThru -RedirectStandardOutput (Join-Path $runRoot 'server.stdout.log') -RedirectStandardError (Join-Path $runRoot 'server.stderr.log')
        $serverPid = $server.Id
    }
    Save-Receipt 'ownership.json' ([ordered]@{pid=$serverPid; executable=$binaryPath; executable_sha256=$oldReceipt.executable_sha256; model_root=$modelRoot; endpoint=$endpoint; started_utc=$started.ToString('o'); generation_calls=0})
    Write-Output ('owned_server_pid=' + $serverPid)
    $version = $null
    for ($attempt=0; $attempt -lt 20; $attempt++) {
        try { $version = Invoke-RestMethod -Uri ($endpoint + '/api/version') -TimeoutSec 2; break } catch { Start-Sleep -Milliseconds 500 }
    }
    if ($version.version -ne '0.40.8') { throw 'Actual runtime version mismatch.' }
    $pull = Start-Process -FilePath $binaryPath -ArgumentList @('pull',$modelName) -WorkingDirectory $runtimeRoot -WindowStyle Hidden -PassThru -RedirectStandardOutput (Join-Path $runRoot 'pull.stdout.log') -RedirectStandardError (Join-Path $runRoot 'pull.stderr.log')
    Save-Receipt 'pull_started.json' ([ordered]@{pid=$pull.Id; executable=$binaryPath; model=$modelName; started_utc=[DateTime]::UtcNow.ToString('o'); timeout_seconds=$DownloadTimeoutSeconds; generation_calls=0})
    $watch = [Diagnostics.Stopwatch]::StartNew()
    $nextNotice = 15
    while (-not $pull.WaitForExit(1000)) {
        if ($watch.Elapsed.TotalSeconds -gt $DownloadTimeoutSeconds) { $pull.Kill(); throw ('Model pull exceeded fixed ' + $DownloadTimeoutSeconds + '-second budget.') }
        if ($watch.Elapsed.TotalSeconds -ge $nextNotice) { Write-Output ('pull_running_seconds=' + [int]$watch.Elapsed.TotalSeconds); $nextNotice += 15 }
    }
    $pull.Refresh()
    if ($pull.ExitCode -ne 0) { throw ('Official model pull failed: exit ' + $pull.ExitCode) }
    $manifestPath = Join-Path $modelRoot 'manifests/registry.ollama.ai/library/qwen3.5/4b-q4_K_M'
    $manifestHash = (Get-FileHash -LiteralPath $manifestPath -Algorithm SHA256).Hash.ToLowerInvariant()
    if (-not $manifestHash.StartsWith('d8b0f5e9760c')) {
        # Recent runtimes can append the authenticated upstream manifest blob.
        # Verify the entire known relationship and every blob; never accept a
        # different digest by simply weakening or removing the identity check.
        & (Join-Path $projectRoot '.runtime/ci-test-venv/Scripts/python.exe') -B -X utf8 (Join-Path $PSScriptRoot 'finalize_qwen35_assets.py') --run-root $runRoot --model-root $modelRoot --pid $serverPid
        if ($LASTEXITCODE -ne 0) { throw 'Upstream/local manifest qualification failed.' }
        return
    }
    $manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
    $blobs = @()
    foreach ($layer in @($manifest.config) + @($manifest.layers)) {
        if ($layer.digest -notmatch '^sha256:[a-f0-9]{64}$') { throw 'Invalid blob digest.' }
        $blobPath = Join-Path $modelRoot ('blobs/sha256-' + $layer.digest.Substring(7))
        $item = Get-Item -LiteralPath $blobPath
        if ($item.Length -ne $layer.size) { throw 'Blob size mismatch.' }
        $actualHash = (Get-FileHash -LiteralPath $blobPath -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($actualHash -ne $layer.digest.Substring(7)) { throw 'Blob SHA256 mismatch.' }
        $blobs += [ordered]@{media_type=$layer.mediaType; digest=$layer.digest; bytes=$item.Length}
    }
    $tags = Invoke-RestMethod -Uri ($endpoint + '/api/tags') -TimeoutSec 5
    $matching = @($tags.models | Where-Object { $_.name -eq $modelName })
    if ($matching.Count -ne 1 -or $matching[0].digest -ne $manifestHash) { throw 'Actual runtime model digest mismatch.' }
    $show = Invoke-RestMethod -Uri ($endpoint + '/api/show') -Method Post -ContentType 'application/json' -Body (@{model=$modelName; verbose=$false} | ConvertTo-Json -Compress) -TimeoutSec 30
    Save-Receipt 'show.json' $show
    $receipt = [ordered]@{status='assets_verified'; model=$modelName; model_digest=$manifestHash; version=$version.version; executable=$binaryPath; executable_sha256=$oldReceipt.executable_sha256; endpoint=$endpoint; pid=$serverPid; model_root=$modelRoot; manifest_path=$manifestPath; blobs=$blobs; capabilities=$show.capabilities; environment=$environment; started_utc=$started.ToString('o'); finished_utc=[DateTime]::UtcNow.ToString('o'); generation_calls=0; inference_qualified=$false; cloud_generation_calls=0}
    Save-Receipt 'asset_receipt.json' $receipt
    Write-Output ($receipt | ConvertTo-Json -Depth 8 -Compress)
} catch {
    Save-Receipt 'failure.json' ([ordered]@{status='failed'; pid=$serverPid; error=$_.Exception.Message; finished_utc=[DateTime]::UtcNow.ToString('o'); generation_calls=0})
    throw
} finally {
    foreach ($entry in $prior.GetEnumerator()) { [Environment]::SetEnvironmentVariable($entry.Key,$entry.Value,'Process') }
}
