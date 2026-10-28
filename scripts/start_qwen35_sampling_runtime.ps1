param([ValidateSet('Plan','Start','Stop')][string]$Mode='Plan')
$ErrorActionPreference = 'Stop'
$taskRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$taskRun = Join-Path $taskRoot 'results/qwen35_sampling_runtime_20261028_run01'
$taskAssetPath = Join-Path $taskRoot 'results/qwen35_assets_20261028_run04/asset_receipt.json'
$taskQualifiedPath = Join-Path $taskRoot 'results/qwen35_assets_20261028_run04/inference_qualification.json'
$taskBinary = Join-Path $taskRoot '.runtime/privacy_agent/ollama/ollama.exe'
$taskModelRoot = Join-Path $taskRoot '.runtime/privacy_qwen35/models'
$taskAsset = Get-Content -LiteralPath $taskAssetPath -Raw | ConvertFrom-Json -DateKind String
$taskQualified = Get-Content -LiteralPath $taskQualifiedPath -Raw | ConvertFrom-Json -DateKind String
$taskDigest = 'd8b0f5e9760cd1682034f292d7ef72ec46f432149be0df7574bf2d6e92e38c04'
$taskExeHash = (Get-FileHash -LiteralPath $taskBinary -Algorithm SHA256).Hash.ToLowerInvariant()
if ($taskExeHash -ne '034a26a71836df581ef8b9ab4db489154f548c81b53aa8816d0e843b9e385c2b' -or $taskAsset.model_digest -ne $taskDigest -or $taskAsset.version -ne '0.40.8' -or $taskQualified.status -ne 'qualified') { throw 'Existing runtime/qualification mismatch.' }
function Save-TaskJson($name,$value) {
    $taskPath = Join-Path $taskRun $name
    if (Test-Path -LiteralPath $taskPath) { throw "Exclusive receipt exists: $name" }
    [IO.File]::WriteAllText($taskPath,($value|ConvertTo-Json -Depth 20)+[Environment]::NewLine,[Text.UTF8Encoding]::new($false))
}
if ($Mode -eq 'Stop') {
    $taskOwned = Get-Content -LiteralPath (Join-Path $taskRun 'ownership.json') -Raw | ConvertFrom-Json -DateKind String
    $taskProc = Get-CimInstance Win32_Process -Filter "ProcessId=$($taskOwned.pid)"
    $taskStarted = [datetimeoffset]::Parse($taskOwned.process_started_utc)
    if ($null -eq $taskProc -or $taskProc.ExecutablePath -ne $taskBinary -or [math]::Abs(($taskProc.CreationDate.ToUniversalTime()-$taskStarted.UtcDateTime).TotalSeconds) -gt 2) { throw 'Owned process identity mismatch.' }
    $taskDescendants = @()
    $taskQueue = @($taskProc)
    while ($taskQueue.Count -gt 0) {
        $taskNext = @()
        foreach ($taskParent in $taskQueue) {
            foreach ($taskChild in @(Get-CimInstance Win32_Process -Filter "ParentProcessId=$($taskParent.ProcessId)")) {
                $taskAllowed = $taskChild.ExecutablePath -eq (Join-Path $taskRoot '.runtime/privacy_agent/ollama/lib/ollama/llama-server.exe') -or $taskChild.ExecutablePath -eq (Join-Path $env:SystemRoot 'system32/conhost.exe')
                if (-not $taskAllowed -or $taskChild.CreationDate.ToUniversalTime() -lt $taskStarted.UtcDateTime.AddSeconds(-2)) { throw 'Unrecognized child; cleanup refuses to stop it.' }
                $taskDescendants += $taskChild; $taskNext += $taskChild
            }
        }
        $taskQueue = $taskNext
    }
    $taskStopped = @()
    foreach ($taskTarget in @($taskDescendants | Sort-Object CreationDate -Descending) + @($taskProc)) {
        $taskCurrent = Get-CimInstance Win32_Process -Filter "ProcessId=$($taskTarget.ProcessId)"
        if ($null -ne $taskCurrent) {
            if ($taskCurrent.ExecutablePath -ne $taskTarget.ExecutablePath -or $taskCurrent.CreationDate -ne $taskTarget.CreationDate) { throw 'Process changed during cleanup.' }
            Stop-Process -Id $taskTarget.ProcessId -ErrorAction Stop
            $taskStopped += [ordered]@{pid=[int]$taskTarget.ProcessId;executable=$taskTarget.ExecutablePath;started_utc=$taskTarget.CreationDate.ToUniversalTime().ToString('o')}
        }
    }
    Save-TaskJson 'service_stopped.json' ([ordered]@{status='stopped';stopped_utc=[datetime]::UtcNow.ToString('o');processes=$taskStopped;new_model_calls=0})
    Write-Output 'Owned Ollama runtime and verified descendants stopped.'
    exit 0
}
$taskListeners = @(Get-NetTCPConnection -LocalPort 11435 -State Listen -ErrorAction SilentlyContinue)
if ($taskListeners.Count -gt 0) { throw 'Port 11435 occupied; refuse to reuse unowned listener.' }
if (Test-Path -LiteralPath $taskRun) { throw 'Run directory exists; inspect its actual ownership before continuing.' }
if ($Mode -eq 'Plan') {
    [ordered]@{mode='existing_assets_only';endpoint='http://127.0.0.1:11435';model_digest=$taskDigest;executable=$taskBinary;generation_calls=0;download_calls=0;new_canary_calls=0} | ConvertTo-Json -Compress
    exit 0
}
if ($taskAsset.model_root -ne $taskModelRoot -or (Get-FileHash -LiteralPath $taskAsset.manifest_path -Algorithm SHA256).Hash.ToLowerInvariant() -ne $taskAsset.local_manifest_sha256) { throw 'Model root/manifest changed.' }
foreach ($taskBlob in $taskAsset.blobs) {
    if ($taskBlob.digest -notmatch '^sha256:[a-f0-9]{64}$') { throw 'Invalid stored blob digest.' }
    $taskBlobPath = Join-Path $taskModelRoot ('blobs/sha256-'+$taskBlob.digest.Substring(7))
    if ((Get-Item -LiteralPath $taskBlobPath).Length -ne $taskBlob.bytes -or (Get-FileHash -LiteralPath $taskBlobPath -Algorithm SHA256).Hash.ToLowerInvariant() -ne $taskBlob.digest.Substring(7)) { throw 'Existing model asset changed.' }
}
New-Item -ItemType Directory -Path $taskRun | Out-Null
$taskEnv = @{OLLAMA_HOST='127.0.0.1:11435';OLLAMA_MODELS=$taskModelRoot;OLLAMA_NO_CLOUD='1';OLLAMA_NUM_PARALLEL='1';OLLAMA_MAX_LOADED_MODELS='1';OLLAMA_DEBUG='0';OLLAMA_DEBUG_LOG_REQUESTS='0';OLLAMA_CONTEXT_LENGTH='4096';OLLAMA_KEEP_ALIVE='30m';USERPROFILE=(Join-Path $taskRoot '.runtime/privacy_qwen35/profile')}
$taskPrevious = @{}
try {
    foreach ($taskEntry in $taskEnv.GetEnumerator()) { $taskPrevious[$taskEntry.Key]=[Environment]::GetEnvironmentVariable($taskEntry.Key,'Process');[Environment]::SetEnvironmentVariable($taskEntry.Key,$taskEntry.Value,'Process') }
    $taskServer = Start-Process -FilePath $taskBinary -ArgumentList 'serve' -WorkingDirectory (Split-Path $taskModelRoot) -WindowStyle Hidden -PassThru -RedirectStandardOutput (Join-Path $taskRun 'server.stdout.log') -RedirectStandardError (Join-Path $taskRun 'server.stderr.log')
    $taskOwnership = [ordered]@{pid=$taskServer.Id;process_started_utc=$taskServer.StartTime.ToUniversalTime().ToString('o');executable=$taskBinary;executable_sha256=$taskExeHash;model_root=$taskModelRoot;endpoint='http://127.0.0.1:11435';environment=$taskEnv;generation_calls=0;download_calls=0}
    Save-TaskJson 'ownership.json' $taskOwnership
    $taskVersion = $null
    for ($taskAttempt=0;$taskAttempt -lt 30;$taskAttempt++) { try { $taskVersion=Invoke-RestMethod -Uri 'http://127.0.0.1:11435/api/version' -TimeoutSec 2;break } catch { Start-Sleep -Milliseconds 500 } }
    $taskTags=Invoke-RestMethod -Uri 'http://127.0.0.1:11435/api/tags' -TimeoutSec 5
    $taskMatches=@($taskTags.models|Where-Object {$_.name -eq 'qwen3.5:4b-q4_K_M' -and $_.digest -eq $taskDigest})
    $taskLiveListeners=@(Get-NetTCPConnection -LocalPort 11435 -State Listen -ErrorAction SilentlyContinue)
    if ($taskVersion.version -ne '0.40.8' -or $taskMatches.Count -ne 1 -or $taskLiveListeners.Count -ne 1 -or $taskLiveListeners[0].LocalAddress -ne '127.0.0.1' -or $taskLiveListeners[0].OwningProcess -ne $taskServer.Id) { throw 'Live runtime/model identity mismatch.' }
    Save-TaskJson 'health.json' ([ordered]@{version=$taskVersion;tags=$taskTags})
    $taskReady=[ordered]@{status='ready';version='0.40.8';model='qwen3.5:4b-q4_K_M';model_digest=$taskDigest;endpoint='http://127.0.0.1:11435';pid=$taskServer.Id;process_started_utc=$taskOwnership.process_started_utc;executable=$taskBinary;executable_sha256=$taskExeHash;asset_receipt_sha256=(Get-FileHash -LiteralPath $taskAssetPath -Algorithm SHA256).Hash.ToLowerInvariant();old_qualification_sha256=(Get-FileHash -LiteralPath $taskQualifiedPath -Algorithm SHA256).Hash.ToLowerInvariant();generation_calls=0;download_calls=0;new_canary_calls=0;qualification_mode='same verified assets/runtime, existing generation qualification, fresh live identity health'}
    Save-TaskJson 'runtime_ready.json' $taskReady
    $taskReady|ConvertTo-Json -Compress
} catch { Save-TaskJson 'failure.json' ([ordered]@{status='failed';error=$_.Exception.Message;generation_calls=0});throw }
finally { foreach ($taskEntry in $taskPrevious.GetEnumerator()) {[Environment]::SetEnvironmentVariable($taskEntry.Key,$taskEntry.Value,'Process')} }
