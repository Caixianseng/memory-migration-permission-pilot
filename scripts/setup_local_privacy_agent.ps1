param([switch]$SkipDownload)
$ErrorActionPreference = 'Stop'
$projectRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$runtimeRoot = Join-Path $projectRoot '.runtime/privacy_agent'
$portableRoot = Join-Path $runtimeRoot 'ollama'
$modelRoot = Join-Path $runtimeRoot 'models'
$archivePath = Join-Path $runtimeRoot 'ollama-windows-amd64-verified.zip'
$modelName = 'qwen3:4b-instruct-2507-q4_K_M'
$archiveHash = '04d1d43ac62c2deb0393307bb49fed7caf6b192de41bdd497aaa9488089d5552'
$manifestHash = '0edcdef34593eac1aa2be9c7d06c432dcf81945adca5eca2f27662c18f168ba0'
$weightHash = '85e4a5b7b8ef0e48af0e8658f5aaab9c2324c76c1641493f4d1e25fce54b18b9'
New-Item -ItemType Directory -Force -Path $runtimeRoot, $portableRoot, $modelRoot, (Join-Path $runtimeRoot 'profile') | Out-Null

if (-not (Test-Path -LiteralPath $archivePath)) {
    if ($SkipDownload) { throw 'Verified archive missing; omit -SkipDownload to download official assets.' }
    & curl.exe --location --fail --retry 2 --output $archivePath 'https://github.com/ollama/ollama/releases/download/v0.40.8/ollama-windows-amd64.zip'
    if ($LASTEXITCODE -ne 0) { throw 'Official Ollama download failed.' }
}
if ((Get-FileHash -LiteralPath $archivePath -Algorithm SHA256).Hash.ToLowerInvariant() -ne $archiveHash) { throw 'Ollama archive SHA256 mismatch.' }
$binaryPath = Join-Path $portableRoot 'ollama.exe'
if (-not (Test-Path -LiteralPath (Join-Path $portableRoot '.verified-extraction'))) {
    # Refuse unexpected symlink destinations. Never remove or relocate user files.
    if ((Get-Item -LiteralPath $portableRoot).Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Portable directory must not be a link.' }
    Expand-Archive -LiteralPath $archivePath -DestinationPath $portableRoot -Force
    Set-Content -LiteralPath (Join-Path $portableRoot '.verified-extraction') -Value $archiveHash -Encoding ASCII
}
if (-not (Test-Path -LiteralPath $binaryPath)) { throw 'Portable executable missing.' }
$environment = @{
    OLLAMA_HOST='127.0.0.1:11435'; OLLAMA_MODELS=$modelRoot; OLLAMA_NO_CLOUD='1';
    OLLAMA_NUM_PARALLEL='1'; OLLAMA_MAX_LOADED_MODELS='1'; OLLAMA_DEBUG='0';
    OLLAMA_DEBUG_LOG_REQUESTS='0'; OLLAMA_CONTEXT_LENGTH='4096'; OLLAMA_KEEP_ALIVE='30m';
    USERPROFILE=(Join-Path $runtimeRoot 'profile')
}
$previousEnvironment = @{}
foreach ($entry in $environment.GetEnumerator()) {
    $previousEnvironment[$entry.Key] = [Environment]::GetEnvironmentVariable($entry.Key, 'Process')
    [Environment]::SetEnvironmentVariable($entry.Key, $entry.Value, 'Process')
}
try {
    $listening = @(Get-NetTCPConnection -LocalPort 11435 -State Listen -ErrorAction SilentlyContinue)
    if ($listening.Count -gt 0) {
        $owner = Get-Process -Id $listening[0].OwningProcess
        if ($owner.Path -ne $binaryPath -or @($listening | Where-Object { $_.LocalAddress -ne '127.0.0.1' }).Count -gt 0) {
            throw 'Port 11435 is occupied by another process or a non-loopback listener.'
        }
        $serverPid = $owner.Id
    } else {
        $server = Start-Process -FilePath $binaryPath -ArgumentList 'serve' -WorkingDirectory $runtimeRoot -WindowStyle Hidden -PassThru -RedirectStandardOutput (Join-Path $runtimeRoot 'server.stdout.log') -RedirectStandardError (Join-Path $runtimeRoot 'server.stderr.log')
        $serverPid = $server.Id
    }
    $version = $null
    for ($attempt=0; $attempt -lt 60; $attempt++) {
        try { $version = Invoke-RestMethod -Uri 'http://127.0.0.1:11435/api/version' -TimeoutSec 2; break } catch { Start-Sleep -Milliseconds 500 }
    }
    if ($version.version -ne '0.40.8') { throw 'Local Ollama version is unavailable or mismatched.' }
    $manifestPath = Join-Path $modelRoot 'manifests/registry.ollama.ai/library/qwen3/4b-instruct-2507-q4_K_M'
    if (-not (Test-Path -LiteralPath $manifestPath)) {
        if ($SkipDownload) { throw 'Pinned model missing; omit -SkipDownload for official registry pull.' }
        & $binaryPath pull $modelName
        if ($LASTEXITCODE -ne 0) { throw 'Official local-model pull failed.' }
    }
    if ((Get-FileHash -LiteralPath $manifestPath -Algorithm SHA256).Hash.ToLowerInvariant() -ne $manifestHash) { throw 'Model manifest SHA256 mismatch.' }
    $weightPath = Join-Path $modelRoot ('blobs/sha256-' + $weightHash)
    if ((Get-FileHash -LiteralPath $weightPath -Algorithm SHA256).Hash.ToLowerInvariant() -ne $weightHash) { throw 'Model weights SHA256 mismatch.' }
    $tags = Invoke-RestMethod -Uri 'http://127.0.0.1:11435/api/tags' -TimeoutSec 5
    $model = @($tags.models | Where-Object { $_.name -eq $modelName })
    if ($model.Count -ne 1 -or $model[0].digest -ne $manifestHash) { throw 'Runtime model digest mismatch.' }
    $receipt = [ordered]@{
        timestamp_utc=[DateTime]::UtcNow.ToString('o'); version=$version.version;
        endpoint='http://127.0.0.1:11435'; pid=$serverPid; executable=$binaryPath;
        executable_sha256=(Get-FileHash -LiteralPath $binaryPath -Algorithm SHA256).Hash.ToLowerInvariant();
        archive_sha256=$archiveHash; model=$modelName; model_digest=$manifestHash;
        weights_sha256=$weightHash; weights_bytes=(Get-Item -LiteralPath $weightPath).Length;
        process_environment=$environment; model_cache=$modelRoot;
        gpu_loading='not_yet_measured'; cloud_generation_calls=0
    }
    [IO.File]::WriteAllText((Join-Path $runtimeRoot 'runtime_receipt.json'), ($receipt | ConvertTo-Json -Depth 8), (New-Object Text.UTF8Encoding($false)))
    Write-Output 'Pinned local Ollama is ready at 127.0.0.1:11435; runtime_receipt.json records verified identities.'
} finally {
    foreach ($entry in $previousEnvironment.GetEnumerator()) {
        [Environment]::SetEnvironmentVariable($entry.Key, $entry.Value, 'Process')
    }
}
