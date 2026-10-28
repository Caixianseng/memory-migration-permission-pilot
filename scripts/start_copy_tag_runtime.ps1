param([switch]$PlanOnly)
$ErrorActionPreference='Stop'
$projectRoot=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$runRoot=Join-Path $projectRoot 'results/copy_tag_runtime_20261028_run01'
$runtimeRoot=Join-Path $projectRoot '.runtime/privacy_agent/ollama'
$executable=Join-Path $runtimeRoot 'lib/ollama/llama-server.exe'
$backendDir=Join-Path $runtimeRoot 'lib/ollama/cuda_v13'
$backend=Join-Path $backendDir 'ggml-cuda.dll'
$weight=Join-Path $projectRoot '.runtime/privacy_qwen35/models/blobs/sha256-a9d0a3e1d8c91732a3812becd31f8d4a8ff57414903f226306069f0437e2ac50'
$modelHash='a9d0a3e1d8c91732a3812becd31f8d4a8ff57414903f226306069f0437e2ac50'
if((Get-FileHash -LiteralPath $weight -Algorithm SHA256).Hash.ToLowerInvariant() -ne $modelHash) {throw 'Verified GGUF changed.'}
if(@(Get-NetTCPConnection -LocalPort 11436 -State Listen -ErrorAction SilentlyContinue).Count -gt 0) {throw 'Refuse occupied runtime port.'}
$arguments=@('--model',$weight,'--host','127.0.0.1','--port','11436','--ctx-size','4096','--parallel','1','--n-gpu-layers','99','--reasoning','off','--jinja')
if($PlanOnly) { [ordered]@{executable=$executable;model_sha256=$modelHash;endpoint='http://127.0.0.1:11436';n_ctx=4096;thinking=$false;backend=$backend;arguments=$arguments;generation_calls=0}|ConvertTo-Json -Depth 5; exit 0 }
if(Test-Path -LiteralPath $runRoot) {throw 'Exclusive runtime directory exists; inspect live ownership before continuing.'}
New-Item -ItemType Directory -Path $runRoot|Out-Null
$priorBackend=$env:GGML_BACKEND_PATH; $priorPathValue=$env:PATH
try {
    $env:GGML_BACKEND_PATH=$backend
    $env:PATH=$runtimeRoot + ';' + $backendDir + ';' + $priorPathValue
    $service=Start-Process -FilePath $executable -ArgumentList $arguments -WorkingDirectory $runtimeRoot -WindowStyle Hidden -PassThru -RedirectStandardOutput (Join-Path $runRoot 'server.stdout.log') -RedirectStandardError (Join-Path $runRoot 'server.stderr.log')
    $receipt=[ordered]@{status='started';pid=$service.Id;process_started_utc=$service.StartTime.ToUniversalTime().ToString('o');executable=$executable;executable_sha256=(Get-FileHash -LiteralPath $executable -Algorithm SHA256).Hash.ToLowerInvariant();model_path=$weight;model_sha256=$modelHash;backend=$backend;backend_sha256=(Get-FileHash -LiteralPath $backend -Algorithm SHA256).Hash.ToLowerInvariant();endpoint='http://127.0.0.1:11436';n_ctx=4096;parallel=1;thinking=$false;arguments=$arguments;generation_calls=0;source_asset_receipt='results/qwen35_assets_20261028_run04/asset_receipt.json'}
    $utf8=New-Object Text.UTF8Encoding($false)
    [IO.File]::WriteAllText((Join-Path $runRoot 'runtime_started.json'),($receipt|ConvertTo-Json -Depth 8),$utf8)
    Write-Output ('owned_runtime_pid=' + $service.Id)
    $health=$null
    for($i=0;$i -lt 40;$i++) {
        if($service.HasExited) {throw 'Runtime exited during startup.'}
        try {$health=Invoke-RestMethod -Uri 'http://127.0.0.1:11436/health' -TimeoutSec 2; if($health.status -eq 'ok') {break}} catch { }
        Start-Sleep -Milliseconds 500
    }
    if($health.status -ne 'ok') {throw 'Runtime health qualification failed.'}
    $props=Invoke-RestMethod -Uri 'http://127.0.0.1:11436/props' -TimeoutSec 5
    [IO.File]::WriteAllText((Join-Path $runRoot 'props.json'),($props|ConvertTo-Json -Depth 30),$utf8)
    [ordered]@{status='healthy';pid=$service.Id;generation_calls=0;props_saved=$true}|ConvertTo-Json -Compress
} finally { $env:GGML_BACKEND_PATH=$priorBackend; $env:PATH=$priorPathValue }
