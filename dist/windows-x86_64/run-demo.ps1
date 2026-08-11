<#
.SYNOPSIS
  Self-contained VaultMesh demo using the prebuilt Windows binaries.

.DESCRIPTION
  No Rust toolchain and no repo clone required. Just needs Python on PATH plus
  the two .exe files and demo.py sitting NEXT TO this script (they ship together
  in this folder). Starts a coordinator + two QUIC-meshed node-agents, runs the
  narrated walkthrough (demo.py), and stops everything on exit.

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File run-demo.ps1
#>
$ErrorActionPreference = "Stop"

$dir      = $PSScriptRoot
$coordExe = Join-Path $dir "coordinator.exe"
$nodeExe  = Join-Path $dir "node-agent.exe"
$demoPy   = Join-Path $dir "demo.py"

foreach ($f in @($coordExe, $nodeExe, $demoPy)) {
    if (-not (Test-Path $f)) { throw "missing required file next to this script: $f" }
}
if (-not (Get-Command python -ErrorAction SilentlyContinue)) {
    throw "python was not found on PATH. Install Python 3, then re-run."
}

$coordPort = 8787
$aHttp = 8790; $aQuic = 8791
$bHttp = 8792; $bQuic = 8893

function Wait-Health([string]$url) {
    for ($i = 0; $i -lt 60; $i++) {
        try { Invoke-WebRequest -UseBasicParsing "$url/health" -TimeoutSec 2 | Out-Null; return }
        catch { Start-Sleep -Milliseconds 300 }
    }
    throw "timed out waiting for $url"
}

$procs = @()
function Start-Vault([string]$exe, [string]$tag) {
    $out = Join-Path $env:TEMP "vm-$tag.out.log"
    $err = Join-Path $env:TEMP "vm-$tag.err.log"
    Start-Process -FilePath $exe -PassThru -WindowStyle Hidden `
        -RedirectStandardOutput $out -RedirectStandardError $err
}

try {
    Get-Process coordinator, node-agent -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 1

    $aRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("vaultmesh-a-" + [System.IO.Path]::GetRandomFileName())
    $bRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("vaultmesh-b-" + [System.IO.Path]::GetRandomFileName())

    Write-Host "==> starting coordinator on :$coordPort"
    $env:VAULT_ANCHOR_ROOT = $aRoot
    Remove-Item Env:\VAULT_NODE_ADDR, Env:\VAULT_TRANSPORT, Env:\VAULT_QUIC_ADDR, Env:\VAULT_PEERS -ErrorAction SilentlyContinue
    $procs += (Start-Vault $coordExe "coord")
    Wait-Health "http://127.0.0.1:$coordPort"

    Write-Host "==> starting node B (peer)   http::$bHttp quic::$bQuic"
    $env:VAULT_NODE_ADDR = "127.0.0.1:$bHttp"
    $env:VAULT_ANCHOR_ROOT = $bRoot
    $env:VAULT_TRANSPORT = "quic"
    $env:VAULT_QUIC_ADDR = "127.0.0.1:$bQuic"
    Remove-Item Env:\VAULT_PEERS -ErrorAction SilentlyContinue
    $procs += (Start-Vault $nodeExe "nodeb")

    Write-Host "==> starting node A (origin) http::$aHttp quic::$aQuic  peers=[node B]"
    $env:VAULT_NODE_ADDR = "127.0.0.1:$aHttp"
    $env:VAULT_ANCHOR_ROOT = $aRoot
    $env:VAULT_TRANSPORT = "quic"
    $env:VAULT_QUIC_ADDR = "127.0.0.1:$aQuic"
    $env:VAULT_PEERS = "127.0.0.1:$bQuic"
    $procs += (Start-Vault $nodeExe "nodea")

    Wait-Health "http://127.0.0.1:$aHttp"
    Wait-Health "http://127.0.0.1:$bHttp"

    Write-Host "==> running narrated walkthrough"
    $env:COORD  = "http://127.0.0.1:$coordPort"
    $env:NODE_A = "http://127.0.0.1:$aHttp"
    $env:AROOT  = $aRoot
    $env:BROOT  = $bRoot
    & python $demoPy
    if ($LASTEXITCODE -ne 0) { throw "demo.py failed" }

    Write-Host ""
    Write-Host "(demo complete - services stopped on exit)"
}
finally {
    foreach ($p in $procs) {
        if ($p -and -not $p.HasExited) { Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue }
    }
}
