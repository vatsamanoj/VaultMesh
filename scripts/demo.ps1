<#
.SYNOPSIS
  Reproducible end-to-end demo of VaultMesh (P0-P4) on Windows (PowerShell).

.DESCRIPTION
  Builds the workspace, starts a coordinator + two QUIC-meshed node-agents,
  runs a narrated walkthrough (scripts/demo.py) that exercises every layer, then
  runs the real client-side-encryption roundtrip example. Everything is stopped
  on exit. Requires the Rust toolchain, python (on PATH), and curl.exe.

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File scripts\demo.ps1
#>
$ErrorActionPreference = "Stop"

$root      = Split-Path $PSScriptRoot -Parent
$coordPort = 8787
$aHttp     = 8790; $aQuic = 8791
$bHttp     = 8792; $bQuic = 8893

$coordExe = Join-Path $root "target\release\coordinator.exe"
$nodeExe  = Join-Path $root "target\release\node-agent.exe"

function Wait-Health([string]$url) {
    for ($i = 0; $i -lt 60; $i++) {
        try { Invoke-WebRequest -UseBasicParsing "$url/health" -TimeoutSec 2 | Out-Null; return }
        catch { Start-Sleep -Milliseconds 300 }
    }
    throw "timed out waiting for $url"
}

# Track the processes we start so we can stop them on exit.
$procs = @()
function Start-Vault([string]$exe, [string]$tag) {
    $out = Join-Path $env:TEMP "vm-$tag.out.log"
    $err = Join-Path $env:TEMP "vm-$tag.err.log"
    Start-Process -FilePath $exe -PassThru -WindowStyle Hidden `
        -RedirectStandardOutput $out -RedirectStandardError $err
}

Push-Location $root
try {
    Write-Host "==> building coordinator + node-agent"
    & cargo build -q -p coordinator -p node-agent -p vault-client
    if ($LASTEXITCODE -ne 0) { throw "cargo build failed" }

    # Clean up any stragglers from a previous run.
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
    $env:VAULT_NODE_ADDR   = "127.0.0.1:$bHttp"
    $env:VAULT_ANCHOR_ROOT = $bRoot
    $env:VAULT_TRANSPORT   = "quic"
    $env:VAULT_QUIC_ADDR   = "127.0.0.1:$bQuic"
    Remove-Item Env:\VAULT_PEERS -ErrorAction SilentlyContinue
    $procs += (Start-Vault $nodeExe "nodeb")

    Write-Host "==> starting node A (origin) http::$aHttp quic::$aQuic  peers=[node B]"
    $env:VAULT_NODE_ADDR   = "127.0.0.1:$aHttp"
    $env:VAULT_ANCHOR_ROOT = $aRoot
    $env:VAULT_TRANSPORT   = "quic"
    $env:VAULT_QUIC_ADDR   = "127.0.0.1:$aQuic"
    $env:VAULT_PEERS       = "127.0.0.1:$bQuic"
    $procs += (Start-Vault $nodeExe "nodea")

    Wait-Health "http://127.0.0.1:$aHttp"
    Wait-Health "http://127.0.0.1:$bHttp"

    Write-Host "==> running narrated walkthrough"
    $env:COORD  = "http://127.0.0.1:$coordPort"
    $env:NODE_A = "http://127.0.0.1:$aHttp"
    $env:AROOT  = $aRoot
    $env:BROOT  = $bRoot
    & python (Join-Path $root "scripts\demo.py")
    if ($LASTEXITCODE -ne 0) { throw "demo.py failed (is python on PATH?)" }

    Write-Host ""
    Write-Host "======================================================================"
    Write-Host "  BONUS: real client-side AES-256-GCM encrypt->put->get->decrypt path"
    Write-Host "======================================================================"
    $env:VAULT_SIDECAR_URL = "http://127.0.0.1:$aHttp"
    & cargo run -q -p vault-client --example roundtrip

    Write-Host ""
    Write-Host "(demo complete — services stopped on exit)"
}
finally {
    foreach ($p in $procs) {
        if ($p -and -not $p.HasExited) { Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue }
    }
    Pop-Location
}
