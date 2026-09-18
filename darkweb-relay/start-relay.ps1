# NEXUS OSINT — Arranque del Dark Web Tor Relay (Windows)
# Detecta Tor Browser, lo abre si no está corriendo, espera al proxy SOCKS
# y lanza el relay local. Todo el tráfico .onion pasa por circuitos Tor.
$ErrorActionPreference = 'Stop'
$relayDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$relayJs = Join-Path $relayDir 'relay.mjs'

function Test-Port([int]$Port) {
    try {
        $c = New-Object System.Net.Sockets.TcpClient
        $iar = $c.BeginConnect('127.0.0.1', $Port, $null, $null)
        if (-not $iar.AsyncWaitHandle.WaitOne(800)) { $c.Close(); return $false }
        if ($c.Connected) { $c.Close(); return $true }
        $c.Close(); return $false
    } catch { return $false }
}

# --- 1. Localizar Tor Browser ---
$tbb = $null
$candidates = @(
    "$env:LOCALAPPDATA\Tor Browser\Browser\TorBrowser\Tor\tor.exe",
    "$env:ProgramFiles\Tor Browser\Browser\TorBrowser\Tor\tor.exe",
    "${env:ProgramFiles(x86)}\Tor Browser\Browser\TorBrowser\Tor\tor.exe"
)
foreach ($c in $candidates) { if (Test-Path $c) { $tbb = $c; break } }
if (-not $tbb) {
    try {
        $reg = Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*', 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*' -ErrorAction SilentlyContinue |
            Where-Object { $_.DisplayName -like '*Tor Browser*' } | Select-Object -First 1
        if ($reg -and $reg.InstallLocation) { $tbb = Join-Path $reg.InstallLocation 'Browser\TorBrowser\Tor\tor.exe' }
    } catch { }
}

Write-Host ''
Write-Host '============================================================'
Write-Host ' NEXUS OSINT — Dark Web Tor Relay (arranque)' -ForegroundColor Cyan
Write-Host '============================================================'

# --- 2. Verificar / iniciar proxy Tor (9150 Tor Browser | 9050 daemon) ---
$torReady = (Test-Port 9150) -or (Test-Port 9050)

if (-not $torReady) {
    if ($tbb) {
        Write-Host '[*] Proxy Tor apagado. Iniciando Tor Browser...' -ForegroundColor Yellow
        Start-Process (Split-Path $tbb) -ArgumentList '--no-remote'  # lanza el launcher del bundle
        Write-Host '[?] Si no se abrió, ejecuta manualmente Tor Browser y pulsa "Connect".' -ForegroundColor Yellow
    } else {
        Write-Host '[!] Tor Browser no encontrado.' -ForegroundColor Red
        Write-Host '    Descárgalo de https://www.torproject.org/download/ e instálalo,' -ForegroundColor Red
        Write-Host '    o instala el daemon Tor:  winget install TorProject.TorBrowser  o  tor daemon' -ForegroundColor Red
    }
}

$waited = 0
while (-not ((Test-Port 9150) -or (Test-Port 9050)) -and $waited -lt 90) {
    Start-Sleep -Seconds 2
    $waited += 2
}
if ($waited -ge 90) {
    Write-Host '[!] Timeout esperando el proxy Tor. ¿Pulsaste "Connect" en Tor Browser?' -ForegroundColor Red
}

if ((Test-Port 9150)) { Write-Host '[+] Proxy Tor: 127.0.0.1:9150 (Tor Browser)' -ForegroundColor Green }
elseif ((Test-Port 9050)) { Write-Host '[+] Proxy Tor: 127.0.0.1:9050 (Tor daemon)' -ForegroundColor Green }
else { Write-Host '[-] Sin proxy Tor — la búsqueda .onion no podrá funcionar.' -ForegroundColor Red }

# --- 3. Lanzar el relay ---
Write-Host '[+] Iniciando relay en http://127.0.0.1:18909 ...' -ForegroundColor Green
Write-Host ''
Write-Host '    Deja esta ventana abierta mientras usas el módulo Dark Web.' -ForegroundColor DarkGray
Write-Host ''
node $relayJs