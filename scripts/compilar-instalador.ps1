# Gera o instalador do Cofre de Contas a partir do codigo-fonte (Windows).
# Normalmente chamado pelo "Compilar instalador.bat" da raiz do projeto.
#
# 1. Confere os pre-requisitos (Node.js, Rust, compilador C++ da Microsoft, WebView2).
# 2. Instala as dependencias do projeto (npm ci).
# 3. Compila o app e gera os instaladores (npx tauri build).
# 4. Abre a pasta do instalador e diz qual arquivo executar.
#
# Nao instala nada no sistema sozinho: se faltar algo, mostra o comando para instalar.
#
# Use -SoVerificar para apenas conferir os pre-requisitos, sem compilar.

param([switch]$SoVerificar)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root

function Write-Step($text) { Write-Host ''; Write-Host "==> $text" -ForegroundColor Cyan }
function Write-Fail($text) { Write-Host ''; Write-Host "ERRO: $text" -ForegroundColor Red }

$missing = @()

Write-Step 'Conferindo pre-requisitos'

# Node.js 20.19+ ou 22.12+
$node = Get-Command node -ErrorAction SilentlyContinue
if (-not $node) {
    $missing += 'Node.js LTS        ->  winget install --id OpenJS.NodeJS.LTS -e'
} else {
    $v = [version]((& node --version).TrimStart('v'))
    # Mesma faixa exigida pelo Vite: ^20.19.0 || >=22.12.0
    $ok = ($v.Major -eq 20 -and $v.Minor -ge 19) -or ($v.Major -eq 22 -and $v.Minor -ge 12) -or ($v.Major -ge 23)
    if (-not $ok) { $missing += "Node.js $v e antigo (precisa 20.19+ ou 22.12+)  ->  winget upgrade --id OpenJS.NodeJS.LTS -e" }
    else { Write-Host "  Node.js $v" }
}

# Rust (cargo). O rustup instala em %USERPROFILE%\.cargo\bin, que as vezes nao entra no PATH.
if (-not (Get-Command cargo -ErrorAction SilentlyContinue)) {
    $cargoBin = Join-Path $env:USERPROFILE '.cargo\bin'
    if (Test-Path (Join-Path $cargoBin 'cargo.exe')) { $env:Path = "$cargoBin;$env:Path" }
}
if (-not (Get-Command cargo -ErrorAction SilentlyContinue)) {
    $missing += 'Rust (rustup)      ->  winget install --id Rustlang.Rustup -e'
} else {
    Write-Host "  $((& cargo --version))"
}

# Compilador C++ da Microsoft (workload "Desktop development with C++")
$vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
$hasVc = $false
if (Test-Path $vswhere) {
    $vc = & $vswhere -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
    $hasVc = [bool]$vc
}
if (-not $hasVc) {
    $missing += 'Build Tools C++    ->  winget install --id Microsoft.VisualStudio.2022.BuildTools -e --override "--wait --passive --add Microsoft.VisualStudio.Workload.VCTools --includeRecommended"'
} else {
    Write-Host '  Compilador C++ da Microsoft encontrado'
}

# WebView2 (necessario para o app abrir; ja vem no Windows 11)
$wv2Key = '{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}'
$wv2 = @(
    "HKLM:\SOFTWARE\WOW6432Node\Microsoft\EdgeUpdate\Clients\$wv2Key",
    "HKLM:\SOFTWARE\Microsoft\EdgeUpdate\Clients\$wv2Key",
    "HKCU:\Software\Microsoft\EdgeUpdate\Clients\$wv2Key"
) | Where-Object { Test-Path $_ }
if (-not $wv2) {
    Write-Host '  AVISO: WebView2 nao encontrado. Se o app abrir em branco, rode:' -ForegroundColor Yellow
    Write-Host '         winget install --id Microsoft.EdgeWebView2Runtime -e' -ForegroundColor Yellow
} else {
    Write-Host '  WebView2 encontrado'
}

if ($missing.Count -gt 0) {
    Write-Fail 'Faltam ferramentas para compilar. Abra o PowerShell e rode:'
    $missing | ForEach-Object { Write-Host "  - $_" }
    Write-Host ''
    Write-Host 'Depois FECHE esta janela, abra de novo e execute "Compilar instalador.bat" outra vez.'
    Write-Host 'Guia completo: docs\INSTALACAO.md'
    exit 1
}

if ($SoVerificar) {
    Write-Host ''
    Write-Host 'Todos os pre-requisitos foram encontrados.' -ForegroundColor Green
    exit 0
}

Write-Step 'Instalando dependencias do projeto (npm ci) - pode levar alguns minutos'
& npm ci
if ($LASTEXITCODE -ne 0) { Write-Fail 'npm ci falhou (veja as mensagens acima).'; exit 1 }

Write-Step 'Compilando o Cofre de Contas (a primeira vez demora de 5 a 15 minutos)'
& npx tauri build
if ($LASTEXITCODE -ne 0) { Write-Fail 'A compilacao falhou (veja as mensagens acima).'; exit 1 }

$targetDir = if ($env:CARGO_TARGET_DIR) { $env:CARGO_TARGET_DIR } else { Join-Path $root 'src-tauri\target' }
$bundle = Join-Path $targetDir 'release\bundle'
$setup = Get-ChildItem -Path (Join-Path $bundle 'nsis') -Filter '*-setup.exe' -ErrorAction SilentlyContinue |
    Sort-Object LastWriteTime -Descending | Select-Object -First 1
$msi = Get-ChildItem -Path (Join-Path $bundle 'msi') -Filter '*.msi' -ErrorAction SilentlyContinue |
    Sort-Object LastWriteTime -Descending | Select-Object -First 1

if (-not $setup) { Write-Fail "Instalador nao encontrado em $bundle"; exit 1 }

Write-Step 'Pronto!'
Write-Host ''
Write-Host 'Para instalar, execute este arquivo (recomendado, nao pede administrador):' -ForegroundColor Green
Write-Host "  $($setup.FullName)" -ForegroundColor Green
if ($msi) {
    Write-Host ''
    Write-Host 'Alternativa para instalar para todos os usuarios do PC (pede administrador):'
    Write-Host "  $($msi.FullName)"
}
Write-Host ''
Write-Host 'Depois de instalar, abra "Cofre de Contas" pelo menu Iniciar.'
Write-Host 'Primeiros passos: docs\INSTALACAO.md'

Start-Process explorer.exe -ArgumentList "/select,`"$($setup.FullName)`""
exit 0
