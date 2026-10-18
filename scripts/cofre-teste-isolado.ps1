# Isola o cofre real durante testes manuais do Cofre de Contas.
#
#   powershell -ExecutionPolicy Bypass -File scripts\cofre-teste-isolado.ps1 Status
#   powershell -ExecutionPolicy Bypass -File scripts\cofre-teste-isolado.ps1 Preparar
#   powershell -ExecutionPolicy Bypass -File scripts\cofre-teste-isolado.ps1 Restaurar
#
# Preparar : renomeia %APPDATA%\<identifier> para <identifier>.COFRE-REAL-GUARDADO. O app passa a
#            se comportar como instalacao nova e cria um cofre de TESTE no lugar.
# Restaurar: renomeia a pasta de teste para <identifier>.TESTE-descartado-<data> e devolve o nome
#            original ao cofre real.
#
# O script NUNCA apaga nada: so renomeia pastas. Apague a pasta TESTE-descartado manualmente
# quando quiser. Feche o Cofre de Contas antes de rodar.

param(
    [Parameter(Mandatory = $true, Position = 0)]
    [ValidateSet('Status', 'Preparar', 'Restaurar')]
    [string]$Acao
)

$ErrorActionPreference = 'Stop'

$confPath = Join-Path $PSScriptRoot '..\src-tauri\tauri.conf.json'
$identifier = (Get-Content -Raw -Encoding UTF8 $confPath | ConvertFrom-Json).identifier
if ([string]::IsNullOrWhiteSpace($identifier)) { throw "Identifier nao encontrado em $confPath" }

$real = Join-Path $env:APPDATA $identifier
$guardado = "$real.COFRE-REAL-GUARDADO"

function Show-Status {
    Write-Host "Identifier : $identifier"
    Write-Host ("Pasta ativa: {0}  [{1}]" -f $real, $(if (Test-Path -LiteralPath $real) { 'existe' } else { 'nao existe' }))
    Write-Host ("Cofre real guardado: {0}  [{1}]" -f $guardado, $(if (Test-Path -LiteralPath $guardado) { 'existe' } else { 'nao existe' }))
    Get-ChildItem -LiteralPath $env:APPDATA -Directory -Filter "$identifier.TESTE-descartado-*" -ErrorAction SilentlyContinue |
        ForEach-Object { Write-Host "Pasta de teste descartada: $($_.FullName)" }
}

function Assert-AppClosed {
    $running = Get-Process -ErrorAction SilentlyContinue | Where-Object { $_.ProcessName -in @('tauri-app', 'Cofre de Contas') }
    if ($running) { throw 'O Cofre de Contas esta aberto. Feche o app (inclusive o modo dev) e rode de novo.' }
}

switch ($Acao) {
    'Status' { Show-Status }

    'Preparar' {
        Assert-AppClosed
        if (Test-Path -LiteralPath $guardado) {
            throw "Ja existe um cofre guardado em $guardado. Rode 'Restaurar' antes de preparar de novo."
        }
        if (Test-Path -LiteralPath $real) {
            Rename-Item -LiteralPath $real -NewName (Split-Path -Leaf $guardado)
            Write-Host "Cofre real guardado em: $guardado"
        } else {
            Write-Host 'Nenhum cofre real encontrado nesta maquina; nada a guardar.'
        }
        Write-Host 'Pronto. Abra o Cofre de Contas: ele vai pedir para criar um cofre novo (use so dados de teste).'
    }

    'Restaurar' {
        Assert-AppClosed
        if (-not (Test-Path -LiteralPath $guardado)) {
            throw "Nao ha cofre guardado em $guardado. Nada a restaurar (o cofre ativo foi mantido como esta)."
        }
        if (Test-Path -LiteralPath $real) {
            $descartado = "$identifier.TESTE-descartado-{0}" -f (Get-Date -Format 'yyyyMMdd-HHmmss')
            Rename-Item -LiteralPath $real -NewName $descartado
            Write-Host "Cofre de teste movido para: $(Join-Path $env:APPDATA $descartado)"
        }
        Rename-Item -LiteralPath $guardado -NewName (Split-Path -Leaf $real)
        Write-Host "Cofre real restaurado em: $real"
    }
}
