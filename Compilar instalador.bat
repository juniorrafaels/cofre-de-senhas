@echo off
rem Gera o instalador do Cofre de Contas a partir do codigo-fonte.
rem De dois cliques neste arquivo. Instrucoes completas: docs\INSTALACAO.md
title Cofre de Contas - compilar instalador
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0scripts\compilar-instalador.ps1"
echo.
pause
