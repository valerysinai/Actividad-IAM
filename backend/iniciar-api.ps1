# Inicia la API local usando las variables de backend/.env.
# Mantén abierta esta ventana mientras uses la aplicación.
$ErrorActionPreference = 'Stop'
Set-Location $PSScriptRoot

Write-Host 'Iniciando IAM API en http://localhost:8080 ...' -ForegroundColor Cyan
go run ./cmd/api
