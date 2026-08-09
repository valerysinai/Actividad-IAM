# API IAM (Go)

API REST en Go que reutiliza los esquemas `identity`, `session` y `rbac` de la base entregada.

1. Copie `.env.example` a `.env` y exporte sus valores en su terminal (PowerShell: `Get-Content .env | ForEach-Object { $k,$v=$_.Split('=',2); Set-Item "Env:$k" $v }`).
2. Aplique los changelogs de `../database` con el orquestador Liquibase del proyecto.
3. Ejecute `go mod tidy` y `go run ./cmd/api`.

Rutas: `POST /api/auth/register`, `login`, `refresh`, `forgot-password`, `reset-password`; `GET /api/me` y `POST /api/auth/change-password` requieren `Authorization: Bearer <accessToken>`.

En desarrollo, `forgot-password` devuelve `developmentToken`; en producción se entrega siempre el mismo mensaje y el token debe enviarse mediante un proveedor de correo. Nunca active `APP_ENV=production` sin integrar ese envío.
