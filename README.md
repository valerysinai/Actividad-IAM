# Módulo de Seguridad IAM: entrega implementable

## Diagnóstico de la base entregada

La fuente usa PostgreSQL 16 y Liquibase. Sus esquemas propios son `identity`, `session`, `rbac`, `rbac_catalog` e `identity_audit`. La aplicación reutiliza:

- `identity.user`: identidad, hash de contraseña, bloqueo por intentos y estado;
- `session.refresh_token`: sesiones revocables;
- `session.password_reset_request`: tokens de recuperación con expiración y uso único;
- `rbac.*`: catálogo de roles, funcionalidades y asignaciones ya sembrados.

No se modifica ni duplica el modelo: contiene exactamente lo necesario para los flujos requeridos.

## Arquitectura

`mobile/` (Expo + React Native) consume `backend/` (Go REST) y este usa `database/` (Liquibase/PostgreSQL). El cliente guarda access/refresh tokens en `expo-secure-store`; el access token JWT dura 15 minutos y el refresh token se hashea en base de datos y rota al usarlo.

## Ejecutar

1. Levante PostgreSQL y aplique `database/changelog/changelog-master.yaml` desde el orquestador Liquibase indicado en `database/README.md`.
2. En `backend`, copie `.env.example` como `.env`, complete `DATABASE_URL` y un `JWT_SECRET` aleatorio de 32+ caracteres; exporte esas variables y ejecute `go mod tidy; go run ./cmd/api`.
3. En `mobile`, copie `.env.example` como `.env`, cambie la IP por la IP LAN del equipo que ejecuta Go (para dispositivo físico), ejecute `npm install` y `npx expo start`.

## Pruebas manuales

Registro crea un registro en `identity.user`; un segundo registro devuelve 409. El login correcto devuelve sesión y `/api/me` es protegido; una contraseña incorrecta devuelve 401 y bloquea tras cinco intentos. Recuperación genera un registro en `session.password_reset_request`; en desarrollo el código aparece en la respuesta para completar el flujo, mientras que producción no lo revela y debe conectarse a correo. Restablecer la contraseña marca el token como usado, revoca sesiones existentes y permite un nuevo login.

## Seguridad incluida

Contraseñas con bcrypt, validación duplicada cliente/servidor, JWT firmado por secreto de entorno, CORS configurable, límite de payload, errores no sensibles, bloqueo temporal tras fallos, tokens aleatorios hasheados (SHA-256), expiración y transacciones para consumo de recuperación.
