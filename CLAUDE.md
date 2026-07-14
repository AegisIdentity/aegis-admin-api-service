# aegis-admin-api-service — working notes

Admin/console API: **admin RBAC** (role catalog + per-tenant role assignments + effective-permission
resolution).  **Port 9107. Postgres (`aegis_admin`), JPA.**  **Maturity: live** (admin RBAC implemented).

## What this is
A Spring Boot 4.1 / Java 21 OAuth2 **resource server** in the Aegis polyrepo. Package root:
`io.aegis.admin`. Security lives in `SecurityConfig` (uses `io.aegis.commons.security.SecurityHardening`);
JWTs are decoded by the split-horizon `config.ResourceServerJwtConfig` (in-network JWKS + issuer allowlist).

### RBAC model
- `rbac.Permission` — the fine-grained permission catalog (`Permission.ALL` is the full set).
- `rbac.AdminRole` — SUPER_ADMIN / USER_ADMIN / HELP_DESK / APP_ADMIN / AUDITOR, each a fixed permission set.
- `domain.AdminRoleAssignment` — per-tenant `(subject -> roles CSV)`, unique `(tenant_id, subject)`.
- `service.AdminRoleService` — list/get/upsert/delete + `effectivePermissions`. Backward-compat: a subject
  with no assignment but a `tenant:admin` token is treated as SUPER_ADMIN.
- Endpoints under `/api/v1/admin/**` (see `web/`): `roles`, `admins`, `me`, `internal/permissions`.

## Non-negotiables (do not regress)
- Default-deny: every new endpoint stays denied until an explicit `authorizeHttpRequests` rule + a
  **negative test** ("no token -> 401", "wrong scope -> 403") is added.
- Keep the shared hardening baseline applied. Validate JWTs against the authorization-server issuer.
- All persistent data must be **tenant-scoped** (see ARCHITECTURE.md §5). No cross-tenant reads.

## Build / test
`./mvnw verify` — resolves `aegis-platform-parent` and `aegis-security-commons` from `~/.m2`
(build `aegis-platform-bom` and `aegis-platform-commons` first).

## Next steps
Wire domain events (role grants/revokes) to `aegis-audit-commons`; have the authorization-server call
`GET /api/v1/admin/internal/permissions` (SCOPE_admin:resolve) to enrich tokens with admin permissions.
