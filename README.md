# aegis-admin-api-service

Admin/console API: policy, admin RBAC, System-Log query.

**Maturity: scaffold.** Buildable, secured resource-server skeleton — health endpoint, a protected
placeholder API, and the shared `aegis-security-commons` hardening baseline. Feature work goes here;
the intended contract is in
[`aegis-platform-docs/architecture/SERVICE-CATALOG.md`](../aegis-platform-docs/architecture/SERVICE-CATALOG.md).

- Port: `9107` · Required scope for `/api/**`: `admin:manage`
- Build: `./mvnw verify` (needs `aegis-platform-parent` + `aegis-platform-commons` installed to `~/.m2` first)
