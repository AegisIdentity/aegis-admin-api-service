package io.aegis.admin.web;

import jakarta.validation.constraints.NotEmpty;
import java.util.List;

/** Payloads for the admin RBAC API. */
public final class AdminRoleDtos {

    private AdminRoleDtos() {
    }

    /** One entry of the role catalog: a role and the permissions it grants. */
    public record RoleCatalogEntry(String role, List<String> permissions) {
    }

    /** A subject's role assignment within the tenant. */
    public record AdminAssignmentView(String subject, List<String> roles) {
    }

    /**
     * Upsert body for {@code PUT /admins/{subject}}: the full set of roles to grant. Must be non-empty —
     * clearing a subject's roles (and re-enabling any {@code tenant:admin} SUPER_ADMIN fallback) is done
     * via {@code DELETE}, not by PUTting an empty list.
     */
    public record UpdateRolesRequest(@NotEmpty List<String> roles) {
    }

    /** The caller's (or a resolved subject's) effective roles and permissions. */
    public record EffectiveAccessView(String subject, List<String> roles, List<String> permissions) {
    }

    /** Server-to-server permission resolution result (no subject echoed; caller passed it in). */
    public record ResolvedPermissions(List<String> roles, List<String> permissions) {
    }
}
