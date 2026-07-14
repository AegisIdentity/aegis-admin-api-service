package io.aegis.admin.web;

import io.aegis.admin.domain.AdminRoleAssignment;
import io.aegis.admin.rbac.AdminRole;
import io.aegis.admin.service.AdminRoleService;
import io.aegis.admin.web.AdminRoleDtos.AdminAssignmentView;
import io.aegis.admin.web.AdminRoleDtos.EffectiveAccessView;
import io.aegis.admin.web.AdminRoleDtos.RoleCatalogEntry;
import io.aegis.admin.web.AdminRoleDtos.UpdateRolesRequest;
import jakarta.validation.Valid;
import java.util.List;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

/**
 * Admin RBAC API. The tenant is always taken from the caller's token, so an admin manages only their
 * own organization's role assignments. Managing assignments requires {@code SCOPE_tenant:admin}; the
 * role catalog and {@code /me} are available to any authenticated caller so the console can render its
 * UI and gate actions.
 */
@RestController
public class AdminRoleController {

    /** The scope that marks a caller as a tenant admin (used for the SUPER_ADMIN fallback in /me). */
    private static final String TENANT_ADMIN_SCOPE = "tenant:admin";

    private final AdminRoleService service;

    public AdminRoleController(AdminRoleService service) {
        this.service = service;
    }

    /** The role catalog: every role and the permissions it grants. Available to any authenticated caller. */
    @GetMapping("/api/v1/admin/roles")
    public List<RoleCatalogEntry> catalog() {
        return java.util.Arrays.stream(AdminRole.values())
                .map(r -> new RoleCatalogEntry(r.name(), List.copyOf(r.permissions())))
                .toList();
    }

    /** The tenant's admins and their assigned roles. Requires {@code SCOPE_tenant:admin}. */
    @GetMapping("/api/v1/admin/admins")
    public List<AdminAssignmentView> listAdmins(@AuthenticationPrincipal Jwt caller) {
        return service.list(tenantOf(caller)).stream()
                .map(AdminRoleController::toView)
                .toList();
    }

    /** Create or replace a subject's roles. Requires {@code SCOPE_tenant:admin}. Unknown role -> 400. */
    @PutMapping("/api/v1/admin/admins/{subject}")
    public AdminAssignmentView upsertAdmin(@PathVariable String subject,
                                           @Valid @RequestBody UpdateRolesRequest request,
                                           @AuthenticationPrincipal Jwt caller) {
        AdminRoleAssignment saved = service.upsert(tenantOf(caller), subject, request.roles());
        return toView(saved);
    }

    /** Remove a subject's assignment entirely. Requires {@code SCOPE_tenant:admin}. */
    @DeleteMapping("/api/v1/admin/admins/{subject}")
    public ResponseEntity<Void> deleteAdmin(@PathVariable String subject,
                                            @AuthenticationPrincipal Jwt caller) {
        service.delete(tenantOf(caller), subject);
        return ResponseEntity.noContent().build();
    }

    /**
     * The caller's own effective roles and permissions — what the console gates its UI on. Falls back
     * to SUPER_ADMIN when the caller has no assignment but carries {@code tenant:admin} (see
     * {@code AdminRoleService}).
     */
    @GetMapping("/api/v1/admin/me")
    public EffectiveAccessView me(@AuthenticationPrincipal Jwt caller) {
        String tenant = tenantOf(caller);
        String subject = caller.getSubject();
        boolean tenantAdmin = hasTenantAdminScope(caller);
        List<String> roles = service.effectiveRoles(tenant, subject, tenantAdmin);
        List<String> permissions = service.effectivePermissions(tenant, subject, tenantAdmin);
        return new EffectiveAccessView(subject, roles, permissions);
    }

    private static AdminAssignmentView toView(AdminRoleAssignment a) {
        return new AdminAssignmentView(a.getSubject(), a.getRoles());
    }

    private static boolean hasTenantAdminScope(Jwt caller) {
        // The `scope` claim may be a JSON array (Spring Authorization Server emits a Set) OR a
        // space-delimited string, depending on the issuer — handle both.
        Object scopeClaim = caller.getClaim("scope");
        if (scopeClaim instanceof java.util.Collection<?> scopes) {
            return scopes.stream().anyMatch(s -> TENANT_ADMIN_SCOPE.equals(String.valueOf(s).trim()));
        }
        String scope = caller.getClaimAsString("scope");
        if (scope == null || scope.isBlank()) {
            return false;
        }
        for (String s : scope.split(" ")) {
            if (TENANT_ADMIN_SCOPE.equals(s.trim())) {
                return true;
            }
        }
        return false;
    }

    private static String tenantOf(Jwt caller) {
        String tenant = caller.getClaimAsString("tenant");
        if (tenant == null || tenant.isBlank()) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "token carries no tenant");
        }
        return tenant;
    }
}
