package io.aegis.admin.web;

import io.aegis.admin.service.AdminRoleService;
import io.aegis.admin.web.AdminRoleDtos.ResolvedPermissions;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * Service-to-service permission resolution for the authorization-server to enrich tokens with a
 * subject's admin roles/permissions. Under {@code /api/v1/admin/internal/**}, gated by
 * {@code SCOPE_admin:resolve} (only the AS's own service token carries it).
 *
 * <p>Unlike the tenant-facing API, tenant and subject are passed as parameters (not read from the
 * token, which here belongs to the AS, not the admin). The {@code tenant:admin} SUPER_ADMIN fallback
 * is assumed false unless {@code tenantAdmin=true} is passed explicitly.
 */
@RestController
public class InternalPermissionController {

    private final AdminRoleService service;

    public InternalPermissionController(AdminRoleService service) {
        this.service = service;
    }

    @GetMapping("/api/v1/admin/internal/permissions")
    public ResolvedPermissions resolve(@RequestParam String tenant,
                                       @RequestParam String subject,
                                       @RequestParam(name = "tenantAdmin", defaultValue = "false")
                                       boolean tenantAdmin) {
        return new ResolvedPermissions(
                service.effectiveRoles(tenant, subject, tenantAdmin),
                service.effectivePermissions(tenant, subject, tenantAdmin));
    }
}
