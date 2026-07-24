package io.aegis.admin.service;

import io.aegis.admin.domain.AdminRoleAssignment;
import io.aegis.admin.domain.AdminRoleAssignmentRepository;
import io.aegis.admin.rbac.AdminRole;
import io.aegis.admin.service.AdminRbacExceptions.AssignmentNotFoundException;
import io.aegis.admin.service.AdminRbacExceptions.UnknownRoleException;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.StringUtils;

/**
 * Manages per-tenant admin role assignments and resolves a subject's effective permissions. Every
 * operation is scoped to a tenant (taken from the caller's token, never the body).
 *
 * <p><strong>Backward compatibility (M-svc-3):</strong> a subject with no explicit assignment but whose
 * token carries the {@code tenant:admin} scope <em>may</em> be treated as {@link AdminRole#SUPER_ADMIN}.
 * This implicit grant nullifies the least-privilege role catalog, so it is <strong>off by default</strong>
 * and must be explicitly opted into via {@code aegis.admin.tenant-admin-super-admin-fallback.enabled=true}.
 * When enabled, every implicit SUPER_ADMIN grant is audit-logged. Prefer assigning SUPER_ADMIN explicitly.
 */
@Service
public class AdminRoleService {

    private static final Logger log = LoggerFactory.getLogger(AdminRoleService.class);

    private final AdminRoleAssignmentRepository assignments;
    private final boolean tenantAdminSuperAdminFallback;

    public AdminRoleService(AdminRoleAssignmentRepository assignments,
                            @Value("${aegis.admin.tenant-admin-super-admin-fallback.enabled:false}")
                            boolean tenantAdminSuperAdminFallback) {
        this.assignments = assignments;
        this.tenantAdminSuperAdminFallback = tenantAdminSuperAdminFallback;
    }

    @Transactional(readOnly = true)
    public List<AdminRoleAssignment> list(String tenantId) {
        requireTenant(tenantId);
        return assignments.findByTenantIdOrderBySubject(tenantId);
    }

    @Transactional(readOnly = true)
    public Optional<AdminRoleAssignment> get(String tenantId, String subject) {
        requireTenant(tenantId);
        return assignments.findByTenantIdAndSubject(tenantId, subject);
    }

    /**
     * Create or replace the roles granted to {@code subject} in {@code tenantId}. Every role name must
     * be a known {@link AdminRole}; an unknown name is rejected (400 via
     * {@link UnknownRoleException}). Role names are de-duplicated and stored in catalog order.
     */
    @Transactional
    public AdminRoleAssignment upsert(String tenantId, String subject, List<String> roleNames) {
        requireTenant(tenantId);
        if (!StringUtils.hasText(subject)) {
            throw new IllegalArgumentException("subject is required");
        }
        List<String> normalized = validateAndNormalize(roleNames);
        AdminRoleAssignment assignment = assignments.findByTenantIdAndSubject(tenantId, subject)
                .orElseGet(() -> new AdminRoleAssignment(UUID.randomUUID(), tenantId, subject));
        assignment.setRoles(normalized);
        return assignments.save(assignment);
    }

    @Transactional
    public void delete(String tenantId, String subject) {
        requireTenant(tenantId);
        AdminRoleAssignment assignment = assignments.findByTenantIdAndSubject(tenantId, subject)
                .orElseThrow(() -> new AssignmentNotFoundException("no role assignment for subject in tenant"));
        assignments.delete(assignment);
    }

    /**
     * The role names effectively held by {@code subject} in {@code tenantId}. Returns the subject's
     * assigned roles, or — if there is no assignment, {@code hasTenantAdminScope} is true, AND the
     * {@code tenant:admin}→SUPER_ADMIN fallback is enabled (M-svc-3) — the single implicit
     * {@link AdminRole#SUPER_ADMIN} (audit-logged). Only known roles are returned (stale names in the CSV
     * are skipped).
     */
    @Transactional(readOnly = true)
    public List<String> effectiveRoles(String tenantId, String subject, boolean hasTenantAdminScope) {
        requireTenant(tenantId);
        // Never fall back to SUPER_ADMIN for a missing/blank subject (e.g. an absent 'sub' claim during
        // token enrichment) — that would over-grant to no one in particular.
        if (!StringUtils.hasText(subject)) {
            return List.of();
        }
        Optional<AdminRoleAssignment> assignment = assignments.findByTenantIdAndSubject(tenantId, subject);
        if (assignment.isEmpty()) {
            if (hasTenantAdminScope && tenantAdminSuperAdminFallback) {
                // Audit every implicit SUPER_ADMIN grant (M-svc-3) — this bypasses least-privilege RBAC.
                log.warn("AUDIT admin.super_admin_fallback granted implicit SUPER_ADMIN via tenant:admin "
                        + "scope (tenant={}, subject={}); assign an explicit SUPER_ADMIN role to remove "
                        + "this fallback", tenantId, subject);
                return List.of(AdminRole.SUPER_ADMIN.name());
            }
            return List.of();
        }
        List<String> roles = new ArrayList<>();
        for (String name : assignment.get().getRoles()) {
            AdminRole.fromName(name).ifPresent(r -> roles.add(r.name()));
        }
        return roles;
    }

    /**
     * The union of the permissions of the subject's {@link #effectiveRoles effective roles}. See that
     * method for the {@code tenant:admin} backward-compatible fallback.
     */
    @Transactional(readOnly = true)
    public List<String> effectivePermissions(String tenantId, String subject, boolean hasTenantAdminScope) {
        Set<String> permissions = new LinkedHashSet<>();
        for (String roleName : effectiveRoles(tenantId, subject, hasTenantAdminScope)) {
            AdminRole.fromName(roleName).ifPresent(r -> permissions.addAll(r.permissions()));
        }
        return new ArrayList<>(permissions);
    }

    /** Validate every role name against the catalog, de-duplicate, and return them in catalog order. */
    private static List<String> validateAndNormalize(List<String> roleNames) {
        Set<AdminRole> resolved = new LinkedHashSet<>();
        if (roleNames != null) {
            for (String name : roleNames) {
                AdminRole role = AdminRole.fromName(name)
                        .orElseThrow(() -> new UnknownRoleException("unknown role: " + name));
                resolved.add(role);
            }
        }
        // Emit in enum declaration order for stable output.
        List<String> out = new ArrayList<>();
        for (AdminRole role : AdminRole.values()) {
            if (resolved.contains(role)) {
                out.add(role.name());
            }
        }
        return out;
    }

    private static void requireTenant(String tenantId) {
        if (!StringUtils.hasText(tenantId)) {
            throw new IllegalArgumentException("tenantId is required");
        }
    }
}
