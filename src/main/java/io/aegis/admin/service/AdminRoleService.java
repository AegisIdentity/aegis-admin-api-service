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
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.StringUtils;

/**
 * Manages per-tenant admin role assignments and resolves a subject's effective permissions. Every
 * operation is scoped to a tenant (taken from the caller's token, never the body).
 *
 * <p><strong>Backward compatibility:</strong> a subject with no explicit assignment but whose token
 * carries the {@code tenant:admin} scope is treated as {@link AdminRole#SUPER_ADMIN}, so existing
 * tenant admins keep full access until roles are explicitly assigned to them.
 */
@Service
public class AdminRoleService {

    private final AdminRoleAssignmentRepository assignments;

    public AdminRoleService(AdminRoleAssignmentRepository assignments) {
        this.assignments = assignments;
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
     * assigned roles, or — if there is no assignment and {@code hasTenantAdminScope} is true — the
     * single implicit {@link AdminRole#SUPER_ADMIN} (backward-compatible fallback). Only known roles
     * are returned (stale names in the CSV are skipped).
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
            return hasTenantAdminScope ? List.of(AdminRole.SUPER_ADMIN.name()) : List.of();
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
