package io.aegis.admin.domain;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import jakarta.persistence.UniqueConstraint;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

/**
 * A per-tenant assignment of admin {@code roles} to a {@code subject} (the admin's username/{@code sub}).
 * Always scoped to a {@code tenantId}; the pair (tenant, subject) is unique — a subject has at most one
 * assignment row per tenant, whose {@code roles} column holds the granted roles as a CSV of
 * {@code AdminRole} names.
 */
@Entity
@Table(name = "admin_role_assignment", uniqueConstraints = {
        @UniqueConstraint(name = "uq_admin_role_tenant_subject", columnNames = {"tenant_id", "subject"})
})
public class AdminRoleAssignment {

    @Id
    @Column(nullable = false, updatable = false)
    private UUID id;

    @Column(name = "tenant_id", nullable = false, updatable = false, length = 64)
    private String tenantId;

    /** The admin's username / token subject this assignment grants roles to. */
    @Column(nullable = false, length = 320)
    private String subject;

    /** Granted {@code AdminRole} names as a comma-separated list (see {@link #getRoles()}). */
    @Column(nullable = false, length = 512)
    private String roles = "";

    @Column(name = "updated_at", nullable = false)
    private Instant updatedAt = Instant.now();

    protected AdminRoleAssignment() {
    }

    public AdminRoleAssignment(UUID id, String tenantId, String subject) {
        this.id = id;
        this.tenantId = tenantId;
        this.subject = subject;
    }

    /** The granted role names, in stored order, with blanks stripped. */
    public List<String> getRoles() {
        List<String> out = new ArrayList<>();
        if (roles == null || roles.isBlank()) {
            return out;
        }
        for (String part : roles.split(",")) {
            String trimmed = part.trim();
            if (!trimmed.isEmpty()) {
                out.add(trimmed);
            }
        }
        return out;
    }

    /** Replace the granted roles (stored as CSV) and stamp {@code updatedAt}. */
    public void setRoles(List<String> roleNames) {
        this.roles = roleNames == null ? "" : String.join(",", roleNames);
        touch();
    }

    public void touch() {
        this.updatedAt = Instant.now();
    }

    public UUID getId() {
        return id;
    }

    public String getTenantId() {
        return tenantId;
    }

    public String getSubject() {
        return subject;
    }

    public Instant getUpdatedAt() {
        return updatedAt;
    }
}
