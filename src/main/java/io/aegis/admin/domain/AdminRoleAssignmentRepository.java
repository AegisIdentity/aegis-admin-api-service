package io.aegis.admin.domain;

import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;

/** Tenant-scoped persistence for {@link AdminRoleAssignment}. No bare findById is exposed to callers. */
public interface AdminRoleAssignmentRepository extends JpaRepository<AdminRoleAssignment, UUID> {

    List<AdminRoleAssignment> findByTenantIdOrderBySubject(String tenantId);

    List<AdminRoleAssignment> findByTenantId(String tenantId);

    Optional<AdminRoleAssignment> findByTenantIdAndSubject(String tenantId, String subject);
}
