package io.aegis.admin.pdp;

import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;

/** Tenant-scoped by construction, like every repository in this platform. */
public interface ToolConsentRepository extends JpaRepository<ToolConsent, UUID> {

    Optional<ToolConsent> findByTenantIdAndSubjectAndAgentIdAndServerIdAndToolName(
            String tenantId, String subject, String agentId, String serverId, String toolName);

    List<ToolConsent> findByTenantIdAndSubject(String tenantId, String subject);

    List<ToolConsent> findByTenantIdAndAgentId(String tenantId, String agentId);
}
