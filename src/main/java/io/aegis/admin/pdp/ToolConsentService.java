package io.aegis.admin.pdp;

import io.aegis.commons.audit.AuditEvent;
import io.aegis.commons.audit.AuditEventPublisher;
import io.aegis.commons.audit.AuditOutcome;
import java.util.List;
import java.util.Optional;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/** Grant, revoke and look up per-tool consent, and re-pin it when drift is only cosmetic. */
@Service
public class ToolConsentService {

    private final ToolConsentRepository consents;
    private final AuditEventPublisher audit;

    public ToolConsentService(ToolConsentRepository consents, AuditEventPublisher audit) {
        this.consents = consents;
        this.audit = audit;
    }

    @Transactional(readOnly = true)
    public Optional<ToolConsent> find(String tenantId, String subject, String agentId,
                                      String serverId, String toolName) {
        return consents.findByTenantIdAndSubjectAndAgentIdAndServerIdAndToolName(
                tenantId, subject, agentId, serverId, toolName);
    }

    /**
     * Grant consent, pinning the definition hash observed at approval time.
     *
     * <p>Re-granting an existing consent re-pins it rather than creating a duplicate: approving the
     * same tool twice is a normal user action, and a unique constraint violation is not a useful
     * thing to show someone who just clicked "allow".
     */
    @Transactional
    public ToolConsent grant(String tenantId, String subject, String agentId, String serverId,
                             String toolName, String definitionHash) {
        ToolConsent consent = find(tenantId, subject, agentId, serverId, toolName)
                .map(existing -> {
                    existing.rePin(definitionHash);
                    return existing;
                })
                .orElseGet(() -> new ToolConsent(tenantId, subject, agentId, serverId, toolName,
                        definitionHash));

        ToolConsent saved = consents.save(consent);
        record(tenantId, "agent.tool.consent.granted", agentId, serverId + "/" + toolName,
                definitionHash, AuditOutcome.SUCCESS);
        return saved;
    }

    @Transactional
    public void revoke(String tenantId, String subject, String agentId, String serverId,
                       String toolName, String reason) {
        find(tenantId, subject, agentId, serverId, toolName).ifPresent(consent -> {
            consent.revoke(reason);
            consents.save(consent);
            record(tenantId, "agent.tool.consent.revoked", agentId, serverId + "/" + toolName,
                    consent.getPinnedDefinitionHash(), AuditOutcome.SUCCESS);
        });
    }

    /**
     * Handle a tool whose definition changed.
     *
     * <p>Only ever called for drift already classified as <b>cosmetic</b>, and only when tenant
     * policy opts in. Semantic drift must go back to the user for re-approval — auto-approving it
     * would defeat the entire control.
     */
    @Transactional
    public void rePinAfterCosmeticDrift(String tenantId, String subject, String agentId,
                                        String serverId, String toolName, String newHash) {
        find(tenantId, subject, agentId, serverId, toolName).ifPresent(consent -> {
            consent.rePin(newHash);
            consents.save(consent);
            record(tenantId, "agent.tool.consent.repinned", agentId, serverId + "/" + toolName,
                    newHash, AuditOutcome.SUCCESS);
        });
    }

    @Transactional(readOnly = true)
    public List<ToolConsent> forAgent(String tenantId, String agentId) {
        return consents.findByTenantIdAndAgentId(tenantId, agentId);
    }

    @Transactional(readOnly = true)
    public List<ToolConsent> forSubject(String tenantId, String subject) {
        return consents.findByTenantIdAndSubject(tenantId, subject);
    }

    private void record(String tenantId, String action, String agentId, String tool, String hash,
                        AuditOutcome outcome) {
        if (audit == null) {
            return;
        }
        audit.publish(AuditEvent.of("agent", action, outcome)
                .tenant(tenantId)
                .actor(agentId)
                .target(tool)
                // The hash identifies WHICH version was approved — it is a digest, never content.
                .attribute("definitionHash", hash)
                .build());
    }
}
