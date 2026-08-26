package io.aegis.admin.pdp;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import jakarta.persistence.UniqueConstraint;
import java.time.Instant;
import java.util.UUID;

/**
 * Consent to invoke one <b>version</b> of one tool (ADR-0013).
 *
 * <p>The platform's existing {@code JdbcOAuth2AuthorizationConsentService} is <em>scope</em>-granular
 * and cannot express "I approved <em>this version</em> of this tool". That gap matters because a
 * tool's description is the instruction surface the model reads: a server can change what a tool
 * means without changing its name or the scopes it needs, and scope-granular consent is blind to it.
 *
 * <p>{@code pinnedDefinitionHash} closes that gap. Consent is bound to a content hash, and any
 * semantic change invalidates it.
 */
@Entity
@Table(name = "tool_consent", uniqueConstraints = @UniqueConstraint(
        name = "uq_tool_consent_scope",
        columnNames = {"tenant_id", "subject", "agent_id", "server_id", "tool_name"}))
public class ToolConsent {

    @Id
    @Column(nullable = false, updatable = false)
    private UUID id;

    @Column(name = "tenant_id", nullable = false, updatable = false, length = 64)
    private String tenantId;

    /** The principal who granted consent — normally the human at the root of the chain. */
    @Column(nullable = false, updatable = false, length = 200)
    private String subject;

    @Column(name = "agent_id", nullable = false, updatable = false, length = 128)
    private String agentId;

    @Column(name = "server_id", nullable = false, updatable = false, length = 200)
    private String serverId;

    @Column(name = "tool_name", nullable = false, updatable = false, length = 200)
    private String toolName;

    /** The content hash of the tool definition at the moment consent was granted. */
    @Column(name = "pinned_definition_hash", nullable = false, length = 128)
    private String pinnedDefinitionHash;

    @Column(name = "granted_at", nullable = false, updatable = false)
    private Instant grantedAt = Instant.now();

    @Column(name = "updated_at", nullable = false)
    private Instant updatedAt = Instant.now();

    @Column(name = "revoked_at")
    private Instant revokedAt;

    @Column(name = "revoked_reason", length = 500)
    private String revokedReason;

    protected ToolConsent() {
    }

    public ToolConsent(String tenantId, String subject, String agentId, String serverId,
                       String toolName, String pinnedDefinitionHash) {
        if (pinnedDefinitionHash == null || pinnedDefinitionHash.isBlank()) {
            throw new IllegalArgumentException(
                    "consent must pin a definition hash — unpinned consent cannot detect a rug pull");
        }
        this.id = UUID.randomUUID();
        this.tenantId = tenantId;
        this.subject = subject;
        this.agentId = agentId;
        this.serverId = serverId;
        this.toolName = toolName;
        this.pinnedDefinitionHash = pinnedDefinitionHash;
    }

    public boolean isActive() {
        return revokedAt == null;
    }

    public void revoke(String reason) {
        this.revokedAt = Instant.now();
        this.revokedReason = reason;
        this.updatedAt = Instant.now();
    }

    /**
     * Move the pin to a new definition hash — the cosmetic-drift path, where tenant policy allows
     * auto-approving a display-only change.
     *
     * @throws IllegalStateException if consent was revoked. Re-pinning a revoked consent would
     *                               resurrect a grant the user deliberately withdrew.
     */
    public void rePin(String newDefinitionHash) {
        if (!isActive()) {
            throw new IllegalStateException("cannot re-pin revoked consent for "
                    + serverId + "/" + toolName);
        }
        if (newDefinitionHash == null || newDefinitionHash.isBlank()) {
            throw new IllegalArgumentException("definition hash is required");
        }
        this.pinnedDefinitionHash = newDefinitionHash;
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

    public String getAgentId() {
        return agentId;
    }

    public String getServerId() {
        return serverId;
    }

    public String getToolName() {
        return toolName;
    }

    public String getPinnedDefinitionHash() {
        return pinnedDefinitionHash;
    }

    public Instant getGrantedAt() {
        return grantedAt;
    }

    public Instant getRevokedAt() {
        return revokedAt;
    }

    public String getRevokedReason() {
        return revokedReason;
    }
}
