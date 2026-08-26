package io.aegis.admin.web;

import io.aegis.admin.pdp.ToolConsent;
import io.aegis.admin.pdp.ToolConsentService;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import java.time.Instant;
import java.util.List;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

/**
 * Per-tool consent management.
 *
 * <p>Tenant is taken from the token's {@code tenant} claim and never from the path or body. That is
 * deliberate after a cross-tenant IDOR was found in a sibling endpoint that accepted a tenant slug
 * as a path variable: an identifier the caller supplies must always be re-checked against the
 * caller's own identity, and the simplest way to be safe is never to accept one.
 */
@RestController
public class AgentPolicyController {

    private final ToolConsentService consents;

    public AgentPolicyController(ToolConsentService consents) {
        this.consents = consents;
    }

    public record GrantConsentRequest(
            @NotBlank String agentId,
            @NotBlank String serverId,
            @NotBlank String toolName,
            @NotBlank String definitionHash) {
    }

    public record ConsentResponse(String subject, String agentId, String serverId, String toolName,
                                  String pinnedDefinitionHash, Instant grantedAt, boolean active) {

        static ConsentResponse from(ToolConsent c) {
            return new ConsentResponse(c.getSubject(), c.getAgentId(), c.getServerId(),
                    c.getToolName(), c.getPinnedDefinitionHash(), c.getGrantedAt(), c.isActive());
        }
    }

    @GetMapping("/api/v1/agent-consents")
    public List<ConsentResponse> list(@AuthenticationPrincipal Jwt jwt,
                                      @RequestParam(required = false) String agentId) {
        String tenant = tenantOf(jwt);
        List<ToolConsent> found = agentId == null || agentId.isBlank()
                ? consents.forSubject(tenant, subjectOf(jwt))
                : consents.forAgent(tenant, agentId);
        return found.stream().map(ConsentResponse::from).toList();
    }

    @PostMapping("/api/v1/agent-consents")
    public ResponseEntity<ConsentResponse> grant(@AuthenticationPrincipal Jwt jwt,
                                                 @Valid @RequestBody GrantConsentRequest request) {
        ToolConsent consent = consents.grant(tenantOf(jwt), subjectOf(jwt), request.agentId(),
                request.serverId(), request.toolName(), request.definitionHash());
        return ResponseEntity.status(HttpStatus.CREATED).body(ConsentResponse.from(consent));
    }

    @DeleteMapping("/api/v1/agent-consents")
    public ResponseEntity<Void> revoke(@AuthenticationPrincipal Jwt jwt,
                                       @RequestParam String agentId,
                                       @RequestParam String serverId,
                                       @RequestParam String toolName,
                                       @RequestParam(required = false) String reason) {
        consents.revoke(tenantOf(jwt), subjectOf(jwt), agentId, serverId, toolName, reason);
        return ResponseEntity.noContent().build();
    }

    private static String tenantOf(Jwt jwt) {
        String tenant = jwt == null ? null : jwt.getClaimAsString("tenant");
        if (tenant == null || tenant.isBlank()) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "token carries no tenant");
        }
        return tenant;
    }

    /** Consent belongs to the authenticated principal — never a subject named in the request. */
    private static String subjectOf(Jwt jwt) {
        String subject = jwt == null ? null : jwt.getSubject();
        if (subject == null || subject.isBlank()) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "token carries no subject");
        }
        return subject;
    }
}
