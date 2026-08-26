package io.aegis.admin.pdp;

import io.aegis.commons.agent.AutonomyLevel;

/**
 * The synchronous control that can actually <b>prevent</b> a bad agent action.
 *
 * <p>Worth being precise about the division of labour: the detection pipeline (ADR-0014) is
 * asynchronous and post-hoc by design and cannot block the first bad call. This can. Anyone who
 * mistakes detection for prevention will build the wrong thing.
 *
 * <p><b>Check order is deliberate.</b> The most fundamental failure is reported first, so the reason
 * a caller receives is the most actionable one. There is no point telling an agent its tool
 * definition drifted when the agent itself has been revoked.
 */
public class PolicyDecisionPoint {

    public PolicyDecision decide(PolicyRequest request, PolicyContext context) {
        if (!context.agentActive()) {
            return PolicyDecision.deny(DecisionReason.AGENT_NOT_ACTIVE,
                    "agent " + request.agentId() + " is not active");
        }

        // Tenant policy overrides prior consent: an emergency deny-list entry has to take effect
        // immediately, not once every outstanding consent has expired.
        if (!context.toolPermittedByTenantPolicy()) {
            return PolicyDecision.deny(DecisionReason.TOOL_DENIED_BY_POLICY,
                    "tenant policy forbids " + request.serverId() + "/" + request.toolName());
        }

        if (request.delegationDepth() > context.maxDelegationDepth()) {
            return PolicyDecision.deny(DecisionReason.DELEGATION_TOO_DEEP,
                    "delegation depth " + request.delegationDepth()
                            + " exceeds tenant maximum " + context.maxDelegationDepth());
        }

        ToolConsent consent = context.consent().orElse(null);
        if (consent == null) {
            return PolicyDecision.deny(DecisionReason.NO_CONSENT,
                    "no consent for " + request.serverId() + "/" + request.toolName());
        }
        if (!consent.isActive()) {
            return PolicyDecision.deny(DecisionReason.CONSENT_REVOKED,
                    "consent revoked for " + request.serverId() + "/" + request.toolName());
        }

        // ADR-0013. A null observed hash means we could not determine what the tool currently is,
        // which is not the same as it being unchanged — so it fails closed.
        String observed = request.observedDefinitionHash();
        if (observed == null || !observed.equals(consent.getPinnedDefinitionHash())) {
            return PolicyDecision.deny(DecisionReason.TOOL_DEFINITION_DRIFTED,
                    "tool definition changed since consent: pinned="
                            + abbreviate(consent.getPinnedDefinitionHash())
                            + " observed=" + abbreviate(observed));
        }

        if (context.agentAutonomy() == AutonomyLevel.CONFIRM_EACH) {
            return PolicyDecision.stepUp("agent autonomy requires human approval for each action");
        }

        return PolicyDecision.permit();
    }

    /** Enough hash to identify a version in an alert, not so much that logs become unreadable. */
    private static String abbreviate(String hash) {
        if (hash == null) {
            return "<none>";
        }
        return hash.length() <= 12 ? hash : hash.substring(0, 12);
    }
}
