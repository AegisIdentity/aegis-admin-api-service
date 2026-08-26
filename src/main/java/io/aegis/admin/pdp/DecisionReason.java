package io.aegis.admin.pdp;

/**
 * Why the PDP decided as it did.
 *
 * <p>Typed rather than boolean because the reason drives what the caller should do next: an
 * {@link #APPROVAL_REQUIRED} outcome should escalate to a human, a {@link #TOOL_DEFINITION_DRIFTED}
 * outcome should alert and re-request consent, and {@link #AGENT_NOT_ACTIVE} should stop entirely.
 */
public enum DecisionReason {

    PERMIT,

    /** The agent is suspended or revoked. */
    AGENT_NOT_ACTIVE,

    /** Tenant policy forbids this tool — an operator control that overrides prior consent. */
    TOOL_DENIED_BY_POLICY,

    /** The delegation chain is deeper than the tenant permits. */
    DELEGATION_TOO_DEEP,

    /** No consent has ever been granted for this tool. */
    NO_CONSENT,

    /** Consent existed and was withdrawn. */
    CONSENT_REVOKED,

    /**
     * The tool's definition has changed since it was approved — the rug-pull / tool-poisoning case
     * (ADR-0013). Distinguished from {@link #NO_CONSENT} because this one is a security event worth
     * alerting on, not merely a missing grant.
     */
    TOOL_DEFINITION_DRIFTED,

    /**
     * Not a denial: the agent's autonomy level requires a human to approve this action. The caller
     * should escalate (A2P / MCP multi-round-trip), not abandon the task.
     */
    APPROVAL_REQUIRED
}
