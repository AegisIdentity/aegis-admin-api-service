package io.aegis.admin.pdp;

/**
 * What an agent is attempting.
 *
 * @param observedDefinitionHash the hash of the tool definition <em>as it is right now</em>, which
 *                               the PDP compares against what was consented to. Null when it could
 *                               not be computed — treated as drift, never as a match.
 * @param delegationDepth        how many hops deep the chain already is
 */
public record PolicyRequest(
        String tenantId,
        String agentId,
        String subject,
        String serverId,
        String toolName,
        String observedDefinitionHash,
        int delegationDepth) {
}
