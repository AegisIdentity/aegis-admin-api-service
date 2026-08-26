package io.aegis.admin.pdp;

import io.aegis.commons.agent.AutonomyLevel;
import java.util.Optional;

/**
 * The facts the PDP needs, gathered by the caller.
 *
 * <p>These live in three different services' databases — agent status in {@code identity-service},
 * tool policy and depth ceiling in {@code tenant-service}, consent here — and ADR-0002 forbids
 * reading another service's tables. Passing them in keeps the decision a pure function, which is
 * both architecturally correct and the reason every branch is straightforward to test.
 */
public record PolicyContext(
        boolean agentActive,
        AutonomyLevel agentAutonomy,
        boolean toolPermittedByTenantPolicy,
        int maxDelegationDepth,
        Optional<ToolConsent> consent) {
}
