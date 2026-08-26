package io.aegis.admin.pdp;

import static org.assertj.core.api.Assertions.assertThat;

import io.aegis.commons.agent.AutonomyLevel;
import java.time.Instant;
import java.util.Optional;
import org.junit.jupiter.api.Test;

/**
 * The synchronous control that can actually <em>prevent</em> a bad agent action — as distinct from
 * the detection pipeline, which is asynchronous and post-hoc by design (ADR-0014).
 *
 * <p>Written as a pure function over an explicit context because the inputs live in three different
 * services' databases (agent status in identity-service, tool policy in tenant-service, consent
 * here) and ADR-0002 forbids reading another service's tables. Passing them in also makes every
 * branch trivially testable.
 */
class PolicyDecisionPointTest {

    private static final String PINNED = "9f2c" + "a".repeat(60);
    private static final String DRIFTED = "dead" + "b".repeat(60);

    private final PolicyDecisionPoint pdp = new PolicyDecisionPoint();

    private static PolicyRequest request(String observedHash) {
        return new PolicyRequest("acme", "agent:planner", "user:alice",
                "files-server", "read", observedHash, 2);
    }

    private static ToolConsent consent(String pinnedHash) {
        ToolConsent c = new ToolConsent("acme", "user:alice", "agent:planner",
                "files-server", "read", pinnedHash);
        return c;
    }

    private static PolicyContext context(Optional<ToolConsent> consent) {
        return new PolicyContext(true, AutonomyLevel.SUPERVISED, true, 3, consent);
    }

    @Test
    void permits_an_active_agent_calling_a_consented_unchanged_tool() {
        PolicyDecision decision = pdp.decide(request(PINNED), context(Optional.of(consent(PINNED))));

        assertThat(decision.permitted()).isTrue();
        assertThat(decision.reason()).isEqualTo(DecisionReason.PERMIT);
    }

    // --- ordering: the most fundamental failure must be reported first -------------------------

    @Test
    void a_revoked_agent_is_denied_before_anything_else_is_considered() {
        PolicyContext ctx = new PolicyContext(false, AutonomyLevel.SUPERVISED, true, 3,
                Optional.of(consent(PINNED)));

        assertThat(pdp.decide(request(PINNED), ctx).reason()).isEqualTo(DecisionReason.AGENT_NOT_ACTIVE);
    }

    @Test
    void a_tool_denied_by_tenant_policy_is_denied_even_with_valid_consent() {
        // Tenant policy is an operator control and must override a user's earlier consent —
        // otherwise an emergency deny-list entry would not take effect until every consent expired.
        PolicyContext ctx = new PolicyContext(true, AutonomyLevel.SUPERVISED, false, 3,
                Optional.of(consent(PINNED)));

        assertThat(pdp.decide(request(PINNED), ctx).reason())
                .isEqualTo(DecisionReason.TOOL_DENIED_BY_POLICY);
    }

    @Test
    void a_chain_deeper_than_the_tenant_ceiling_is_denied() {
        PolicyRequest deep = new PolicyRequest("acme", "agent:planner", "user:alice",
                "files-server", "read", PINNED, 4);

        assertThat(pdp.decide(deep, context(Optional.of(consent(PINNED)))).reason())
                .isEqualTo(DecisionReason.DELEGATION_TOO_DEEP);
    }

    // --- consent --------------------------------------------------------------------------------

    @Test
    void a_tool_with_no_consent_is_denied() {
        assertThat(pdp.decide(request(PINNED), context(Optional.empty())).reason())
                .isEqualTo(DecisionReason.NO_CONSENT);
    }

    @Test
    void a_revoked_consent_is_denied() {
        ToolConsent revoked = consent(PINNED);
        revoked.revoke("user withdrew");

        assertThat(pdp.decide(request(PINNED), context(Optional.of(revoked))).reason())
                .isEqualTo(DecisionReason.CONSENT_REVOKED);
    }

    // --- ADR-0013: the rug pull -----------------------------------------------------------------

    @Test
    void a_tool_whose_definition_drifted_since_consent_is_denied() {
        // The rug pull: same server, same tool name, same scopes — but the description the model
        // acts on has changed. Scope-granular consent cannot see this at all; a pinned hash can.
        PolicyDecision decision = pdp.decide(request(DRIFTED), context(Optional.of(consent(PINNED))));

        assertThat(decision.permitted()).isFalse();
        assertThat(decision.reason()).isEqualTo(DecisionReason.TOOL_DEFINITION_DRIFTED);
    }

    @Test
    void drift_is_reported_with_both_hashes_so_the_alert_can_show_what_changed() {
        PolicyDecision decision = pdp.decide(request(DRIFTED), context(Optional.of(consent(PINNED))));

        assertThat(decision.detail()).contains(PINNED.substring(0, 12));
        assertThat(decision.detail()).contains(DRIFTED.substring(0, 12));
    }

    @Test
    void an_absent_observed_hash_is_treated_as_drift_not_as_a_match() {
        // Failing closed. If we cannot compute what the tool currently is, we cannot claim it is
        // still the tool that was approved.
        assertThat(pdp.decide(request(null), context(Optional.of(consent(PINNED)))).reason())
                .isEqualTo(DecisionReason.TOOL_DEFINITION_DRIFTED);
    }

    // --- autonomy / step-up ----------------------------------------------------------------------

    @Test
    void a_confirm_each_agent_requires_approval_rather_than_being_denied_outright() {
        // Not a denial: this is the A2P human-in-the-loop path. The caller should escalate to a
        // person, not give up — so the two outcomes must be distinguishable.
        PolicyContext ctx = new PolicyContext(true, AutonomyLevel.CONFIRM_EACH, true, 3,
                Optional.of(consent(PINNED)));

        PolicyDecision decision = pdp.decide(request(PINNED), ctx);

        assertThat(decision.permitted()).isFalse();
        assertThat(decision.reason()).isEqualTo(DecisionReason.APPROVAL_REQUIRED);
        assertThat(decision.stepUpRequired()).isTrue();
    }

    @Test
    void an_autonomous_agent_with_valid_consent_proceeds_without_approval() {
        PolicyContext ctx = new PolicyContext(true, AutonomyLevel.AUTONOMOUS, true, 3,
                Optional.of(consent(PINNED)));

        assertThat(pdp.decide(request(PINNED), ctx).permitted()).isTrue();
    }

    @Test
    void a_denial_is_never_marked_as_requiring_step_up() {
        // Otherwise a caller would escalate a revoked agent to a human for approval, which is both
        // useless and a social-engineering surface.
        PolicyContext ctx = new PolicyContext(false, AutonomyLevel.CONFIRM_EACH, true, 3,
                Optional.of(consent(PINNED)));

        assertThat(pdp.decide(request(PINNED), ctx).stepUpRequired()).isFalse();
    }

    // --- consent pinning ------------------------------------------------------------------------

    @Test
    void consent_records_when_it_was_granted_and_what_it_pinned() {
        ToolConsent c = consent(PINNED);
        assertThat(c.getPinnedDefinitionHash()).isEqualTo(PINNED);
        assertThat(c.getGrantedAt()).isBefore(Instant.now().plusSeconds(1));
        assertThat(c.isActive()).isTrue();
    }

    @Test
    void re_pinning_updates_the_hash_and_keeps_the_consent_active() {
        // The cosmetic-drift path: tenant policy may allow auto-re-pinning a display-only change.
        ToolConsent c = consent(PINNED);
        c.rePin(DRIFTED);

        assertThat(c.getPinnedDefinitionHash()).isEqualTo(DRIFTED);
        assertThat(c.isActive()).isTrue();
    }

    @Test
    void a_revoked_consent_cannot_be_re_pinned_back_into_life() {
        ToolConsent c = consent(PINNED);
        c.revoke("withdrawn");

        org.assertj.core.api.Assertions.assertThatThrownBy(() -> c.rePin(DRIFTED))
                .isInstanceOf(IllegalStateException.class);
    }
}
