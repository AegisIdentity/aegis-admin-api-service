package io.aegis.admin.pdp;

/**
 * A policy decision.
 *
 * @param permitted      whether the action may proceed now
 * @param reason         why
 * @param stepUpRequired whether escalating to a human could turn this into a permit. Only ever true
 *                       for {@link DecisionReason#APPROVAL_REQUIRED} — escalating a revoked agent to
 *                       a person for approval would be both useless and a social-engineering
 *                       surface, so the two are kept strictly apart.
 * @param detail         human-readable context for the audit event; never contains tool arguments
 */
public record PolicyDecision(boolean permitted, DecisionReason reason, boolean stepUpRequired,
                             String detail) {

    public static PolicyDecision permit() {
        return new PolicyDecision(true, DecisionReason.PERMIT, false, null);
    }

    public static PolicyDecision deny(DecisionReason reason, String detail) {
        return new PolicyDecision(false, reason, false, detail);
    }

    public static PolicyDecision stepUp(String detail) {
        return new PolicyDecision(false, DecisionReason.APPROVAL_REQUIRED, true, detail);
    }
}
