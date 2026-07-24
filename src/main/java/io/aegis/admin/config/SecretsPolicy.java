package io.aegis.admin.config;

import java.util.Arrays;
import org.springframework.core.env.Environment;

/**
 * Decides whether externally-supplied secrets (DB/client passwords) are mandatory. True in a
 * {@code prod}/{@code stage} deployment, or whenever {@code aegis.security.require-external-secrets=true}
 * is set explicitly. False for local dev and tests (no active profile), where built-in dev defaults apply.
 */
public final class SecretsPolicy {

    private SecretsPolicy() {
    }

    public static boolean externalSecretsRequired(Environment env) {
        boolean prodLike = Arrays.stream(env.getActiveProfiles())
                .anyMatch(p -> p.equalsIgnoreCase("prod")
                        || p.equalsIgnoreCase("production")
                        || p.equalsIgnoreCase("stage")
                        || p.equalsIgnoreCase("staging"));
        return prodLike || env.getProperty("aegis.security.require-external-secrets", Boolean.class, false);
    }
}
