package io.aegis.admin.vault;

import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.server.ResponseStatusException;

/**
 * The cross-tenant negative test, on the endpoint where it matters most.
 *
 * <p>This surface fronts every tenant's key material. The identical defect was found on the
 * agent-policy endpoint earlier in this branch — scope proved the caller was <em>a</em> tenant admin
 * but not <em>which</em> — so it is pinned here from the outset rather than discovered later.
 */
class TenantVaultOwnershipTest {

    private static Jwt tokenFor(String tenant) {
        return new Jwt("t", Instant.now(), Instant.now().plusSeconds(300),
                Map.of("alg", "none"), Map.of("sub", "admin", "tenant", tenant));
    }

    private static Authentication authWith(String... authorities) {
        return new TestingAuthenticationToken("admin", null,
                List.of(authorities).stream().map(SimpleGrantedAuthority::new).toList());
    }

    @Test
    void a_tenant_admin_may_reach_its_own_vault() {
        assertThatCode(() -> TenantVaultController.requireOwnership(
                "acme", tokenFor("acme"), authWith("SCOPE_tenant:admin")))
                .doesNotThrowAnyException();
    }

    @Test
    void a_tenant_admin_may_not_reach_another_tenants_vault() {
        assertThatThrownBy(() -> TenantVaultController.requireOwnership(
                "acme", tokenFor("globex"), authWith("SCOPE_tenant:admin")))
                .isInstanceOf(ResponseStatusException.class)
                .hasFieldOrPropertyWithValue("statusCode", HttpStatus.NOT_FOUND);
    }

    @Test
    void the_denial_is_404_so_it_is_not_a_tenant_existence_oracle() {
        assertThatThrownBy(() -> TenantVaultController.requireOwnership(
                "some-other-tenant", tokenFor("globex"), authWith("SCOPE_tenant:admin")))
                .isInstanceOf(ResponseStatusException.class)
                .hasFieldOrPropertyWithValue("statusCode", HttpStatus.NOT_FOUND);
    }

    @Test
    void a_platform_operator_may_reach_any_tenants_vault() {
        assertThatCode(() -> TenantVaultController.requireOwnership(
                "acme", tokenFor("globex"), authWith("SCOPE_tenant:platform-admin")))
                .doesNotThrowAnyException();
    }

    @Test
    void a_token_with_no_tenant_claim_is_forbidden() {
        Jwt noTenant = new Jwt("t", Instant.now(), Instant.now().plusSeconds(300),
                Map.of("alg", "none"), Map.of("sub", "admin"));

        assertThatThrownBy(() -> TenantVaultController.requireOwnership(
                "acme", noTenant, authWith("SCOPE_tenant:admin")))
                .isInstanceOf(ResponseStatusException.class)
                .hasFieldOrPropertyWithValue("statusCode", HttpStatus.FORBIDDEN);
    }

    @Test
    void a_missing_principal_is_forbidden_not_permitted() {
        assertThatThrownBy(() -> TenantVaultController.requireOwnership(
                "acme", null, authWith("SCOPE_tenant:admin")))
                .isInstanceOf(ResponseStatusException.class)
                .hasFieldOrPropertyWithValue("statusCode", HttpStatus.FORBIDDEN);
    }
}
