package io.aegis.admin.vault;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import io.aegis.commons.audit.AuditEvent;
import io.aegis.commons.audit.AuditEventPublisher;
import io.aegis.commons.tenant.TenantContext;
import io.aegis.commons.vault.TenantVaultPaths;
import io.aegis.commons.vault.TransitKeyType;
import io.aegis.commons.vault.VaultClient;
import io.aegis.commons.vault.VaultIsolation;
import io.aegis.commons.vault.VaultSecrets;
import io.aegis.commons.vault.VaultTransit;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * Key- and Secrets-Management as a service (ADR-0016, VAULT-ARCHITECTURE.md §5).
 *
 * <p>The whole surface is <b>brokered</b>: a tenant never receives a raw Vault token, and never
 * supplies a Vault path. Both rules exist because this endpoint is, by construction, a
 * high-value target — it is an authenticated HTTP front door to the system that holds every tenant's
 * keys.
 */
class TenantVaultServiceTest {

    private static final class RecordingClient implements VaultClient {
        final List<String> paths = new ArrayList<>();
        final Map<String, Map<String, Object>> responses = new LinkedHashMap<>();

        @Override
        public Map<String, Object> read(String path, String namespace) {
            paths.add(path);
            return responses.getOrDefault(path, Map.of());
        }

        @Override
        public Map<String, Object> write(String path, Map<String, Object> data, String namespace) {
            paths.add(path);
            return responses.getOrDefault(path, Map.of());
        }

        @Override
        public void delete(String path, String namespace) {
            paths.add(path);
        }
    }

    private RecordingClient client;
    private TenantVaultService service;
    private List<AuditEvent> published;

    @BeforeEach
    void setUp() {
        client = new RecordingClient();
        published = new ArrayList<>();
        AuditEventPublisher audit = published::add;
        TenantVaultPaths paths = new TenantVaultPaths("aegis", VaultIsolation.PATH);
        service = new TenantVaultService(
                new VaultTransit(client, paths, audit), new VaultSecrets(client, paths), audit);
    }

    @AfterEach
    void tearDown() {
        TenantContext.clear();
    }

    // --- tenant scoping: the reason the broker exists ---------------------------------------------

    @Test
    void a_tenant_can_only_reach_its_own_vault_path() {
        service.createKey("acme", "my-key", TransitKeyType.RSA_4096);

        assertThat(client.paths).containsExactly("aegis/transit/keys/acme-tenant-managed-my-key");
    }

    @Test
    void two_tenants_never_touch_the_same_path() {
        service.createKey("acme", "shared-name", TransitKeyType.RSA_4096);
        service.createKey("globex", "shared-name", TransitKeyType.RSA_4096);

        assertThat(client.paths).containsExactly(
                "aegis/transit/keys/acme-tenant-managed-shared-name",
                "aegis/transit/keys/globex-tenant-managed-shared-name");
    }

    @Test
    void every_tenant_managed_key_is_forced_under_the_tenant_managed_prefix() {
        // A tenant must not be able to name a key that collides with a PLATFORM key — most obviously
        // "token-signing", which is the key Aegis uses to sign that tenant's own tokens. Server-side
        // prefixing makes the collision impossible rather than merely disallowed.
        service.createKey("acme", "token-signing", TransitKeyType.RSA_4096);

        assertThat(client.paths).containsExactly("aegis/transit/keys/acme-tenant-managed-token-signing");
        assertThat(client.paths.get(0)).isNotEqualTo("aegis/transit/keys/acme-token-signing");
    }

    @Test
    void a_tenant_supplied_path_traversal_is_refused() {
        assertThatThrownBy(() -> service.createKey("acme", "../token-signing", TransitKeyType.RSA_4096))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> service.getSecret("acme", "../../other"))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void a_tenant_supplied_key_name_cannot_smuggle_a_path_separator() {
        assertThatThrownBy(() -> service.createKey("acme", "a/b", TransitKeyType.RSA_4096))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void the_tenant_binding_is_restored_after_every_operation() {
        // The broker binds TenantContext to reach a tenant's path. Leaving it bound on a pooled
        // request thread would be a cross-tenant read on the NEXT request.
        TenantContext.set(io.aegis.commons.tenant.TenantId.of("original"));

        service.createKey("acme", "my-key", TransitKeyType.RSA_4096);

        assertThat(TenantContext.currentOrThrow().value()).isEqualTo("original");
    }

    @Test
    void the_binding_is_restored_even_when_the_operation_fails() {
        TenantContext.set(io.aegis.commons.tenant.TenantId.of("original"));

        assertThatThrownBy(() -> service.createKey("acme", "../evil", TransitKeyType.RSA_4096))
                .isInstanceOf(IllegalArgumentException.class);

        assertThat(TenantContext.currentOrThrow().value()).isEqualTo("original");
    }

    // --- operations ---------------------------------------------------------------------------------

    @Test
    void signs_with_a_tenant_managed_key() {
        client.responses.put("aegis/transit/sign/acme-tenant-managed-my-key",
                Map.of("data", Map.of("signature", "vault:v1:"
                        + Base64.getEncoder().encodeToString("sig".getBytes()))));

        assertThat(service.sign("acme", "my-key", "payload".getBytes())).isNotEmpty();
        assertThat(client.paths).contains("aegis/transit/sign/acme-tenant-managed-my-key");
    }

    @Test
    void reads_and_writes_tenant_secrets_under_the_tenant_path() {
        client.responses.put("aegis/kv/data/acme/app/db",
                Map.of("data", Map.of("data", Map.of("password", "s3cret"))));

        service.putSecret("acme", "app/db", Map.of("password", "s3cret"));
        assertThat(service.getSecret("acme", "app/db")).containsEntry("password", "s3cret");
        assertThat(client.paths).allMatch(path -> path.startsWith("aegis/kv/data/acme/"));
    }

    // --- audit ---------------------------------------------------------------------------------------

    @Test
    void audit_records_the_operation_and_key_name_but_never_the_secret_value() {
        service.putSecret("acme", "app/db", Map.of("password", "SUPERSECRETVALUE"));

        assertThat(published).isNotEmpty();
        String rendered = published.toString();
        assertThat(rendered).doesNotContain("SUPERSECRETVALUE");
        assertThat(rendered).contains("app/db");
    }

    @Test
    void audit_names_the_tenant_the_operation_ran_for() {
        service.createKey("acme", "my-key", TransitKeyType.RSA_4096);

        assertThat(published).anySatisfy(event -> {
            assertThat(event.type()).isEqualTo("vault");
            assertThat(event.tenantId()).isEqualTo("acme");
        });
    }
}
