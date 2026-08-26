package io.aegis.admin.vault;

import io.aegis.commons.audit.AuditEvent;
import io.aegis.commons.audit.AuditEventPublisher;
import io.aegis.commons.audit.AuditOutcome;
import io.aegis.commons.tenant.TenantContext;
import io.aegis.commons.tenant.TenantId;
import io.aegis.commons.vault.TransitKeyType;
import io.aegis.commons.vault.VaultSecrets;
import io.aegis.commons.vault.VaultTransit;
import java.util.Map;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Service;

/**
 * Key- and Secrets-Management as a service (ADR-0016).
 *
 * <p>Everything here is <b>brokered</b>, and the two rules that make it safe are worth stating
 * plainly because this endpoint is by construction a high-value target — an authenticated HTTP front
 * door to the system holding every tenant's keys.
 *
 * <ol>
 *   <li><b>A tenant never receives a raw Vault token.</b> The platform holds the credential and
 *       performs the operation; a leaked API response therefore exposes a result, not an
 *       authorization.</li>
 *   <li><b>A tenant never supplies a Vault path.</b> It supplies a leaf name; the tenant segment and
 *       the {@code tenant-managed} prefix are both applied server-side.</li>
 * </ol>
 *
 * <p>Conditional on {@code aegis.vault.enabled}: the broker is an optional product surface, and
 * admin-api-service must still start in an environment where Vault is not deployed. Without the
 * condition the whole service fails to boot on a missing {@code VaultTransit} bean.
 *
 * <p>The forced {@code tenant-managed-} prefix is the load-bearing detail. Without it a tenant could
 * name a key {@code token-signing} and collide with the platform key Aegis uses to sign that very
 * tenant's tokens. Prefixing server-side makes that collision <em>impossible</em> rather than merely
 * forbidden — a distinction that matters, because "forbidden" relies on a check somebody could later
 * move, reorder or forget.
 */
@Service
@ConditionalOnProperty(prefix = "aegis.vault", name = "enabled", havingValue = "true")
public class TenantVaultService {

    /** Namespace for keys a tenant owns. Never reachable by a caller-supplied name. */
    private static final String TENANT_MANAGED = "tenant-managed-";

    private final VaultTransit transit;
    private final VaultSecrets secrets;
    private final AuditEventPublisher audit;

    public TenantVaultService(VaultTransit transit, VaultSecrets secrets, AuditEventPublisher audit) {
        this.transit = transit;
        this.secrets = secrets;
        this.audit = audit;
    }

    public void createKey(String tenantId, String keyName, TransitKeyType type) {
        inTenant(tenantId, () -> {
            transit.createKey(TENANT_MANAGED + keyName, type);
            return null;
        });
        record(tenantId, "vault.key.create", keyName);
    }

    public byte[] sign(String tenantId, String keyName, byte[] data) {
        byte[] signature = inTenant(tenantId, () -> transit.signJws(TENANT_MANAGED + keyName, data));
        record(tenantId, "vault.key.sign", keyName);
        return signature;
    }

    public void rotateKey(String tenantId, String keyName) {
        inTenant(tenantId, () -> {
            transit.rotate(TENANT_MANAGED + keyName);
            return null;
        });
        record(tenantId, "vault.key.rotate", keyName);
    }

    public Map<String, String> getSecret(String tenantId, String path) {
        Map<String, String> value = inTenant(tenantId, () -> secrets.getAll(path));
        record(tenantId, "vault.secret.read", path);
        return value;
    }

    public void putSecret(String tenantId, String path, Map<String, String> values) {
        inTenant(tenantId, () -> {
            secrets.put(path, values);
            return null;
        });
        record(tenantId, "vault.secret.write", path);
    }

    public void deleteSecret(String tenantId, String path) {
        inTenant(tenantId, () -> {
            secrets.delete(path);
            return null;
        });
        record(tenantId, "vault.secret.delete", path);
    }

    /**
     * Bind the tenant for the duration of one operation.
     *
     * <p>{@code callAs} restores the previous binding in a finally block even when the operation
     * throws. That matters more than it looks: a binding left behind on a pooled request thread
     * becomes a cross-tenant read on the <em>next</em> request through that thread, which is both
     * severe and very hard to reproduce.
     */
    private <T> T inTenant(String tenantId, java.util.function.Supplier<T> operation) {
        return TenantContext.callAs(TenantId.of(tenantId), operation);
    }

    /**
     * Audit the operation and the key or secret <em>name</em>.
     *
     * <p>Never the key material, the signature, or the secret value — audit events are widely
     * readable and streamed to customer SIEMs, and this is precisely the surface where a slip would
     * put a tenant's secret into another tenant's log pipeline.
     */
    private void record(String tenantId, String action, String target) {
        if (audit == null) {
            return;
        }
        audit.publish(AuditEvent.of("vault", action, AuditOutcome.SUCCESS)
                .tenant(tenantId)
                .target(target)
                .build());
    }
}
