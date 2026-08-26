package io.aegis.admin.vault;

import io.aegis.commons.vault.TransitKeyType;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import java.util.Base64;
import java.util.Map;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

/**
 * Key- and Secrets-Management as a service (VAULT-ARCHITECTURE.md §5).
 *
 * <p><b>Authorization is two-part, and the second part is the one that matters.</b> Scope proves the
 * caller is <em>a</em> tenant admin; it does not prove <em>which</em> tenant they administer. Because
 * the tenant comes from the path here, ownership is enforced against the JWT {@code tenant} claim —
 * the same defect was found and fixed on the agent-policy endpoint earlier in this branch, and this
 * endpoint fronts every tenant's key material, so getting it wrong would be considerably worse.
 */
@RestController
@ConditionalOnProperty(prefix = "aegis.vault", name = "enabled", havingValue = "true")
public class TenantVaultController {

    private static final String PLATFORM_ADMIN = "SCOPE_tenant:platform-admin";

    private final TenantVaultService vault;

    public TenantVaultController(TenantVaultService vault) {
        this.vault = vault;
    }

    public record CreateKeyRequest(@NotBlank String name, String type) {
    }

    public record SignRequest(@NotBlank String payloadBase64) {
    }

    public record SignResponse(String signatureBase64) {
    }

    @PostMapping("/api/v1/tenants/{slug}/vault/transit/keys")
    public ResponseEntity<Void> createKey(@PathVariable String slug,
                                          @Valid @RequestBody CreateKeyRequest request,
                                          @AuthenticationPrincipal Jwt caller,
                                          Authentication authentication) {
        requireOwnership(slug, caller, authentication);
        vault.createKey(slug, request.name(), keyType(request.type()));
        return ResponseEntity.status(HttpStatus.CREATED).build();
    }

    @PostMapping("/api/v1/tenants/{slug}/vault/transit/keys/{name}:sign")
    public SignResponse sign(@PathVariable String slug, @PathVariable String name,
                             @Valid @RequestBody SignRequest request,
                             @AuthenticationPrincipal Jwt caller, Authentication authentication) {
        requireOwnership(slug, caller, authentication);
        byte[] payload = decode(request.payloadBase64());
        return new SignResponse(Base64.getEncoder().encodeToString(vault.sign(slug, name, payload)));
    }

    @PostMapping("/api/v1/tenants/{slug}/vault/transit/keys/{name}:rotate")
    public ResponseEntity<Void> rotate(@PathVariable String slug, @PathVariable String name,
                                       @AuthenticationPrincipal Jwt caller,
                                       Authentication authentication) {
        requireOwnership(slug, caller, authentication);
        vault.rotateKey(slug, name);
        return ResponseEntity.noContent().build();
    }

    @GetMapping("/api/v1/tenants/{slug}/vault/kv/{*path}")
    public Map<String, String> readSecret(@PathVariable String slug, @PathVariable String path,
                                          @AuthenticationPrincipal Jwt caller,
                                          Authentication authentication) {
        requireOwnership(slug, caller, authentication);
        return vault.getSecret(slug, trimLeadingSlash(path));
    }

    @PutMapping("/api/v1/tenants/{slug}/vault/kv/{*path}")
    public ResponseEntity<Void> writeSecret(@PathVariable String slug, @PathVariable String path,
                                            @RequestBody Map<String, String> values,
                                            @AuthenticationPrincipal Jwt caller,
                                            Authentication authentication) {
        requireOwnership(slug, caller, authentication);
        vault.putSecret(slug, trimLeadingSlash(path), values);
        return ResponseEntity.noContent().build();
    }

    @DeleteMapping("/api/v1/tenants/{slug}/vault/kv/{*path}")
    public ResponseEntity<Void> deleteSecret(@PathVariable String slug, @PathVariable String path,
                                             @AuthenticationPrincipal Jwt caller,
                                             Authentication authentication) {
        requireOwnership(slug, caller, authentication);
        vault.deleteSecret(slug, trimLeadingSlash(path));
        return ResponseEntity.noContent().build();
    }

    /**
     * A non-operator may only reach its own tenant's Vault.
     *
     * <p>404 rather than 403, matching the rest of the platform: a 403 would confirm the slug exists
     * and turn this into a tenant enumeration oracle.
     */
    static void requireOwnership(String slug, Jwt caller, Authentication authentication) {
        if (isPlatformOperator(authentication)) {
            return;
        }
        String tenant = caller == null ? null : caller.getClaimAsString("tenant");
        if (tenant == null || tenant.isBlank()) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "token carries no tenant");
        }
        if (!slug.equals(tenant)) {
            throw new ResponseStatusException(HttpStatus.NOT_FOUND, "no tenant with that slug");
        }
    }

    private static boolean isPlatformOperator(Authentication authentication) {
        return authentication != null && authentication.getAuthorities().stream()
                .anyMatch(a -> PLATFORM_ADMIN.equals(a.getAuthority()));
    }

    private static TransitKeyType keyType(String requested) {
        if (requested == null || requested.isBlank()) {
            return TransitKeyType.RSA_4096;
        }
        try {
            return TransitKeyType.valueOf(requested);
        } catch (IllegalArgumentException e) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "unsupported key type");
        }
    }

    private static byte[] decode(String base64) {
        try {
            return Base64.getDecoder().decode(base64);
        } catch (IllegalArgumentException e) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "payloadBase64 is not valid base64");
        }
    }

    private static String trimLeadingSlash(String path) {
        return path != null && path.startsWith("/") ? path.substring(1) : path;
    }
}
