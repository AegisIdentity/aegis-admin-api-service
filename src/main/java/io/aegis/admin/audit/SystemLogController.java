package io.aegis.admin.audit;

import java.time.Instant;
import java.util.List;
import org.springframework.data.domain.PageRequest;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.http.HttpStatus;

/**
 * The System Log query — reads the platform audit store (the CloudTrail equivalent that
 * {@link AuditEventConsumer} fills from the Kafka stream).
 *
 * <p><b>Tenant-scoped by default.</b> A caller sees only their own tenant's events, derived from the
 * JWT {@code tenant} claim — never a request parameter — so this cannot become a cross-tenant
 * disclosure oracle. A platform operator ({@code SCOPE_tenant:platform-admin}) may read across
 * tenants and optionally filter to one. This mirrors the H3 fix pattern used in tenant-service.
 */
@RestController
public class SystemLogController {

    private static final String PLATFORM_ADMIN = "SCOPE_tenant:platform-admin";
    private static final int MAX_LIMIT = 200;

    private final AuditLogRepository repository;

    public SystemLogController(AuditLogRepository repository) {
        this.repository = repository;
    }

    @GetMapping("/api/v1/admin/system-log")
    public List<SystemLogEntryDto> query(
            @AuthenticationPrincipal Jwt caller,
            Authentication authentication,
            @RequestParam(required = false) String action,
            @RequestParam(required = false) Instant since,
            @RequestParam(required = false, name = "tenant") String tenantFilter,
            @RequestParam(defaultValue = "50") int limit) {

        PageRequest page = PageRequest.of(0, Math.min(Math.max(limit, 1), MAX_LIMIT));
        boolean operator = isPlatformOperator(authentication);

        List<AuditLogEntry> rows;
        if (operator) {
            // Operators may scope to one tenant or see the whole platform.
            if (tenantFilter != null && !tenantFilter.isBlank()) {
                rows = filteredForTenant(tenantFilter, action, since, page);
            } else {
                rows = repository.findAllAcrossTenants(page);
            }
        } else {
            // Everyone else is locked to their own tenant, taken from the token.
            String own = tenantOf(caller);
            // A non-operator asking for someone else's tenant gets their own, not an error — no oracle.
            rows = filteredForTenant(own, action, since, page);
        }
        return rows.stream().map(SystemLogEntryDto::from).toList();
    }

    private List<AuditLogEntry> filteredForTenant(String tenant, String action, Instant since,
                                                  PageRequest page) {
        if (action != null && !action.isBlank()) {
            return repository.findByTenantIdAndActionOrderByEventTimeDesc(tenant, action, page);
        }
        if (since != null) {
            return repository.findByTenantIdAndEventTimeAfterOrderByEventTimeDesc(tenant, since, page);
        }
        return repository.findByTenantIdOrderByEventTimeDesc(tenant, page);
    }

    private static boolean isPlatformOperator(Authentication authentication) {
        return authentication != null && authentication.getAuthorities().stream()
                .anyMatch(a -> PLATFORM_ADMIN.equals(a.getAuthority()));
    }

    private static String tenantOf(Jwt caller) {
        String tenant = caller == null ? null : caller.getClaimAsString("tenant");
        if (tenant == null || tenant.isBlank()) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "token carries no tenant");
        }
        return tenant;
    }

    /** Read-model view of an audit row. */
    public record SystemLogEntryDto(
            String id, String type, String action, String outcome, String tenantId,
            String actor, String target, String correlationId, Instant eventTime, String attributes) {

        static SystemLogEntryDto from(AuditLogEntry e) {
            return new SystemLogEntryDto(
                    e.getId().toString(), e.getType(), e.getAction(), e.getOutcome(), e.getTenantId(),
                    e.getActor(), e.getTarget(), e.getCorrelationId(), e.getEventTime(),
                    e.getAttributesJson());
        }
    }
}
