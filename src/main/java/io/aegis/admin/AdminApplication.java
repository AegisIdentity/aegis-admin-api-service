package io.aegis.admin;

import io.aegis.commons.web.ApiExceptionHandler;
import io.aegis.commons.web.CorrelationIdFilter;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Import;

/** Admin/console API: admin RBAC (role catalog, per-tenant role assignments, effective-permission
 * resolution).
 *
 * <p>A secured JPA resource server. Console-facing endpoints take the tenant from the caller's token;
 * a service-to-service endpoint lets the authorization-server enrich tokens with a subject's admin
 * permissions. See aegis-platform-docs/architecture/SERVICE-CATALOG.md for the intended contract.
 *
 * <p>Imports the shared {@link ApiExceptionHandler} (uniform RFC-7807 errors: bare
 * {@code IllegalArgumentException} -&gt; 400, unexpected exceptions redacted to a generic 500 with a
 * correlation id) and {@link CorrelationIdFilter} that supplies that correlation id. The module's own
 * {@code AdminExceptionHandler} adds the RBAC domain exceptions on top. */
@SpringBootApplication
@Import({CorrelationIdFilter.class, ApiExceptionHandler.class})
public class AdminApplication {
    public static void main(String[] args) {
        SpringApplication.run(AdminApplication.class, args);
    }
}
