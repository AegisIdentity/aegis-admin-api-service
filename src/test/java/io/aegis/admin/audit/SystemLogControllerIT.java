package io.aegis.admin.audit;

import static io.aegis.commons.testing.AegisJwtTest.jwtForTenant;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import io.aegis.admin.AdminTestConfig;
import java.time.Instant;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

/**
 * The System Log read side. Tests the security property that matters most for an audit trail that
 * spans tenants: a caller sees only their own tenant's events (derived from the token, never a
 * parameter), while a platform operator can read across tenants. This is the cross-tenant-disclosure
 * guard for the CloudTrail store — the read-side analogue of the H3 fix.
 *
 * <p>Rows are written directly through the repository here (not via Kafka) so the query behaviour is
 * tested in isolation; the Kafka→store path is proven by {@code AuditSinkIT}.
 */
@SpringBootTest
@Import(AdminTestConfig.class)
class SystemLogControllerIT {

    @Autowired
    WebApplicationContext context;

    @Autowired
    AuditLogRepository repository;

    MockMvc mockMvc;

    @BeforeEach
    void setUp() {
        mockMvc = MockMvcBuilders.webAppContextSetup(context).apply(springSecurity()).build();
        repository.deleteAll();
        // Two tenants' worth of events in the shared store.
        save("acme", "auth", "login", "alice", 1);
        save("acme", "identity", "user.created", "admin@acme", 2);
        save("globex", "auth", "login", "bob", 3);
    }

    private void save(String tenant, String type, String action, String actor, int offset) {
        repository.save(new AuditLogEntry(type, action, "SUCCESS", tenant, actor, null, null,
                Instant.now(), null, 0, offset));
    }

    @Test
    void a_caller_sees_only_their_own_tenants_events() throws Exception {
        mockMvc.perform(get("/api/v1/admin/system-log")
                        .with(jwtForTenant("acme", "admin@acme", "audit:read")))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.length()").value(2))
                .andExpect(jsonPath("$[*].tenantId", org.hamcrest.Matchers.everyItem(
                        org.hamcrest.Matchers.is("acme"))));
    }

    @Test
    void a_caller_cannot_read_another_tenants_events_even_by_asking() throws Exception {
        // A non-operator passing ?tenant=globex is still scoped to its own tenant — no oracle.
        mockMvc.perform(get("/api/v1/admin/system-log")
                        .param("tenant", "globex")
                        .with(jwtForTenant("acme", "admin@acme", "audit:read")))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[*].tenantId", org.hamcrest.Matchers.everyItem(
                        org.hamcrest.Matchers.is("acme"))));
    }

    @Test
    void a_platform_operator_can_read_across_tenants() throws Exception {
        mockMvc.perform(get("/api/v1/admin/system-log")
                        .with(jwtForTenant("acme", "operator", "audit:read", "tenant:platform-admin")))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.length()").value(3)); // both tenants
    }

    @Test
    void a_platform_operator_can_scope_to_one_tenant() throws Exception {
        mockMvc.perform(get("/api/v1/admin/system-log")
                        .param("tenant", "globex")
                        .with(jwtForTenant("acme", "operator", "audit:read", "tenant:platform-admin")))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.length()").value(1))
                .andExpect(jsonPath("$[0].tenantId").value("globex"));
    }

    @Test
    void the_endpoint_requires_authentication() throws Exception {
        mockMvc.perform(get("/api/v1/admin/system-log"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void the_endpoint_requires_the_audit_read_scope() throws Exception {
        mockMvc.perform(get("/api/v1/admin/system-log")
                        .with(jwtForTenant("acme", "admin@acme", "tenant:admin")))
                .andExpect(status().isForbidden());
    }

    @Test
    void results_can_be_filtered_by_action() throws Exception {
        mockMvc.perform(get("/api/v1/admin/system-log")
                        .param("action", "user.created")
                        .with(jwtForTenant("acme", "admin@acme", "audit:read")))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.length()").value(1))
                .andExpect(jsonPath("$[0].action").value("user.created"));
    }
}
