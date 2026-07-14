package io.aegis.admin;

import static io.aegis.commons.testing.AegisJwtTest.jwtForTenant;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

/**
 * Integration tests for admin RBAC against real Postgres. Covers the role catalog, scope-gated
 * assignment management, unknown-role rejection, the {@code /me} SUPER_ADMIN fallback and post-assignment
 * permissions, the scope-gated internal resolution endpoint, and tenant isolation.
 */
@SpringBootTest
@Import(AdminTestConfig.class)
class AdminRoleIT {

    @Autowired
    WebApplicationContext context;
    MockMvc mockMvc;

    @BeforeEach
    void setUp() {
        mockMvc = MockMvcBuilders.webAppContextSetup(context).apply(springSecurity()).build();
    }

    @Test
    void role_catalog_lists_every_role_with_its_permissions() throws Exception {
        mockMvc.perform(get("/api/v1/admin/roles")
                        .with(jwtForTenant("acme", "admin", "tenant:admin")))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[?(@.role=='SUPER_ADMIN')]").exists())
                .andExpect(jsonPath("$[?(@.role=='USER_ADMIN')]").exists())
                .andExpect(jsonPath("$[?(@.role=='HELP_DESK')]").exists())
                .andExpect(jsonPath("$[?(@.role=='APP_ADMIN')]").exists())
                .andExpect(jsonPath("$[?(@.role=='AUDITOR')]").exists())
                .andExpect(jsonPath("$[?(@.role=='USER_ADMIN')].permissions[?(@=='users:read')]").exists())
                .andExpect(jsonPath("$[?(@.role=='USER_ADMIN')].permissions[?(@=='groups:write')]").exists())
                .andExpect(jsonPath("$[?(@.role=='HELP_DESK')].permissions[?(@=='users:reset-password')]").exists());
    }

    @Test
    void managing_admins_is_scope_gated() throws Exception {
        mockMvc.perform(get("/api/v1/admin/admins")).andExpect(status().isUnauthorized());
        mockMvc.perform(get("/api/v1/admin/admins")
                        .with(jwtForTenant("acme", "someone", "openid")))
                .andExpect(status().isForbidden());
        mockMvc.perform(get("/api/v1/admin/admins")
                        .with(jwtForTenant("acme", "admin", "tenant:admin")))
                .andExpect(status().isOk());
    }

    @Test
    void assign_roles_then_list_reflects_them() throws Exception {
        mockMvc.perform(put("/api/v1/admin/admins/alice")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"roles\":[\"USER_ADMIN\",\"HELP_DESK\"]}")
                        .with(jwtForTenant("assign-co", "admin", "tenant:admin")))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.subject").value("alice"))
                .andExpect(jsonPath("$.roles[?(@=='USER_ADMIN')]").exists())
                .andExpect(jsonPath("$.roles[?(@=='HELP_DESK')]").exists());

        mockMvc.perform(get("/api/v1/admin/admins")
                        .with(jwtForTenant("assign-co", "admin", "tenant:admin")))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[?(@.subject=='alice')]").exists())
                .andExpect(jsonPath("$[?(@.subject=='alice')].roles[?(@=='USER_ADMIN')]").exists());
    }

    @Test
    void unknown_role_is_rejected() throws Exception {
        mockMvc.perform(put("/api/v1/admin/admins/bob")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"roles\":[\"USER_ADMIN\",\"WIZARD\"]}")
                        .with(jwtForTenant("acme", "admin", "tenant:admin")))
                .andExpect(status().isBadRequest());
    }

    @Test
    void empty_roles_list_is_rejected_use_delete_to_clear() throws Exception {
        // An empty PUT is rejected (400) so an admin can't silently strip a subject to zero roles and
        // suppress the tenant:admin SUPER_ADMIN fallback — clearing is done via DELETE.
        mockMvc.perform(put("/api/v1/admin/admins/nemo")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"roles\":[]}")
                        .with(jwtForTenant("acme", "admin", "tenant:admin")))
                .andExpect(status().isBadRequest());
    }

    @Test
    void me_returns_super_admin_permissions_for_tenant_admin_without_assignment() throws Exception {
        mockMvc.perform(get("/api/v1/admin/me")
                        .with(jwtForTenant("fresh-co", "root", "tenant:admin")))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.subject").value("root"))
                .andExpect(jsonPath("$.roles[?(@=='SUPER_ADMIN')]").exists())
                .andExpect(jsonPath("$.permissions[?(@=='users:write')]").exists())
                .andExpect(jsonPath("$.permissions[?(@=='audit:read')]").exists())
                .andExpect(jsonPath("$.permissions[?(@=='idp:admin')]").exists());
    }

    @Test
    void me_reflects_the_assigned_role_permissions_after_assignment() throws Exception {
        // Grant carol only HELP_DESK; her /me should show exactly HELP_DESK's permissions (not SUPER_ADMIN),
        // even though her token also carries tenant:admin.
        mockMvc.perform(put("/api/v1/admin/admins/carol")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"roles\":[\"HELP_DESK\"]}")
                        .with(jwtForTenant("helpco", "admin", "tenant:admin")))
                .andExpect(status().isOk());

        mockMvc.perform(get("/api/v1/admin/me")
                        .with(jwtForTenant("helpco", "carol", "tenant:admin")))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.roles[?(@=='HELP_DESK')]").exists())
                .andExpect(jsonPath("$.roles[?(@=='SUPER_ADMIN')]").doesNotExist())
                .andExpect(jsonPath("$.permissions[?(@=='users:reset-password')]").exists())
                .andExpect(jsonPath("$.permissions[?(@=='users:unlock')]").exists())
                .andExpect(jsonPath("$.permissions[?(@=='users:write')]").doesNotExist());
    }

    @Test
    void internal_permissions_endpoint_requires_admin_resolve_scope() throws Exception {
        // No token -> 401.
        mockMvc.perform(get("/api/v1/admin/internal/permissions")
                        .param("tenant", "acme").param("subject", "alice"))
                .andExpect(status().isUnauthorized());

        // Wrong scope -> 403.
        mockMvc.perform(get("/api/v1/admin/internal/permissions")
                        .param("tenant", "acme").param("subject", "alice")
                        .with(jwtForTenant("system", "as", "tenant:admin")))
                .andExpect(status().isForbidden());

        // Right scope -> 200.
        mockMvc.perform(get("/api/v1/admin/internal/permissions")
                        .param("tenant", "acme").param("subject", "nobody")
                        .with(jwtForTenant("system", "as", "admin:resolve")))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.roles").isArray())
                .andExpect(jsonPath("$.permissions").isArray());
    }

    @Test
    void internal_permissions_resolves_assigned_roles_and_tenant_admin_fallback() throws Exception {
        mockMvc.perform(put("/api/v1/admin/admins/dave")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"roles\":[\"AUDITOR\"]}")
                        .with(jwtForTenant("intco", "admin", "tenant:admin")))
                .andExpect(status().isOk());

        // Assigned subject resolves to AUDITOR's permissions.
        mockMvc.perform(get("/api/v1/admin/internal/permissions")
                        .param("tenant", "intco").param("subject", "dave")
                        .with(jwtForTenant("system", "as", "admin:resolve")))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.roles[?(@=='AUDITOR')]").exists())
                .andExpect(jsonPath("$.permissions[?(@=='audit:read')]").exists());

        // Unassigned subject with tenantAdmin=true falls back to SUPER_ADMIN.
        mockMvc.perform(get("/api/v1/admin/internal/permissions")
                        .param("tenant", "intco").param("subject", "ghost").param("tenantAdmin", "true")
                        .with(jwtForTenant("system", "as", "admin:resolve")))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.roles[?(@=='SUPER_ADMIN')]").exists());

        // Unassigned subject without tenantAdmin -> empty.
        mockMvc.perform(get("/api/v1/admin/internal/permissions")
                        .param("tenant", "intco").param("subject", "ghost")
                        .with(jwtForTenant("system", "as", "admin:resolve")))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.roles").isEmpty())
                .andExpect(jsonPath("$.permissions").isEmpty());

        // A blank subject must NOT fall back to SUPER_ADMIN even with tenantAdmin=true (guards against
        // over-granting when the 'sub' claim is missing during token enrichment).
        mockMvc.perform(get("/api/v1/admin/internal/permissions")
                        .param("tenant", "intco").param("subject", "").param("tenantAdmin", "true")
                        .with(jwtForTenant("system", "as", "admin:resolve")))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.roles").isEmpty())
                .andExpect(jsonPath("$.permissions").isEmpty());
    }

    @Test
    void assignments_are_tenant_isolated() throws Exception {
        mockMvc.perform(put("/api/v1/admin/admins/erin")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"roles\":[\"USER_ADMIN\"]}")
                        .with(jwtForTenant("tenant-a", "admin", "tenant:admin")))
                .andExpect(status().isOk());

        // Tenant B does not see tenant A's assignment.
        mockMvc.perform(get("/api/v1/admin/admins")
                        .with(jwtForTenant("tenant-b", "admin", "tenant:admin")))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[?(@.subject=='erin')]").doesNotExist());
    }

    @Test
    void delete_removes_the_assignment() throws Exception {
        mockMvc.perform(put("/api/v1/admin/admins/frank")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"roles\":[\"APP_ADMIN\"]}")
                        .with(jwtForTenant("delco", "admin", "tenant:admin")))
                .andExpect(status().isOk());

        mockMvc.perform(delete("/api/v1/admin/admins/frank")
                        .with(jwtForTenant("delco", "admin", "tenant:admin")))
                .andExpect(status().isNoContent());

        mockMvc.perform(get("/api/v1/admin/admins")
                        .with(jwtForTenant("delco", "admin", "tenant:admin")))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[?(@.subject=='frank')]").doesNotExist());
    }
}
