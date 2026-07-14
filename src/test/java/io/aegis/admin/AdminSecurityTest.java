package io.aegis.admin;

import static io.aegis.commons.testing.AegisJwtTest.jwtForTenant;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

/** Verifies the security baseline: health is open, the API is default-deny (401 without a token). */
@SpringBootTest
@Import(AdminTestConfig.class)
class AdminSecurityTest {

    @Autowired
    WebApplicationContext context;
    MockMvc mockMvc;

    @BeforeEach
    void setUp() {
        mockMvc = MockMvcBuilders.webAppContextSetup(context).apply(springSecurity()).build();
    }

    @Test
    void health_is_public() throws Exception {
        mockMvc.perform(get("/actuator/health")).andExpect(status().isOk());
    }

    @Test
    void roles_catalog_requires_authentication() throws Exception {
        mockMvc.perform(get("/api/v1/admin/roles")).andExpect(status().isUnauthorized());
    }

    @Test
    void admins_endpoint_requires_authentication() throws Exception {
        mockMvc.perform(get("/api/v1/admin/admins")).andExpect(status().isUnauthorized());
    }

    @Test
    void any_authenticated_caller_can_read_the_role_catalog() throws Exception {
        mockMvc.perform(get("/api/v1/admin/roles")
                        .with(jwtForTenant("acme", "someone", "openid")))
                .andExpect(status().isOk());
    }
}
