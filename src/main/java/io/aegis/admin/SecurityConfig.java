package io.aegis.admin;

import io.aegis.commons.security.SecurityHardening;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;

/**
 * Resource-server security baseline (default-deny, shared hardening headers, stateless bearer,
 * 401-not-302) plus the admin RBAC endpoint authorization rules.
 */
@Configuration(proxyBeanMethods = false)
public class SecurityConfig {

    @Bean
    public SecurityFilterChain apiSecurityFilterChain(HttpSecurity http) throws Exception {
        SecurityHardening.applyHardeningHeaders(http);
        SecurityHardening.statelessBearerApi(http);
        http
                .authorizeHttpRequests(authorize -> authorize
                        .requestMatchers("/actuator/health", "/actuator/health/**").permitAll()
                        // Service-to-service token enrichment: only the AS's service token carries this.
                        .requestMatchers("/api/v1/admin/internal/**").hasAuthority("SCOPE_admin:resolve")
                        // Managing the tenant's admin role assignments.
                        .requestMatchers("/api/v1/admin/admins", "/api/v1/admin/admins/**")
                        .hasAuthority("SCOPE_tenant:admin")
                        // Role catalog + the caller's own effective access: any authenticated caller.
                        .requestMatchers("/api/v1/admin/roles", "/api/v1/admin/me").authenticated()
                        .anyRequest().authenticated())
                .oauth2ResourceServer(oauth2 -> oauth2.jwt(Customizer.withDefaults()));
        return http.build();
    }
}
