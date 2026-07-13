package io.aegis.admin;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/** Admin/console API: policy, admin RBAC, System-Log query.
 *
 * <p>Maturity: scaffold. This is a buildable, secured resource-server skeleton (health + a
 * protected info endpoint + the shared hardening baseline) ready for feature work. See
 * aegis-platform-docs/architecture/SERVICE-CATALOG.md for the intended contract. */
@SpringBootApplication
public class AdminApplication {
    public static void main(String[] args) {
        SpringApplication.run(AdminApplication.class, args);
    }
}
