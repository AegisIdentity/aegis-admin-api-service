package io.aegis.admin.rbac;

import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.Optional;
import java.util.Set;

/**
 * The catalog of admin roles, each carrying a fixed set of {@link Permission}s. A subject's effective
 * permissions are the union of the permissions of the roles assigned to them (see
 * {@code AdminRoleService}). {@link #SUPER_ADMIN} carries every permission in the catalog so that new
 * permissions are automatically granted to super admins.
 */
public enum AdminRole {

    /** Full control: every permission in the catalog. Derived from {@link Permission#ALL}, so a newly
     * added permission is automatically granted to super admins. */
    SUPER_ADMIN(Permission.ALL.toArray(new String[0])),

    /** User and group lifecycle management. */
    USER_ADMIN(
            Permission.USERS_READ,
            Permission.USERS_WRITE,
            Permission.GROUPS_READ,
            Permission.GROUPS_WRITE),

    /** Front-line support: read users, reset passwords, unlock accounts. */
    HELP_DESK(
            Permission.USERS_READ,
            Permission.USERS_RESET_PASSWORD,
            Permission.USERS_UNLOCK),

    /** Application and identity-provider administration. */
    APP_ADMIN(
            Permission.APPS_ADMIN,
            Permission.IDP_ADMIN),

    /** Read-only oversight across users, groups, apps, and the audit trail. */
    AUDITOR(
            Permission.USERS_READ,
            Permission.GROUPS_READ,
            Permission.APPS_READ,
            Permission.AUDIT_READ);

    private final Set<String> permissions;

    AdminRole(String... permissions) {
        // LinkedHashSet preserves declaration order for stable, human-readable API output.
        this.permissions = Collections.unmodifiableSet(new LinkedHashSet<>(Arrays.asList(permissions)));
    }

    /** The permissions this role grants (immutable, in declaration order). */
    public Set<String> permissions() {
        return permissions;
    }

    /** Resolve a role by its exact enum name, if it is a known role. */
    public static Optional<AdminRole> fromName(String name) {
        if (name == null) {
            return Optional.empty();
        }
        for (AdminRole role : values()) {
            if (role.name().equals(name)) {
                return Optional.of(role);
            }
        }
        return Optional.empty();
    }
}
