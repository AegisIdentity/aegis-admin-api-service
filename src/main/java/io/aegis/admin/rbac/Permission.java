package io.aegis.admin.rbac;

import java.util.List;

/**
 * The fixed catalog of fine-grained admin permission strings. These are the atoms an
 * {@link AdminRole} is composed of and what the console (and token-enrichment) gate UI/actions on.
 * Permissions are namespaced {@code resource:action}; new ones are added here, appended to {@link #ALL},
 * and wired into the roles that should carry them. {@link AdminRole#SUPER_ADMIN} derives its grant from
 * {@link #ALL}, so a new permission is automatically granted to super admins.
 */
public final class Permission {

    private Permission() {
    }

    public static final String USERS_READ = "users:read";
    public static final String USERS_WRITE = "users:write";
    public static final String USERS_RESET_PASSWORD = "users:reset-password";
    public static final String USERS_UNLOCK = "users:unlock";

    public static final String GROUPS_READ = "groups:read";
    public static final String GROUPS_WRITE = "groups:write";

    public static final String APPS_READ = "apps:read";
    public static final String APPS_ADMIN = "apps:admin";

    public static final String IDP_ADMIN = "idp:admin";

    public static final String AUDIT_READ = "audit:read";

    /** Every permission in the catalog, in declaration order. SUPER_ADMIN is granted exactly this set. */
    public static final List<String> ALL = List.of(
            USERS_READ,
            USERS_WRITE,
            USERS_RESET_PASSWORD,
            USERS_UNLOCK,
            GROUPS_READ,
            GROUPS_WRITE,
            APPS_READ,
            APPS_ADMIN,
            IDP_ADMIN,
            AUDIT_READ);
}
