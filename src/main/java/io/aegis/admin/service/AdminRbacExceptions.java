package io.aegis.admin.service;

/** Domain exceptions for admin RBAC. */
public final class AdminRbacExceptions {

    private AdminRbacExceptions() {
    }

    /** A request referenced a role name that is not part of the {@code AdminRole} catalog. */
    public static class UnknownRoleException extends RuntimeException {
        public UnknownRoleException(String message) {
            super(message);
        }
    }

    /** No role assignment exists for the (tenant, subject). */
    public static class AssignmentNotFoundException extends RuntimeException {
        public AssignmentNotFoundException(String message) {
            super(message);
        }
    }
}
