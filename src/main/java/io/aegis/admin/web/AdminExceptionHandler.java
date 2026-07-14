package io.aegis.admin.web;

import io.aegis.admin.service.AdminRbacExceptions.AssignmentNotFoundException;
import io.aegis.admin.service.AdminRbacExceptions.UnknownRoleException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ProblemDetail;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

/** Maps admin RBAC domain exceptions to RFC-7807 responses. */
@RestControllerAdvice
public class AdminExceptionHandler {

    @ExceptionHandler(UnknownRoleException.class)
    public ProblemDetail handleUnknownRole(UnknownRoleException ex) {
        return ProblemDetail.forStatusAndDetail(HttpStatus.BAD_REQUEST, ex.getMessage());
    }

    @ExceptionHandler(AssignmentNotFoundException.class)
    public ProblemDetail handleNotFound(AssignmentNotFoundException ex) {
        return ProblemDetail.forStatusAndDetail(HttpStatus.NOT_FOUND, ex.getMessage());
    }
}
