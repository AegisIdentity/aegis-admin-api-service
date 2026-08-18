package io.aegis.admin.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import io.aegis.admin.domain.AdminRoleAssignment;
import io.aegis.admin.domain.AdminRoleAssignmentRepository;
import io.aegis.commons.audit.AuditEvent;
import io.aegis.commons.audit.AuditEventPublisher;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

/**
 * Privilege changes must record WHO made them — the single most important field on an admin audit
 * event ("who granted SUPER_ADMIN"). These assert the actor is the acting admin, not "system".
 */
class AdminRoleAuditTest {

    private final AdminRoleAssignmentRepository repository = mock(AdminRoleAssignmentRepository.class);
    private final AuditEventPublisher publisher = mock(AuditEventPublisher.class);
    private final AdminRoleService service = new AdminRoleService(repository, false, publisher);

    @Test
    void assigning_roles_attributes_the_acting_admin() {
        when(repository.findByTenantIdAndSubject("acme", "bob")).thenReturn(Optional.empty());
        when(repository.save(any())).thenAnswer(i -> i.getArgument(0));

        service.upsert("acme", "bob", List.of("USER_ADMIN"), "alice-the-admin");

        AuditEvent event = capturedEvent();
        assertThat(event.action()).isEqualTo("admin.role.assigned");
        assertThat(event.actor()).isEqualTo("alice-the-admin"); // who granted
        assertThat(event.target()).isEqualTo("bob");            // whose roles changed
        assertThat(event.tenantId()).isEqualTo("acme");
        assertThat(event.attributes()).containsEntry("detail", "roles=USER_ADMIN");
    }

    @Test
    void revoking_roles_attributes_the_acting_admin() {
        when(repository.findByTenantIdAndSubject("acme", "bob"))
                .thenReturn(Optional.of(new AdminRoleAssignment(UUID.randomUUID(), "acme", "bob")));

        service.delete("acme", "bob", "alice-the-admin");

        AuditEvent event = capturedEvent();
        assertThat(event.action()).isEqualTo("admin.role.revoked");
        assertThat(event.actor()).isEqualTo("alice-the-admin");
        assertThat(event.target()).isEqualTo("bob");
    }

    @Test
    void a_missing_actor_falls_back_to_system_rather_than_being_blank() {
        when(repository.findByTenantIdAndSubject("acme", "bob")).thenReturn(Optional.empty());
        when(repository.save(any())).thenAnswer(i -> i.getArgument(0));

        service.upsert("acme", "bob", List.of("USER_ADMIN"), null);

        assertThat(capturedEvent().actor()).isEqualTo("system");
    }

    private AuditEvent capturedEvent() {
        ArgumentCaptor<AuditEvent> captor = ArgumentCaptor.forClass(AuditEvent.class);
        verify(publisher).publish(captor.capture());
        return captor.getValue();
    }
}
