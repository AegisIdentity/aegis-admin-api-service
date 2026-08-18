package io.aegis.admin.audit;

import static org.assertj.core.api.Assertions.assertThat;

import io.aegis.admin.AdminTestConfig;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.data.domain.PageRequest;

/**
 * Retention purge behaviour, against real Postgres: events older than the window are deleted; events
 * inside it are kept. The bounded window is what stops the append-only store growing without limit.
 */
@SpringBootTest(properties = {
        "aegis.audit.retention.enabled=true",
        "aegis.audit.retention.days=30",
        "aegis.audit.retention.batch-size=100"
})
@Import(AdminTestConfig.class)
class AuditLogRetentionIT {

    @Autowired
    AuditLogRepository repository;

    @Autowired
    AuditLogRetentionService retention;

    @BeforeEach
    void seed() {
        repository.deleteAll();
        // Two well outside a 30-day window, one inside it.
        save("old-1", Instant.now().minus(100, ChronoUnit.DAYS), 1);
        save("old-2", Instant.now().minus(40, ChronoUnit.DAYS), 2);
        save("recent", Instant.now().minus(5, ChronoUnit.DAYS), 3);
    }

    private void save(String action, Instant when, long offset) {
        repository.save(new AuditLogEntry("auth", action, "SUCCESS", "acme", "alice", null, null,
                when, null, 0, offset));
    }

    @Test
    void purge_removes_events_older_than_the_window_and_keeps_the_rest() {
        assertThat(repository.count()).isEqualTo(3);

        retention.purgeExpired();

        var remaining = repository.findByTenantIdOrderByEventTimeDesc("acme", PageRequest.of(0, 10));
        assertThat(remaining).extracting(AuditLogEntry::getAction).containsExactly("recent");
        assertThat(repository.count()).isEqualTo(1);
    }

    @Test
    void purge_is_a_no_op_when_nothing_is_expired() {
        repository.deleteAll();
        save("fresh", Instant.now().minus(1, ChronoUnit.DAYS), 9);

        retention.purgeExpired();

        assertThat(repository.count()).isEqualTo(1);
    }
}
