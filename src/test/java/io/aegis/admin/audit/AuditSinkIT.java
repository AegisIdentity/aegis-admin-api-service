package io.aegis.admin.audit;

import static org.assertj.core.api.Assertions.assertThat;

import io.aegis.commons.audit.AuditEvent;
import io.aegis.commons.audit.AuditOutcome;
import io.aegis.commons.audit.KafkaAuditEventPublisher;
import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import org.awaitility.Awaitility;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.boot.testcontainers.service.connection.ServiceConnection;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.data.domain.PageRequest;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.kafka.ConfluentKafkaContainer;
import org.testcontainers.utility.DockerImageName;

/**
 * End-to-end proof of the CloudTrail-style audit pipeline: an event published to Kafka by the shared
 * {@link KafkaAuditEventPublisher} (the same publisher every service uses) is consumed by the sink,
 * persisted append-only, and made queryable.
 *
 * <p>This is the test that turns "we built a Kafka backbone" from a claim into a fact — it exercises
 * the real publisher, a real broker, the real {@code @KafkaListener}, and the real database. The
 * broker is wired via {@code @DynamicPropertySource} (Boot's Kafka {@code @ServiceConnection} factory
 * does not match the apache-kafka-native container); Postgres uses {@code @ServiceConnection}.
 */
@SpringBootTest(properties = {
        // Turn the listener on for this test — it is off by default so the service runs without Kafka.
        "spring.kafka.listener.auto-startup=true",
        "spring.kafka.consumer.auto-offset-reset=earliest"
})
@Import(AuditSinkIT.PostgresInfra.class)
class AuditSinkIT {

    @SuppressWarnings("resource")
    private static final ConfluentKafkaContainer KAFKA =
            new ConfluentKafkaContainer(DockerImageName.parse("confluentinc/cp-kafka:7.8.0"));

    static {
        KAFKA.start();
    }

    @DynamicPropertySource
    static void kafkaProperties(DynamicPropertyRegistry registry) {
        registry.add("spring.kafka.bootstrap-servers", KAFKA::getBootstrapServers);
    }

    @TestConfiguration(proxyBeanMethods = false)
    static class PostgresInfra {
        @Bean
        @ServiceConnection
        PostgreSQLContainer<?> postgres() {
            return new PostgreSQLContainer<>(DockerImageName.parse("postgres:16-alpine"))
                    .withDatabaseName("aegis_admin");
        }
    }

    @Autowired
    KafkaTemplate<String, String> kafkaTemplate;

    @Autowired
    AuditLogRepository repository;

    private KafkaAuditEventPublisher publisher() {
        return new KafkaAuditEventPublisher(kafkaTemplate, "aegis.audit.events");
    }

    @Test
    void an_event_published_to_kafka_lands_in_the_append_only_audit_store() {
        String action = "user.created." + java.util.UUID.randomUUID();
        AuditEvent event = new AuditEvent("identity", action, AuditOutcome.SUCCESS,
                "acme", "admin@acme", "bob@acme", "corr-42",
                Instant.parse("2026-08-18T12:00:00Z"), Map.of("source", "console"));

        publisher().publish(event);

        Awaitility.await().atMost(Duration.ofSeconds(30)).untilAsserted(() -> {
            var rows = repository.findByTenantIdAndActionOrderByEventTimeDesc(
                    "acme", action, PageRequest.of(0, 10));
            assertThat(rows).hasSize(1);
            AuditLogEntry row = rows.get(0);
            assertThat(row.getType()).isEqualTo("identity");
            assertThat(row.getActor()).isEqualTo("admin@acme");
            assertThat(row.getTarget()).isEqualTo("bob@acme");
            assertThat(row.getOutcome()).isEqualTo("SUCCESS");
            assertThat(row.getEventTime()).isEqualTo(Instant.parse("2026-08-18T12:00:00Z"));
            assertThat(row.getAttributesJson()).contains("console");
        });
    }

    @Test
    void events_from_different_services_all_land_in_the_one_store() {
        // Several services publishing to the same topic — the "capture everything" property.
        String tag = java.util.UUID.randomUUID().toString();
        publisher().publish(new AuditEvent("auth", "login." + tag, AuditOutcome.SUCCESS,
                "globex", "alice", null, null, Instant.now(), Map.of()));
        publisher().publish(new AuditEvent("authz", "access.denied." + tag, AuditOutcome.DENIED,
                "globex", "mallory", "/admin", null, Instant.now(), Map.of()));
        publisher().publish(new AuditEvent("tenant", "tenant.suspended." + tag, AuditOutcome.SUCCESS,
                "globex", "root", "globex", null, Instant.now(), Map.of()));

        Awaitility.await().atMost(Duration.ofSeconds(30)).untilAsserted(() -> {
            var rows = repository.findByTenantIdOrderByEventTimeDesc("globex", PageRequest.of(0, 50));
            assertThat(rows).extracting(AuditLogEntry::getAction)
                    .contains("login." + tag, "access.denied." + tag, "tenant.suspended." + tag);
        });
    }
}
