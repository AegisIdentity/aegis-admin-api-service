package io.aegis.admin.audit;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import java.time.Instant;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.kafka.annotation.KafkaListener;
import org.springframework.messaging.handler.annotation.Header;
import org.springframework.messaging.handler.annotation.Payload;
import org.springframework.kafka.support.KafkaHeaders;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

/**
 * The audit sink — the consumer that turns the Kafka audit stream into the append-only, queryable
 * platform log (the CloudTrail equivalent). It subscribes to the single audit topic every service
 * publishes to, so one component sees every security-relevant event across the platform.
 *
 * <p>Deliberately tolerant on the read side: it parses the event JSON field-by-field rather than
 * binding to a shared class, so a producer on a newer schema (an extra field) does not break the
 * sink during a rolling deploy. A message it genuinely cannot parse is logged and dropped rather
 * than blocking the partition forever (a poison message must not stall the whole audit pipeline).
 *
 * <p>Idempotent: the Kafka {@code (partition, offset)} of each message is stored with a unique
 * constraint, so an at-least-once redelivery is a no-op insert rather than a duplicate audit line.
 */
@Component
public class AuditEventConsumer {

    private static final Logger log = LoggerFactory.getLogger(AuditEventConsumer.class);

    private final AuditLogRepository repository;
    private final ObjectMapper mapper;

    public AuditEventConsumer(AuditLogRepository repository) {
        this.repository = repository;
        this.mapper = new ObjectMapper().registerModule(new JavaTimeModule());
    }

    @KafkaListener(
            topics = "${aegis.audit.kafka.topic:aegis.audit.events}",
            groupId = "${aegis.audit.kafka.consumer-group:aegis-audit-sink}")
    @Transactional
    public void consume(@Payload String json,
                        @Header(KafkaHeaders.RECEIVED_PARTITION) int partition,
                        @Header(KafkaHeaders.OFFSET) long offset) {
        // Fast idempotency check; the unique constraint is the real guarantee (see below).
        if (repository.existsByKafkaCoordinate(partition, offset)) {
            return;
        }
        AuditLogEntry entry;
        try {
            entry = parse(json, partition, offset);
        } catch (Exception e) {
            // Poison message: log and move on. Blocking the partition on one bad record would stop
            // the entire platform audit trail.
            log.warn("dropping unparseable audit message at partition={} offset={}", partition, offset);
            return;
        }
        try {
            repository.save(entry);
        } catch (DataIntegrityViolationException duplicate) {
            // Another consumer/redelivery won the race on the unique (partition, offset) — the event
            // is already recorded, so this is success, not an error.
            log.debug("audit message at partition={} offset={} already persisted", partition, offset);
        }
    }

    private AuditLogEntry parse(String json, int partition, long offset) throws Exception {
        JsonNode n = mapper.readTree(json);
        String type = text(n, "type");
        String action = text(n, "action");
        if (type == null || action == null) {
            throw new IllegalArgumentException("audit event missing required type/action");
        }
        JsonNode attrs = n.get("attributes");
        return new AuditLogEntry(
                type,
                action,
                text(n, "outcome"),
                text(n, "tenantId"),
                text(n, "actor"),
                text(n, "target"),
                text(n, "correlationId"),
                n.hasNonNull("at") ? Instant.parse(n.get("at").asText()) : Instant.now(),
                attrs != null && !attrs.isNull() ? mapper.writeValueAsString(attrs) : null,
                partition,
                offset);
    }

    private static String text(JsonNode node, String field) {
        JsonNode v = node.get(field);
        return v != null && !v.isNull() ? v.asText() : null;
    }
}
