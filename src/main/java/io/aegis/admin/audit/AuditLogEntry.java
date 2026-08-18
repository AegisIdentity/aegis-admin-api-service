package io.aegis.admin.audit;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Index;
import jakarta.persistence.Table;
import jakarta.persistence.UniqueConstraint;
import java.time.Instant;
import java.util.UUID;

/**
 * One row of the platform-wide audit log — the CloudTrail / Okta System Log store. Every
 * security-relevant event from every service lands here via the Kafka audit stream, so this table is
 * the single queryable record of "what happened across the platform".
 *
 * <p><b>Append-only by design.</b> There are no setters and no update/delete paths: an audit trail
 * that can be edited is not an audit trail. Rows are only inserted (by the sink) and read (by the
 * System Log query).
 *
 * <p><b>Exactly-once persistence over at-least-once delivery.</b> Kafka redelivers on rebalance/retry,
 * so the raw stream is at-least-once. The unique constraint on {@code (kafka_partition, kafka_offset)}
 * makes a redelivered message a no-op insert rather than a duplicate log line — the message's own
 * coordinates are a natural idempotency key, needing no id added to the event model.
 */
@Entity
@Table(
        name = "audit_log",
        uniqueConstraints = @UniqueConstraint(
                name = "uk_audit_log_kafka_coord", columnNames = {"kafka_partition", "kafka_offset"}),
        indexes = {
                @Index(name = "ix_audit_log_tenant_time", columnList = "tenant_id, event_time"),
                @Index(name = "ix_audit_log_action", columnList = "action"),
                @Index(name = "ix_audit_log_actor", columnList = "actor")
        })
public class AuditLogEntry {

    @Id
    @Column(name = "id", nullable = false, updatable = false)
    private UUID id;

    @Column(name = "type", nullable = false, length = 32)
    private String type;

    @Column(name = "action", nullable = false, length = 64)
    private String action;

    @Column(name = "outcome", nullable = false, length = 16)
    private String outcome;

    @Column(name = "tenant_id", length = 64)
    private String tenantId;

    @Column(name = "actor", length = 320)
    private String actor;

    @Column(name = "target", length = 320)
    private String target;

    @Column(name = "correlation_id", length = 64)
    private String correlationId;

    /** When the event actually occurred (from the event), not when it was stored. */
    @Column(name = "event_time", nullable = false)
    private Instant eventTime;

    /** Non-sensitive context, stored as the event's JSON attributes map. */
    @Column(name = "attributes", columnDefinition = "text")
    private String attributesJson;

    /** When the sink persisted the row — lets you measure end-to-end audit latency. */
    @Column(name = "received_at", nullable = false)
    private Instant receivedAt;

    @Column(name = "kafka_partition", nullable = false)
    private int kafkaPartition;

    @Column(name = "kafka_offset", nullable = false)
    private long kafkaOffset;

    protected AuditLogEntry() {
        // JPA
    }

    public AuditLogEntry(String type, String action, String outcome, String tenantId, String actor,
                         String target, String correlationId, Instant eventTime, String attributesJson,
                         int kafkaPartition, long kafkaOffset) {
        this.id = UUID.randomUUID();
        this.type = type;
        this.action = action;
        this.outcome = outcome;
        this.tenantId = tenantId;
        this.actor = actor;
        this.target = target;
        this.correlationId = correlationId;
        this.eventTime = eventTime;
        this.attributesJson = attributesJson;
        this.receivedAt = Instant.now();
        this.kafkaPartition = kafkaPartition;
        this.kafkaOffset = kafkaOffset;
    }

    public UUID getId() {
        return id;
    }

    public String getType() {
        return type;
    }

    public String getAction() {
        return action;
    }

    public String getOutcome() {
        return outcome;
    }

    public String getTenantId() {
        return tenantId;
    }

    public String getActor() {
        return actor;
    }

    public String getTarget() {
        return target;
    }

    public String getCorrelationId() {
        return correlationId;
    }

    public Instant getEventTime() {
        return eventTime;
    }

    public String getAttributesJson() {
        return attributesJson;
    }

    public Instant getReceivedAt() {
        return receivedAt;
    }
}
