--
-- Platform-wide audit log (the CloudTrail / Okta System Log store).
--
-- Filled by AuditEventConsumer from the Kafka audit stream that every service publishes to. This is
-- the single queryable record of every security-relevant event across the platform. Append-only:
-- the application never updates or deletes rows.
--
-- The unique (kafka_partition, kafka_offset) makes Kafka's at-least-once redelivery idempotent — a
-- redelivered message is a no-op insert, not a duplicate audit line.
--
CREATE TABLE IF NOT EXISTS audit_log (
    id              uuid        NOT NULL,
    type            varchar(32) NOT NULL,
    action          varchar(64) NOT NULL,
    outcome         varchar(16) NOT NULL,
    tenant_id       varchar(64),
    actor           varchar(320),
    target          varchar(320),
    correlation_id  varchar(64),
    event_time      timestamptz NOT NULL,
    attributes      text,
    received_at     timestamptz NOT NULL,
    kafka_partition integer     NOT NULL,
    kafka_offset    bigint      NOT NULL,
    PRIMARY KEY (id),
    CONSTRAINT uk_audit_log_kafka_coord UNIQUE (kafka_partition, kafka_offset)
);

CREATE INDEX IF NOT EXISTS ix_audit_log_tenant_time ON audit_log (tenant_id, event_time);
CREATE INDEX IF NOT EXISTS ix_audit_log_action ON audit_log (action);
CREATE INDEX IF NOT EXISTS ix_audit_log_actor ON audit_log (actor);
