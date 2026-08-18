package io.aegis.admin.audit;

import java.time.Instant;
import java.util.List;
import java.util.UUID;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

/**
 * Read/append access to the platform audit log. No update or delete methods — the store is
 * append-only. Query methods are tenant-scoped by construction; the one cross-tenant method is named
 * so its use is explicit and easy to audit.
 */
public interface AuditLogRepository extends JpaRepository<AuditLogEntry, UUID> {

    /** A tenant's events, newest first — the per-tenant System Log. */
    List<AuditLogEntry> findByTenantIdOrderByEventTimeDesc(String tenantId, Pageable pageable);

    /** A tenant's events filtered by action, newest first. */
    List<AuditLogEntry> findByTenantIdAndActionOrderByEventTimeDesc(
            String tenantId, String action, Pageable pageable);

    /** A tenant's events since a point in time, newest first. */
    List<AuditLogEntry> findByTenantIdAndEventTimeAfterOrderByEventTimeDesc(
            String tenantId, Instant since, Pageable pageable);

    /**
     * Every tenant's events, newest first — for platform operators only. Named explicitly (not a
     * bare {@code findAll}) so a cross-tenant read is never accidental.
     */
    @Query("select a from AuditLogEntry a order by a.eventTime desc")
    List<AuditLogEntry> findAllAcrossTenants(Pageable pageable);

    /** True if a message at these Kafka coordinates was already persisted (idempotency fast-path). */
    @Query("select (count(a) > 0) from AuditLogEntry a "
            + "where a.kafkaPartition = :partition and a.kafkaOffset = :offset")
    boolean existsByKafkaCoordinate(@Param("partition") int partition, @Param("offset") long offset);

    /**
     * Delete events older than {@code cutoff} — the retention purge. A bulk modifying delete, so it
     * does not load rows into memory; batch-limited by the caller so one run cannot lock the table
     * for long. This is the ONLY delete path on an otherwise append-only store, and it removes only
     * rows beyond the retention window.
     */
    @org.springframework.data.jpa.repository.Modifying
    @Query(value = "DELETE FROM audit_log WHERE id IN "
            + "(SELECT id FROM audit_log WHERE event_time < :cutoff ORDER BY event_time LIMIT :batchSize)",
            nativeQuery = true)
    int deleteOlderThan(@Param("cutoff") java.time.Instant cutoff, @Param("batchSize") int batchSize);
}
