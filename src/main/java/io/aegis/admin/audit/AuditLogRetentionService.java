package io.aegis.admin.audit;

import java.time.Duration;
import java.time.Instant;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Retention for the append-only audit log. The store grows with every security event on the
 * platform, so it needs a bounded window; this service purges events older than the configured
 * retention period on a schedule, in bounded batches so a purge never long-locks the table.
 *
 * <p><b>Retention window.</b> Default 365 days ({@code aegis.audit.retention.days}) — a common
 * compliance floor for security audit trails. Set it to your regulatory requirement. A deployment
 * that must keep records longer than it wants them hot should <em>archive to object storage before
 * purge</em> (S3/Blob, cheaper cold storage) and keep this window as the hot-store TTL; the archival
 * hook is a documented follow-up, not built here.
 *
 * <p><b>Scaling beyond retention.</b> For very high event volume, native time-based <em>partitioning</em>
 * (a monthly-partitioned {@code audit_log}) makes purge a partition-drop (instant, no row scan) and
 * keeps indexes small. That is a schema change (partitioned parent + per-month children) and is the
 * next step when a single table's purge cost becomes material; retention-by-delete is the pragmatic
 * control until then.
 */
@Service
public class AuditLogRetentionService {

    private static final Logger log = LoggerFactory.getLogger(AuditLogRetentionService.class);

    private final AuditLogRepository repository;
    private final boolean enabled;
    private final Duration retention;
    private final int batchSize;

    public AuditLogRetentionService(
            AuditLogRepository repository,
            @Value("${aegis.audit.retention.enabled:true}") boolean enabled,
            @Value("${aegis.audit.retention.days:365}") long retentionDays,
            @Value("${aegis.audit.retention.batch-size:5000}") int batchSize) {
        this.repository = repository;
        this.enabled = enabled;
        this.retention = Duration.ofDays(retentionDays);
        this.batchSize = batchSize;
    }

    /**
     * Nightly purge (03:15 by default). Deletes in batches until nothing older than the window
     * remains, so a large backlog is cleared over several bounded statements rather than one giant
     * lock. Bounded batch count as a safety valve against an unexpectedly huge backlog in one run.
     */
    @Scheduled(cron = "${aegis.audit.retention.cron:0 15 3 * * *}")
    @Transactional
    public void purgeExpired() {
        if (!enabled) {
            return;
        }
        Instant cutoff = Instant.now().minus(retention);
        long total = 0;
        for (int i = 0; i < 1000; i++) { // safety cap: at most 1000 * batchSize per run
            int deleted = repository.deleteOlderThan(cutoff, batchSize);
            total += deleted;
            if (deleted < batchSize) {
                break;
            }
        }
        if (total > 0) {
            log.info("audit_log retention: purged {} events older than {} ({} day window)",
                    total, cutoff, retention.toDays());
        }
    }
}
