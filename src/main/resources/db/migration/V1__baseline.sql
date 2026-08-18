--
-- Baseline schema for admin-api-service.
--
-- GENERATED from the JPA entities by Hibernate's schema exporter, not hand-written. The service
-- runs with ddl-auto: validate, so any drift between this file and the entities fails startup —
-- generating it is what guarantees the two agree.
--
-- Regenerate after an entity change (then add a NEW V<n>__ migration; never edit an applied one):
--   mvn -o verify -Dit.test=<AnIT> -DfailIfNoSpecifiedTests=false \
--     -Dspring.jpa.properties.jakarta.persistence.schema-generation.scripts.action=create \
--     -Dspring.jpa.properties.jakarta.persistence.schema-generation.scripts.create-target=target/generated-schema.sql
--
-- Existing (pre-Flyway) databases are handled by flyway.baseline-on-migrate=true: they are marked
-- at the baseline version and this migration is skipped, since their tables already exist.
--
create table admin_role_assignment (updated_at timestamp(6) with time zone not null, id uuid not null, tenant_id varchar(64) not null, subject varchar(320) not null, roles varchar(512) not null, primary key (id), constraint uq_admin_role_tenant_subject unique (tenant_id, subject));

