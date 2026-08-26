--
-- Per-tool consent with a pinned definition hash (ADR-0013).
--
-- The platform's existing OAuth consent store is SCOPE-granular and cannot express "I approved THIS
-- VERSION of this tool". That gap matters because a tool's description is the instruction surface
-- the model reads: a server can change what a tool means without changing its name or its scopes,
-- and scope-granular consent is blind to it. pinned_definition_hash closes it.
--
CREATE TABLE IF NOT EXISTS tool_consent (
    id                     uuid         NOT NULL,
    tenant_id              varchar(64)  NOT NULL,
    subject                varchar(200) NOT NULL,
    agent_id               varchar(128) NOT NULL,
    server_id              varchar(200) NOT NULL,
    tool_name              varchar(200) NOT NULL,
    pinned_definition_hash varchar(128) NOT NULL,
    granted_at             timestamptz  NOT NULL,
    updated_at             timestamptz  NOT NULL,
    revoked_at             timestamptz,
    revoked_reason         varchar(500),
    PRIMARY KEY (id),
    CONSTRAINT uq_tool_consent_scope UNIQUE (tenant_id, subject, agent_id, server_id, tool_name)
);

-- The PDP does this lookup on every tool invocation, so it must not be a sequential scan.
CREATE INDEX IF NOT EXISTS ix_tool_consent_lookup
    ON tool_consent (tenant_id, agent_id, server_id, tool_name);

-- "What has this agent been allowed to do?" — the query an incident responder runs first.
CREATE INDEX IF NOT EXISTS ix_tool_consent_agent
    ON tool_consent (tenant_id, agent_id);
