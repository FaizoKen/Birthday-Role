-- Role links: one per guild+role pair registered via POST /register.
--
-- The rule tree is stored as JSONB and validated by `parse_rule_tree`.
-- Until an admin opens the iframe and saves, rule_tree stays at
-- '{"grant_on_any_birthday":false,"groups":[]}' which means "grant to
-- nobody" (Convention 42). There is no external identity target column
-- (no channel / no API key) — the only data this plugin holds is the
-- member's self-reported birthday, so an empty rule is the sole
-- "unconfigured" sentinel.
--
-- `rule_tree_version` powers optimistic locking on save: two dashboard
-- tabs editing the same role link cannot silently clobber each other.

CREATE TABLE IF NOT EXISTS role_links (
    id                     BIGSERIAL PRIMARY KEY,
    guild_id               TEXT NOT NULL,
    role_id                TEXT NOT NULL,
    api_token              TEXT NOT NULL,
    rule_tree              JSONB NOT NULL DEFAULT '{"grant_on_any_birthday":false,"groups":[]}',
    rule_tree_version      INTEGER NOT NULL DEFAULT 1,
    created_at             TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at             TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (guild_id, role_id)
);

-- Sync workers fan out by (guild_id, role_id) when a config changes, and
-- sync_for_player scans by guild_id; this index supports both.
CREATE INDEX IF NOT EXISTS idx_role_links_guild_role
    ON role_links (guild_id, role_id);

-- Role assignments: local mirror of who currently holds which Discord role.
-- Source of truth is RoleLogic; we keep this to diff against when computing
-- add/remove deltas. CASCADE keeps it consistent on DELETE /config.
CREATE TABLE IF NOT EXISTS role_assignments (
    guild_id        TEXT NOT NULL,
    role_id         TEXT NOT NULL,
    discord_id      TEXT NOT NULL,
    assigned_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (guild_id, role_id, discord_id),
    FOREIGN KEY (guild_id, role_id) REFERENCES role_links (guild_id, role_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_role_assignments_discord
    ON role_assignments (discord_id);
