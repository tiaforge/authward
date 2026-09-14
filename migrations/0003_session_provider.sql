-- Which provider (config::ResolvedHost::provider_key) authenticated the
-- session. Empty for rows created before this column existed; those are
-- read back as their base domain's default provider.
ALTER TABLE sessions ADD COLUMN provider_key TEXT NOT NULL DEFAULT '';
