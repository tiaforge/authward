-- The normalized client address the session was created from (see
-- ratelimit::bound_client_ip). NULL when binding was off or the address
-- was unknown at login, and for rows created before this column existed;
-- such sessions are never bound.
ALTER TABLE sessions ADD COLUMN client_ip TEXT;
