-- A quarantined device revocation is served again only when its row holds the
-- container that was quarantined, not another genuine one filed under the same
-- replay ID. The mark records the SHA-256 of the row's container bytes (NULL for
-- every other kind, and for a mark whose content is unknown, which is never
-- served again). The column is added in place: the table keeps its rows and its
-- three triggers, so a mark still never changes or goes.
ALTER TABLE v2_grant_quarantine
    ADD COLUMN container_sha256 BLOB
    CHECK (container_sha256 IS NULL OR length(container_sha256) = 32);
