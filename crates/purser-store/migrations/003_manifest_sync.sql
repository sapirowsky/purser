ALTER TABLE projects ADD COLUMN updated_at TEXT NOT NULL DEFAULT '';

UPDATE projects SET updated_at = created_at WHERE updated_at = '';

CREATE TABLE settings (
    key        TEXT PRIMARY KEY,
    value      TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
