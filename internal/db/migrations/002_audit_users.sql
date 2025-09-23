BEGIN;
-- audit log
CREATE TABLE audit_log(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  actor TEXT NOT NULL,
  action TEXT NOT NULL,       -- e.g., add_rule, del_rule, apply, import_yaml
  object TEXT NOT NULL,       -- e.g., rule:42
  details TEXT NOT NULL       -- json/text
);

-- users & roles (very simple)
CREATE TABLE users(
  name TEXT PRIMARY KEY,
  role TEXT NOT NULL CHECK(role IN('admin','operator','viewer'))
);
-- default bootstrap admin (change/remove later)
INSERT OR IGNORE INTO users(name, role) VALUES ('root', 'admin');

INSERT INTO schema_migrations(version) VALUES(2);
COMMIT;
