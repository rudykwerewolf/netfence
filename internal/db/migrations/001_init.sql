BEGIN;
CREATE TABLE IF NOT EXISTS schema_migrations(version INTEGER PRIMARY KEY);
-- defaults
CREATE TABLE defaults(
  id INTEGER PRIMARY KEY CHECK(id=1),
  input_policy TEXT NOT NULL DEFAULT 'drop' CHECK(input_policy IN('accept','drop')),
  forward_policy TEXT NOT NULL DEFAULT 'drop' CHECK(forward_policy IN('accept','drop')),
  output_policy TEXT NOT NULL DEFAULT 'accept' CHECK(output_policy IN('accept','drop')),
  log_prefix TEXT NOT NULL DEFAULT ''
);
INSERT OR IGNORE INTO defaults(id) VALUES(1);

-- rules + parts
CREATE TABLE rules(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  chain TEXT NOT NULL CHECK(chain IN('input','forward','output')),
  proto TEXT NOT NULL CHECK(proto IN('all','tcp','udp','icmp')),
  action TEXT NOT NULL CHECK(action IN('accept','drop')),
  in_if TEXT, out_if TEXT, comment TEXT,
  enabled INTEGER NOT NULL DEFAULT 1,
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TRIGGER IF NOT EXISTS trg_rules_updated_at
AFTER UPDATE ON rules FOR EACH ROW
BEGIN
  UPDATE rules SET updated_at=CURRENT_TIMESTAMP WHERE id=OLD.id;
END;

CREATE TABLE rule_port(rule_id INTEGER NOT NULL REFERENCES rules(id) ON DELETE CASCADE,
  port INTEGER NOT NULL CHECK(port BETWEEN 1 AND 65535),
  PRIMARY KEY(rule_id, port)
);
CREATE TABLE rule_src_cidr(rule_id INTEGER NOT NULL REFERENCES rules(id) ON DELETE CASCADE,
  cidr TEXT NOT NULL,
  PRIMARY KEY(rule_id, cidr)
);
CREATE TABLE rule_dst_cidr(rule_id INTEGER NOT NULL REFERENCES rules(id) ON DELETE CASCADE,
  cidr TEXT NOT NULL,
  PRIMARY KEY(rule_id, cidr)
);
CREATE TABLE rule_icmp_type(rule_id INTEGER NOT NULL REFERENCES rules(id) ON DELETE CASCADE,
  itype INTEGER NOT NULL CHECK(itype BETWEEN 0 AND 255),
  PRIMARY KEY(rule_id, itype)
);
INSERT INTO schema_migrations(version) VALUES(1);
COMMIT;
