CREATE TABLE IF NOT EXISTS pending (
  endpoint TEXT NOT NULL,
  tag      TEXT NOT NULL,
  at       INTEGER NOT NULL,
  sub      TEXT NOT NULL,
  title    TEXT NOT NULL,
  body     TEXT NOT NULL,
  PRIMARY KEY (endpoint, tag)
);
CREATE INDEX IF NOT EXISTS pending_at ON pending (at);

CREATE TABLE IF NOT EXISTS stats (
  id     INTEGER PRIMARY KEY CHECK (id = 1),
  salts  INTEGER NOT NULL DEFAULT 0,
  grams  INTEGER NOT NULL DEFAULT 0
);
INSERT OR IGNORE INTO stats (id, salts, grams) VALUES (1, 0, 0);

CREATE TABLE IF NOT EXISTS players (
  cid   TEXT PRIMARY KEY,
  first INTEGER NOT NULL
);
