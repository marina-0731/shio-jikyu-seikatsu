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
