-- Run once: npx wrangler d1 execute sniff --remote --file=schema.sql
CREATE TABLE IF NOT EXISTS usage (
  day TEXT NOT NULL,          -- UTC day, YYYY-MM-DD
  who TEXT NOT NULL,          -- "ip:<ip>" or "key:<wallet>"
  n INTEGER NOT NULL,         -- checks used that day
  PRIMARY KEY (day, who)
);
CREATE TABLE IF NOT EXISTS keys (
  hash TEXT PRIMARY KEY,      -- sha256 of the API key (the key itself is never stored)
  wallet TEXT NOT NULL,
  created INTEGER NOT NULL,
  expires INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS keys_by_wallet ON keys (wallet);
CREATE TABLE IF NOT EXISTS burns (
  tx TEXT PRIMARY KEY,        -- each $SNIFF burn pays for one key purchase
  wallet TEXT NOT NULL,
  amount REAL NOT NULL,
  created INTEGER NOT NULL
);
