-- Fake Meridian Analytics database
-- All data here is fictional canary bait.

CREATE TABLE IF NOT EXISTS users (
  id SERIAL PRIMARY KEY,
  email TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  role TEXT DEFAULT 'user',
  created_at TIMESTAMPTZ DEFAULT NOW()
);

INSERT INTO users (email, password_hash, role) VALUES
  ('j.walsh@meridian.io',  '$2b$12$CANARY_HASH_001_fake', 'admin'),
  ('admin@meridian.io',    '$2b$12$CANARY_HASH_002_fake', 'superadmin'),
  ('sarah.chen@meridian.io','$2b$12$CANARY_HASH_003_fake','analyst');

CREATE TABLE IF NOT EXISTS api_keys (
  id SERIAL PRIMARY KEY,
  user_id INTEGER REFERENCES users(id),
  key TEXT UNIQUE NOT NULL,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

INSERT INTO api_keys (user_id, key) VALUES
  (1, 'int_CANARY005REPLACE'),
  (2, 'int_CANARY011REPLACE');

CREATE TABLE IF NOT EXISTS sessions (
  token TEXT PRIMARY KEY,
  user_id INTEGER REFERENCES users(id),
  expires_at TIMESTAMPTZ
);
