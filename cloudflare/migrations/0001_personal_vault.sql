-- A separate schema: never import a native Vaultwarden database into this schema.
CREATE TABLE users (
  id TEXT PRIMARY KEY,
  auth0_sub TEXT NOT NULL UNIQUE,
  email TEXT NOT NULL COLLATE NOCASE,
  email_verified INTEGER NOT NULL DEFAULT 1,
  kdf_salt TEXT NOT NULL,
  name TEXT NOT NULL,
  verifier TEXT,
  salt TEXT,
  kdf INTEGER NOT NULL CHECK(kdf IN (0,1)),
  iterations INTEGER NOT NULL,
  memory INTEGER,
  parallelism INTEGER,
  wrapped_key TEXT NOT NULL DEFAULT '',
  private_key TEXT,
  public_key TEXT,
  hint TEXT,
  stamp TEXT NOT NULL,
  created TEXT NOT NULL,
  revision INTEGER NOT NULL,
  domains TEXT NOT NULL DEFAULT '[]',
  excluded_domains TEXT NOT NULL DEFAULT '[]',
  avatar TEXT
);
CREATE TABLE sessions (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  device_id TEXT NOT NULL,
  device_name TEXT NOT NULL,
  device_type INTEGER NOT NULL,
  client_id TEXT NOT NULL,
  stamp TEXT NOT NULL,
  refresh_hash TEXT NOT NULL UNIQUE,
  expires INTEGER NOT NULL,
  auth_exp INTEGER NOT NULL,
  token_box TEXT NOT NULL,
  refreshing TEXT,
  created INTEGER NOT NULL
);
CREATE INDEX sessions_user ON sessions(user_id);
CREATE TABLE folders (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  revision TEXT NOT NULL,
  UNIQUE(id,user_id)
);
CREATE INDEX folders_user ON folders(user_id);
CREATE TABLE ciphers (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  folder_id TEXT,
  payload TEXT NOT NULL CHECK(json_valid(payload)),
  created TEXT NOT NULL,
  revision TEXT NOT NULL,
  deleted TEXT,
  archived TEXT,
  FOREIGN KEY(folder_id,user_id) REFERENCES folders(id,user_id)
);
CREATE INDEX ciphers_user ON ciphers(user_id);
CREATE TABLE throttle (
  key TEXT PRIMARY KEY,
  window INTEGER NOT NULL,
  count INTEGER NOT NULL
);
-- CHECK is a transactional assertion: zero-row conditional UPDATE is not one.
CREATE TABLE transaction_guard (valid INTEGER NOT NULL CHECK(valid = 1));
CREATE TABLE sso_pending (
  id TEXT PRIMARY KEY,
  client_state TEXT NOT NULL,
  challenge TEXT NOT NULL,
  client_id TEXT NOT NULL,
  redirect TEXT NOT NULL,
  nonce TEXT NOT NULL,
  binding TEXT NOT NULL,
  expires INTEGER NOT NULL,
  code_hash TEXT UNIQUE,
  code_box TEXT
);
