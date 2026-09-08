-- 한산 발주 관리 시스템 - Cloudflare D1 스키마
-- 적용: wrangler d1 execute hansan-order-system --remote --file=./schema.sql
-- 관리자/거래처 초기 비밀번호 1111 은 워커 최초 기동 시 시드됩니다.

PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS settings (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS admins (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  password_salt TEXT NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS clients (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  password_salt TEXT NOT NULL,
  label TEXT NOT NULL DEFAULT '',
  active INTEGER NOT NULL DEFAULT 1,
  allowed_regions TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS client_accounts (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  account_id TEXT NOT NULL UNIQUE,
  client_id INTEGER NOT NULL,
  client_name TEXT NOT NULL,
  region TEXT NOT NULL,
  login_id TEXT NOT NULL,
  password_hash TEXT NOT NULL,
  password_salt TEXT NOT NULL,
  label TEXT NOT NULL DEFAULT '',
  active INTEGER NOT NULL DEFAULT 1,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  FOREIGN KEY (client_id) REFERENCES clients(id) ON DELETE CASCADE,
  UNIQUE (client_id, login_id, region)
);

CREATE TABLE IF NOT EXISTS oil_matching (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  product TEXT NOT NULL,
  product_key TEXT NOT NULL UNIQUE,
  oil TEXT NOT NULL DEFAULT '',
  restricted_clients TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS orders (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  record_id TEXT NOT NULL UNIQUE,
  year INTEGER NOT NULL,
  month INTEGER NOT NULL,
  day INTEGER NOT NULL,
  date_num INTEGER NOT NULL,
  client TEXT NOT NULL,
  region TEXT NOT NULL,
  product TEXT NOT NULL,
  oil TEXT NOT NULL,
  qty INTEGER NOT NULL,
  edit_count INTEGER NOT NULL DEFAULT 0,
  confirmed INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS auth_tokens (
  token_id TEXT PRIMARY KEY,
  role TEXT NOT NULL,
  client TEXT NOT NULL DEFAULT '',
  label TEXT NOT NULL DEFAULT '',
  account_id TEXT NOT NULL DEFAULT '',
  login_id TEXT NOT NULL DEFAULT '',
  account_region TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  revoked_at TEXT
);

CREATE TABLE IF NOT EXISTS login_attempts (
  attempt_key TEXT PRIMARY KEY,
  fail_count INTEGER NOT NULL DEFAULT 0,
  updated_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_orders_client_date ON orders(client, date_num);
CREATE INDEX IF NOT EXISTS idx_orders_date_num ON orders(date_num);
CREATE INDEX IF NOT EXISTS idx_orders_confirmed ON orders(confirmed, date_num);
CREATE INDEX IF NOT EXISTS idx_oil_product_key ON oil_matching(product_key);
CREATE INDEX IF NOT EXISTS idx_accounts_client ON client_accounts(client_id);
CREATE INDEX IF NOT EXISTS idx_accounts_login ON client_accounts(client_name, login_id, region);
CREATE INDEX IF NOT EXISTS idx_tokens_expires ON auth_tokens(expires_at);
CREATE INDEX IF NOT EXISTS idx_tokens_role_client ON auth_tokens(role, client);
