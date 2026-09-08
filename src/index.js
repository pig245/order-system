/**
 * 한산 전용 발주 관리 시스템
 * Cloudflare Workers + Hono.js + D1
 */

import { Hono } from 'hono';
import { cors } from 'hono/cors';

import loginHtml from './pages/login.html';
import indexHtml from './pages/index.html';
import adminHtml from './pages/admin.html';
import dbHtml from './pages/db.html';

const app = new Hono();

const CONFIG = Object.freeze({
  MAX_EDIT_COUNT: 2,
  MAX_SAVE_ROWS: 200,
  MAX_QTY_PER_ORDER: 10000,
  CLIENT_TOKEN_TTL_DAYS: 30,
  ADMIN_TOKEN_TTL_DAYS: 7,
  AUTH_TOKEN_RETENTION_DAYS: 7,
  MIN_PASSWORD_LENGTH: 4,
  MAX_PASSWORD_LENGTH: 100,
  DEFAULT_PASSWORD: '1111',
  LOGIN_FAIL_LIMIT: 5,
  LOGIN_FAIL_WINDOW_MS: 10 * 60 * 1000,
  GUI_TABLES: Object.freeze([
    'orders',
    'oil_matching',
    'clients',
    'client_accounts',
    'auth_tokens',
    'admins',
    'settings',
    'login_attempts'
  ])
});

app.use('*', cors({
  origin: '*',
  allowMethods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
  allowHeaders: ['Content-Type', 'Authorization', 'X-Auth-Token']
}));

app.use('*', async (c, next) => {
  try {
    await ensureSystemReady_(c.env);
  } catch (error) {
    console.error('ensureSystemReady', error);
  }
  await next();
});

app.onError((error, c) => {
  const message = error && error.message ? error.message : '서버 오류가 발생했습니다.';
  const status = error && error.status ? error.status : 400;
  return c.json({ success: false, message }, status);
});

/* ==========================================================
 * 공통 유틸리티
 * ========================================================== */

function httpError(message, status = 400) {
  const error = new Error(message);
  error.status = status;
  return error;
}

function cleanString(value) {
  return String(value == null ? '' : value).trim();
}

function normalizeProductKey_(value) {
  return cleanString(value).replace(/\s/g, '');
}

function normalizeRegionKey_(value) {
  return cleanString(value)
    .replace(/\s+/g, '')
    .replace(/,+/g, ',')
    .replace(/^,|,$/g, '');
}

function parseAllowedRegions_(value) {
  const raw = cleanString(value);
  if (!raw) return [];
  return uniqueArray_(raw.split(',')
    .map((item) => normalizeRegionKey_(item))
    .filter(Boolean));
}

function isRegionAllowed_(allowedRegions, region) {
  const allowed = Array.isArray(allowedRegions) ? allowedRegions : parseAllowedRegions_(allowedRegions);
  if (allowed.length === 0) return true;
  const target = normalizeRegionKey_(region);
  return !!target && allowed.includes(target);
}

function uniqueArray_(array) {
  return [...new Set(array)];
}

function safeInteger_(value, defaultValue = 0) {
  const number = Number(value);
  return Number.isFinite(number) ? Math.floor(number) : defaultValue;
}

function parseMonth_(value) {
  const match = cleanString(value).match(/\d+/);
  return match ? Number(match[0]) : 0;
}

function parseDay_(value) {
  const match = cleanString(value).match(/\d+/);
  return match ? Number(match[0]) : 0;
}

function getLastDayOfMonth_(year, month) {
  if (month < 1 || month > 12) throw httpError('잘못된 월입니다.');
  return new Date(year, month, 0).getDate();
}

function isValidDateParts_(year, month, day) {
  if (!year || !month || !day) return false;
  if (month < 1 || month > 12) return false;
  return day >= 1 && day <= getLastDayOfMonth_(year, month);
}

function makeDateKey_(year, month, day) {
  return Number(year) * 10000 + Number(month) * 100 + Number(day);
}

function createId_() {
  return crypto.randomUUID();
}

function nowIso_() {
  return new Date().toISOString();
}

function bytesToBase64Url_(bytes) {
  let binary = '';
  const view = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  for (let i = 0; i < view.length; i++) binary += String.fromCharCode(view[i]);
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

function base64UrlToBytes_(value) {
  const padded = value.replace(/-/g, '+').replace(/_/g, '/') + '==='.slice((value.length + 3) % 4);
  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

function constantTimeEquals_(a, b) {
  const left = String(a);
  const right = String(b);
  if (left.length !== right.length) return false;
  let result = 0;
  for (let i = 0; i < left.length; i++) result |= left.charCodeAt(i) ^ right.charCodeAt(i);
  return result === 0;
}

async function sha256Base64Url_(text) {
  const bytes = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(String(text)));
  return bytesToBase64Url_(bytes);
}

async function hmacSha256_(secret, message) {
  const key = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(String(secret)),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );
  const signature = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(String(message)));
  return bytesToBase64Url_(signature);
}

function validatePassword_(password, fieldName) {
  const value = cleanString(password);
  const name = fieldName || '비밀번호';
  if (!value) throw httpError(name + '를 입력하세요.');
  if (value.length < CONFIG.MIN_PASSWORD_LENGTH) {
    throw httpError(name + '는 ' + CONFIG.MIN_PASSWORD_LENGTH + '자 이상이어야 합니다.');
  }
  if (value.length > CONFIG.MAX_PASSWORD_LENGTH) {
    throw httpError(name + '는 ' + CONFIG.MAX_PASSWORD_LENGTH + '자 이하로 입력하세요.');
  }
  return value;
}

async function createPasswordCredential_(password) {
  const value = validatePassword_(password);
  const salt = createId_();
  return { salt, hash: await hashPassword_(value, salt) };
}

async function hashPassword_(password, salt) {
  return sha256Base64Url_(String(salt) + '\n' + String(password));
}

async function verifyPassword_(password, credential) {
  if (!credential || !credential.password_hash || !credential.password_salt) return false;
  const expected = await hashPassword_(cleanString(password), credential.password_salt);
  return constantTimeEquals_(credential.password_hash, expected);
}

function getTimeZone_(env) {
  return cleanString(env.ORDER_TIME_ZONE) || 'Asia/Seoul';
}

function getZonedParts_(timeZone, date = new Date()) {
  const formatter = new Intl.DateTimeFormat('en-CA', {
    timeZone,
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    hourCycle: 'h23'
  });
  const parts = Object.fromEntries(formatter.formatToParts(date).map((part) => [part.type, part.value]));
  return {
    year: Number(parts.year),
    month: Number(parts.month),
    day: Number(parts.day),
    hour: Number(parts.hour),
    minute: Number(parts.minute),
    second: Number(parts.second)
  };
}

function pad2_(value) {
  return String(value).padStart(2, '0');
}

function getCurrentYear_(env) {
  return getZonedParts_(getTimeZone_(env)).year;
}

function getOrderWindowStatus_(env) {
  const timeZone = getTimeZone_(env);
  const now = new Date();
  const parts = getZonedParts_(timeZone, now);
  const currentMinutes = parts.hour * 60 + parts.minute;
  const startHour = safeInteger_(env.ORDER_ENTRY_START_HOUR, 0);
  const cutoffHour = safeInteger_(env.ORDER_ENTRY_CUTOFF_HOUR, 24);
  const startMinutes = startHour * 60;
  const cutoffMinutes = cutoffHour * 60;
  const allowed = currentMinutes >= startMinutes && currentMinutes < cutoffMinutes;

  let message = '현재 발주 및 수정이 가능합니다.';
  if (currentMinutes < startMinutes) {
    message = '발주 가능 시간은 오전 ' + startHour + '시부터입니다.';
  } else if (currentMinutes >= cutoffMinutes) {
    message = '오늘 발주가 마감되었습니다. 다음 발주 가능 시간은 오전 ' + startHour + '시부터입니다.';
  }

  return {
    allowed,
    timeZone,
    currentTime: `${parts.year}-${pad2_(parts.month)}-${pad2_(parts.day)} ${pad2_(parts.hour)}:${pad2_(parts.minute)}:${pad2_(parts.second)}`,
    startTime: pad2_(startHour) + ':00',
    cutoffTime: pad2_(cutoffHour) + ':00',
    message
  };
}

function requireOrderWindowOpen_(env) {
  const status = getOrderWindowStatus_(env);
  if (!status.allowed) throw httpError(status.message);
  return status;
}

function getDb_(env) {
  if (!env.DB) throw httpError('D1 바인딩(DB)이 없습니다. wrangler.toml 을 확인하세요.', 500);
  return env.DB;
}

function getTokenSecret_(env) {
  return cleanString(env.TOKEN_SECRET) || 'change-me-in-production';
}

function publicOrigin_(c) {
  const url = new URL(c.req.url);
  return url.origin;
}

function jsonBody_(c) {
  return c.req.json().catch(() => ({}));
}

function bearerToken_(c) {
  const header = cleanString(c.req.header('Authorization'));
  if (header.toLowerCase().startsWith('bearer ')) return header.slice(7).trim();
  return cleanString(c.req.header('X-Auth-Token')) || cleanString(c.req.query('token'));
}

async function readJsonOrForm_(c) {
  const contentType = cleanString(c.req.header('Content-Type')).toLowerCase();
  if (contentType.includes('application/json')) return jsonBody_(c);
  if (contentType.includes('application/x-www-form-urlencoded') || contentType.includes('multipart/form-data')) {
    const form = await c.req.parseBody();
    return form || {};
  }
  return jsonBody_(c);
}

/* ==========================================================
 * Google Sheets 연동 모듈
 * ========================================================== */

const GOOGLE_SHEETS_SCOPE = 'https://www.googleapis.com/auth/spreadsheets';

async function getGoogleAccessToken_(env) {
  const clientEmail = cleanString(env.GOOGLE_SERVICE_ACCOUNT_EMAIL);
  const privateKeyPem = cleanString(env.GOOGLE_PRIVATE_KEY);
  if (!clientEmail || !privateKeyPem || clientEmail === 'your-service-account@your-project.iam.gserviceaccount.com') {
    return null;
  }

  const privateKey = privateKeyPem
    .replace(/-----BEGIN PRIVATE KEY-----/, '')
    .replace(/-----END PRIVATE KEY-----/, '')
    .replace(/\\n/g, '')    // 리터럴 '\n' (붙여넣기 그대로) 제거
    .replace(/\\r/g, '')    // 리터럴 '\r' 제거
    .replace(/\s+/g, '')    // 실제 줄바꿈/공백/탭 일괄 제거
    .trim();

  const header = { alg: 'RS256', typ: 'JWT' };
  const now = Math.floor(Date.now() / 1000);
  const claim = {
    iss: clientEmail,
    scope: GOOGLE_SHEETS_SCOPE,
    aud: 'https://oauth2.googleapis.com/token',
    exp: now + 3600,
    iat: now
  };

  const encodedHeader = bytesToBase64Url_(new TextEncoder().encode(JSON.stringify(header)));
  const encodedClaim = bytesToBase64Url_(new TextEncoder().encode(JSON.stringify(claim)));
  const signingInput = encodedHeader + '.' + encodedClaim;

  const privateKeyCrypto = await crypto.subtle.importKey(
    'pkcs8',
    base64UrlToBytes_(privateKey),
    { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
    false,
    ['sign']
  );
  const signature = await crypto.subtle.sign('RSASSA-PKCS1-v1_5', privateKeyCrypto, new TextEncoder().encode(signingInput));
  const jwt = signingInput + '.' + bytesToBase64Url_(signature);

  const tokenResp = await fetch('https://oauth2.googleapis.com/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer',
      assertion: jwt
    })
  });

  if (!tokenResp.ok) {
    const err = await tokenResp.text();
    console.error('[Google Sheets] 토큰 발급 실패:', err);
    return null;
  }

  const tokenData = await tokenResp.json();
  return tokenData.access_token;
}

async function appendRowToGoogleSheets_(env, sheetName, values) {
  const accessToken = await getGoogleAccessToken_(env);
  if (!accessToken) {
    console.warn('[Google Sheets] 인증 정보가 설정되지 않음. 시트 저장을 건너뜁니다.');
    return { success: false, reason: '인증 정보 없음' };
  }

  const spreadsheetId = cleanString(env.GOOGLE_SPREADSHEET_ID);
  const sheet = cleanString(env.GOOGLE_SHEET_NAME) || sheetName;
  if (!spreadsheetId || spreadsheetId === 'your-spreadsheet-id-here') {
    console.warn('[Google Sheets] SPREADSHEET_ID 미설정. 시트 저장을 건너뜁니다.');
    return { success: false, reason: 'SPREADSHEET_ID 미설정' };
  }

  const url = `https://sheets.googleapis.com/v4/spreadsheets/${spreadsheetId}/values/${encodeURIComponent(sheet)}:append?valueInputOption=USER_ENTERED&insertDataOption=INSERT_ROWS`;
  const response = await fetch(url, {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${accessToken}`,
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({
      values: [values]
    })
  });

  if (!response.ok) {
    const err = await response.text();
    console.error('[Google Sheets] 행 추가 실패:', response.status, err);
    return { success: false, reason: `API 오류: ${response.status}` };
  }

  return { success: true };
}

/* ==========================================================
 * 시스템 초기화 / 시드
 * ========================================================== */

async function ensureSystemReady_(env) {
  const db = getDb_(env);
  const admin = await db.prepare('SELECT id FROM admins WHERE username = ?').bind('admin').first();
  if (!admin) {
    const credential = await createPasswordCredential_(CONFIG.DEFAULT_PASSWORD);
    const now = nowIso_();
    await db.prepare(`
      INSERT OR IGNORE INTO admins (username, password_hash, password_salt, created_at, updated_at)
      VALUES (?, ?, ?, ?, ?)
    `).bind('admin', credential.hash, credential.salt, now, now).run();
  }

  const seeded = await db.prepare('SELECT value FROM settings WHERE key = ?').bind('seeded').first();
  if (!seeded) {
    await db.prepare('INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)').bind('seeded', nowIso_()).run();
    await db.prepare('INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)').bind('default_password', CONFIG.DEFAULT_PASSWORD).run();
  }
}

/* ==========================================================
 * 인증 / 토큰
 * ========================================================== */

async function createSignedToken_(env, role, clientName, label, accountContext) {
  const now = Date.now();
  const ttlDays = role === 'CLIENT' ? CONFIG.CLIENT_TOKEN_TTL_DAYS : CONFIG.ADMIN_TOKEN_TTL_DAYS;
  const context = accountContext || {};
  const tokenId = createId_();
  const payload = {
    id: tokenId,
    role,
    client: clientName || '',
    label: label || '',
    accountId: cleanString(context.accountId),
    loginId: cleanString(context.loginId),
    accountRegion: cleanString(context.accountRegion),
    iat: now,
    exp: now + ttlDays * 24 * 60 * 60 * 1000
  };
  const payloadPart = bytesToBase64Url_(new TextEncoder().encode(JSON.stringify(payload)));
  const signaturePart = await hmacSha256_(getTokenSecret_(env), payloadPart);
  return {
    tokenId,
    token: payloadPart + '.' + signaturePart,
    payload,
    role,
    client: clientName || '',
    label: label || '',
    accountId: payload.accountId,
    loginId: payload.loginId,
    accountRegion: payload.accountRegion
  };
}

async function registerToken_(env, tokenInfo) {
  const db = getDb_(env);
  await db.prepare(`
    INSERT INTO auth_tokens (
      token_id, role, client, label, account_id, login_id, account_region, created_at, expires_at, revoked_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, NULL)
  `).bind(
    tokenInfo.tokenId,
    tokenInfo.role,
    tokenInfo.client || '',
    tokenInfo.label || '',
    tokenInfo.accountId || '',
    tokenInfo.loginId || '',
    tokenInfo.accountRegion || '',
    new Date(tokenInfo.payload.iat).toISOString(),
    new Date(tokenInfo.payload.exp).toISOString()
  ).run();
}

async function findTokenRecordById_(env, tokenId) {
  return getDb_(env).prepare('SELECT * FROM auth_tokens WHERE token_id = ?').bind(tokenId).first();
}

async function verifyAccessToken_(env, token, expectedRole) {
  const rawToken = cleanString(token);
  if (!rawToken) throw httpError('접속 토큰이 없습니다.', 401);
  const parts = rawToken.split('.');
  if (parts.length !== 2) throw httpError('잘못된 토큰 형식입니다.', 401);
  const [payloadPart, signaturePart] = parts;
  const expectedSignature = await hmacSha256_(getTokenSecret_(env), payloadPart);
  if (!constantTimeEquals_(signaturePart, expectedSignature)) throw httpError('잘못된 토큰입니다.', 401);

  let payload;
  try {
    payload = JSON.parse(new TextDecoder().decode(base64UrlToBytes_(payloadPart)));
  } catch (error) {
    throw httpError('토큰 정보를 읽을 수 없습니다.', 401);
  }
  if (!payload || !payload.id || !payload.role || !payload.exp) throw httpError('잘못된 토큰 정보입니다.', 401);
  if (!Number.isFinite(Number(payload.exp)) || Number(payload.exp) <= Date.now()) {
    throw httpError('만료된 접속 토큰입니다.', 401);
  }
  if (expectedRole && payload.role !== expectedRole) {
    throw httpError('해당 페이지에 사용할 수 없는 토큰입니다.', 403);
  }

  const record = await findTokenRecordById_(env, payload.id);
  if (!record) throw httpError('등록되지 않은 토큰입니다.', 401);
  if (record.role !== payload.role) throw httpError('토큰 권한 정보가 일치하지 않습니다.', 401);
  if (record.revoked_at) throw httpError('관리자에 의해 폐기된 토큰입니다. 관리자에게 문의하세요.', 401);
  const storedExpiresAt = Date.parse(record.expires_at);
  if (Number.isFinite(storedExpiresAt) && storedExpiresAt <= Date.now()) {
    throw httpError('만료된 접속 토큰입니다.', 401);
  }

  return {
    tokenId: payload.id,
    role: payload.role,
    client: record.client || '',
    label: record.label || payload.label || '',
    accountId: record.account_id || cleanString(payload.accountId),
    loginId: record.login_id || cleanString(payload.loginId),
    accountRegion: record.account_region || cleanString(payload.accountRegion),
    expiresAt: new Date(Number(payload.exp)).toISOString()
  };
}

async function requireAdminToken_(env, token) {
  return verifyAccessToken_(env, token, 'ADMIN');
}

async function requireClientToken_(env, token) {
  const session = await verifyAccessToken_(env, token, 'CLIENT');
  if (!session.client) throw httpError('거래처 정보가 없는 클라이언트 토큰입니다.', 401);
  // 마스터 거래처(지역계정이 아닌 계정)는 지역계정 점유 지역을 차단 목록으로 주입한다.
  if (!session.accountRegion && !session.accountId) {
    session.blockedRegions = await getMasterBlockedRegions_(env, session.client);
  } else {
    session.blockedRegions = [];
  }
  return session;
}

async function loginAttemptKey_(role, identity) {
  return 'LOGIN_FAIL_' + await sha256Base64Url_(String(role) + ':' + cleanString(identity).toLowerCase());
}

async function assertLoginAllowed_(env, key) {
  const row = await getDb_(env).prepare('SELECT fail_count, updated_at FROM login_attempts WHERE attempt_key = ?').bind(key).first();
  if (!row) return;
  const updatedAt = Date.parse(row.updated_at);
  if (!Number.isFinite(updatedAt) || Date.now() - updatedAt > CONFIG.LOGIN_FAIL_WINDOW_MS) {
    await getDb_(env).prepare('DELETE FROM login_attempts WHERE attempt_key = ?').bind(key).run();
    return;
  }
  if (Number(row.fail_count) >= CONFIG.LOGIN_FAIL_LIMIT) {
    throw httpError('로그인 시도 횟수를 초과했습니다. 10분 후 다시 시도하세요.', 429);
  }
}

async function recordLoginFailure_(env, key) {
  const now = nowIso_();
  const row = await getDb_(env).prepare('SELECT fail_count, updated_at FROM login_attempts WHERE attempt_key = ?').bind(key).first();
  if (!row) {
    await getDb_(env).prepare('INSERT INTO login_attempts (attempt_key, fail_count, updated_at) VALUES (?, 1, ?)').bind(key, now).run();
    return;
  }
  const updatedAt = Date.parse(row.updated_at);
  const count = (!Number.isFinite(updatedAt) || Date.now() - updatedAt > CONFIG.LOGIN_FAIL_WINDOW_MS)
    ? 1
    : Number(row.fail_count) + 1;
  await getDb_(env).prepare('UPDATE login_attempts SET fail_count = ?, updated_at = ? WHERE attempt_key = ?').bind(count, now, key).run();
}

async function clearLoginFailures_(env, key) {
  await getDb_(env).prepare('DELETE FROM login_attempts WHERE attempt_key = ?').bind(key).run();
}

async function revokeTokenById_(env, tokenId) {
  const id = cleanString(tokenId);
  if (!id) return false;
  const record = await findTokenRecordById_(env, id);
  if (!record || record.revoked_at) return false;
  await getDb_(env).prepare('UPDATE auth_tokens SET revoked_at = ? WHERE token_id = ?').bind(nowIso_(), id).run();
  return true;
}

async function revokeActiveClientTokens_(env, clientName, accountId) {
  const now = nowIso_();
  if (accountId) {
    await getDb_(env).prepare(`
      UPDATE auth_tokens
      SET revoked_at = ?
      WHERE role = 'CLIENT' AND account_id = ? AND revoked_at IS NULL
    `).bind(now, cleanString(accountId)).run();
    return;
  }
  await getDb_(env).prepare(`
    UPDATE auth_tokens
    SET revoked_at = ?
    WHERE role = 'CLIENT' AND client = ? AND IFNULL(account_id, '') = '' AND revoked_at IS NULL
  `).bind(now, cleanString(clientName)).run();
}

async function cleanupAuthTokens_(env) {
  const cutoff = new Date(Date.now() - CONFIG.AUTH_TOKEN_RETENTION_DAYS * 24 * 60 * 60 * 1000).toISOString();
  const result = await getDb_(env).prepare(`
    DELETE FROM auth_tokens
    WHERE (revoked_at IS NOT NULL AND revoked_at <= ?)
       OR (revoked_at IS NULL AND expires_at <= ?)
  `).bind(cutoff, cutoff).run();
  return { success: true, removedCount: result.meta?.changes || 0 };
}

/* ==========================================================
 * 거래처 / 지역 계정
 * ========================================================== */

function mapClientRow_(row) {
  if (!row) return null;
  return {
    id: row.id,
    client: row.name,
    password_hash: row.password_hash,
    password_salt: row.password_salt,
    label: row.label || '',
    active: Number(row.active) === 1,
    allowedRegions: parseAllowedRegions_(row.allowed_regions),
    created_at: row.created_at,
    updated_at: row.updated_at
  };
}

function mapAccountRow_(row) {
  if (!row) return null;
  return {
    id: row.id,
    accountId: row.account_id,
    clientId: row.client_id,
    client: row.client_name,
    password_hash: row.password_hash,
    password_salt: row.password_salt,
    label: row.label || '',
    active: Number(row.active) === 1,
    allowedRegions: [normalizeRegionKey_(row.region)].filter(Boolean),
    accountIdValue: row.account_id,
    loginId: row.login_id,
    accountRegion: row.region,
    created_at: row.created_at,
    updated_at: row.updated_at
  };
}

async function findClientByName_(env, clientName) {
  const row = await getDb_(env).prepare('SELECT * FROM clients WHERE name = ?').bind(cleanString(clientName)).first();
  return mapClientRow_(row);
}

async function findAccountById_(env, accountId) {
  const row = await getDb_(env).prepare('SELECT * FROM client_accounts WHERE account_id = ?').bind(cleanString(accountId)).first();
  return mapAccountRow_(row);
}

async function findAccountByLogin_(env, clientName, loginId, region) {
  const row = await getDb_(env).prepare(`
    SELECT * FROM client_accounts
    WHERE client_name = ? AND login_id = ? AND region = ?
  `).bind(cleanString(clientName), cleanString(loginId), cleanString(region)).first();
  return mapAccountRow_(row);
}

function sessionCredential_(clientOrAccount) {
  return {
    client: clientOrAccount.client,
    label: clientOrAccount.label,
    accountId: clientOrAccount.accountId || '',
    loginId: clientOrAccount.loginId || '',
    accountRegion: clientOrAccount.accountRegion || '',
    allowedRegions: clientOrAccount.allowedRegions || [],
    blockedRegions: clientOrAccount.blockedRegions || []
  };
}

async function getMasterBlockedRegions_(env, clientName) {
  // 지역계정(client_accounts)이 점유한 지역은 마스터 거래처가 볼 수 없도록
  // 차단 지역 목록으로 반환한다.
  const { results: accountRows } = await getDb_(env).prepare(
    'SELECT region FROM client_accounts WHERE client_name = ? AND active = 1'
  ).bind(cleanString(clientName)).all();
  return uniqueArray_((accountRows || [])
    .map((row) => normalizeRegionKey_(row.region))
    .filter(Boolean));
}

async function getClientRegionPolicy_(env, sessionOrClient) {
  if (sessionOrClient && typeof sessionOrClient === 'object') {
    const accountRegion = normalizeRegionKey_(sessionOrClient.accountRegion || '');
    if (accountRegion) return [accountRegion];
    if (sessionOrClient.accountId) {
      const account = await findAccountById_(env, sessionOrClient.accountId);
      if (account) return account.allowedRegions || [];
    }
    return getClientRegionPolicy_(env, sessionOrClient.client || '');
  }
  const credential = await findClientByName_(env, sessionOrClient);
  return credential ? credential.allowedRegions : [];
}

// 마스터 거래처 세션에 차단 지역을 주입한다. (지역계정 점유 지역)
async function buildMasterSession_(env, clientCredential) {
  const blockedRegions = await getMasterBlockedRegions_(env, clientCredential.client);
  return {
    client: clientCredential.client,
    label: clientCredential.label,
    accountId: '',
    loginId: '',
    accountRegion: '',
    allowedRegions: clientCredential.allowedRegions || [],
    blockedRegions
  };
}

// 세션의 허용/차단 규칙을 종합하여 특정 지역 사용이 가능한지 판정한다.
function isSessionRegionAllowed_(session, region) {
  const target = normalizeRegionKey_(region);
  if (!target) return false;
  if (session.accountRegion) return normalizeRegionKey_(session.accountRegion) === target;
  const blocked = Array.isArray(session.blockedRegions) ? session.blockedRegions : [];
  if (blocked.includes(target)) return false;
  return isRegionAllowed_(session.allowedRegions || [], region);
}

async function requireClientRegionAllowed_(env, session, region) {
  const target = normalizeRegionKey_(region);
  if (!target) throw httpError('지역을 입력하세요.');
  if (session.accountRegion) {
    if (normalizeRegionKey_(session.accountRegion) !== target) {
      throw httpError('현재 로그인 계정은 [' + session.accountRegion + '] 지역만 사용할 수 있습니다.');
    }
    return [normalizeRegionKey_(session.accountRegion)];
  }
  if (!isSessionRegionAllowed_(session, region)) {
    throw httpError('허용되지 않은 지역입니다. 관리자에게 등록된 허용 지역만 발주할 수 있습니다.');
  }
  if (Array.isArray(session.allowedRegions) && session.allowedRegions.length > 0) {
    return session.allowedRegions.filter((item) => !(session.blockedRegions || []).includes(item));
  }
  return [];
}

async function createClient_(env, clientName, label, password, allowedRegions) {
  const client = cleanString(clientName);
  if (!client) throw httpError('거래처명을 입력하세요.');
  if (client.length > 100) throw httpError('거래처명은 100자 이하로 입력하세요.');
  const existing = await findClientByName_(env, client);
  if (existing) throw httpError('이미 등록된 거래처입니다. 관리자에게 비밀번호 재설정을 요청하세요.');
  const credential = await createPasswordCredential_(password || CONFIG.DEFAULT_PASSWORD);
  const now = nowIso_();
  const regions = parseAllowedRegions_(allowedRegions).join(',');
  await getDb_(env).prepare(`
    INSERT INTO clients (name, password_hash, password_salt, label, active, allowed_regions, created_at, updated_at)
    VALUES (?, ?, ?, ?, 1, ?, ?, ?)
  `).bind(client, credential.hash, credential.salt, cleanString(label), regions, now, now).run();
  return findClientByName_(env, client);
}

async function createRegionalAccount_(env, clientName, region, loginId, label, password) {
  const client = cleanString(clientName);
  const cleanRegion = cleanString(region);
  const cleanLoginId = cleanString(loginId);
  if (!client) throw httpError('거래처명을 입력하세요.');
  if (!cleanRegion) throw httpError('계정 지역을 입력하세요.');
  if (!cleanLoginId) throw httpError('로그인 ID를 입력하세요.');
  if (cleanRegion.length > 50) throw httpError('계정 지역은 50자 이하로 입력하세요.');
  if (cleanLoginId.length > 100) throw httpError('로그인 ID는 100자 이하로 입력하세요.');
  validatePassword_(password || CONFIG.DEFAULT_PASSWORD);

  let parent = await findClientByName_(env, client);
  if (!parent) {
    parent = await createClient_(env, client, label || client, password || CONFIG.DEFAULT_PASSWORD, cleanRegion);
  }
  if (await findAccountByLogin_(env, client, cleanLoginId, cleanRegion)) {
    throw httpError('같은 거래처/지역/로그인 ID 계정이 이미 존재합니다.');
  }

  const credential = await createPasswordCredential_(password || CONFIG.DEFAULT_PASSWORD);
  const now = nowIso_();
  const accountId = 'RA-' + createId_().replace(/-/g, '').slice(0, 14);
  await getDb_(env).prepare(`
    INSERT INTO client_accounts (
      account_id, client_id, client_name, region, login_id, password_hash, password_salt, label, active, created_at, updated_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?)
  `).bind(
    accountId,
    parent.id,
    client,
    cleanRegion,
    cleanLoginId,
    credential.hash,
    credential.salt,
    cleanString(label) || (client + ' ' + cleanRegion),
    now,
    now
  ).run();
  return findAccountById_(env, accountId);
}

async function updatePasswordHash_(env, table, idColumn, idValue, credential) {
  const now = nowIso_();
  await getDb_(env).prepare(`
    UPDATE ${table}
    SET password_hash = ?, password_salt = ?, updated_at = ?
    WHERE ${idColumn} = ?
  `).bind(credential.hash, credential.salt, now, idValue).run();
}

/* ==========================================================
 * 품목 / 유종 매칭
 * ========================================================== */

async function getMatchingData_(env) {
  const { results } = await getDb_(env).prepare('SELECT product, product_key, oil, restricted_clients FROM oil_matching').all();
  const oilMap = {};
  const clientMap = {};
  const displayMap = {};
  (results || []).forEach((row) => {
    const key = row.product_key || normalizeProductKey_(row.product);
    oilMap[key] = cleanString(row.oil);
    displayMap[key] = cleanString(row.product);
    clientMap[key] = cleanString(row.restricted_clients)
      ? cleanString(row.restricted_clients).split(',').map((item) => item.trim()).filter(Boolean)
      : [];
  });
  return { oilMap, clientMap, displayMap };
}

function resolveProductMatch_(data, product, clientName) {
  const cleanProduct = cleanString(product);
  const key = normalizeProductKey_(cleanProduct);
  if (!Object.prototype.hasOwnProperty.call(data.oilMap, key)) {
    return {
      allowed: true,
      registered: false,
      displayName: cleanProduct,
      oilName: '미등록'
    };
  }
  const allowed = data.clientMap[key] || [];
  if (allowed.length > 0 && !allowed.includes(clientName)) {
    return { allowed: false, registered: true, displayName: cleanProduct, oilName: '' };
  }
  return {
    allowed: true,
    registered: true,
    displayName: data.displayMap[key] || cleanProduct,
    oilName: cleanString(data.oilMap[key]) || '미등록'
  };
}

async function getMatchingDataForClient_(env, session) {
  const data = await getMatchingData_(env);
  const products = Object.keys(data.oilMap)
    .filter((key) => {
      const allowed = data.clientMap[key] || [];
      return allowed.length === 0 || allowed.includes(session.client);
    })
    .map((key) => ({
      name: data.displayMap[key] || key,
      oil: data.oilMap[key] || '미등록'
    }))
    .sort((a, b) => a.name.localeCompare(b.name, 'ko'));
  return { client: session.client, products };
}

/* ==========================================================
 * 발주
 * ========================================================== */

function formatOrderDate_(year, month, day) {
  return `${year}년 ${month}월 ${day}일`;
}

function mapOrderRow_(row) {
  if (!row) return null;
  return {
    recordId: row.record_id,
    year: Number(row.year),
    month: Number(row.month),
    day: Number(row.day),
    date: formatOrderDate_(row.year, row.month, row.day),
    dateNum: Number(row.date_num),
    client: row.client,
    region: row.region,
    product: row.product,
    oil: row.oil,
    qty: Number(row.qty),
    editCount: Number(row.edit_count || 0),
    isConfirmed: Number(row.confirmed) === 1
  };
}

function normalizePeriod_(env, startM, startD, endM, endD) {
  const year = getCurrentYear_(env);
  const startMonth = parseMonth_(startM);
  const startDay = parseDay_(startD);
  const endMonth = parseMonth_(endM);
  let endDay = parseDay_(endD);

  if ((startMonth && !startDay) || (!startMonth && startDay)) {
    throw httpError('시작일의 월과 일을 모두 입력하세요.');
  }
  if (endMonth && !endDay) endDay = getLastDayOfMonth_(year, endMonth);
  if (!endMonth && endDay) throw httpError('종료일의 월과 일을 모두 입력하세요.');

  let startValue = year * 10000 + 101;
  let endValue = year * 10000 + 1231;
  if (startMonth && startDay) {
    if (!isValidDateParts_(year, startMonth, startDay)) throw httpError('올바르지 않은 시작 날짜입니다.');
    startValue = makeDateKey_(year, startMonth, startDay);
  }
  if (endMonth && endDay) {
    if (!isValidDateParts_(year, endMonth, endDay)) throw httpError('올바르지 않은 종료 날짜입니다.');
    endValue = makeDateKey_(year, endMonth, endDay);
  }
  if (startValue > endValue) throw httpError('시작일이 종료일보다 늦습니다.');
  return { year, startValue, endValue };
}

async function getOrdersByPeriod_(env, startM, startD, endM, endD) {
  const period = normalizePeriod_(env, startM, startD, endM, endD);
  const { results } = await getDb_(env).prepare(`
    SELECT * FROM orders
    WHERE date_num >= ? AND date_num <= ?
    ORDER BY date_num ASC, id ASC
  `).bind(period.startValue, period.endValue).all();
  return (results || []).map(mapOrderRow_);
}

async function saveOrderData_(env, session, orderDataList) {
  requireOrderWindowOpen_(env);
  if (!Array.isArray(orderDataList) || orderDataList.length === 0) throw httpError('저장할 발주가 없습니다.');
  if (orderDataList.length > CONFIG.MAX_SAVE_ROWS) {
    throw httpError(`한 번에 최대 ${CONFIG.MAX_SAVE_ROWS}건까지만 저장할 수 있습니다.`);
  }

  const currentYear = getCurrentYear_(env);
  const matching = await getMatchingData_(env);
  const invalidProducts = [];
  const prepared = [];

  for (const item of orderDataList) {
    const raw = Array.isArray(item) ? {
      date: item[0],
      client: item[1],
      region: item[2],
      product: item[3],
      oil: item[4],
      qty: item[5]
    } : item;

    const rawDate = cleanString(raw.date);
    const region = cleanString(raw.region);
    const product = cleanString(raw.product);
    const quantity = Number(raw.qty);
    const numbers = rawDate.match(/\d+/g) || [];
    if (numbers.length < 3) throw httpError('날짜 형식이 잘못되었습니다.');
    const year = Number(numbers[0]);
    const month = Number(numbers[1]);
    const day = Number(numbers[2]);
    if (year !== currentYear) throw httpError(`${currentYear}년도 발주만 입력할 수 있습니다.`);
    if (!isValidDateParts_(year, month, day)) throw httpError('올바르지 않은 날짜입니다.');
    if (!region) throw httpError('지역을 입력하세요.');
    if (region.length > 50) throw httpError('지역은 50자 이하로 입력하세요.');
    await requireClientRegionAllowed_(env, session, region);
    if (!product) throw httpError('품명을 입력하세요.');
    if (product.length > 100) throw httpError('품명은 100자 이하로 입력하세요.');
    if (!Number.isInteger(quantity) || quantity <= 0) throw httpError('수량은 1 이상의 정수여야 합니다.');
    if (quantity > CONFIG.MAX_QTY_PER_ORDER) {
      throw httpError(`1회 발주 수량은 ${CONFIG.MAX_QTY_PER_ORDER}개를 초과할 수 없습니다.`);
    }

    const matched = resolveProductMatch_(matching, product, session.client);
    if (!matched.allowed) invalidProducts.push(cleanString(product));
    else {
      prepared.push({
        recordId: createId_(),
        year,
        month,
        day,
        dateNum: makeDateKey_(year, month, day),
        client: session.client,
        region,
        product: matched.displayName,
        oil: matched.oilName,
        qty: quantity
      });
    }
  }

  if (invalidProducts.length > 0) {
    throw httpError(`다음 품목은 해당 거래처에서 사용할 수 없습니다.\n\n[ ${uniqueArray_(invalidProducts).join(', ')} ]`);
  }

  const now = nowIso_();
  const statements = prepared.map((row) => getDb_(env).prepare(`
    INSERT INTO orders (
      record_id, year, month, day, date_num, client, region, product, oil, qty, edit_count, confirmed, created_at, updated_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, 0, ?, ?)
  `).bind(
    row.recordId, row.year, row.month, row.day, row.dateNum, row.client, row.region, row.product, row.oil, row.qty, now, now
  ));
  await getDb_(env).batch(statements);

  // Google Sheets에 비동기로 추가 (실패해도 D1 저장은 유지)
  try {
    const sheetName = cleanString(env.GOOGLE_SHEET_NAME) || '발주_DB';
    for (const row of prepared) {
      const values = [
        row.year + '년',
        row.month + '월',
        row.day + '일',
        row.client,
        row.region,
        row.product,
        row.oil,
        String(row.qty),
        now
      ];
      await appendRowToGoogleSheets_(env, sheetName, values);
    }
  } catch (gsError) {
    console.error('[Google Sheets] 연동 중 오류 발생 (D1 저장은 완료됨):', gsError);
    // Google Sheets 실패해도 D1 저장은 성공으로 처리
  }

  return { success: true, count: prepared.length };
}

async function findOrderById_(env, recordId) {
  const row = await getDb_(env).prepare('SELECT * FROM orders WHERE record_id = ?').bind(cleanString(recordId)).first();
  return mapOrderRow_(row);
}

/* ==========================================================
 * 엑셀 (최소 XLSX)
 * ========================================================== */

function crc32_(bytes) {
  let crc = 0xFFFFFFFF;
  for (let i = 0; i < bytes.length; i++) {
    crc ^= bytes[i];
    for (let j = 0; j < 8; j++) crc = (crc >>> 1) ^ (crc & 1 ? 0xEDB88320 : 0);
  }
  return (crc ^ 0xFFFFFFFF) >>> 0;
}

function concatBytes_(chunks) {
  const total = chunks.reduce((sum, chunk) => sum + chunk.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  chunks.forEach((chunk) => {
    out.set(chunk, offset);
    offset += chunk.length;
  });
  return out;
}

function u16_(value) {
  const buffer = new Uint8Array(2);
  buffer[0] = value & 255;
  buffer[1] = (value >>> 8) & 255;
  return buffer;
}

function u32_(value) {
  const buffer = new Uint8Array(4);
  buffer[0] = value & 255;
  buffer[1] = (value >>> 8) & 255;
  buffer[2] = (value >>> 16) & 255;
  buffer[3] = (value >>> 24) & 255;
  return buffer;
}

function zipStore_(files) {
  const encoder = new TextEncoder();
  const locals = [];
  const centrals = [];
  let offset = 0;
  files.forEach((file) => {
    const nameBytes = encoder.encode(file.name);
    const data = typeof file.data === 'string' ? encoder.encode(file.data) : file.data;
    const crc = crc32_(data);
    const local = concatBytes_([
      u32_(0x04034b50), u16_(20), u16_(0), u16_(0), u16_(0), u16_(0),
      u32_(crc), u32_(data.length), u32_(data.length), u16_(nameBytes.length), u16_(0),
      nameBytes, data
    ]);
    const central = concatBytes_([
      u32_(0x02014b50), u16_(20), u16_(20), u16_(0), u16_(0), u16_(0), u16_(0),
      u32_(crc), u32_(data.length), u32_(data.length), u16_(nameBytes.length), u16_(0), u16_(0),
      u16_(0), u16_(0), u32_(0), u32_(offset), nameBytes
    ]);
    locals.push(local);
    centrals.push(central);
    offset += local.length;
  });
  const centralDir = concatBytes_(centrals);
  const end = concatBytes_([
    u32_(0x06054b50), u16_(0), u16_(0), u16_(files.length), u16_(files.length),
    u32_(centralDir.length), u32_(offset), u16_(0)
  ]);
  return concatBytes_([...locals, centralDir, end]);
}

function xmlEscape_(value) {
  return String(value ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

function buildXlsx_(headers, rows) {
  const sheetRows = [headers, ...rows].map((row, rowIndex) => {
    const cells = row.map((value, colIndex) => {
      const ref = String.fromCharCode(65 + colIndex) + (rowIndex + 1);
      const numeric = typeof value === 'number';
      return numeric
        ? `<c r="${ref}"><v>${value}</v></c>`
        : `<c r="${ref}" t="inlineStr"><is><t>${xmlEscape_(value)}</t></is></c>`;
    }).join('');
    return `<row r="${rowIndex + 1}">${cells}</row>`;
  }).join('');

  const sheet = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">
  <sheetData>${sheetRows}</sheetData>
</worksheet>`;
  const workbook = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">
  <sheets><sheet name="확정발주" sheetId="1" r:id="rId1"/></sheets>
</workbook>`;
  const rels = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/>
</Relationships>`;
  const workbookRels = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet1.xml"/>
</Relationships>`;
  const contentTypes = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
  <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
  <Default Extension="xml" ContentType="application/xml"/>
  <Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>
  <Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>
</Types>`;

  const zip = zipStore_([
    { name: '[Content_Types].xml', data: contentTypes },
    { name: '_rels/.rels', data: rels },
    { name: 'xl/workbook.xml', data: workbook },
    { name: 'xl/_rels/workbook.xml.rels', data: workbookRels },
    { name: 'xl/worksheets/sheet1.xml', data: sheet }
  ]);
  return bytesToBase64Url_(zip).replace(/-/g, '+').replace(/_/g, '/');
}

function padBase64_(value) {
  return value + '==='.slice((value.length + 3) % 4);
}

/* ==========================================================
 * API 라우트
 * ========================================================== */

app.get('/api/health', (c) => c.json({ ok: true, service: 'order-system' }));
app.get('/api/order-window', (c) => c.json(getOrderWindowStatus_(c.env)));

app.post('/api/auth/client', async (c) => {
  const body = await readJsonOrForm_(c);
  const targetClient = cleanString(body.clientName || body.client);
  const targetPassword = validatePassword_(body.secretCode || body.password);
  const targetLoginId = cleanString(body.loginId);
  const targetRegion = cleanString(body.accountRegion || body.region);
  const identity = [targetClient, targetLoginId || 'LEGACY', targetRegion || 'ALL'].join('|');
  const attemptKey = await loginAttemptKey_('CLIENT', identity);
  await assertLoginAllowed_(c.env, attemptKey);

  let credential = null;
  if (targetLoginId || targetRegion) {
    if (!targetLoginId || !targetRegion) throw httpError('지역별 계정은 지역과 로그인 ID를 모두 입력해야 합니다.');
    credential = await findAccountByLogin_(c.env, targetClient, targetLoginId, targetRegion);
  } else {
    // 마스터 거래처는 거래처명 + 비밀번호로 그대로 로그인할 수 있다.
    // 지역별 계정이 존재한다고 해서 마스터 거래처 로그인을 막지 않는다.
    credential = await findClientByName_(c.env, targetClient);
  }

  if (!credential || !credential.active || !(await verifyPassword_(targetPassword, credential))) {
    await recordLoginFailure_(c.env, attemptKey);
    throw httpError('거래처명, 지역, 로그인 ID 또는 비밀번호가 올바르지 않습니다.', 401);
  }

  await clearLoginFailures_(c.env, attemptKey);
  // 지역계정이면 그 지역으로 고정, 마스터 거래처면 지역계정 점유 지역을 차단한다.
  const isRegional = !!credential.accountRegion || !!credential.accountId;
  const sessionCred = isRegional
    ? sessionCredential_(credential)
    : await buildMasterSession_(c.env, credential);
  const tokenInfo = await createSignedToken_(c.env, 'CLIENT', sessionCred.client, sessionCred.label, sessionCred);
  await registerToken_(c.env, tokenInfo);
  const allowedRegions = await getClientRegionPolicy_(c.env, sessionCred);
  return c.json({
    success: true,
    token: tokenInfo.token,
    client: sessionCred.client,
    label: sessionCred.label,
    accountId: sessionCred.accountId,
    loginId: sessionCred.loginId,
    accountRegion: sessionCred.accountRegion,
    allowedRegions,
    blockedRegions: sessionCred.blockedRegions || [],
    expiresAt: new Date(tokenInfo.payload.exp).toISOString()
  });
});

app.post('/api/auth/admin', async (c) => {
  const body = await readJsonOrForm_(c);
  const adminCode = cleanString(body.adminCode || body.password);
  const attemptKey = await loginAttemptKey_('ADMIN', 'GLOBAL');
  await assertLoginAllowed_(c.env, attemptKey);
  const admin = await getDb_(c.env).prepare('SELECT * FROM admins WHERE username = ?').bind('admin').first();
  if (!admin || !(await verifyPassword_(adminCode, admin))) {
    await recordLoginFailure_(c.env, attemptKey);
    throw httpError('관리자 비밀코드가 올바르지 않습니다.', 401);
  }
  await clearLoginFailures_(c.env, attemptKey);
  const tokenInfo = await createSignedToken_(c.env, 'ADMIN', '', '로그인 화면 인증');
  await registerToken_(c.env, tokenInfo);
  return c.json({ success: true, token: tokenInfo.token, expiresAt: new Date(tokenInfo.payload.exp).toISOString() });
});

app.post('/api/auth/logout', async (c) => {
  const token = bearerToken_(c);
  try {
    const session = await verifyAccessToken_(c.env, token);
    await revokeTokenById_(c.env, session.tokenId);
  } catch (error) {}
  return c.json({ success: true });
});

app.get('/api/session', async (c) => {
  const session = await verifyAccessToken_(c.env, bearerToken_(c));
  // 마스터 거래처(지역계정 아님)는 지역계정 점유 지역을 차단 목록으로 다시 계산해 주입한다.
  let blockedRegions = [];
  if (session.role === 'CLIENT' && !session.accountId && !session.accountRegion) {
    blockedRegions = await getMasterBlockedRegions_(c.env, session.client);
  }
  const allowedRegions = session.role === 'CLIENT' ? await getClientRegionPolicy_(c.env, session) : [];
  return c.json({
    success: true,
    role: session.role,
    client: session.client,
    label: session.label,
    accountId: session.accountId,
    loginId: session.loginId,
    accountRegion: session.accountRegion,
    allowedRegions,
    blockedRegions,
    expiresAt: session.expiresAt,
    orderWindow: getOrderWindowStatus_(c.env)
  });
});

app.get('/api/client/products', async (c) => {
  const session = await requireClientToken_(c.env, bearerToken_(c));
  return c.json(await getMatchingDataForClient_(c.env, session));
});

app.get('/api/client/orders', async (c) => {
  const session = await requireClientToken_(c.env, bearerToken_(c));
  const regionValue = cleanString(c.req.query('region'));
  const monthValue = parseMonth_(c.req.query('month'));
  const dayValue = parseDay_(c.req.query('day'));
  const { results } = await getDb_(c.env).prepare('SELECT * FROM orders WHERE client = ? ORDER BY date_num ASC, id ASC').bind(session.client).all();
  const orders = (results || []).map(mapOrderRow_).filter((order) => {
    if (!isSessionRegionAllowed_(session, order.region)) return false;
    if (regionValue && regionValue !== '전체 지역' && regionValue !== '비우면 전체 조회' && order.region !== regionValue) return false;
    if (monthValue && order.month !== monthValue) return false;
    if (dayValue && order.day !== dayValue) return false;
    return true;
  });
  return c.json(orders);
});

app.post('/api/client/orders', async (c) => {
  const session = await requireClientToken_(c.env, bearerToken_(c));
  const body = await readJsonOrForm_(c);
  const list = body.orders || body.orderDataList || body;
  return c.json(await saveOrderData_(c.env, session, list));
});

app.patch('/api/client/orders/:id', async (c) => {
  const session = await requireClientToken_(c.env, bearerToken_(c));
  requireOrderWindowOpen_(c.env);
  const body = await readJsonOrForm_(c);
  const quantity = Number(body.qty ?? body.newQty);
  if (!Number.isInteger(quantity) || quantity <= 0 || quantity > CONFIG.MAX_QTY_PER_ORDER) {
    return c.json({ success: false, message: '수량은 1 이상 10,000 이하의 정수여야 합니다.' });
  }
  const order = await findOrderById_(c.env, c.req.param('id'));
  if (!order) return c.json({ success: false, message: '발주 내역을 찾을 수 없습니다.' });
  if (order.client !== session.client) return c.json({ success: false, message: '본인 내역만 수정 가능합니다.' });
  if (!isSessionRegionAllowed_(session, order.region)) {
    return c.json({ success: false, message: '현재 거래처에 허용되지 않은 지역의 내역은 수정할 수 없습니다.' });
  }
  if (order.isConfirmed) return c.json({ success: false, message: '확정된 내역은 수정할 수 없습니다.' });
  if (order.editCount >= CONFIG.MAX_EDIT_COUNT) return c.json({ success: false, message: '수정 횟수(2회)를 초과했습니다.' });
  await getDb_(c.env).prepare('UPDATE orders SET qty = ?, edit_count = ?, updated_at = ? WHERE record_id = ?')
    .bind(quantity, order.editCount + 1, nowIso_(), order.recordId).run();
  return c.json({ success: true });
});

app.delete('/api/client/orders/:id', async (c) => {
  const session = await requireClientToken_(c.env, bearerToken_(c));
  requireOrderWindowOpen_(c.env);
  const order = await findOrderById_(c.env, c.req.param('id'));
  if (!order) return c.json({ success: false, message: '발주 내역을 찾을 수 없습니다.' });
  if (order.client !== session.client) return c.json({ success: false, message: '본인 내역만 삭제 가능합니다.' });
  if (!isSessionRegionAllowed_(session, order.region)) {
    return c.json({ success: false, message: '현재 거래처에 허용되지 않은 지역의 내역은 삭제할 수 없습니다.' });
  }
  if (order.isConfirmed) return c.json({ success: false, message: '확정된 내역은 삭제할 수 없습니다.' });
  await getDb_(c.env).prepare('DELETE FROM orders WHERE record_id = ?').bind(order.recordId).run();
  return c.json({ success: true });
});

app.post('/api/client/password', async (c) => {
  const session = await requireClientToken_(c.env, bearerToken_(c));
  const body = await readJsonOrForm_(c);
  const current = validatePassword_(body.currentPassword, '현재 비밀번호');
  const next = validatePassword_(body.newPassword, '새 비밀번호');
  if (current === next) throw httpError('현재 비밀번호와 다른 비밀번호를 입력하세요.');
  const credential = session.accountId
    ? await findAccountById_(c.env, session.accountId)
    : await findClientByName_(c.env, session.client);
  if (!credential || !credential.active || !(await verifyPassword_(current, credential))) {
    throw httpError('현재 비밀번호가 올바르지 않습니다.');
  }
  const updatedCred = await createPasswordCredential_(next);
  if (session.accountId) {
    await updatePasswordHash_(c.env, 'client_accounts', 'account_id', session.accountId, updatedCred);
  } else {
    await updatePasswordHash_(c.env, 'clients', 'name', session.client, updatedCred);
  }
  await revokeActiveClientTokens_(c.env, session.client, session.accountId);
  const fresh = session.accountId
    ? await findAccountById_(c.env, session.accountId)
    : await findClientByName_(c.env, session.client);
  const sessionCred = sessionCredential_(fresh);
  const tokenInfo = await createSignedToken_(c.env, 'CLIENT', sessionCred.client, sessionCred.label, sessionCred);
  await registerToken_(c.env, tokenInfo);
  return c.json({
    success: true,
    token: tokenInfo.token,
    client: sessionCred.client,
    label: sessionCred.label,
    accountId: sessionCred.accountId,
    loginId: sessionCred.loginId,
    accountRegion: sessionCred.accountRegion,
    allowedRegions: await getClientRegionPolicy_(c.env, sessionCred),
    expiresAt: new Date(tokenInfo.payload.exp).toISOString()
  });
});

app.get('/api/admin/orders', async (c) => {
  await requireAdminToken_(c.env, bearerToken_(c));
  const matched = await getOrdersByPeriod_(c.env, c.req.query('startM'), c.req.query('startD'), c.req.query('endM'), c.req.query('endD'));
  if (!matched.length) return c.json({ hasData: false });
  const totals = {};
  matched.forEach((order) => {
    if (!order.product) return;
    totals[order.product] = (totals[order.product] || 0) + order.qty;
  });
  return c.json({
    hasData: true,
    count: matched.length,
    totals,
    summary: matched.map((order) => ({
      date: order.date,
      client: order.client,
      region: order.region,
      product: order.product,
      qty: order.qty,
      oil: order.oil,
      isConfirmed: order.isConfirmed,
      recordId: order.recordId
    }))
  });
});

app.post('/api/admin/orders/confirm', async (c) => {
  await requireAdminToken_(c.env, bearerToken_(c));
  const body = await readJsonOrForm_(c);
  const matched = (await getOrdersByPeriod_(c.env, body.startM, body.startD, body.endM, body.endD))
    .filter((order) => !order.isConfirmed);
  if (!matched.length) return c.json({ count: 0 });
  const now = nowIso_();
  const statements = matched.map((order) => getDb_(c.env).prepare(
    'UPDATE orders SET confirmed = 1, updated_at = ? WHERE record_id = ?'
  ).bind(now, order.recordId));
  await getDb_(c.env).batch(statements);
  return c.json({ count: matched.length });
});

app.get('/api/admin/excel', async (c) => {
  await requireAdminToken_(c.env, bearerToken_(c));
  const period = normalizePeriod_(c.env, c.req.query('startM'), c.req.query('startD'), c.req.query('endM'), c.req.query('endD'));
  const { results } = await getDb_(c.env).prepare(`
    SELECT * FROM orders
    WHERE confirmed = 1 AND date_num >= ? AND date_num <= ?
    ORDER BY date_num ASC, id ASC
  `).bind(period.startValue, period.endValue).all();
  const data = (results || []).map(mapOrderRow_);
  if (!data.length) return c.json({ success: false, message: '지정한 기간에 확정된 내역이 없습니다.' });
  const headers = ['년도', '월', '일', '거래처', '지역', '품명', '유종', '수량'];
  const rows = data.map((order) => [
    order.year + '년', order.month + '월', order.day + '일',
    order.client, order.region, order.product, order.oil, order.qty
  ]);
  const today = getZonedParts_(getTimeZone_(c.env));
  return c.json({
    success: true,
    base64: padBase64_(buildXlsx_(headers, rows)),
    fileName: `확정발주내역_${today.year}-${pad2_(today.month)}-${pad2_(today.day)}.xlsx`
  });
});

app.get('/api/admin/products', async (c) => {
  await requireAdminToken_(c.env, bearerToken_(c));
  const { results } = await getDb_(c.env).prepare('SELECT * FROM oil_matching ORDER BY product COLLATE NOCASE').all();
  return c.json({ success: true, items: results || [] });
});

app.post('/api/admin/products', async (c) => {
  await requireAdminToken_(c.env, bearerToken_(c));
  const body = await readJsonOrForm_(c);
  const productName = cleanString(body.product || body.productName);
  const oilName = cleanString(body.oil);
  const clientText = cleanString(body.clients || body.restrictedClients);
  if (!productName) return c.json({ success: false, message: '품명을 입력해주세요.' });
  if (productName.length > 100) return c.json({ success: false, message: '품명은 100자 이하로 입력해주세요.' });
  if (oilName.length > 100) return c.json({ success: false, message: '유종은 100자 이하로 입력해주세요.' });
  const key = normalizeProductKey_(productName);
  const existing = await getDb_(c.env).prepare('SELECT id FROM oil_matching WHERE product_key = ?').bind(key).first();
  if (existing) return c.json({ success: false, message: '이미 등록된 품명입니다.' });
  const normalizedClients = clientText
    ? uniqueArray_(clientText.split(',').map((item) => item.trim()).filter(Boolean)).join(',')
    : '';
  const now = nowIso_();
  await getDb_(c.env).prepare(`
    INSERT INTO oil_matching (product, product_key, oil, restricted_clients, created_at, updated_at)
    VALUES (?, ?, ?, ?, ?, ?)
  `).bind(productName, key, oilName, normalizedClients, now, now).run();
  return c.json({ success: true });
});

app.put('/api/admin/products/:id', async (c) => {
  await requireAdminToken_(c.env, bearerToken_(c));
  const body = await readJsonOrForm_(c);
  const productName = cleanString(body.product);
  const oilName = cleanString(body.oil);
  const clients = cleanString(body.restricted_clients || body.clients);
  if (!productName) throw httpError('품명을 입력해주세요.');
  const now = nowIso_();
  await getDb_(c.env).prepare(`
    UPDATE oil_matching
    SET product = ?, product_key = ?, oil = ?, restricted_clients = ?, updated_at = ?
    WHERE id = ?
  `).bind(productName, normalizeProductKey_(productName), oilName, clients, now, Number(c.req.param('id'))).run();
  return c.json({ success: true });
});

app.delete('/api/admin/products/:id', async (c) => {
  await requireAdminToken_(c.env, bearerToken_(c));
  await getDb_(c.env).prepare('DELETE FROM oil_matching WHERE id = ?').bind(Number(c.req.param('id'))).run();
  return c.json({ success: true });
});

app.post('/api/admin/products/import', async (c) => {
  await requireAdminToken_(c.env, bearerToken_(c));
  const body = await readJsonOrForm_(c);
  const rows = Array.isArray(body.rows) ? body.rows : parseCsvRows_(cleanString(body.csv));
  if (!rows.length) throw httpError('업로드할 유종 매칭 데이터가 없습니다.');
  const now = nowIso_();
  let upserted = 0;
  const statements = [];
  for (const row of rows) {
    const product = cleanString(row.product || row.품명 || row[0]);
    if (!product) continue;
    const oil = cleanString(row.oil || row.유종 || row[1]);
    const clients = cleanString(row.restricted_clients || row.clients || row['제한 거래처'] || row[2]);
    const key = normalizeProductKey_(product);
    statements.push(getDb_(c.env).prepare(`
      INSERT INTO oil_matching (product, product_key, oil, restricted_clients, created_at, updated_at)
      VALUES (?, ?, ?, ?, ?, ?)
      ON CONFLICT(product_key) DO UPDATE SET
        product = excluded.product,
        oil = excluded.oil,
        restricted_clients = excluded.restricted_clients,
        updated_at = excluded.updated_at
    `).bind(product, key, oil, clients, now, now));
    upserted += 1;
  }
  if (statements.length) await getDb_(c.env).batch(statements);
  return c.json({ success: true, count: upserted });
});

app.post('/api/admin/clients', async (c) => {
  await requireAdminToken_(c.env, bearerToken_(c));
  const body = await readJsonOrForm_(c);
  const client = await createClient_(c.env, body.clientName || body.client, body.label, body.password || CONFIG.DEFAULT_PASSWORD, body.allowedRegions);
  const tokenInfo = await createSignedToken_(c.env, 'CLIENT', client.client, client.label, sessionCredential_(client));
  await registerToken_(c.env, tokenInfo);
  const origin = publicOrigin_(c);
  return c.json({
    success: true,
    tokenId: tokenInfo.tokenId,
    token: tokenInfo.token,
    role: 'CLIENT',
    client: client.client,
    label: client.label,
    allowedRegions: client.allowedRegions,
    expiresAt: new Date(tokenInfo.payload.exp).toISOString(),
    url: origin + '/order?token=' + encodeURIComponent(tokenInfo.token),
    warning: '접속 링크는 최초 접속용입니다. 이후에는 거래처명과 비밀번호로 로그인할 수 있습니다. 초기 비밀번호가 비어 있으면 1111 입니다.'
  });
});

app.post('/api/admin/clients/password', async (c) => {
  await requireAdminToken_(c.env, bearerToken_(c));
  const body = await readJsonOrForm_(c);
  const client = await findClientByName_(c.env, body.clientName || body.client);
  if (!client || !client.active) throw httpError('등록된 거래처 인증 정보가 없습니다.');
  const credential = await createPasswordCredential_(body.password || body.newPassword || CONFIG.DEFAULT_PASSWORD);
  await updatePasswordHash_(c.env, 'clients', 'name', client.client, credential);
  await revokeActiveClientTokens_(c.env, client.client, '');
  return c.json({ success: true, client: client.client });
});

app.post('/api/admin/clients/regions', async (c) => {
  await requireAdminToken_(c.env, bearerToken_(c));
  const body = await readJsonOrForm_(c);
  const clientName = cleanString(body.clientName || body.client);
  if (!clientName) throw httpError('거래처명을 입력하세요.');
  const normalized = parseAllowedRegions_(body.allowedRegions);
  if (normalized.length > 50) throw httpError('허용 지역은 최대 50개까지 등록할 수 있습니다.');
  const client = await findClientByName_(c.env, clientName);
  if (!client || !client.active) throw httpError('등록된 거래처 인증 정보가 없습니다.');
  await getDb_(c.env).prepare('UPDATE clients SET allowed_regions = ?, updated_at = ? WHERE name = ?')
    .bind(normalized.join(','), nowIso_(), client.client).run();
  return c.json({ success: true, client: client.client, allowedRegions: normalized });
});

app.get('/api/admin/accounts', async (c) => {
  await requireAdminToken_(c.env, bearerToken_(c));
  const clientName = cleanString(c.req.query('client'));
  const sql = clientName
    ? 'SELECT * FROM client_accounts WHERE client_name = ? ORDER BY client_name, region, login_id'
    : 'SELECT * FROM client_accounts ORDER BY client_name, region, login_id';
  const stmt = clientName ? getDb_(c.env).prepare(sql).bind(clientName) : getDb_(c.env).prepare(sql);
  const { results } = await stmt.all();
  return c.json((results || []).map((row) => ({
    accountId: row.account_id,
    client: row.client_name,
    region: row.region,
    loginId: row.login_id,
    label: row.label,
    active: Number(row.active) === 1,
    createdAt: row.created_at,
    updatedAt: row.updated_at
  })));
});

app.post('/api/admin/accounts', async (c) => {
  await requireAdminToken_(c.env, bearerToken_(c));
  const body = await readJsonOrForm_(c);
  const credential = await createRegionalAccount_(
    c.env,
    body.clientName || body.client,
    body.region,
    body.loginId,
    body.label,
    body.password || CONFIG.DEFAULT_PASSWORD
  );
  const tokenInfo = await createSignedToken_(c.env, 'CLIENT', credential.client, credential.label, sessionCredential_(credential));
  await registerToken_(c.env, tokenInfo);
  return c.json({
    success: true,
    accountId: credential.accountId,
    loginId: credential.loginId,
    accountRegion: credential.accountRegion,
    allowedRegions: [normalizeRegionKey_(credential.accountRegion)],
    token: tokenInfo.token,
    url: publicOrigin_(c) + '/order?token=' + encodeURIComponent(tokenInfo.token),
    warning: '지역별 계정이 생성되었습니다. 이 계정은 ' + credential.accountRegion + ' 지역만 발주할 수 있습니다. 비밀번호를 비우면 1111 입니다.'
  });
});

app.post('/api/admin/accounts/:id/password', async (c) => {
  await requireAdminToken_(c.env, bearerToken_(c));
  const body = await readJsonOrForm_(c);
  const credential = await findAccountById_(c.env, c.req.param('id'));
  if (!credential || !credential.active) throw httpError('지역별 계정을 찾을 수 없습니다.');
  const password = await createPasswordCredential_(body.password || body.newPassword || CONFIG.DEFAULT_PASSWORD);
  await updatePasswordHash_(c.env, 'client_accounts', 'account_id', credential.accountId, password);
  await revokeActiveClientTokens_(c.env, credential.client, credential.accountId);
  return c.json({
    success: true,
    accountId: credential.accountId,
    client: credential.client,
    region: credential.accountRegion,
    loginId: credential.loginId
  });
});

app.post('/api/admin/accounts/:id/active', async (c) => {
  await requireAdminToken_(c.env, bearerToken_(c));
  const body = await readJsonOrForm_(c);
  const credential = await findAccountById_(c.env, c.req.param('id'));
  if (!credential) throw httpError('계정을 찾을 수 없습니다.');
  const active = body.active === true || body.active === 1 || body.active === '1';
  await getDb_(c.env).prepare('UPDATE client_accounts SET active = ?, updated_at = ? WHERE account_id = ?')
    .bind(active ? 1 : 0, nowIso_(), credential.accountId).run();
  if (!active) await revokeActiveClientTokens_(c.env, credential.client, credential.accountId);
  return c.json({ success: true, accountId: credential.accountId, active });
});

app.get('/api/admin/tokens', async (c) => {
  await requireAdminToken_(c.env, bearerToken_(c));
  const { results } = await getDb_(c.env).prepare('SELECT * FROM auth_tokens ORDER BY created_at DESC').all();
  const items = [];
  for (const row of results || []) {
    let status = '활성';
    const expiresAt = Date.parse(row.expires_at);
    if (row.revoked_at) status = '폐기';
    else if (Number.isFinite(expiresAt) && expiresAt <= Date.now()) status = '만료';
    const allowedRegions = row.account_region
      ? [normalizeRegionKey_(row.account_region)]
      : await getClientRegionPolicy_(c.env, row.client);
    items.push({
      tokenId: row.token_id,
      role: row.role,
      client: row.client,
      label: row.label,
      allowedRegions,
      accountId: row.account_id,
      accountRegion: row.account_region,
      loginId: row.login_id,
      createdAt: row.created_at,
      expiresAt: row.expires_at,
      revokedAt: row.revoked_at || '',
      status
    });
  }
  return c.json(items);
});

app.post('/api/admin/tokens/:id/revoke', async (c) => {
  await requireAdminToken_(c.env, bearerToken_(c));
  const ok = await revokeTokenById_(c.env, c.req.param('id'));
  if (!ok) return c.json({ success: false, message: '토큰을 찾을 수 없거나 이미 폐기되었습니다.' });
  return c.json({ success: true });
});

app.post('/api/admin/password', async (c) => {
  await requireAdminToken_(c.env, bearerToken_(c));
  const body = await readJsonOrForm_(c);
  const current = body.currentPassword ? validatePassword_(body.currentPassword, '현재 비밀번호') : '';
  const next = validatePassword_(body.newPassword || body.password, '새 비밀번호');
  const admin = await getDb_(c.env).prepare('SELECT * FROM admins WHERE username = ?').bind('admin').first();
  if (current && !(await verifyPassword_(current, admin))) throw httpError('현재 비밀번호가 올바르지 않습니다.');
  const credential = await createPasswordCredential_(next);
  await updatePasswordHash_(c.env, 'admins', 'username', 'admin', credential);
  return c.json({ success: true });
});

app.post('/api/admin/cleanup-tokens', async (c) => {
  await requireAdminToken_(c.env, bearerToken_(c));
  return c.json(await cleanupAuthTokens_(c.env));
});

app.get('/api/admin/db/tables', async (c) => {
  await requireAdminToken_(c.env, bearerToken_(c));
  const tables = [];
  for (const name of CONFIG.GUI_TABLES) {
    const row = await getDb_(c.env).prepare(`SELECT COUNT(*) AS cnt FROM ${name}`).first();
    tables.push({ name, count: Number(row?.cnt || 0) });
  }
  return c.json({ success: true, tables });
});

app.get('/api/admin/db/:table', async (c) => {
  await requireAdminToken_(c.env, bearerToken_(c));
  const table = cleanString(c.req.param('table'));
  if (!CONFIG.GUI_TABLES.includes(table)) throw httpError('허용되지 않은 테이블입니다.');
  const limit = Math.min(500, Math.max(1, safeInteger_(c.req.query('limit'), 200)));
  const offset = Math.max(0, safeInteger_(c.req.query('offset'), 0));
  const info = await getDb_(c.env).prepare(`PRAGMA table_info(${table})`).all();
  const columns = (info.results || []).map((col) => col.name);
  const countRow = await getDb_(c.env).prepare(`SELECT COUNT(*) AS cnt FROM ${table}`).first();
  const { results } = await getDb_(c.env).prepare(`SELECT * FROM ${table} LIMIT ? OFFSET ?`).bind(limit, offset).all();
  return c.json({
    success: true,
    table,
    columns,
    total: Number(countRow?.cnt || 0),
    rows: results || []
  });
});

app.post('/api/admin/db/:table', async (c) => {
  await requireAdminToken_(c.env, bearerToken_(c));
  const table = cleanString(c.req.param('table'));
  if (!CONFIG.GUI_TABLES.includes(table)) throw httpError('허용되지 않은 테이블입니다.');
  const body = await readJsonOrForm_(c);
  const info = await getDb_(c.env).prepare(`PRAGMA table_info(${table})`).all();
  const columns = (info.results || []).map((col) => col.name).filter((name) => name !== 'id' && body[name] !== undefined);
  if (!columns.length) throw httpError('저장할 컬럼이 없습니다.');
  const placeholders = columns.map(() => '?').join(', ');
  const values = columns.map((name) => body[name]);
  await getDb_(c.env).prepare(`INSERT INTO ${table} (${columns.join(', ')}) VALUES (${placeholders})`).bind(...values).run();
  return c.json({ success: true });
});

app.put('/api/admin/db/:table/:id', async (c) => {
  await requireAdminToken_(c.env, bearerToken_(c));
  const table = cleanString(c.req.param('table'));
  if (!CONFIG.GUI_TABLES.includes(table)) throw httpError('허용되지 않은 테이블입니다.');
  const body = await readJsonOrForm_(c);
  const info = await getDb_(c.env).prepare(`PRAGMA table_info(${table})`).all();
  const pk = (info.results || []).find((col) => Number(col.pk) === 1)?.name || 'id';
  const columns = (info.results || []).map((col) => col.name).filter((name) => name !== pk && body[name] !== undefined);
  if (!columns.length) throw httpError('수정할 컬럼이 없습니다.');
  const sql = `UPDATE ${table} SET ${columns.map((name) => `${name} = ?`).join(', ')} WHERE ${pk} = ?`;
  await getDb_(c.env).prepare(sql).bind(...columns.map((name) => body[name]), c.req.param('id')).run();
  return c.json({ success: true });
});

app.delete('/api/admin/db/:table/:id', async (c) => {
  await requireAdminToken_(c.env, bearerToken_(c));
  const table = cleanString(c.req.param('table'));
  if (!CONFIG.GUI_TABLES.includes(table)) throw httpError('허용되지 않은 테이블입니다.');
  const info = await getDb_(c.env).prepare(`PRAGMA table_info(${table})`).all();
  const pk = (info.results || []).find((col) => Number(col.pk) === 1)?.name || 'id';
  await getDb_(c.env).prepare(`DELETE FROM ${table} WHERE ${pk} = ?`).bind(c.req.param('id')).run();
  return c.json({ success: true });
});

function parseCsvRows_(csv) {
  const text = cleanString(csv);
  if (!text) return [];
  const lines = text.replace(/\r\n/g, '\n').replace(/\r/g, '\n').split('\n').filter(Boolean);
  if (!lines.length) return [];
  const headers = splitCsvLine_(lines[0]).map((item) => item.trim());
  return lines.slice(1).map((line) => {
    const cells = splitCsvLine_(line);
    const row = {};
    headers.forEach((header, index) => {
      row[header] = cells[index] || '';
      row[index] = cells[index] || '';
    });
    return row;
  });
}

function splitCsvLine_(line) {
  const out = [];
  let current = '';
  let quoted = false;
  for (let i = 0; i < line.length; i++) {
    const ch = line[i];
    if (ch === '"') {
      if (quoted && line[i + 1] === '"') {
        current += '"';
        i += 1;
      } else quoted = !quoted;
    } else if (ch === ',' && !quoted) {
      out.push(current);
      current = '';
    } else current += ch;
  }
  out.push(current);
  return out;
}

/* ==========================================================
 * 정적 파일 / 페이지
 * ----------------------------------------------------------
 * [assets] 작업자 에셋을 쓰지 않고, Worker 가 public/ 의
 * HTML 파일을 직접 읽어 서빙한다. (dev 로컬 307 루프 방지)
 * ========================================================== */

function htmlResponse_(html, title) {
  return new Response(html, {
    headers: {
      'Content-Type': 'text/html; charset=utf-8',
      'Cache-Control': 'no-store'
    }
  });
}

app.get('/', (c) => htmlResponse_(loginHtml, '발주 시스템 로그인'));
app.get('/login', (c) => htmlResponse_(loginHtml, '발주 시스템 로그인'));
app.get('/order', (c) => htmlResponse_(indexHtml, '발주 관리 시스템'));
app.get('/admin', (c) => htmlResponse_(adminHtml, '관리자 대시보드'));
app.get('/db', (c) => htmlResponse_(dbHtml, 'D1 데이터베이스 관리'));

app.all('*', (c) => c.json({ success: false, message: 'Not Found' }, 404));

export default {
  fetch: app.fetch,
  async scheduled(event, env) {
    try {
      await cleanupAuthTokens_(env);
    } catch (error) {
      console.error('scheduled cleanup failed', error);
    }
  }
};
