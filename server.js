import express from 'express';
import http from 'http';
import path from 'path';
import { fileURLToPath } from 'url';
import { readFile } from 'node:fs/promises';
import crypto from 'crypto';
import bcrypt from 'bcryptjs';
import pg from 'pg';
import { Server } from 'socket.io';

const { Pool } = pg;
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const PORT = Number(process.env.PORT || 3000);
const COOKIE_NAME = 'talkon_session';
const SESSION_DAYS = 30;
const DATABASE_URL = process.env.DATABASE_URL;
const ADMIN_NICKNAME = String(process.env.TALKON_ADMIN_NICKNAME || '최연욱').trim().normalize('NFKC');
const ADMIN_PASSWORD = String(process.env.TALKON_ADMIN_PASSWORD || '');

if (!DATABASE_URL) {
  console.error('DATABASE_URL 환경변수가 없습니다. Render에서 PostgreSQL을 만들고 Web Service에 DATABASE_URL을 연결하세요.');
  process.exit(1);
}

const app = express();
app.set('trust proxy', 1);
app.disable('x-powered-by');
app.use(express.json({ limit: '32kb' }));

const server = http.createServer(app);

// Render Web Service와 같은 리전에 만든 Postgres의 Internal Database URL을 권장합니다.
const pool = new Pool({
  connectionString: DATABASE_URL,
  max: 10,
  idleTimeoutMillis: 30_000,
  connectionTimeoutMillis: 10_000,
});

async function initDatabase() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id BIGSERIAL PRIMARY KEY,
      nickname TEXT NOT NULL,
      nickname_key TEXT NOT NULL UNIQUE,
      password_hash TEXT NOT NULL,
      is_admin BOOLEAN NOT NULL DEFAULT FALSE,
      is_banned BOOLEAN NOT NULL DEFAULT FALSE,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS sessions (
      token TEXT PRIMARY KEY,
      user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      expires_at BIGINT NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS messages (
      id BIGSERIAL PRIMARY KEY,
      conversation_key TEXT NOT NULL,
      sender_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      receiver_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      body TEXT NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE INDEX IF NOT EXISTS idx_messages_conversation_id
      ON messages(conversation_key, id);

    CREATE INDEX IF NOT EXISTS idx_sessions_expires_at
      ON sessions(expires_at);
  `);

  // Upgrade older databases without losing existing users or messages.
  await pool.query(`
    ALTER TABLE users ADD COLUMN IF NOT EXISTS is_admin BOOLEAN NOT NULL DEFAULT FALSE;
    ALTER TABLE users ADD COLUMN IF NOT EXISTS is_banned BOOLEAN NOT NULL DEFAULT FALSE;
    CREATE TABLE IF NOT EXISTS reports (
      id BIGSERIAL PRIMARY KEY,
      reporter_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      reported_user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      reason TEXT NOT NULL,
      details TEXT NOT NULL DEFAULT '',
      status TEXT NOT NULL DEFAULT 'open',
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    CREATE INDEX IF NOT EXISTS idx_reports_status_created_at ON reports(status, created_at DESC);
  `);

  if (ADMIN_PASSWORD.length >= 12 && ADMIN_NICKNAME.length >= 2 && ADMIN_NICKNAME.length <= 16) {
    const passwordHash = await bcrypt.hash(ADMIN_PASSWORD, 12);
    await pool.query(
      `INSERT INTO users (nickname, nickname_key, password_hash, is_admin, is_banned)
       VALUES ($1, $2, $3, TRUE, FALSE)
       ON CONFLICT (nickname_key) DO UPDATE
       SET nickname = EXCLUDED.nickname,
           password_hash = EXCLUDED.password_hash,
           is_admin = TRUE,
           is_banned = FALSE`,
      [ADMIN_NICKNAME, nicknameKey(ADMIN_NICKNAME), passwordHash]
    );
    console.log(`TalkOn admin account ready: ${ADMIN_NICKNAME}`);
  } else {
    console.warn('관리자 계정이 아직 설정되지 않았습니다. TALKON_ADMIN_PASSWORD에 12자 이상의 비밀번호를 설정하세요.');
  }
}

function normalizeNickname(value) {
  return String(value ?? '').trim().normalize('NFKC');
}

function nicknameKey(value) {
  return normalizeNickname(value).toLocaleLowerCase('ko-KR');
}

function conversationKey(a, b) {
  return [Number(a), Number(b)].sort((x, y) => x - y).join(':');
}

function cleanMessage(value) {
  return String(value ?? '').trim().slice(0, 1000);
}

function getToken(req) {
  const raw = req.headers.cookie || '';
  const item = raw
    .split(';')
    .map(v => v.trim())
    .find(v => v.startsWith(COOKIE_NAME + '='));
  if (!item) return null;
  try {
    return decodeURIComponent(item.slice(COOKIE_NAME.length + 1));
  } catch {
    return null;
  }
}

async function currentUser(req) {
  const token = getToken(req);
  if (!token) return null;

  const { rows } = await pool.query(
    `SELECT s.user_id, u.nickname, u.is_admin, u.is_banned
       FROM sessions s
       JOIN users u ON u.id = s.user_id
      WHERE s.token = $1 AND s.expires_at > $2`,
    [token, Date.now()]
  );

  if (!rows[0]) return null;
  if (rows[0].is_banned) {
    await pool.query('DELETE FROM sessions WHERE token = $1', [token]);
    return null;
  }
  return {
    id: Number(rows[0].user_id),
    nickname: rows[0].nickname,
    is_admin: Boolean(rows[0].is_admin),
    is_banned: Boolean(rows[0].is_banned),
    token,
  };
}

function setSessionCookie(req, res, token) {
  const forwardedProto = String(req.headers['x-forwarded-proto'] || '').split(',')[0].trim();
  const secure = req.secure || forwardedProto === 'https';
  const securePart = secure ? '; Secure' : '';

  res.setHeader(
    'Set-Cookie',
    `${COOKIE_NAME}=${encodeURIComponent(token)}; HttpOnly; Path=/; SameSite=Lax; Max-Age=${SESSION_DAYS * 86400}${securePart}`
  );
}

function clearSessionCookie(req, res) {
  const forwardedProto = String(req.headers['x-forwarded-proto'] || '').split(',')[0].trim();
  const secure = req.secure || forwardedProto === 'https';
  const securePart = secure ? '; Secure' : '';
  res.setHeader('Set-Cookie', `${COOKIE_NAME}=; HttpOnly; Path=/; SameSite=Lax; Max-Age=0${securePart}`);
}

function publicUser(user) {
  return { id: Number(user.id), nickname: user.nickname, isAdmin: Boolean(user.is_admin) };
}

async function requireAdminApi(req, res) {
  const user = await currentUser(req);
  if (!user) {
    res.status(401).json({ ok: false, message: '로그인이 필요합니다.' });
    return null;
  }
  if (!user.is_admin) {
    res.status(403).json({ ok: false, message: '관리자 권한이 필요합니다.' });
    return null;
  }
  return user;
}

async function findUserByNickname(nickname) {
  const { rows } = await pool.query(
    `SELECT id, nickname, password_hash, is_admin, is_banned FROM users WHERE nickname_key = $1 AND is_banned = FALSE`,
    [nicknameKey(nickname)]
  );
  return rows[0] || null;
}

async function findUserById(id) {
  const { rows } = await pool.query(
    `SELECT id, nickname, is_admin, is_banned FROM users WHERE id = $1 AND is_banned = FALSE`,
    [Number(id)]
  );
  return rows[0] || null;
}

async function createSession(userId) {
  const token = crypto.randomUUID();
  await pool.query(
    `INSERT INTO sessions (token, user_id, expires_at) VALUES ($1, $2, $3)`,
    [token, Number(userId), Date.now() + SESSION_DAYS * 86400 * 1000]
  );
  return token;
}

const onlineCounts = new Map();
const userSockets = new Map();

function emitOnlineStatus(userId) {
  const online = (onlineCounts.get(Number(userId)) || 0) > 0;
  io.emit('presence:update', { userId: Number(userId), online });
}

function joinOnline(userId, socketId) {
  const id = Number(userId);
  onlineCounts.set(id, (onlineCounts.get(id) || 0) + 1);
  if (!userSockets.has(id)) userSockets.set(id, new Set());
  userSockets.get(id).add(socketId);
  emitOnlineStatus(id);
}

function leaveOnline(userId, socketId) {
  const id = Number(userId);
  const sockets = userSockets.get(id);
  if (sockets) {
    sockets.delete(socketId);
    if (sockets.size === 0) userSockets.delete(id);
  }
  const next = Math.max(0, (onlineCounts.get(id) || 1) - 1);
  if (next === 0) onlineCounts.delete(id);
  else onlineCounts.set(id, next);
  emitOnlineStatus(id);
}

function socketUser(socket) {
  return socket.data.user || null;
}

app.get('/api/me', async (req, res, next) => {
  try {
    const user = await currentUser(req);
    if (!user) return res.json({ loggedIn: false });
    res.json({ loggedIn: true, user: publicUser(user) });
  } catch (error) {
    next(error);
  }
});

app.post('/api/signup', async (req, res, next) => {
  const nickname = normalizeNickname(req.body?.nickname);
  const password = String(req.body?.password ?? '');

  if (!/^[\p{L}\p{N}_-]{2,16}$/u.test(nickname)) {
    return res.status(400).json({ ok: false, message: '닉네임은 한글/영문/숫자/_/-만 사용해서 2~16자로 입력하세요.' });
  }
  if (nicknameKey(nickname) === nicknameKey(ADMIN_NICKNAME)) {
    return res.status(403).json({ ok: false, message: '이 닉네임은 관리자 전용입니다.' });
  }
  if (password.length < 6 || password.length > 72) {
    return res.status(400).json({ ok: false, message: '비밀번호는 6~72자로 입력하세요.' });
  }

  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    const existing = await client.query(
      `SELECT id FROM users WHERE nickname_key = $1 LIMIT 1`,
      [nicknameKey(nickname)]
    );
    if (existing.rows[0]) {
      await client.query('ROLLBACK');
      return res.status(409).json({ ok: false, message: '이미 사용 중인 닉네임입니다.' });
    }

    const passwordHash = await bcrypt.hash(password, 12);
    const inserted = await client.query(
      `INSERT INTO users (nickname, nickname_key, password_hash)
       VALUES ($1, $2, $3)
       RETURNING id, nickname`,
      [nickname, nicknameKey(nickname), passwordHash]
    );

    const user = inserted.rows[0];
    const token = crypto.randomUUID();
    await client.query(
      `INSERT INTO sessions (token, user_id, expires_at) VALUES ($1, $2, $3)`,
      [token, Number(user.id), Date.now() + SESSION_DAYS * 86400 * 1000]
    );

    await client.query('COMMIT');
    setSessionCookie(req, res, token);
    return res.json({ ok: true, user: publicUser(user) });
  } catch (error) {
    await client.query('ROLLBACK').catch(() => {});
    if (error?.code === '23505') {
      return res.status(409).json({ ok: false, message: '이미 사용 중인 닉네임입니다.' });
    }
    next(error);
  } finally {
    client.release();
  }
});

app.post('/api/login', async (req, res, next) => {
  try {
    const nickname = normalizeNickname(req.body?.nickname);
    const password = String(req.body?.password ?? '');
    const user = await findUserByNickname(nickname);

    if (!user || !(await bcrypt.compare(password, user.password_hash))) {
      return res.status(401).json({ ok: false, message: '닉네임 또는 비밀번호가 올바르지 않습니다.' });
    }

    const token = await createSession(user.id);
    setSessionCookie(req, res, token);
    res.json({ ok: true, user: publicUser(user) });
  } catch (error) {
    next(error);
  }
});

app.post('/api/logout', async (req, res, next) => {
  try {
    const token = getToken(req);
    if (token) await pool.query(`DELETE FROM sessions WHERE token = $1`, [token]);
    clearSessionCookie(req, res);
    res.json({ ok: true });
  } catch (error) {
    next(error);
  }
});

app.get('/api/users/search', async (req, res, next) => {
  try {
    const me = await currentUser(req);
    if (!me) return res.status(401).json({ ok: false, message: '로그인이 필요합니다.' });

    const nickname = normalizeNickname(req.query.nickname);
    if (!nickname) return res.json({ ok: true, found: false });

    const user = await findUserByNickname(nickname);
    if (!user || Number(user.id) === me.id) return res.json({ ok: true, found: false });

    res.json({
      ok: true,
      found: true,
      user: {
        id: Number(user.id),
        nickname: user.nickname,
        online: (onlineCounts.get(Number(user.id)) || 0) > 0,
      },
    });
  } catch (error) {
    next(error);
  }
});

app.post('/api/reports', async (req, res, next) => {
  try {
    const me = await currentUser(req);
    if (!me) return res.status(401).json({ ok: false, message: '로그인이 필요합니다.' });

    const reportedUserId = Number(req.body?.userId);
    const reason = String(req.body?.reason || '').trim().slice(0, 120);
    const details = String(req.body?.details || '').trim().slice(0, 1000);
    if (!Number.isSafeInteger(reportedUserId) || reportedUserId <= 0 || reportedUserId === me.id) {
      return res.status(400).json({ ok: false, message: '신고할 사용자를 확인해주세요.' });
    }
    if (!reason) return res.status(400).json({ ok: false, message: '신고 사유를 입력해주세요.' });

    const target = await pool.query('SELECT id FROM users WHERE id = $1 AND is_banned = FALSE', [reportedUserId]);
    if (!target.rows[0]) return res.status(404).json({ ok: false, message: '사용자를 찾을 수 없습니다.' });
    const duplicate = await pool.query(
      `SELECT id FROM reports
       WHERE reporter_id = $1 AND reported_user_id = $2 AND status = 'open'
       LIMIT 1`,
      [me.id, reportedUserId]
    );
    if (duplicate.rows[0]) {
      return res.status(409).json({ ok: false, message: '이미 처리 대기 중인 신고가 있습니다.' });
    }

    await pool.query(
      `INSERT INTO reports (reporter_id, reported_user_id, reason, details)
       VALUES ($1, $2, $3, $4)`,
      [me.id, reportedUserId, reason, details]
    );
    res.json({ ok: true, message: '신고가 접수되었습니다.' });
  } catch (error) {
    next(error);
  }
});

app.get('/api/admin/overview', async (req, res, next) => {
  try {
    const admin = await requireAdminApi(req, res);
    if (!admin) return;
    const [usersResult, reportsResult, statsResult] = await Promise.all([
      pool.query(
        `SELECT u.id, u.nickname, u.is_admin, u.is_banned, u.created_at,
                (SELECT COUNT(*) FROM messages m WHERE m.sender_id = u.id OR m.receiver_id = u.id) AS message_count
         FROM users u
         ORDER BY u.created_at DESC, u.id DESC
         LIMIT 300`
      ),
      pool.query(
        `SELECT r.id, r.reason, r.details, r.status, r.created_at,
                r.reporter_id, reporter.nickname AS reporter_nickname,
                r.reported_user_id, reported.nickname AS reported_nickname,
                reported.is_admin AS reported_is_admin, reported.is_banned AS reported_is_banned
         FROM reports r
         JOIN users reporter ON reporter.id = r.reporter_id
         JOIN users reported ON reported.id = r.reported_user_id
         WHERE r.status = 'open'
         ORDER BY r.created_at DESC
         LIMIT 200`
      ),
      pool.query(
        `SELECT COUNT(*)::int AS total_users,
                COUNT(*) FILTER (WHERE is_banned = TRUE)::int AS banned_users
         FROM users`
      )
    ]);
    res.json({
      ok: true,
      users: usersResult.rows.map(u => ({
        id: Number(u.id), nickname: u.nickname, isAdmin: Boolean(u.is_admin),
        isBanned: Boolean(u.is_banned), createdAt: u.created_at, messageCount: Number(u.message_count)
      })),
      reports: reportsResult.rows.map(r => ({
        id: Number(r.id), reason: r.reason, details: r.details, createdAt: r.created_at,
        reporterId: Number(r.reporter_id), reporterNickname: r.reporter_nickname,
        reportedUserId: Number(r.reported_user_id), reportedNickname: r.reported_nickname,
        reportedIsAdmin: Boolean(r.reported_is_admin), reportedIsBanned: Boolean(r.reported_is_banned)
      })),
      stats: {
        totalUsers: Number(statsResult.rows[0]?.total_users || 0),
        bannedUsers: Number(statsResult.rows[0]?.banned_users || 0),
        openReports: reportsResult.rows.length
      }
    });
  } catch (error) {
    next(error);
  }
});

app.post('/api/admin/users/:userId/ban', async (req, res, next) => {
  try {
    const admin = await requireAdminApi(req, res);
    if (!admin) return;
    const targetId = Number(req.params.userId);
    const banned = req.body?.banned;
    if (!Number.isSafeInteger(targetId) || targetId <= 0 || typeof banned !== 'boolean') {
      return res.status(400).json({ ok: false, message: '요청 값이 올바르지 않습니다.' });
    }
    const targetResult = await pool.query('SELECT id, is_admin FROM users WHERE id = $1', [targetId]);
    const target = targetResult.rows[0];
    if (!target) return res.status(404).json({ ok: false, message: '사용자를 찾을 수 없습니다.' });
    if (Number(target.id) === admin.id || target.is_admin) {
      return res.status(400).json({ ok: false, message: '관리자 계정은 여기서 정지할 수 없습니다.' });
    }

    await pool.query('UPDATE users SET is_banned = $1 WHERE id = $2', [banned, targetId]);
    if (banned) {
      await pool.query('DELETE FROM sessions WHERE user_id = $1', [targetId]);
      io.in(`user:${targetId}`).disconnectSockets(true);
    }
    res.json({ ok: true, banned });
  } catch (error) {
    next(error);
  }
});

app.post('/api/admin/reports/:reportId/close', async (req, res, next) => {
  try {
    const admin = await requireAdminApi(req, res);
    if (!admin) return;
    const reportId = Number(req.params.reportId);
    if (!Number.isSafeInteger(reportId) || reportId <= 0) {
      return res.status(400).json({ ok: false, message: '신고 번호가 올바르지 않습니다.' });
    }
    const result = await pool.query(
      `UPDATE reports SET status = 'closed' WHERE id = $1 AND status = 'open' RETURNING id`,
      [reportId]
    );
    if (!result.rows[0]) return res.status(404).json({ ok: false, message: '처리할 신고가 없습니다.' });
    res.json({ ok: true });
  } catch (error) {
    next(error);
  }
});

app.get('/api/messages/:userId', async (req, res, next) => {
  try {
    const me = await currentUser(req);
    if (!me) return res.status(401).json({ ok: false, message: '로그인이 필요합니다.' });

    const other = await findUserById(req.params.userId);
    if (!other || Number(other.id) === me.id) {
      return res.status(404).json({ ok: false, message: '대화 상대를 찾을 수 없습니다.' });
    }

    const { rows: messages } = await pool.query(
      `SELECT m.id, m.sender_id, m.receiver_id, m.body, m.created_at, u.nickname AS sender_nickname
         FROM messages m
         JOIN users u ON u.id = m.sender_id
        WHERE m.conversation_key = $1
        ORDER BY m.id ASC
        LIMIT 200`,
      [conversationKey(me.id, other.id)]
    );

    res.json({
      ok: true,
      with: {
        id: Number(other.id),
        nickname: other.nickname,
        online: (onlineCounts.get(Number(other.id)) || 0) > 0,
      },
      messages,
    });
  } catch (error) {
    next(error);
  }
});

app.get('/api/chats', async (req, res, next) => {
  try {
    const me = await currentUser(req);
    if (!me) return res.status(401).json({ ok: false, message: '로그인이 필요합니다.' });

    const { rows } = await pool.query(
      `SELECT DISTINCT ON (m.conversation_key)
          m.conversation_key,
          m.body AS last_body,
          m.created_at AS last_created_at,
          CASE WHEN m.sender_id = $1 THEN m.receiver_id ELSE m.sender_id END AS other_id,
          u.nickname AS other_nickname
         FROM messages m
         JOIN users u
           ON u.id = CASE WHEN m.sender_id = $1 THEN m.receiver_id ELSE m.sender_id END
        WHERE m.sender_id = $1 OR m.receiver_id = $1
        ORDER BY m.conversation_key, m.id DESC`,
      [me.id]
    );

    const chats = rows
      .map(row => ({
        id: Number(row.other_id),
        nickname: row.other_nickname,
        last: row.last_body,
        created_at: row.last_created_at,
        online: (onlineCounts.get(Number(row.other_id)) || 0) > 0,
      }))
      .sort((a, b) => new Date(b.created_at).getTime() - new Date(a.created_at).getTime())
      .slice(0, 50);

    res.json({ ok: true, chats });
  } catch (error) {
    next(error);
  }
});

app.use('/api', (req, res) => {
  res.status(404).json({ ok: false, message: 'API를 찾을 수 없습니다.' });
});

const INDEX_HTML = "<!doctype html>\n<html lang=\"ko\">\n<head>\n  <meta charset=\"UTF-8\" />\n  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\" />\n  <title>톡온 · TalkOn</title>\n  <style>\n    :root {\n      --bg: #f5f7fb;\n      --panel: rgba(255,255,255,.93);\n      --line: #e7eaf0;\n      --text: #171923;\n      --muted: #7a8190;\n      --accent: #5b5ce2;\n      --accent-dark: #494acc;\n      --bubble: #eef0ff;\n      --danger: #e5484d;\n      --shadow: 0 22px 60px rgba(30, 35, 65, .12);\n    }\n\n    * { box-sizing: border-box; }\n    body {\n      margin: 0;\n      font-family: Pretendard, -apple-system, BlinkMacSystemFont, \"Segoe UI\", sans-serif;\n      color: var(--text);\n      background:\n        radial-gradient(circle at 10% 10%, rgba(91,92,226,.14), transparent 28%),\n        radial-gradient(circle at 95% 85%, rgba(120,90,255,.10), transparent 25%),\n        var(--bg);\n      min-height: 100vh;\n    }\n    button, input { font: inherit; }\n    button { cursor: pointer; }\n    .hidden { display: none !important; }\n\n    .auth-wrap {\n      min-height: 100vh;\n      display: grid;\n      place-items: center;\n      padding: 24px;\n    }\n    .auth-card {\n      width: min(440px, 100%);\n      padding: 34px;\n      background: var(--panel);\n      border: 1px solid rgba(255,255,255,.8);\n      border-radius: 28px;\n      box-shadow: var(--shadow);\n      backdrop-filter: blur(18px);\n    }\n    .logo {\n      display: flex; align-items: center; gap: 12px;\n      font-size: 26px; font-weight: 900; letter-spacing: -1px;\n    }\n    .logo-mark {\n      width: 42px; height: 42px; border-radius: 14px;\n      display: grid; place-items: center;\n      color: white; background: linear-gradient(135deg, #7374ff, #4d4fd3);\n      box-shadow: 0 10px 24px rgba(91,92,226,.28);\n    }\n    .auth-subtitle { color: var(--muted); margin: 10px 0 24px; }\n    .tabs { display: grid; grid-template-columns: 1fr 1fr; background: #f1f2f7; padding: 4px; border-radius: 13px; margin-bottom: 22px; }\n    .tabs button { border: 0; background: transparent; padding: 11px; border-radius: 10px; color: var(--muted); font-weight: 800; }\n    .tabs button.active { background: white; color: var(--text); box-shadow: 0 2px 10px rgba(0,0,0,.06); }\n    label { display: block; font-size: 13px; font-weight: 800; margin: 14px 0 7px; }\n    input {\n      width: 100%; border: 1px solid var(--line); background: white; color: var(--text);\n      border-radius: 13px; padding: 13px 14px; outline: none; transition: .2s;\n    }\n    input:focus { border-color: var(--accent); box-shadow: 0 0 0 4px rgba(91,92,226,.10); }\n    .primary { width: 100%; border: 0; border-radius: 13px; padding: 13px; margin-top: 18px; color: white; font-weight: 900; background: var(--accent); }\n    .primary:hover { background: var(--accent-dark); }\n    .message { min-height: 21px; margin-top: 12px; font-size: 13px; color: var(--danger); }\n    .hint { font-size: 12px; color: var(--muted); margin-top: 12px; line-height: 1.55; }\n\n    .app { height: 100vh; padding: 22px; display: flex; }\n    .shell {\n      display: grid; grid-template-columns: 320px 1fr; width: 100%; max-width: 1240px; margin: auto;\n      min-height: 0; overflow: hidden; border-radius: 28px; background: var(--panel); box-shadow: var(--shadow); border: 1px solid rgba(255,255,255,.8);\n    }\n    .sidebar { padding: 22px; border-right: 1px solid var(--line); min-width: 0; }\n    .profile { display: flex; align-items: center; justify-content: space-between; gap: 12px; margin-bottom: 18px; }\n    .userbox { display: flex; align-items: center; gap: 11px; min-width: 0; }\n    .avatar { width: 42px; height: 42px; flex: 0 0 42px; border-radius: 14px; display: grid; place-items: center; color: white; font-weight: 900; background: linear-gradient(135deg, #7071ff, #7e4fd4); }\n    .name { font-weight: 900; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }\n    .status { color: #43a047; font-size: 11px; margin-top: 3px; font-weight: 700; }\n    .logout { border: 1px solid var(--line); background: white; border-radius: 10px; padding: 8px 10px; color: var(--muted); }\n    .search-title { font-size: 13px; font-weight: 900; margin: 22px 0 9px; }\n    .search-row { display: grid; grid-template-columns: 1fr 42px; gap: 7px; }\n    .search-row button { border: 0; border-radius: 12px; background: var(--accent); color: white; font-weight: 900; }\n    .search-result { margin-top: 10px; }\n    .result-card, .empty-card { border: 1px solid var(--line); background: #fff; border-radius: 15px; padding: 13px; }\n    .result-card { display:flex; align-items:center; justify-content:space-between; gap:8px; }\n    .result-card .open { border:0; border-radius:10px; background: #eef0ff; color: var(--accent-dark); padding: 8px 10px; font-weight: 900; }\n    .chat-list { margin-top: 18px; }\n    .list-title { font-size: 12px; color: var(--muted); font-weight: 900; margin-bottom: 8px; }\n    .chat-item { width:100%; display:flex; align-items:center; gap:10px; border:0; background:transparent; padding:10px 8px; border-radius:12px; text-align:left; }\n    .chat-item:hover { background:#f6f7fb; }\n    .chat-item .small-avatar { width:36px; height:36px; border-radius:11px; display:grid; place-items:center; color:white; font-size:12px; font-weight:900; background:#8184a8; }\n    .chat-item .meta { min-width:0; flex:1; }\n    .chat-item .last { color:var(--muted); font-size:11px; white-space:nowrap; overflow:hidden; text-overflow:ellipsis; margin-top:3px; }\n\n    .chat { min-width: 0; min-height: 0; display:grid; grid-template-rows: 72px 1fr 72px; }\n    .chat-head { display:flex; align-items:center; justify-content:space-between; padding: 0 26px; border-bottom: 1px solid var(--line); }\n    .mobile-search-btn { display:none; border:0; border-radius:11px; background:#eef0ff; color:var(--accent-dark); padding:9px 11px; font-weight:900; }\n    .chat-title { display:flex; align-items:center; gap:11px; }\n    .chat-title h2 { margin:0; font-size:17px; }\n    .online-dot { width:8px; height:8px; border-radius:50%; background:#b6bcc8; display:inline-block; }\n    .online-dot.on { background:#41b86a; }\n    .chat-messages { padding: 24px 26px; overflow:auto; display:flex; flex-direction:column; gap:10px; background: linear-gradient(180deg, rgba(249,250,253,.8), rgba(255,255,255,.4)); }\n    .notice { align-self:center; color:var(--muted); font-size:12px; padding:8px 12px; background:#f1f2f6; border-radius:999px; }\n    .bubble-row { display:flex; }\n    .bubble-row.mine { justify-content:flex-end; }\n    .bubble { max-width:min(72%, 560px); padding:11px 13px; border-radius:16px; background:#fff; border:1px solid var(--line); line-height:1.5; white-space:pre-wrap; overflow-wrap:anywhere; }\n    .mine .bubble { color:white; background:var(--accent); border-color:var(--accent); border-bottom-right-radius:5px; }\n    .other .bubble { border-bottom-left-radius:5px; }\n    .time { color:var(--muted); font-size:10px; align-self:flex-end; margin:0 6px 3px; }\n    .composer { padding:14px 20px; border-top:1px solid var(--line); display:grid; grid-template-columns:1fr auto; gap:9px; }\n    .composer input { border-radius:14px; }\n    .send { border:0; border-radius:14px; padding:0 18px; background:var(--accent); color:white; font-weight:900; }\n    .typing { min-height:16px; margin-top:-7px; padding:0 26px; color:var(--muted); font-size:11px; }\n    .welcome { display:grid; place-items:center; height:100%; color:var(--muted); text-align:center; padding:30px; }\n    .welcome strong { display:block; color:var(--text); font-size:24px; margin-bottom:7px; }\n\n    @media (max-width: 820px) {\n      .app { padding:0; }\n      .shell { border-radius:0; grid-template-columns:1fr; }\n      .sidebar { display:none; }\n      .mobile-search-btn { display:block; }\n      .chat-head { padding:0 14px 0 18px; }\n      .chat { height:100vh; }\n      .chat-messages { padding:18px 14px; }\n      .composer { padding:10px 12px; }\n      .typing { padding:0 14px; }\n    }\n  </style>\n</head>\n<body>\n  <section id=\"authView\" class=\"auth-wrap\">\n    <div class=\"auth-card\">\n      <div class=\"logo\"><div class=\"logo-mark\">T</div>톡온</div>\n      <div class=\"auth-subtitle\">닉네임으로 찾아 바로 대화하는 실시간 채팅</div>\n      <div class=\"tabs\">\n        <button id=\"loginTab\" class=\"active\">로그인</button>\n        <button id=\"signupTab\">회원가입</button>\n      </div>\n\n      <form id=\"authForm\">\n        <label for=\"nickname\">닉네임</label>\n        <input id=\"nickname\" autocomplete=\"username\" maxlength=\"16\" placeholder=\"2~16자\" required />\n        <label for=\"password\">비밀번호</label>\n        <input id=\"password\" type=\"password\" autocomplete=\"current-password\" minlength=\"6\" maxlength=\"72\" placeholder=\"6자 이상\" required />\n        <div id=\"authMessage\" class=\"message\"></div>\n        <button id=\"authButton\" class=\"primary\">로그인</button>\n      </form>\n      <div class=\"hint\">닉네임은 중복해서 사용할 수 없습니다. 비밀번호는 서버에서 해시 처리되어 저장됩니다.</div>\n    </div>\n  </section>\n\n  <section id=\"appView\" class=\"app hidden\">\n    <div class=\"shell\">\n      <aside class=\"sidebar\">\n        <div class=\"profile\">\n          <div class=\"userbox\">\n            <div id=\"myAvatar\" class=\"avatar\">T</div>\n            <div>\n              <div id=\"myNickname\" class=\"name\">-</div>\n              <div class=\"status\">● 접속 중</div>\n            </div>\n          </div>\n          <button id=\"logout\" class=\"logout\">로그아웃</button><a id=\"adminLink\" href=\"/admin\" class=\"logout hidden\" style=\"text-decoration:none\">관리자</a>\n        </div>\n\n        <div class=\"search-title\">친구 닉네임으로 찾기</div>\n        <div class=\"search-row\">\n          <input id=\"friendNickname\" maxlength=\"16\" placeholder=\"닉네임 입력\" />\n          <button id=\"searchBtn\">찾기</button>\n        </div>\n        <div id=\"searchResult\" class=\"search-result\"></div>\n\n        <div class=\"chat-list\">\n          <div class=\"list-title\">최근 대화</div>\n          <div id=\"recentChats\"></div>\n        </div>\n      </aside>\n\n      <main class=\"chat\">\n        <header class=\"chat-head\">\n          <div id=\"chatHeader\" class=\"chat-title\">\n            <span class=\"online-dot\"></span>\n            <h2>대화할 사람을 찾아보세요</h2>\n          </div>\n          <button id=\"mobileSearchBtn\" class=\"mobile-search-btn\" type=\"button\">사람 찾기</button>\n        </header>\n        <div id=\"messages\" class=\"chat-messages\">\n          <div class=\"welcome\"><div><strong>톡온에 오신 것을 환영해요 👋</strong>왼쪽에서 상대방의 닉네임을 입력해 대화를 시작하세요.</div></div>\n        </div>\n        <div>\n          <div id=\"typing\" class=\"typing\"></div>\n          <form id=\"composer\" class=\"composer\">\n            <input id=\"messageInput\" maxlength=\"1000\" placeholder=\"메시지를 입력하세요\" disabled />\n            <button class=\"send\" disabled>전송</button>\n          </form>\n        </div>\n      </main>\n    </div>\n  </section>\n\n  <script src=\"/socket.io/socket.io.js\"></script>\n  <script>\n    const state = {\n      user: null,\n      socket: null,\n      activeUser: null,\n      recent: new Map(),\n      typingTimer: null,\n    };\n\n    const $ = (id) => document.getElementById(id);\n\n    const loginTab = $('loginTab');\n    const signupTab = $('signupTab');\n    const authForm = $('authForm');\n    const authButton = $('authButton');\n    const authMessage = $('authMessage');\n    let mode = 'login';\n\n    async function requestJson(url, options) {\n      const res = await fetch(url, options);\n      const text = await res.text();\n      let data;\n      try {\n        data = text ? JSON.parse(text) : {};\n      } catch {\n        throw new Error(`서버 응답 오류 (${res.status})`);\n      }\n      if (!res.ok) throw new Error(data.message || '요청에 실패했습니다.');\n      return data;\n    }\n\n    function setMode(next) {\n      mode = next;\n      loginTab.classList.toggle('active', mode === 'login');\n      signupTab.classList.toggle('active', mode === 'signup');\n      authButton.textContent = mode === 'login' ? '로그인' : '회원가입';\n      $('password').autocomplete = mode === 'login' ? 'current-password' : 'new-password';\n      authMessage.textContent = '';\n    }\n\n    loginTab.onclick = () => setMode('login');\n    signupTab.onclick = () => setMode('signup');\n\n    authForm.onsubmit = async (e) => {\n      e.preventDefault();\n      authMessage.textContent = '';\n      authButton.disabled = true;\n      try {\n        const endpoint = mode === 'login' ? '/api/login' : '/api/signup';\n        const data = await requestJson(endpoint, {\n          method: 'POST',\n          headers: { 'Content-Type': 'application/json' },\n          body: JSON.stringify({ nickname: $('nickname').value, password: $('password').value })\n        });\n        await enterApp(data.user);\n      } catch (err) {\n        authMessage.textContent = err.message;\n      } finally {\n        authButton.disabled = false;\n      }\n    };\n\n    $('logout').onclick = async () => {\n      await fetch('/api/logout', { method: 'POST' });\n      location.reload();\n    };\n\n    async function enterApp(user) {\n      state.user = user;\n      $('authView').classList.add('hidden');\n      $('appView').classList.remove('hidden');\n      $('myNickname').textContent = user.nickname;\n      $('myAvatar').textContent = user.nickname.charAt(0).toUpperCase();\n      $('adminLink').classList.toggle('hidden', !user.isAdmin);\n      await loadRecentChats();\n      connectSocket();\n    }\n\n    async function loadRecentChats() {\n      try {\n        const data = await requestJson('/api/chats');\n        state.recent.clear();\n        for (const chat of (data.chats || [])) {\n          state.recent.set(chat.id, chat);\n        }\n        renderRecent();\n      } catch (err) {\n        console.error('최근 대화 불러오기 실패', err);\n      }\n    }\n\nfunction connectSocket() {\n      state.socket = io({ transports: ['websocket', 'polling'] });\n\n      state.socket.on('connect', () => {\n        if (state.activeUser) refreshPresenceHeader();\n      });\n\n      state.socket.on('connect_error', (err) => {\n        if (err.message.includes('만료')) location.reload();\n      });\n\n      state.socket.on('presence:update', ({ userId, online }) => {\n        if (state.activeUser?.id === Number(userId)) {\n          state.activeUser.online = online;\n          refreshPresenceHeader();\n        }\n        renderRecent();\n      });\n\n      state.socket.on('chat:new', (message) => {\n        if (!state.activeUser) return;\n        const belongs =\n          (message.sender_id === state.user.id && message.receiver_id === state.activeUser.id) ||\n          (message.sender_id === state.activeUser.id && message.receiver_id === state.user.id);\n        if (!belongs) {\n          const otherId = message.sender_id === state.user.id ? message.receiver_id : message.sender_id;\n          const otherName = message.sender_id === state.user.id ? state.activeUser.nickname : message.sender_nickname;\n          state.recent.set(otherId, { id: otherId, nickname: otherName, last: message.body });\n          renderRecent();\n          return;\n        }\n        appendMessage(message);\n        const otherId = message.sender_id === state.user.id ? message.receiver_id : message.sender_id;\n        const otherName = message.sender_id === state.user.id ? state.activeUser.nickname : message.sender_nickname;\n        state.recent.set(otherId, { id: otherId, nickname: otherName, last: message.body });\n        renderRecent();\n      });\n\n      state.socket.on('chat:typing', ({ userId, nickname, typing }) => {\n        if (state.activeUser?.id === Number(userId)) $('typing').textContent = typing ? `${nickname}님이 입력 중...` : '';\n      });\n    }\n\n    $('searchBtn').onclick = searchFriend;\n    $('mobileSearchBtn').onclick = async () => {\n      const nickname = window.prompt('찾을 사람의 닉네임을 입력하세요.');\n      if (nickname === null) return;\n      const value = nickname.trim();\n      if (!value) return;\n      try {\n        const data = await requestJson('/api/users/search?nickname=' + encodeURIComponent(value));\n        if (!data.found) {\n          window.alert('해당 닉네임의 사용자를 찾을 수 없습니다.');\n          return;\n        }\n        await openChat(data.user);\n      } catch (err) {\n        window.alert(err.message);\n      }\n    };\n    $('friendNickname').addEventListener('keydown', (e) => {\n      if (e.key === 'Enter') { e.preventDefault(); searchFriend(); }\n    });\n\n    async function searchFriend() {\n      const nickname = $('friendNickname').value.trim();\n      const box = $('searchResult');\n      box.innerHTML = '';\n      if (!nickname) return;\n      const data = await requestJson('/api/users/search?nickname=' + encodeURIComponent(nickname));\n      if (!data.found) {\n        box.innerHTML = '<div class=\"empty-card\">해당 닉네임의 사용자를 찾을 수 없습니다.</div>';\n        return;\n      }\n      const card = document.createElement('div');\n      card.className = 'result-card';\n      const left = document.createElement('div');\n      left.innerHTML = `<div class=\"name\"></div><div class=\"status\"></div>`;\n      left.querySelector('.name').textContent = data.user.nickname;\n      left.querySelector('.status').textContent = data.user.online ? '● 온라인' : '○ 오프라인';\n      const actions = document.createElement('div');\n      actions.style.cssText = 'display:flex;gap:6px;flex-shrink:0;flex-wrap:wrap;';\n      const btn = document.createElement('button');\n      btn.className = 'open';\n      btn.textContent = '대화하기';\n      btn.onclick = () => openChat(data.user);\n      const reportBtn = document.createElement('button');\n      reportBtn.className = 'open';\n      reportBtn.textContent = '신고';\n      reportBtn.style.background = '#fff0f0';\n      reportBtn.style.color = '#b42336';\n      reportBtn.onclick = async () => {\n        const reason = window.prompt('신고 사유를 입력해주세요.');\n        if (reason === null || !reason.trim()) return;\n        const details = window.prompt('추가 설명(선택사항)을 입력해주세요.') || '';\n        try {\n          await requestJson('/api/reports', {\n            method: 'POST',\n            headers: { 'Content-Type': 'application/json' },\n            body: JSON.stringify({ userId: data.user.id, reason: reason.trim(), details: details.trim() })\n          });\n          window.alert('신고가 접수되었습니다.');\n        } catch (err) {\n          window.alert(err.message);\n        }\n      };\n      actions.append(btn, reportBtn);\n      card.append(left, actions);\n      box.appendChild(card);\n    }\n\n    async function openChat(user) {\n      state.activeUser = user;\n      refreshPresenceHeader();\n      $('messageInput').disabled = false;\n      $('composer').querySelector('button').disabled = false;\n      $('messageInput').focus();\n      $('typing').textContent = '';\n\n      let data;\n      try {\n        data = await requestJson('/api/messages/' + user.id);\n      } catch (err) {\n        $('messages').innerHTML = '';\n        const notice = document.createElement('div');\n        notice.className = 'notice';\n        notice.textContent = err.message;\n        $('messages').appendChild(notice);\n        return;\n      }\n\n      $('messages').innerHTML = '';\n      if (data.messages.length === 0) {\n        const notice = document.createElement('div');\n        notice.className = 'notice';\n        notice.textContent = `${user.nickname}님과의 대화를 시작해 보세요.`;\n        $('messages').appendChild(notice);\n      } else {\n        data.messages.forEach(appendMessage);\n      }\n      state.recent.set(user.id, { id: user.id, nickname: user.nickname, last: data.messages.at(-1)?.body || '' });\n      renderRecent();\n      scrollBottom();\n    }\n\n    function refreshPresenceHeader() {\n      const h = $('chatHeader');\n      h.innerHTML = '';\n      const dot = document.createElement('span');\n      dot.className = 'online-dot' + (state.activeUser?.online ? ' on' : '');\n      const title = document.createElement('h2');\n      title.textContent = state.activeUser ? state.activeUser.nickname : '대화할 사람을 찾아보세요';\n      h.append(dot, title);\n    }\n\n    function appendMessage(message) {\n      const wrap = document.createElement('div');\n      const mine = message.sender_id === state.user.id;\n      wrap.className = 'bubble-row ' + (mine ? 'mine' : 'other');\n\n      const bubble = document.createElement('div');\n      bubble.className = 'bubble';\n      bubble.textContent = message.body;\n      const time = document.createElement('span');\n      time.className = 'time';\n      const raw = String(message.created_at || '');\n      const parsed = /Z$|[+-]\\d\\d:\\d\\d$/.test(raw) ? new Date(raw) : new Date(raw.replace(' ', 'T') + 'Z');\n      time.textContent = parsed.toLocaleTimeString('ko-KR', { hour: '2-digit', minute: '2-digit' });\n      wrap.append(bubble, time);\n      $('messages').appendChild(wrap);\n      scrollBottom();\n    }\n\n    function scrollBottom() {\n      requestAnimationFrame(() => {\n        $('messages').scrollTop = $('messages').scrollHeight;\n      });\n    }\n\n    $('composer').onsubmit = (e) => {\n      e.preventDefault();\n      sendMessage();\n    };\n\n    $('messageInput').addEventListener('input', () => {\n      if (!state.activeUser || !state.socket) return;\n      state.socket.emit('chat:typing', { receiverId: state.activeUser.id, typing: $('messageInput').value.length > 0 });\n      clearTimeout(state.typingTimer);\n      state.typingTimer = setTimeout(() => {\n        state.socket.emit('chat:typing', { receiverId: state.activeUser.id, typing: false });\n      }, 900);\n    });\n\n    function sendMessage() {\n      if (!state.activeUser || !state.socket) return;\n      const body = $('messageInput').value.trim();\n      if (!body) return;\n      state.socket.emit('chat:send', { receiverId: state.activeUser.id, body }, (result) => {\n        if (!result?.ok) return alert(result?.message || '전송에 실패했습니다.');\n        $('messageInput').value = '';\n        state.socket.emit('chat:typing', { receiverId: state.activeUser.id, typing: false });\n      });\n    }\n\n    function renderRecent() {\n      const root = $('recentChats');\n      root.innerHTML = '';\n      if (state.recent.size === 0) {\n        root.innerHTML = '<div class=\"empty-card\">아직 대화가 없습니다.</div>';\n        return;\n      }\n      [...state.recent.values()].slice(-12).reverse().forEach(item => {\n        const btn = document.createElement('button');\n        btn.className = 'chat-item';\n        const av = document.createElement('div');\n        av.className = 'small-avatar';\n        av.textContent = item.nickname.charAt(0).toUpperCase();\n        const meta = document.createElement('div');\n        meta.className = 'meta';\n        const name = document.createElement('div');\n        name.className = 'name';\n        name.textContent = item.nickname;\n        const last = document.createElement('div');\n        last.className = 'last';\n        last.textContent = item.last || '대화 시작하기';\n        meta.append(name, last);\n        btn.append(av, meta);\n        btn.onclick = () => openChat(item);\n        root.appendChild(btn);\n      });\n    }\n\n    async function boot() {\n      try {\n        const data = await requestJson('/api/me');\n        if (data.loggedIn) await enterApp(data.user);\n      } catch (err) {\n        authMessage.textContent = err.message;\n      }\n    }\n\n    boot();\n  </script>\n</body>\n</html>\n";

const io = new Server(server);

io.use(async (socket, next) => {
  try {
    const cookieHeader = socket.handshake.headers?.cookie || '';
    const cookieToken = cookieHeader
      .split(';')
      .map(v => v.trim())
      .find(v => v.startsWith(COOKIE_NAME + '='))
      ?.slice(COOKIE_NAME.length + 1);
    const rawToken = socket.handshake.auth?.token || cookieToken;
    if (!rawToken) return next(new Error('로그인이 필요합니다.'));

    const token = decodeURIComponent(rawToken);
    const { rows } = await pool.query(
      `SELECT s.user_id, u.nickname, u.is_admin, u.is_banned
         FROM sessions s
         JOIN users u ON u.id = s.user_id
        WHERE s.token = $1 AND s.expires_at > $2`,
      [token, Date.now()]
    );
    const session = rows[0];
    if (!session || session.is_banned) return next(new Error('세션이 만료되었거나 계정이 정지되었습니다.'));

    socket.data.user = {
      id: Number(session.user_id),
      nickname: session.nickname,
      is_admin: Boolean(session.is_admin),
      token,
    };
    next();
  } catch (error) {
    next(new Error('서버 연결에 실패했습니다.'));
  }
});

io.on('connection', (socket) => {
  const me = socketUser(socket);
  joinOnline(me.id, socket.id);
  socket.join(`user:${me.id}`);

  socket.on('chat:send', async (payload, ack) => {
    try {
      const receiverId = Number(payload?.receiverId);
      const body = cleanMessage(payload?.body);
      const receiver = await findUserById(receiverId);

      if (!receiver || receiverId === me.id) {
        return ack?.({ ok: false, message: '대화 상대가 올바르지 않습니다.' });
      }
      if (!body) return ack?.({ ok: false, message: '메시지를 입력하세요.' });

      const inserted = await pool.query(
        `INSERT INTO messages (conversation_key, sender_id, receiver_id, body)
         VALUES ($1, $2, $3, $4)
         RETURNING id, created_at`,
        [conversationKey(me.id, receiver.id), me.id, receiver.id, body]
      );

      const row = inserted.rows[0];
      const message = {
        id: Number(row.id),
        sender_id: me.id,
        receiver_id: Number(receiver.id),
        body,
        created_at: row.created_at,
        sender_nickname: me.nickname,
      };

      io.to(`user:${me.id}`).emit('chat:new', message);
      io.to(`user:${receiver.id}`).emit('chat:new', message);
      ack?.({ ok: true, message });
    } catch (error) {
      console.error('chat:send error', error);
      ack?.({ ok: false, message: '메시지 저장 중 오류가 발생했습니다.' });
    }
  });

  socket.on('chat:typing', ({ receiverId, typing }) => {
    const id = Number(receiverId);
    if (!id || id === me.id) return;
    io.to(`user:${id}`).emit('chat:typing', {
      userId: me.id,
      nickname: me.nickname,
      typing: Boolean(typing),
    });
  });

  socket.on('disconnect', () => {
    leaveOnline(me.id, socket.id);
  });
});

setInterval(() => {
  pool.query(`DELETE FROM sessions WHERE expires_at <= $1`, [Date.now()]).catch(error => {
    console.error('session cleanup error', error);
  });
}, 60 * 60 * 1000).unref();

app.use((error, req, res, next) => {
  console.error(error);
  if (req.path.startsWith('/api/')) {
    return res.status(500).json({ ok: false, message: '서버 오류가 발생했습니다.' });
  }
  next(error);
});

app.get('/admin', async (req, res, next) => {
  try {
    const user = await currentUser(req);
    if (!user) {
      return res.status(401).type('html').send(
        '<!doctype html><html lang="ko"><meta charset="utf-8"><title>토킹온 관리자</title><body style="font-family:sans-serif;padding:40px"><h1>로그인이 필요합니다.</h1><p>토킹온에 관리자 계정으로 로그인한 뒤 다시 열어주세요.</p><a href="/">토킹온으로 돌아가기</a></body></html>'
      );
    }
    if (!user.is_admin) {
      return res.status(403).type('html').send(
        '<!doctype html><html lang="ko"><meta charset="utf-8"><title>접근 거부</title><body style="font-family:sans-serif;padding:40px"><h1>관리자 권한이 없습니다.</h1><a href="/">토킹온으로 돌아가기</a></body></html>'
      );
    }
    res.type('html').send(await readFile(path.join(__dirname, 'admin.html'), 'utf8'));
  } catch (error) {
    next(error);
  }
});

app.get('/{*splat}', (req, res) => {
  res.type('html').send(INDEX_HTML);
});

async function start() {
  await initDatabase();
  server.listen(PORT, '0.0.0.0', () => {
    console.log(`TalkOn running on port ${PORT}`);
  });
}

start().catch(error => {
  console.error('TalkOn startup failed:', error);
  process.exit(1);
});

process.on('SIGTERM', async () => {
  await pool.end().catch(() => {});
  process.exit(0);
});
