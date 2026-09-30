// partnerka.io — лендинг раннего доступа.
// Регистрация с паролем → код подтверждения на почту → кабинет-заглушка с формой контакта.
// Лиды и обращения сохраняются в SQLite и отправляются в канал Mattermost.

import express from 'express';
import nodemailer from 'nodemailer';
import { DatabaseSync } from 'node:sqlite';
import { scryptSync, randomBytes, randomInt, timingSafeEqual, createHash } from 'node:crypto';
import { mkdirSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const env = process.env;
const PORT = Number(env.PORT || 3000);
const IS_PROD = env.NODE_ENV === 'production';
const DATA_DIR = env.DATA_DIR || path.join(__dirname, 'data');
const MM_WEBHOOK = env.MATTERMOST_WEBHOOK_URL || '';
const SMTP_READY = Boolean(env.SMTP_HOST && env.SMTP_USER && env.SMTP_PASS);
const CODE_TTL_MIN = 15, CODE_MAX_ATTEMPTS = 5, RESEND_COOLDOWN_S = 30, SESSION_DAYS = 30;
const PLANS = { start: 'Старт', plus: 'Плюс', premium: 'Премиум', ultra: 'Ультра', unknown: 'Пока не выбран' };

if (IS_PROD && !SMTP_READY) console.warn('[warn] SMTP не настроен: письма с кодом не будут отправляться');
if (IS_PROD && !MM_WEBHOOK) console.warn('[warn] MATTERMOST_WEBHOOK_URL не задан: лиды сохраняются только в базе');

// ---------- база ----------
mkdirSync(DATA_DIR, { recursive: true });
const db = new DatabaseSync(path.join(DATA_DIR, 'partnerka.db'));
db.exec(`
  PRAGMA journal_mode = WAL;
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    plan TEXT NOT NULL DEFAULT 'unknown',
    verified_at TEXT,
    code_hash TEXT, code_expires_at INTEGER, code_attempts INTEGER NOT NULL DEFAULT 0, code_sent_at INTEGER,
    utm TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
  );
  CREATE TABLE IF NOT EXISTS sessions (
    token_hash TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id),
    expires_at INTEGER NOT NULL
  );
  CREATE TABLE IF NOT EXISTS leads (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    kind TEXT NOT NULL,
    user_id INTEGER REFERENCES users(id),
    email TEXT, channel TEXT, contact TEXT, product TEXT, company TEXT, phone TEXT, message TEXT, plan TEXT, utm TEXT,
    delivered INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
  );
`);
const q = {
  userByEmail: db.prepare('SELECT * FROM users WHERE email = ?'),
  userById: db.prepare('SELECT * FROM users WHERE id = ?'),
  insertUser: db.prepare('INSERT INTO users (email, password_hash, plan, utm) VALUES (?, ?, ?, ?)'),
  updatePending: db.prepare('UPDATE users SET password_hash = ?, plan = ?, utm = COALESCE(?, utm) WHERE id = ?'),
  setCode: db.prepare('UPDATE users SET code_hash = ?, code_expires_at = ?, code_attempts = 0, code_sent_at = ? WHERE id = ?'),
  bumpAttempts: db.prepare('UPDATE users SET code_attempts = code_attempts + 1 WHERE id = ?'),
  verify: db.prepare("UPDATE users SET verified_at = datetime('now'), code_hash = NULL, code_expires_at = NULL WHERE id = ?"),
  insertSession: db.prepare('INSERT INTO sessions (token_hash, user_id, expires_at) VALUES (?, ?, ?)'),
  session: db.prepare('SELECT user_id FROM sessions WHERE token_hash = ? AND expires_at > ?'),
  deleteSession: db.prepare('DELETE FROM sessions WHERE token_hash = ?'),
  purgeSessions: db.prepare('DELETE FROM sessions WHERE expires_at <= ?'),
  insertLead: db.prepare('INSERT INTO leads (kind, user_id, email, channel, contact, product, company, phone, message, plan, utm) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)'),
  markDelivered: db.prepare('UPDATE leads SET delivered = 1 WHERE id = ?'),
  contactLead: db.prepare("SELECT channel, contact FROM leads WHERE user_id = ? AND kind = 'contact' ORDER BY id DESC LIMIT 1"),
};

// ---------- утилиты ----------
const sha256 = s => createHash('sha256').update(s).digest('hex');
const hashPassword = pw => { const salt = randomBytes(16); return `scrypt$${salt.toString('hex')}$${scryptSync(pw, salt, 64).toString('hex')}`; };
const checkPassword = (pw, stored) => {
  const [, saltHex, hashHex] = String(stored).split('$');
  if (!saltHex || !hashHex) return false;
  const a = scryptSync(pw, Buffer.from(saltHex, 'hex'), 64), b = Buffer.from(hashHex, 'hex');
  return a.length === b.length && timingSafeEqual(a, b);
};
const EMAIL_RE = /^[^\s@]{1,64}@[^\s@]{1,255}\.[^\s@]{2,}$/;
const normEmail = e => String(e || '').trim().toLowerCase();
const clip = (v, n = 300) => (v == null ? null : String(v).trim().slice(0, n) || null);
const cleanUtm = u => {
  if (!u || typeof u !== 'object') return null;
  const out = {};
  for (const k of ['utm_source', 'utm_medium', 'utm_campaign', 'utm_content', 'utm_term', 'seg', 'ref']) if (u[k]) out[k] = clip(u[k], 120);
  return Object.keys(out).length ? JSON.stringify(out) : null;
};
const esc = s => String(s ?? '').replace(/[|\n\r]/g, ' ').trim();

// простое ограничение частоты запросов в памяти процесса
const hits = new Map();
const limited = (key, max, windowMs) => {
  const now = Date.now(), arr = (hits.get(key) || []).filter(t => now - t < windowMs);
  arr.push(now); hits.set(key, arr);
  return arr.length > max;
};
setInterval(() => { const now = Date.now(); for (const [k, v] of hits) if (!v.some(t => now - t < 3600_000)) hits.delete(k); q.purgeSessions.run(now); }, 600_000).unref();

// ---------- почта ----------
const mailer = SMTP_READY ? nodemailer.createTransport({
  host: env.SMTP_HOST, port: Number(env.SMTP_PORT || 465), secure: String(env.SMTP_SECURE ?? (Number(env.SMTP_PORT || 465) === 465)) === 'true',
  auth: { user: env.SMTP_USER, pass: env.SMTP_PASS },
}) : null;
async function sendCode(email, code) {
  const subject = `${code} — код подтверждения partnerka.io`;
  const text = `Ваш код подтверждения: ${code}\n\nКод действует ${CODE_TTL_MIN} минут. Если вы не регистрировались на partnerka.io, просто проигнорируйте это письмо.`;
  const html = `<div style="font-family:Arial,sans-serif;max-width:480px;margin:0 auto;padding:24px;color:#090B22">
    <div style="font-size:20px;font-weight:600">partnerka<span style="color:#4B5BEA">.io</span></div>
    <p style="font-size:16px;margin:24px 0 8px">Ваш код подтверждения:</p>
    <div style="font-size:32px;font-weight:700;letter-spacing:6px;background:#F6F6F8;border-radius:12px;padding:16px 20px;display:inline-block">${code}</div>
    <p style="font-size:14px;color:#68686A;margin-top:20px">Код действует ${CODE_TTL_MIN} минут. Если вы не регистрировались на partnerka.io, просто проигнорируйте это письмо.</p></div>`;
  if (!mailer) { console.log(`[dev] код для ${email}: ${code}`); return; }
  await mailer.sendMail({ from: env.SMTP_FROM || env.SMTP_USER, to: email, subject, text, html });
}

// ---------- Mattermost ----------
async function notifyMattermost(leadId, title, rows) {
  const table = ['| | |', '|:--|:--|', ...rows.filter(([, v]) => v).map(([k, v]) => `| ${k} | ${esc(v)} |`)].join('\n');
  const text = `#### ${title}\n${table}`;
  if (!MM_WEBHOOK) { console.log('[dev] mattermost:\n' + text); return; }
  try {
    const r = await fetch(MM_WEBHOOK, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ username: 'partnerka.io', text }) });
    if (r.ok) q.markDelivered.run(leadId); else console.error('[mattermost]', r.status, await r.text());
  } catch (e) { console.error('[mattermost]', e.message); }
}
const utmRow = utm => { try { const u = JSON.parse(utm || '{}'); return Object.entries(u).map(([k, v]) => `${k}=${v}`).join(', '); } catch { return ''; } };

// ---------- сессии ----------
const COOKIE = 'pk_session';
const readCookie = (req, name) => { const m = (req.headers.cookie || '').match(new RegExp(`(?:^|;\\s*)${name}=([^;]+)`)); return m ? decodeURIComponent(m[1]) : null; };
function startSession(res, userId) {
  const token = randomBytes(32).toString('base64url');
  q.insertSession.run(sha256(token), userId, Date.now() + SESSION_DAYS * 864e5);
  res.cookie(COOKIE, token, { httpOnly: true, secure: IS_PROD, sameSite: 'lax', maxAge: SESSION_DAYS * 864e5, path: '/' });
}
function currentUser(req) {
  const token = readCookie(req, COOKIE); if (!token) return null;
  const s = q.session.get(sha256(token), Date.now()); if (!s) return null;
  const u = q.userById.get(s.user_id);
  return u && u.verified_at ? u : null;
}

// ---------- приложение ----------
const app = express();
app.disable('x-powered-by');
app.set('trust proxy', 1);
app.use(express.json({ limit: '20kb' }));
app.use((req, res, next) => {
  res.set({ 'X-Content-Type-Options': 'nosniff', 'Referrer-Policy': 'strict-origin-when-cross-origin', 'X-Frame-Options': 'SAMEORIGIN' });
  next();
});
// все POST-запросы API принимаем только в JSON: так форму с чужого сайта не отправить
app.use('/api', (req, res, next) => (req.method === 'POST' && !req.is('application/json') ? res.status(415).json({ error: 'Неверный формат запроса' }) : next()));
const fail = (res, status, error, extra = {}) => res.status(status).json({ error, ...extra });

async function issueCode(user) {
  const code = String(randomInt(0, 1_000_000)).padStart(6, '0');
  q.setCode.run(sha256(`${user.id}:${code}`), Date.now() + CODE_TTL_MIN * 60_000, Date.now(), user.id);
  await sendCode(user.email, code);
}

app.post('/api/signup', async (req, res) => {
  const { email: rawEmail, password, plan, consent, utm } = req.body || {};
  const email = normEmail(rawEmail);
  if (limited(`signup:${req.ip}`, 10, 3600_000)) return fail(res, 429, 'Слишком много попыток. Попробуйте через час.');
  if (!EMAIL_RE.test(email)) return fail(res, 400, 'Укажите корректный e-mail.');
  if (typeof password !== 'string' || password.length < 8 || password.length > 200) return fail(res, 400, 'Пароль должен быть не короче 8 символов.');
  if (!consent) return fail(res, 400, 'Нужно дать согласие на обработку персональных данных.');
  const planKey = PLANS[plan] ? plan : 'unknown';
  let user = q.userByEmail.get(email);
  if (user && user.verified_at) return fail(res, 409, 'Аккаунт с этой почтой уже есть. Войдите.', { code: 'exists' });
  if (user) q.updatePending.run(hashPassword(password), planKey, cleanUtm(utm), user.id);
  else q.insertUser.run(email, hashPassword(password), planKey, cleanUtm(utm));
  user = q.userByEmail.get(email);
  try { await issueCode(user); } catch (e) { console.error('[mail]', e.message); return fail(res, 502, 'Не удалось отправить письмо. Проверьте адрес или попробуйте позже.'); }
  res.json({ ok: true, email });
});

app.post('/api/resend', async (req, res) => {
  const email = normEmail(req.body?.email);
  const user = q.userByEmail.get(email);
  if (!user || user.verified_at) return res.json({ ok: true });
  const wait = RESEND_COOLDOWN_S - Math.floor((Date.now() - (user.code_sent_at || 0)) / 1000);
  if (wait > 0) return fail(res, 429, `Повторно отправить можно через ${wait} с.`, { wait });
  if (limited(`resend:${email}`, 5, 3600_000)) return fail(res, 429, 'Слишком много писем. Попробуйте позже.');
  try { await issueCode(user); } catch (e) { console.error('[mail]', e.message); return fail(res, 502, 'Не удалось отправить письмо. Попробуйте позже.'); }
  res.json({ ok: true });
});

app.post('/api/verify', async (req, res) => {
  const email = normEmail(req.body?.email), code = String(req.body?.code || '').replace(/\D/g, '');
  const user = q.userByEmail.get(email);
  if (!user || user.verified_at) return fail(res, 400, 'Код устарел. Запросите новый.');
  if (!user.code_hash || Date.now() > user.code_expires_at) return fail(res, 400, 'Срок действия кода истёк. Отправьте код ещё раз.');
  if (user.code_attempts >= CODE_MAX_ATTEMPTS) return fail(res, 429, 'Слишком много неверных попыток. Отправьте код ещё раз.');
  if (sha256(`${user.id}:${code}`) !== user.code_hash) { q.bumpAttempts.run(user.id); return fail(res, 400, 'Неверный код. Проверьте письмо.'); }
  q.verify.run(user.id);
  startSession(res, user.id);
  const lead = q.insertLead.run('signup', user.id, user.email, null, null, null, null, null, null, user.plan, user.utm);
  notifyMattermost(Number(lead.lastInsertRowid), '✅ Регистрация подтверждена', [['E-mail', user.email], ['Тариф', PLANS[user.plan]], ['Источник', utmRow(user.utm)]]);
  res.json({ ok: true, redirect: '/app' });
});

app.post('/api/login', async (req, res) => {
  const email = normEmail(req.body?.email), password = String(req.body?.password || '');
  if (limited(`login:${req.ip}`, 20, 900_000)) return fail(res, 429, 'Слишком много попыток входа. Попробуйте через 15 минут.');
  const user = q.userByEmail.get(email);
  if (!user || !checkPassword(password, user.password_hash)) return fail(res, 401, 'Неверная почта или пароль.');
  if (!user.verified_at) {
    try { await issueCode(user); } catch (e) { console.error('[mail]', e.message); return fail(res, 502, 'Не удалось отправить письмо. Попробуйте позже.'); }
    return res.json({ ok: true, needVerify: true, email });
  }
  startSession(res, user.id);
  res.json({ ok: true, redirect: '/app' });
});

app.post('/api/logout', (req, res) => {
  const token = readCookie(req, COOKIE); if (token) q.deleteSession.run(sha256(token));
  res.clearCookie(COOKIE, { path: '/' }); res.json({ ok: true });
});

app.get('/api/me', (req, res) => {
  const u = currentUser(req); if (!u) return res.json({ authenticated: false });
  const c = q.contactLead.get(u.id);
  res.json({ authenticated: true, email: u.email, plan: u.plan, planName: PLANS[u.plan], contact: c || null });
});

const CHANNELS = { telegram: 'Telegram', max: 'MAX' };
app.post('/api/lead', async (req, res) => {
  const u = currentUser(req); if (!u) return fail(res, 401, 'Войдите, чтобы оставить контакт.');
  if (limited(`lead:${u.id}`, 10, 3600_000)) return fail(res, 429, 'Слишком много попыток. Попробуйте позже.');
  const channel = CHANNELS[req.body?.channel] ? req.body.channel : null;
  const contact = clip(req.body?.contact, 64), product = clip(req.body?.product, 300);
  if (!channel || !contact) return fail(res, 400, 'Укажите контакт в Telegram или MAX.');
  const ok = channel === 'telegram' ? /^(@?[a-zA-Z0-9_]{5,32}|\+?[\d\s()-]{10,20})$/.test(contact) : /^(@?[a-zA-Z0-9_.]{3,32}|\+?[\d\s()-]{10,20})$/.test(contact);
  if (!ok) return fail(res, 400, channel === 'telegram' ? 'Укажите ник в Telegram (например, @username) или номер телефона.' : 'Укажите ник или номер телефона в MAX.');
  const lead = q.insertLead.run('contact', u.id, u.email, channel, contact, product, null, null, null, u.plan, u.utm);
  await notifyMattermost(Number(lead.lastInsertRowid), '🟢 Новый лид раннего доступа', [
    ['E-mail', u.email], [CHANNELS[channel], contact], ['Тариф', PLANS[u.plan]], ['Продукт', product], ['Источник', utmRow(u.utm)],
  ]);
  res.json({ ok: true, channel, contact });
});

// обращения из окна поддержки и «Подобрать решение»
app.post('/api/request', async (req, res) => {
  if (limited(`request:${req.ip}`, 10, 3600_000)) return fail(res, 429, 'Слишком много обращений. Попробуйте позже.');
  const { kind, email: rawEmail, message, company, phone, consent, utm } = req.body || {};
  const email = normEmail(rawEmail), type = kind === 'demo' ? 'demo' : 'support';
  if (!EMAIL_RE.test(email)) return fail(res, 400, 'Укажите корректный e-mail.');
  if (!consent) return fail(res, 400, 'Нужно дать согласие на обработку персональных данных.');
  if (type === 'support' && !clip(message)) return fail(res, 400, 'Напишите пару слов о вашем проекте.');
  if (type === 'demo' && !clip(phone, 40)) return fail(res, 400, 'Укажите телефон, чтобы мы могли связаться.');
  const lead = q.insertLead.run(type, null, email, null, null, null, clip(company, 120), clip(phone, 40), clip(message, 2000), null, cleanUtm(utm));
  await notifyMattermost(Number(lead.lastInsertRowid), type === 'demo' ? '📝 Заявка «Подобрать решение»' : '💬 Вопрос в поддержку', [
    ['E-mail', email], ['Компания', clip(company, 120)], ['Телефон', clip(phone, 40)], ['Сообщение', clip(message, 2000)], ['Источник', utmRow(cleanUtm(utm))],
  ]);
  res.json({ ok: true });
});

app.get('/healthz', (req, res) => res.json({ ok: true }));

// кабинет-заглушка доступен только после подтверждения почты
app.get(['/app', '/app/'], (req, res) => (currentUser(req) ? res.sendFile(path.join(__dirname, 'public', 'app.html')) : res.redirect('/?login=1')));
app.use(express.static(path.join(__dirname, 'public'), { extensions: ['html'], index: 'index.html', maxAge: IS_PROD ? '1h' : 0 }));
app.use((req, res) => res.status(404).sendFile(path.join(__dirname, 'public', 'index.html')));

app.listen(PORT, () => console.log(`partnerka.io слушает :${PORT} (${IS_PROD ? 'production' : 'development'}), SMTP: ${SMTP_READY ? 'настроен' : 'нет, коды в логах'}, Mattermost: ${MM_WEBHOOK ? 'настроен' : 'нет, сообщения в логах'}`));
