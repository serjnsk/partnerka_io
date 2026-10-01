// partnerka.io — лендинг и регистрация.
// Регистрация: почта, пароль, контакт в Telegram или MAX, название продукта → кабинет /app.
// Регистрации и обращения сохраняются в SQLite и отправляются в канал Mattermost.
// /admin — список лидов и выгрузка в CSV, вход по паролю ADMIN_PASSWORD.

import express from 'express';
import { DatabaseSync } from 'node:sqlite';
import { scryptSync, randomBytes, timingSafeEqual, createHash } from 'node:crypto';
import { mkdirSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const env = process.env;
const PORT = Number(env.PORT || 3000);
const IS_PROD = env.NODE_ENV === 'production';
const DATA_DIR = env.DATA_DIR || path.join(__dirname, 'data');
const MM_WEBHOOK = env.MATTERMOST_WEBHOOK_URL || '';
const ADMIN_PASSWORD = env.ADMIN_PASSWORD || '';
const ADMIN_DAYS = 7;
const SESSION_DAYS = 30;
const PLANS = { start: 'Старт', plus: 'Плюс', premium: 'Премиум', ultra: 'Ультра' };
const CHANNELS = { telegram: 'Telegram', max: 'MAX' };

if (IS_PROD && !MM_WEBHOOK) console.warn('[warn] MATTERMOST_WEBHOOK_URL не задан: регистрации сохраняются только в базе');
if (!ADMIN_PASSWORD) console.warn('[warn] ADMIN_PASSWORD не задан: страница /admin отключена');
else if (ADMIN_PASSWORD.length < 12) console.warn('[warn] ADMIN_PASSWORD короче 12 символов, лучше задать длиннее');

// ---------- база ----------
mkdirSync(DATA_DIR, { recursive: true });
const db = new DatabaseSync(path.join(DATA_DIR, 'partnerka.db'));
db.exec(`
  PRAGMA journal_mode = WAL;
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    plan TEXT NOT NULL DEFAULT 'plus',
    channel TEXT, contact TEXT, product TEXT,
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
  CREATE TABLE IF NOT EXISTS admin_sessions (
    token_hash TEXT PRIMARY KEY,
    pw_tag TEXT NOT NULL,
    expires_at INTEGER NOT NULL
  );
`);
// база с прошлой версии (с подтверждением почты): добавляем недостающие колонки
const userCols = new Set(db.prepare('PRAGMA table_info(users)').all().map(c => c.name));
for (const col of ['channel', 'contact', 'product']) if (!userCols.has(col)) db.exec(`ALTER TABLE users ADD COLUMN ${col} TEXT`);

const q = {
  userByEmail: db.prepare('SELECT * FROM users WHERE email = ?'),
  userById: db.prepare('SELECT * FROM users WHERE id = ?'),
  insertUser: db.prepare('INSERT INTO users (email, password_hash, plan, channel, contact, product, utm) VALUES (?, ?, ?, ?, ?, ?, ?)'),
  insertSession: db.prepare('INSERT INTO sessions (token_hash, user_id, expires_at) VALUES (?, ?, ?)'),
  session: db.prepare('SELECT user_id FROM sessions WHERE token_hash = ? AND expires_at > ?'),
  deleteSession: db.prepare('DELETE FROM sessions WHERE token_hash = ?'),
  purgeSessions: db.prepare('DELETE FROM sessions WHERE expires_at <= ?'),
  insertLead: db.prepare('INSERT INTO leads (kind, user_id, email, channel, contact, product, company, phone, message, plan, utm) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)'),
  markDelivered: db.prepare('UPDATE leads SET delivered = 1 WHERE id = ?'),
  allLeads: db.prepare('SELECT id, kind, email, channel, contact, product, company, phone, message, plan, utm, delivered, created_at FROM leads ORDER BY id DESC'),
  insertAdminSession: db.prepare('INSERT INTO admin_sessions (token_hash, pw_tag, expires_at) VALUES (?, ?, ?)'),
  adminSession: db.prepare('SELECT 1 FROM admin_sessions WHERE token_hash = ? AND pw_tag = ? AND expires_at > ?'),
  deleteAdminSession: db.prepare('DELETE FROM admin_sessions WHERE token_hash = ?'),
  purgeAdminSessions: db.prepare('DELETE FROM admin_sessions WHERE expires_at <= ?'),
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
// контакт приводим к единому виду: ник Telegram → https://t.me/ник, номер оставляем как есть.
// Возвращает null, если формат не распознан.
const PHONE_RE = /^\+?[\d\s()-]{10,20}$/;
function normalizeContact(channel, raw) {
  const v = String(raw || '').trim();
  if (PHONE_RE.test(v) && v.replace(/\D/g, '').length >= 10) return v;
  if (channel === 'telegram') {
    const m = v.match(/^(?:https?:\/\/)?(?:www\.)?(?:t\.me|telegram\.me)\/@?([a-zA-Z0-9_]{5,32})\/?$/i) || v.match(/^@?([a-zA-Z0-9_]{5,32})$/);
    return m ? `https://t.me/${m[1]}` : null;
  }
  if (/^(?:https?:\/\/)?(?:web\.)?max\.ru\/\S{2,200}$/i.test(v)) return v.startsWith('http') ? v : `https://${v}`;
  return /^@?[a-zA-Z0-9_.]{3,32}$/.test(v) ? v : null;
}
const esc = s => String(s ?? '').replace(/[|\n\r]/g, ' ').trim();

// простое ограничение частоты запросов в памяти процесса
const hits = new Map();
const limited = (key, max, windowMs) => {
  const now = Date.now(), arr = (hits.get(key) || []).filter(t => now - t < windowMs);
  arr.push(now); hits.set(key, arr);
  return arr.length > max;
};
setInterval(() => { const now = Date.now(); for (const [k, v] of hits) if (!v.some(t => now - t < 3600_000)) hits.delete(k); q.purgeSessions.run(now); q.purgeAdminSessions.run(now); }, 600_000).unref();

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
  const s = q.session.get(sha256(token), Date.now());
  return s ? q.userById.get(s.user_id) || null : null;
}

// ---------- приложение ----------
const app = express();
app.disable('x-powered-by');
app.set('trust proxy', 1);
app.use(express.json({ limit: '20kb' }));
app.use((req, res, next) => {
  // www.partnerka.io → partnerka.io, чтобы у сайта был один адрес
  const host = String(req.headers.host || '');
  if (IS_PROD && host.startsWith('www.')) return res.redirect(301, `https://${host.slice(4)}${req.originalUrl}`);
  res.set({ 'X-Content-Type-Options': 'nosniff', 'Referrer-Policy': 'strict-origin-when-cross-origin', 'X-Frame-Options': 'SAMEORIGIN' });
  if (IS_PROD) res.set('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
  next();
});
// все POST-запросы API принимаем только в JSON: так форму с чужого сайта не отправить
app.use('/api', (req, res, next) => (req.method === 'POST' && !req.is('application/json') ? res.status(415).json({ error: 'Неверный формат запроса' }) : next()));
const fail = (res, status, error, extra = {}) => res.status(status).json({ error, ...extra });

app.post('/api/signup', async (req, res) => {
  const { email: rawEmail, password, plan, channel, contact: rawContact, product: rawProduct, consent, utm } = req.body || {};
  const email = normEmail(rawEmail), product = clip(rawProduct, 120);
  if (limited(`signup:${req.ip}`, 10, 3600_000)) return fail(res, 429, 'Слишком много попыток. Попробуйте через час.');
  if (!EMAIL_RE.test(email)) return fail(res, 400, 'Укажите корректный e-mail.');
  if (typeof password !== 'string' || password.length < 8 || password.length > 200) return fail(res, 400, 'Пароль должен быть не короче 8 символов.');
  if (!CHANNELS[channel] || !clip(rawContact)) return fail(res, 400, 'Укажите контакт в Telegram или MAX.');
  const contact = normalizeContact(channel, clip(rawContact, 220));
  if (!contact) return fail(res, 400, channel === 'telegram' ? 'Укажите ссылку на профиль вида https://t.me/username, @username или номер телефона.' : 'Укажите номер телефона, к которому привязан аккаунт в MAX.');
  if (!product || product.length < 2) return fail(res, 400, 'Укажите название продукта.');
  if (!consent) return fail(res, 400, 'Нужно дать согласие на обработку персональных данных.');
  if (q.userByEmail.get(email)) return fail(res, 409, 'Аккаунт с этой почтой уже есть. Войдите.', { code: 'exists' });
  const planKey = PLANS[plan] ? plan : 'plus', utmJson = cleanUtm(utm);
  const user = q.insertUser.run(email, hashPassword(password), planKey, channel, contact, product, utmJson);
  const userId = Number(user.lastInsertRowid);
  startSession(res, userId);
  const lead = q.insertLead.run('signup', userId, email, channel, contact, product, null, null, null, planKey, utmJson);
  await notifyMattermost(Number(lead.lastInsertRowid), '🟢 Новая регистрация', [
    ['Продукт', product], [CHANNELS[channel], contact], ['E-mail', email], ['Тариф', PLANS[planKey]], ['Источник', utmRow(utmJson)],
  ]);
  res.json({ ok: true, redirect: '/app' });
});

app.post('/api/login', (req, res) => {
  const email = normEmail(req.body?.email), password = String(req.body?.password || '');
  if (limited(`login:${req.ip}`, 20, 900_000)) return fail(res, 429, 'Слишком много попыток входа. Попробуйте через 15 минут.');
  const user = q.userByEmail.get(email);
  if (!user || !checkPassword(password, user.password_hash)) return fail(res, 401, 'Неверная почта или пароль.');
  startSession(res, user.id);
  res.json({ ok: true, redirect: '/app' });
});

app.post('/api/logout', (req, res) => {
  const token = readCookie(req, COOKIE); if (token) q.deleteSession.run(sha256(token));
  res.clearCookie(COOKIE, { path: '/' }); res.json({ ok: true });
});

app.get('/api/me', (req, res) => {
  const u = currentUser(req); if (!u) return res.json({ authenticated: false });
  res.json({ authenticated: true, email: u.email, plan: u.plan, planName: PLANS[u.plan] || null, channel: u.channel, channelName: CHANNELS[u.channel] || null, contact: u.contact, product: u.product });
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

// ---------- админка: лиды и выгрузка в CSV ----------
// Сессии админа привязаны к текущему паролю: после смены ADMIN_PASSWORD все входы сбрасываются.
const ADMIN_COOKIE = 'pk_admin';
const ADMIN_PW_TAG = ADMIN_PASSWORD ? sha256(`admin:${ADMIN_PASSWORD}`).slice(0, 16) : '';
const isAdmin = req => { const t = readCookie(req, ADMIN_COOKIE); return Boolean(ADMIN_PASSWORD && t && q.adminSession.get(sha256(t), ADMIN_PW_TAG, Date.now())); };
// contact — строки прошлой версии: тогда контакт и продукт приходили отдельно после подтверждения почты
const KINDS = { signup: 'Регистрация', contact: 'Регистрация: контакт', support: 'Поддержка', demo: 'Подобрать решение' };
const KIND_GROUPS = { signup: ['signup', 'contact'], support: ['support'], demo: ['demo'] };
const UTM_KEYS = ['utm_source', 'utm_medium', 'utm_campaign', 'utm_content', 'utm_term', 'seg', 'ref'];
const parseUtm = utm => { try { const u = JSON.parse(utm || '{}'); return u && typeof u === 'object' ? u : {}; } catch { return {}; } };
const leadRows = () => q.allLeads.all().map(l => ({ ...l, created_at: `${l.created_at.replace(' ', 'T')}Z`, delivered: Boolean(l.delivered), utm: parseUtm(l.utm) }));
const filterLeads = (leads, kind, search) => {
  const s = String(search || '').trim().toLowerCase();
  const group = KIND_GROUPS[kind];
  return leads.filter(l => (!group || group.includes(l.kind))
    && (!s || [l.email, l.contact, l.product, l.company, l.phone, l.message, ...Object.values(l.utm)].some(v => String(v ?? '').toLowerCase().includes(s))));
};
const mskDate = iso => new Intl.DateTimeFormat('ru-RU', { timeZone: 'Europe/Moscow', dateStyle: 'short', timeStyle: 'short' }).format(new Date(iso)).replace(',', '');
// значение ячейки CSV: кавычки, а ведущие = + - @ гасим апострофом, чтобы Excel не выполнил формулу
const csvCell = v => { let s = String(v ?? '').replace(/\r?\n/g, ' '); if (/^[=+\-@\t\r]/.test(s)) s = `'${s}`; return /[";\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s; };

app.use('/admin', (req, res, next) => (ADMIN_PASSWORD ? next() : res.status(404).sendFile(path.join(__dirname, 'public', 'index.html'))));
app.use(['/admin', '/api/admin'], (req, res, next) => { res.set({ 'X-Robots-Tag': 'noindex, nofollow', 'Cache-Control': 'no-store' }); next(); });
app.get(['/admin', '/admin/'], (req, res) => res.sendFile(path.join(__dirname, 'private', 'admin.html')));

app.post('/api/admin/login', (req, res) => {
  if (!ADMIN_PASSWORD) return fail(res, 404, 'Не найдено');
  if (limited(`admin:${req.ip}`, 10, 900_000)) return fail(res, 429, 'Слишком много попыток. Попробуйте через 15 минут.');
  const a = createHash('sha256').update(String(req.body?.password || '')).digest(), b = createHash('sha256').update(ADMIN_PASSWORD).digest();
  if (!timingSafeEqual(a, b)) return fail(res, 401, 'Неверный пароль.');
  const token = randomBytes(32).toString('base64url');
  q.insertAdminSession.run(sha256(token), ADMIN_PW_TAG, Date.now() + ADMIN_DAYS * 864e5);
  res.cookie(ADMIN_COOKIE, token, { httpOnly: true, secure: IS_PROD, sameSite: 'strict', maxAge: ADMIN_DAYS * 864e5, path: '/' });
  res.json({ ok: true });
});
app.post('/api/admin/logout', (req, res) => {
  const t = readCookie(req, ADMIN_COOKIE); if (t) q.deleteAdminSession.run(sha256(t));
  res.clearCookie(ADMIN_COOKIE, { path: '/' }); res.json({ ok: true });
});
app.use('/api/admin', (req, res, next) => (ADMIN_PASSWORD && isAdmin(req) ? next() : fail(res, ADMIN_PASSWORD ? 401 : 404, ADMIN_PASSWORD ? 'Нужно войти.' : 'Не найдено')));
app.get('/api/admin/leads', (req, res) => res.json({ leads: leadRows(), kinds: KINDS, plans: PLANS, channels: CHANNELS }));
app.get('/api/admin/leads.csv', (req, res) => {
  const leads = filterLeads(leadRows(), req.query.kind, req.query.q);
  const head = ['ID', 'Дата (МСК)', 'Тип', 'Продукт', 'Мессенджер', 'Контакт', 'E-mail', 'Тариф', 'Компания', 'Телефон', 'Сообщение', ...UTM_KEYS, 'Отправлено в Mattermost'];
  const lines = leads.map(l => [l.id, mskDate(l.created_at), KINDS[l.kind] || l.kind, l.product, CHANNELS[l.channel] || l.channel, l.contact, l.email,
    PLANS[l.plan] || l.plan, l.company, l.phone, l.message, ...UTM_KEYS.map(k => l.utm[k]), l.delivered ? 'да' : 'нет']);
  const csv = '﻿' + [head, ...lines].map(r => r.map(csvCell).join(';')).join('\r\n') + '\r\n';
  const day = new Intl.DateTimeFormat('sv-SE', { timeZone: 'Europe/Moscow' }).format(new Date());
  res.set({ 'Content-Type': 'text/csv; charset=utf-8', 'Content-Disposition': `attachment; filename="partnerka-leads-${day}.csv"` }).send(csv);
});

// кабинет доступен только после входа
app.get(['/app', '/app/'], (req, res) => (currentUser(req) ? res.sendFile(path.join(__dirname, 'public', 'app.html')) : res.redirect('/?login=1')));
app.use(express.static(path.join(__dirname, 'public'), {
  extensions: ['html'], index: 'index.html', maxAge: IS_PROD ? '1h' : 0,
  // HTML всегда проверяем на свежесть, чтобы правки лендинга были видны сразу; логотипы и прочее кешируются на час
  setHeaders: (res, file) => { if (file.endsWith('.html')) res.setHeader('Cache-Control', 'no-cache'); },
}));
app.use((req, res) => res.status(404).sendFile(path.join(__dirname, 'public', 'index.html')));

app.listen(PORT, () => console.log(`partnerka.io слушает :${PORT} (${IS_PROD ? 'production' : 'development'}), Mattermost: ${MM_WEBHOOK ? 'настроен' : 'нет, сообщения в логах'}`));
