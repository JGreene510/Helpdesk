'use strict';
/*
 * Helpdesk v4 — self-hosted ticketing for a Raspberry Pi / small LAN.
 *
 * No runtime dependencies except optional nodemailer (email notifications).
 * See README.md for configuration and the list of what changed in each version.
 *
 * Environment variables (all optional):
 *   PORT                 listen port (default 3000)
 *   HOST                 bind address (default 0.0.0.0; use 127.0.0.1 behind a proxy)
 *   DATA_DIR             where tickets.json / users.json / email-config.json live
 *   TRUST_PROXY=1        trust X-Forwarded-For (only when behind your own reverse proxy)
 *   GMAIL_APP_PASSWORD   overrides the app password stored in email-config.json
 *   OPEN_ACCESS=on       OPTIONAL "no password" mode: people on your own private network
 *                        can use the staff console (agent level) without logging in.
 *                        Never grants admin. See Install.txt for how to turn it on/off.
 *
 * Recovery:  node server.js --reset-admin [username]
 */

const http = require('http');
const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');
const net = require('net');
const { promisify } = require('util');
const scrypt = promisify(crypto.scrypt);

let nodemailer;
try { nodemailer = require('nodemailer'); } catch { nodemailer = null; }

// ─── Config ──────────────────────────────────────────────────────────────────
const PORT        = Number(process.env.PORT) || 3000;
const HOST        = process.env.HOST || '0.0.0.0';
const TRUST_PROXY = process.env.TRUST_PROXY === '1';
const DATA_DIR    = path.resolve(process.env.DATA_DIR || __dirname);
const DATA_FILE   = path.join(DATA_DIR, 'tickets.json');
const USERS_FILE  = path.join(DATA_DIR, 'users.json');
const EMAIL_FILE  = path.join(DATA_DIR, 'email-config.json');
const PUBLIC_DIR  = fs.realpathSync(path.join(__dirname, 'public'));

const CATEGORIES = ['software', 'hardware', 'network', 'other'];
const PRIORITIES = ['low', 'medium', 'high'];
let VERSION = '4';
try { VERSION = require('./package.json').version; } catch { /* keep default */ }
const STATUSES   = ['open', 'assigned', 'resolved'];
const ROLES      = ['admin', 'agent'];
const LIMITS     = { name: 100, email: 254, subject: 200, desc: 5000, resolution: 5000 };

const SESSION_ABSOLUTE_MS = 8 * 3600 * 1000;   // hard cap
const SESSION_IDLE_MS     = 60 * 60 * 1000;    // idle timeout
const MASK                = '••••••••••••••••';

const SCRYPT_PARAMS = { N: 32768, r: 8, p: 1 };
const SCRYPT_MAXMEM = 128 * 1024 * 1024;

const COMMON_PASSWORDS = new Set([
  'password12', 'password123', '1234567890', 'qwertyuiop', 'helpdesk123',
  'changeme123', 'alphabeta12', 'administrator', 'letmein1234'
]);

const OPEN_ACCESS_RAW = String(process.env.OPEN_ACCESS || '').trim().toLowerCase();
const OPEN_ACCESS = ['on', 'yes', 'true', '1'].includes(OPEN_ACCESS_RAW);

fs.mkdirSync(DATA_DIR, { recursive: true, mode: 0o700 });

// ─── Small utilities ─────────────────────────────────────────────────────────
const HTML_ESC = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' };
const esc = v => String(v ?? '').replace(/[&<>"']/g, c => HTML_ESC[c]);

// Coerce to a trimmed string with control characters removed and a length cap.
function cleanStr(v, max, multiline = false) {
  let s = typeof v === 'string' ? v : '';
  s = s.replace(multiline
    ? /[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/g
    : /[\u0000-\u001F\u007F]/g, '');
  return s.trim().slice(0, max);
}

// Deliberately strict: no commas/semicolons/angle brackets, so one field = one address.
const EMAIL_RE = /^[^\s@<>"',;()[\]\\]+@[^\s@<>"',;()[\]\\]+\.[^\s@<>"',;()[\]\\]+$/;
const validEmail = v => typeof v === 'string' && v.length <= LIMITS.email && EMAIL_RE.test(v);

const logStr = v => JSON.stringify(String(v ?? '').slice(0, 80)); // safe for log lines
const audit  = (actor, action, detail = '') =>
  console.log(`[audit] ${logStr(actor)} ${action}${detail ? ' ' + detail : ''}`);

function httpError(status, message) {
  const e = new Error(message);
  e.status = status;
  return e;
}

function clientIp(req) {
  if (TRUST_PROXY) {
    const xff = String(req.headers['x-forwarded-for'] || '').split(',').map(s => s.trim()).filter(Boolean);
    if (xff.length) return xff[xff.length - 1];   // right-most = added by our own proxy
  }
  return String(req.socket.remoteAddress || 'unknown').replace(/^::ffff:/, '');
}

// ─── JSON storage (atomic, owner-only permissions) ───────────────────────────
function loadJSON(file, def) {
  try { return JSON.parse(fs.readFileSync(file, 'utf8')); }
  catch { return def; }
}
function saveJSON(file, data) {
  const tmp = `${file}.${process.pid}.tmp`;
  fs.writeFileSync(tmp, JSON.stringify(data, null, 2), { mode: 0o600 });
  fs.renameSync(tmp, file);
}
// Always load → change → save synchronously (no await in between) so concurrent
// requests can never overwrite each other with a stale copy.
function mutateUsers(fn)   { const d = loadJSON(USERS_FILE, []); const r = fn(d); saveJSON(USERS_FILE, d); return r; }
function mutateTickets(fn) { const d = loadJSON(DATA_FILE, { counter: 0, tickets: [] }); const r = fn(d); saveJSON(DATA_FILE, d); return r; }

// ─── Rate limiting (in-memory sliding window) ────────────────────────────────
function makeLimiter(max, windowMs, maxKeys = 5000) {
  const hits = new Map();
  const prune = (arr, now) => { while (arr.length && arr[0] <= now - windowMs) arr.shift(); };
  return {
    peek(key) {                       // currently blocked? (does not record)
      const arr = hits.get(key);
      if (!arr) return false;
      prune(arr, Date.now());
      return arr.length >= max;
    },
    add(key) {                        // record a hit
      const now = Date.now();
      let arr = hits.get(key);
      if (!arr) {
        if (hits.size >= maxKeys) hits.delete(hits.keys().next().value);
        arr = []; hits.set(key, arr);
      }
      prune(arr, now);
      arr.push(now);
    },
    take(key) {                       // allowed? if so, record it
      if (this.peek(key)) return false;
      this.add(key);
      return true;
    },
    clear(key) { hits.delete(key); },
    retryAfter(key) {
      const arr = hits.get(key);
      if (!arr || !arr.length) return 1;
      return Math.max(1, Math.ceil((arr[0] + windowMs - Date.now()) / 1000));
    },
    sweep() {
      const now = Date.now();
      for (const [k, arr] of hits) { prune(arr, now); if (!arr.length) hits.delete(k); }
    }
  };
}

const loginIpFails   = makeLimiter(10, 15 * 60e3);   // failed logins per IP
const loginUserFails = makeLimiter(20, 15 * 60e3);   // failed logins per username
const ticketCreate   = makeLimiter(5, 10 * 60e3);    // new tickets per IP
const trackLookup    = makeLimiter(30, 10 * 60e3);   // ticket lookups per IP
const emailGlobal    = makeLimiter(60, 3600e3, 10);  // total outbound emails / hour
const emailPerRcpt   = makeLimiter(10, 3600e3);      // emails to one address / hour (drops are logged)
setInterval(() => {
  [loginIpFails, loginUserFails, ticketCreate, trackLookup, emailGlobal, emailPerRcpt].forEach(l => l.sweep());
  const now = Date.now();
  for (const [t, s] of sessions) if (now - s.created > SESSION_ABSOLUTE_MS || now - s.last > SESSION_IDLE_MS) sessions.delete(t);
}, 5 * 60e3).unref();

// ─── Passwords (scrypt, per-user salt, constant-time compare) ────────────────
async function hashPassword(password) {
  const salt = crypto.randomBytes(16);
  const key = await scrypt(password, salt, 64, { ...SCRYPT_PARAMS, maxmem: SCRYPT_MAXMEM });
  return `scrypt$${SCRYPT_PARAMS.N}$${SCRYPT_PARAMS.r}$${SCRYPT_PARAMS.p}$${salt.toString('hex')}$${key.toString('hex')}`;
}

async function verifyScryptHash(stored, password) {
  try {
    const [, N, r, p, saltHex, keyHex] = String(stored).split('$');
    const expected = Buffer.from(keyHex, 'hex');
    const key = await scrypt(password, Buffer.from(saltHex, 'hex'), expected.length,
      { N: Number(N), r: Number(r), p: Number(p), maxmem: SCRYPT_MAXMEM });
    return key.length === expected.length && crypto.timingSafeEqual(key, expected);
  } catch { return false; }
}

const isLegacyUser = u => !!u.salt && !String(u.passwordHash || '').startsWith('scrypt$');

async function verifyPassword(user, password) {
  if (String(user.passwordHash || '').startsWith('scrypt$')) return verifyScryptHash(user.passwordHash, password);
  if (isLegacyUser(user)) {                       // v2 users.json: sha256(salt + password)
    const got = Buffer.from(crypto.createHash('sha256').update(user.salt + password).digest('hex'));
    const want = Buffer.from(String(user.passwordHash || ''));
    return got.length === want.length && crypto.timingSafeEqual(got, want);
  }
  return false;
}

// Used so "unknown user" costs the same time as "wrong password".
let dummyHashPromise = null;
const dummyHash = () => (dummyHashPromise ??= hashPassword('timing-equaliser-not-a-real-password'));

function passwordProblem(pw, username) {
  if (typeof pw !== 'string' || !pw) return 'Password is required.';
  if (pw.length < 10) return 'Password must be at least 10 characters.';
  if (pw.length > 200) return 'Password is too long (max 200 characters).';
  if (username && pw.toLowerCase().includes(String(username).toLowerCase())) return 'Password must not contain the username.';
  if (COMMON_PASSWORDS.has(pw.toLowerCase())) return 'That password is too common.';
  return null;
}

const randomPassword = () => crypto.randomBytes(12).toString('base64url');

// ─── Sessions ────────────────────────────────────────────────────────────────
const sessions = new Map(); // token → { username, role, mustChange, created, last }

function createSession(username, role, mustChange) {
  const token = crypto.randomBytes(32).toString('hex');
  const now = Date.now();
  sessions.set(token, { username, role, mustChange: !!mustChange, created: now, last: now });
  return token;
}

function getSession(req) {
  if (!req.headers['authorization']) return openSession(req);   // optional no-password mode (below)
  const m = /^Bearer ([a-f0-9]{64})$/.exec(req.headers['authorization']);
  if (!m) return null;
  const s = sessions.get(m[1]);
  if (!s) return null;
  const now = Date.now();
  if (now - s.created > SESSION_ABSOLUTE_MS || now - s.last > SESSION_IDLE_MS) { sessions.delete(m[1]); return null; }
  s.last = now;
  s.token = m[1];
  return s;
}

function destroySessions(username, exceptToken) {
  for (const [t, s] of sessions) if (s.username === username && t !== exceptToken) sessions.delete(t);
}

// ─── Optional "open access" (no password) mode ───────────────────────────────
// Off unless the owner sets OPEN_ACCESS=on on the machine itself. When on, a
// request WITHOUT a login token is treated as an AGENT (view and work tickets;
// never admin) but only if ALL of these hold:
//   * it comes from a private/LAN address (10.x, 172.16-31.x, 192.168.x, loopback, link-local, IPv6 ULA)
//   * it was not relayed by a proxy (no X-Forwarded-For / Forwarded / X-Real-IP headers)
//   * the Host header looks local (an IP address, "localhost", a single-word name, or *.local/.lan/...)
// Anything else (for example traffic arriving through a port-forward or a web
// address on the public internet) must log in with a password as normal.
function isPrivateAddr(addr) {
  const a = String(addr || '').toLowerCase().replace(/^::ffff:/, '');
  if (net.isIPv4(a)) {
    const [o1, o2] = a.split('.').map(Number);
    return o1 === 10 || o1 === 127 || (o1 === 172 && o2 >= 16 && o2 <= 31) ||
           (o1 === 192 && o2 === 168) || (o1 === 169 && o2 === 254);
  }
  if (net.isIPv6(a)) return a === '::1' || /^f[cd]/.test(a) || /^fe[89ab]/.test(a);
  return false;
}

function hostLooksLocal(req) {
  const m = /^(\[[^\]]+\]|[^:]+)(?::\d+)?$/.exec(String(req.headers.host || '').toLowerCase());
  if (!m) return false;
  const host = m[1].replace(/^\[|\]$/g, '');
  if (net.isIP(host)) return true;
  return host === 'localhost' || !host.includes('.') ||
    /\.(local|lan|localdomain|home|internal|home\.arpa|fritz\.box)$/.test(host);
}

function openSession(req) {
  if (!OPEN_ACCESS) return null;
  for (const h of ['x-forwarded-for', 'forwarded', 'x-real-ip', 'x-forwarded-host']) if (req.headers[h]) return null;
  if (!isPrivateAddr(req.socket.remoteAddress) || !hostLooksLocal(req)) return null;
  return { username: 'open-access', role: 'agent', mustChange: false, open: true };
}

function warnOpenAccess() {
  if (OPEN_ACCESS) {
    console.warn('\n  ⚠  OPEN ACCESS is ON: anyone on your private network can view and work tickets');
    console.warn('     WITHOUT a password (agent level only). Admin tasks still need a login.');
    console.warn('     To turn it off: see Install.txt, "Turn the password off (and back on)".\n');
  } else if (OPEN_ACCESS_RAW) {
    console.warn(`\n  ⚠  OPEN_ACCESS=${JSON.stringify(OPEN_ACCESS_RAW)} is not recognised and was ignored (use "on").\n`);
  }
}

function requireAuth(req, res, { admin = false, allowMustChange = false } = {}) {
  const s = getSession(req);
  if (!s) { jsonResponse(res, 401, { error: 'Unauthorized' }); return null; }
  if (s.mustChange && !allowMustChange) {
    jsonResponse(res, 403, { error: 'You must change your password before continuing.', mustChange: true });
    return null;
  }
  if (admin && s.role !== 'admin') { jsonResponse(res, 403, { error: 'Administrator access required.' }); return null; }
  return s;
}

// ─── Email ───────────────────────────────────────────────────────────────────
let transporter = null;

// Test-only hook: HELPDESK_MAIL_FIXTURE=/path/to/module exporting createTransport()
const MAIL_FIXTURE = process.env.HELPDESK_MAIL_FIXTURE || '';
const RETRY_MS = (process.env.HELPDESK_MAIL_RETRY_MS || '30000,120000,600000')
  .split(',').map(n => Number(n)).filter(n => n >= 0);
const SEND_TIMEOUT_MS = Number(process.env.HELPDESK_MAIL_TIMEOUT_MS) || 45000;

function emailConfig() {
  const cfg = loadJSON(EMAIL_FILE, {});
  if (process.env.GMAIL_APP_PASSWORD) cfg.gmailAppPassword = process.env.GMAIL_APP_PASSWORD;
  return cfg;
}

function reloadEmail() {
  const cfg = emailConfig();
  transporter = null;
  if ((!nodemailer && !MAIL_FIXTURE) || !cfg.enabled) return;
  if (!cfg.gmailAppPassword || cfg.gmailAppPassword === 'your-16-char-app-password-here') return;
  if (!validEmail(cfg.fromEmail)) return;
  if (MAIL_FIXTURE) {
    transporter = require(MAIL_FIXTURE).createTransport();
  } else {
    transporter = nodemailer.createTransport({
      host: 'smtp.gmail.com',
      port: 465,
      secure: true,
      family: 4,                    // Gmail over IPv6 often hangs on small home networks
      connectionTimeout: 15000,     // fail in seconds, not minutes
      greetingTimeout: 15000,
      socketTimeout: 30000,
      auth: { user: cfg.fromEmail, pass: cfg.gmailAppPassword }
    });
  }
  console.log('[email] Gmail transporter ready →', cfg.fromEmail);
}

// Recent activity, newest last, kept in memory and shown in Admin → Email.
const mailLog = [];
function logMail(entry) {
  mailLog.push({ time: new Date().toISOString(), ...entry });
  if (mailLog.length > 50) mailLog.shift();
}

function friendlyMailError(err) {
  const code = err && (err.code || err.responseCode);
  const msg = String((err && err.message) || err);
  if (code === 'EAUTH' || code === 535 || /535|Invalid login|Username and Password/i.test(msg))
    return 'Gmail refused the login. Use a 16-character App Password (not your normal Gmail password), and make sure 2-Step Verification is on for that Gmail account.';
  if (['ETIMEDOUT', 'ESOCKET', 'ECONNECTION', 'ECONNREFUSED', 'EDNS', 'ENOTFOUND', 'EAI_AGAIN', 'ENETUNREACH'].includes(code))
    return 'Could not reach Gmail (smtp.gmail.com port 465). Check that this machine has working internet and DNS. (' + code + ')';
  return cleanStr(msg, 300);
}

function isPermanentMailError(err) {
  const code = err && (err.code || err.responseCode);
  return code === 'EAUTH' || (typeof code === 'number' && code >= 500) || (err && err.permanent === true);
}

// One delivery attempt with a hard time limit.
async function deliverMail(job) {
  if (!transporter) { const e = new Error('Email is not configured or not enabled.'); e.permanent = true; throw e; }
  const cfg = emailConfig();
  let timer;
  const limit = new Promise((_, rej) => { timer = setTimeout(() => rej(Object.assign(new Error('Timed out talking to the mail server'), { code: 'ETIMEDOUT' })), SEND_TIMEOUT_MS); });
  try {
    await Promise.race([
      transporter.sendMail({ from: `"Helpdesk" <${cfg.fromEmail}>`, to: job.to, subject: cleanStr(job.subject, 200), html: job.html }),
      limit
    ]);
  } finally { clearTimeout(timer); }
}

// Messages go through a small in-memory queue: the web request never waits on
// Gmail, and a failed message is retried (30 s, 2 min, 10 min) instead of lost.
const mailQueue = [];
let mailBusy = false;

async function pumpMail() {
  if (mailBusy) return;
  mailBusy = true;
  try {
    while (mailQueue.length) {
      const job = mailQueue.shift();
      const started = Date.now();
      try {
        await deliverMail(job);
        console.log(`[email] Sent ${logStr(job.subject)} → ${logStr(job.to)} (${Date.now() - started} ms, attempt ${job.attempts + 1})`);
        logMail({ to: job.to, subject: cleanStr(job.subject, 120), status: 'sent', note: `${Date.now() - started} ms` });
      } catch (err) {
        job.attempts++;
        const why = friendlyMailError(err);
        if (!isPermanentMailError(err) && job.attempts <= RETRY_MS.length) {
          const wait = RETRY_MS[job.attempts - 1];
          console.warn(`[email] Attempt ${job.attempts} failed for ${logStr(job.to)}: ${logStr(why)} — retrying in ${Math.round(wait / 1000)} s`);
          logMail({ to: job.to, subject: cleanStr(job.subject, 120), status: 'retrying', note: why });
          const t = setTimeout(() => { mailQueue.push(job); pumpMail(); }, wait);
          if (t.unref) t.unref();
        } else {
          console.error(`[email] GAVE UP on ${logStr(job.subject)} → ${logStr(job.to)}: ${logStr(why)}`);
          logMail({ to: job.to, subject: cleanStr(job.subject, 120), status: 'failed', note: why });
        }
      }
    }
  } finally { mailBusy = false; }
}

// Queue a message. Returns true if queued; never waits for the network.
function sendEmail(to, subject, html) {
  if (!transporter) return false;
  if (!validEmail(to)) return false;
  if (!emailGlobal.take('all')) {
    console.warn('[email] hourly send cap reached — message dropped');
    logMail({ to, subject: cleanStr(subject, 120), status: 'dropped', note: 'Hourly cap of 60 messages reached' });
    return false;
  }
  mailQueue.push({ to, subject, html, attempts: 0 });
  pumpMail();
  return true;
}

function takeRecipientSlot(addr, subject) {
  if (emailPerRcpt.take(addr.toLowerCase())) return true;
  console.warn(`[email] per-recipient cap reached for ${logStr(addr)} — message dropped`);
  logMail({ to: addr, subject: cleanStr(subject, 120), status: 'dropped', note: 'More than 10 messages to this address in one hour' });
  return false;
}

// Every dynamic value is escaped. bodyHtml must be built only from esc()'d values.
function ticketEmailHtml(ticket, bodyHtml) {
  return `
<div style="font-family:-apple-system,sans-serif;max-width:560px;margin:0 auto;background:#f5f5f4;padding:24px">
  <div style="background:#fff;border-radius:10px;padding:24px;border:1px solid #e0ddd8">
    <div style="font-size:18px;font-weight:600;color:#1a1a1a;margin-bottom:4px">Helpdesk</div>
    <hr style="border:none;border-top:1px solid #e5e7eb;margin:14px 0">
    ${bodyHtml}
    <div style="margin-top:20px;padding:14px;background:#f5f5f4;border-radius:8px;font-size:13px;color:#6b7280">
      Ticket ID: <strong>${esc(ticket.id)}</strong> &nbsp;·&nbsp;
      Submitted: ${esc(new Date(ticket.date).toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' }))}
    </div>
  </div>
  <div style="text-align:center;font-size:11px;color:#9ca3af;margin-top:14px">
    This email was sent automatically by your Helpdesk system.
  </div>
</div>`;
}

async function notifyNewTicket(ticket) {
  const cfg = emailConfig();
  if (!cfg.notifyNewTicket) return;

  if (cfg.adminEmail) {
    sendEmail(cfg.adminEmail,
      `[Helpdesk] New ticket ${ticket.id}: ${ticket.subject}`,
      ticketEmailHtml(ticket, `
        <h2 style="font-size:16px;margin:0 0 10px">New Support Ticket</h2>
        <p style="margin:0 0 6px"><strong>From:</strong> ${esc(ticket.name)} &lt;${esc(ticket.email)}&gt;</p>
        <p style="margin:0 0 6px"><strong>Subject:</strong> ${esc(ticket.subject)}</p>
        <p style="margin:0 0 6px"><strong>Category:</strong> ${esc(ticket.category)} &nbsp;·&nbsp; <strong>Priority:</strong> ${esc(ticket.priority)}</p>
        <div style="margin-top:12px;padding:12px;background:#f5f5f4;border-radius:8px;font-size:14px;white-space:pre-wrap">${esc(ticket.desc)}</div>
      `));
  }

  // Confirmation to the submitter: fixed template, no free-text echoed back,
  // and capped per recipient so the form can't be used to mail-bomb someone.
  if (ticket.email && takeRecipientSlot(ticket.email, 'Ticket received ' + ticket.id)) {
    sendEmail(ticket.email,
      `Your support ticket has been received — ${ticket.id}`,
      ticketEmailHtml(ticket, `
        <h2 style="font-size:16px;margin:0 0 10px">Ticket Received</h2>
        <p style="color:#374151;margin:0 0 12px">Hi ${esc(ticket.name)}, we've received your support request and will get back to you shortly.</p>
        <p style="color:#6b7280;font-size:13px;margin-top:10px">Keep your ticket ID handy. You can check the status any time using the ID and this email address.</p>
      `));
  }
}

async function notifyStatusChange(ticket, oldStatus, byUser) {
  const cfg = emailConfig();
  if (!cfg.notifyStatusChange || ticket.status === oldStatus) return;

  const labels = { open: 'Open', assigned: 'Assigned', resolved: 'Resolved' };
  const label = labels[ticket.status] || ticket.status;
  const resolutionBlock = ticket.resolution
    ? `<div style="margin-top:14px;padding:12px;background:#f0fdf4;border-radius:8px;border-left:3px solid #4ade80;white-space:pre-wrap">
         <strong>Resolution:</strong><br>${esc(ticket.resolution)}
       </div>`
    : '';

  if (ticket.email && takeRecipientSlot(ticket.email, 'Status update ' + ticket.id)) {
    sendEmail(ticket.email,
      `Your ticket ${ticket.id} is now "${label}"`,
      ticketEmailHtml(ticket, `
        <h2 style="font-size:16px;margin:0 0 10px">Ticket Status Update</h2>
        <p style="margin:0 0 6px">Hi ${esc(ticket.name)}, the status of your ticket has been updated.</p>
        <p style="margin:10px 0 4px"><strong>${esc(ticket.id)}:</strong> ${esc(ticket.subject)}</p>
        <p style="margin:0 0 4px">
          <span style="display:inline-block;padding:3px 10px;border-radius:20px;font-size:12px;background:#dbeafe;color:#1e40af">${esc(label)}</span>
        </p>
        ${ticket.assign ? `<p style="margin:8px 0 0;font-size:13px;color:#6b7280">Assigned to: ${esc(ticket.assign)}</p>` : ''}
        ${resolutionBlock}
      `));
  }

  // When a ticket is resolved (closed), the assigned technician gets a copy too.
  if (ticket.status === 'resolved' && ticket.assign) {
    const user = loadJSON(USERS_FILE, []).find(u => u.username === ticket.assign);
    if (!user || !validEmail(user.email)) {
      logMail({ to: ticket.assign, subject: 'Ticket ' + ticket.id + ' resolved', status: 'dropped', note: 'No email address saved for user "' + ticket.assign + '" (Admin → Users)' });
    } else if (takeRecipientSlot(user.email, 'Resolved ' + ticket.id)) {
      sendEmail(user.email,
        `[Helpdesk] Ticket ${ticket.id} resolved: ${ticket.subject}`,
        ticketEmailHtml(ticket, `
          <h2 style="font-size:16px;margin:0 0 10px">Ticket Resolved</h2>
          <p style="margin:0 0 6px">Hi ${esc(user.username)}, ${esc(byUser || 'someone')} marked this ticket as resolved.</p>
          <p style="margin:0 0 6px"><strong>${esc(ticket.id)}:</strong> ${esc(ticket.subject)}</p>
          <p style="margin:0 0 6px"><strong>From:</strong> ${esc(ticket.name)} &lt;${esc(ticket.email)}&gt;</p>
          ${resolutionBlock}
        `));
    }
  }
}

// Tell the staff member a ticket was assigned to them (needs an email on their user account).
async function notifyAssignee(ticket, oldAssign, byUser) {
  const cfg = emailConfig();
  if (cfg.notifyAssignee === false) return '';                // switched off on purpose
  const who = ticket.assign || '';
  if (!who || who === oldAssign) return '';
  if (who === byUser) return '';                              // assigned it to themselves
  if (!transporter) return `No email was sent to ${who}: email is not turned on (Admin > Users > Email tab).`;
  const user = loadJSON(USERS_FILE, []).find(u => u.username === who);
  if (!user || !validEmail(user.email)) {
    logMail({ to: who, subject: 'Ticket ' + ticket.id + ' assigned', status: 'dropped', note: 'No email address saved for user "' + who + '" (Admin → Users)' });
    return `No email was sent to ${who}: they have no email address saved (Users > Email button).`;
  }
  if (!takeRecipientSlot(user.email, 'Assigned ' + ticket.id)) return `No email was sent to ${who}: too many messages to that address this hour.`;
  sendEmail(user.email,
    `[Helpdesk] Ticket ${ticket.id} assigned to you: ${ticket.subject}`,
    ticketEmailHtml(ticket, `
      <h2 style="font-size:16px;margin:0 0 10px">Ticket Assigned to You</h2>
      <p style="margin:0 0 6px">Hi ${esc(who)}, ${esc(byUser)} assigned this ticket to you.</p>
      <p style="margin:0 0 6px"><strong>From:</strong> ${esc(ticket.name)} &lt;${esc(ticket.email)}&gt;</p>
      <p style="margin:0 0 6px"><strong>Subject:</strong> ${esc(ticket.subject)}</p>
      <p style="margin:0 0 6px"><strong>Category:</strong> ${esc(ticket.category)} &nbsp;·&nbsp; <strong>Priority:</strong> ${esc(ticket.priority)}</p>
      <div style="margin-top:12px;padding:12px;background:#f5f5f4;border-radius:8px;font-size:14px;white-space:pre-wrap">${esc(ticket.desc)}</div>
    `));
  return `Email queued to ${who}.`;
}

// ─── HTTP helpers ────────────────────────────────────────────────────────────
const CSP = [
  "default-src 'self'",
  "script-src 'self' 'unsafe-inline'",   // page uses inline handlers; output escaping is the real XSS defence
  "style-src 'self' 'unsafe-inline'",
  "img-src 'self' data:",
  "connect-src 'self'",                  // injected script could not phone home
  "object-src 'none'",
  "base-uri 'none'",
  "form-action 'none'",
  "frame-ancestors 'none'"
].join('; ');

const SEC_HEADERS = {
  'Content-Security-Policy': CSP,
  'X-Content-Type-Options': 'nosniff',
  'X-Frame-Options': 'DENY',
  'Referrer-Policy': 'no-referrer',
  'Cross-Origin-Opener-Policy': 'same-origin',
  'Cross-Origin-Resource-Policy': 'same-origin'
};

function jsonResponse(res, status, data, extra = {}) {
  res.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Cache-Control': 'no-store',
    ...SEC_HEADERS, ...extra
  });
  res.end(JSON.stringify(data));
}

function textResponse(res, status, text, extra = {}) {
  res.writeHead(status, { 'Content-Type': 'text/plain; charset=utf-8', ...SEC_HEADERS, ...extra });
  res.end(text);
}

function tooMany(res, seconds, message = 'Too many requests. Please slow down and try again shortly.') {
  jsonResponse(res, 429, { error: message }, { 'Retry-After': String(seconds) });
}

// Requires application/json (so a cross-site <form> can't post tickets: JSON
// needs a CORS preflight and we send no CORS headers) and caps the body size.
function readJson(req, limit = 64 * 1024) {
  return new Promise((resolve, reject) => {
    const ct = String(req.headers['content-type'] || '').split(';')[0].trim().toLowerCase();
    if (ct !== 'application/json') return reject(httpError(415, 'Content-Type must be application/json.'));
    if (Number(req.headers['content-length']) > limit) return reject(httpError(413, 'Request too large.'));
    let size = 0, finished = false;
    const chunks = [];
    req.on('data', c => {
      if (finished) return;
      size += c.length;
      if (size > limit) { finished = true; reject(httpError(413, 'Request too large.')); return; }
      chunks.push(c);
    });
    req.on('end', () => {
      if (finished) return;
      finished = true;
      try {
        const v = JSON.parse(Buffer.concat(chunks).toString('utf8'));
        if (v === null || typeof v !== 'object' || Array.isArray(v)) throw new Error('not an object');
        resolve(v);
      } catch { reject(httpError(400, 'Invalid JSON body.')); }
    });
    req.on('error', () => { if (!finished) { finished = true; reject(httpError(400, 'Bad request.')); } });
  });
}

const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.js':   'application/javascript; charset=utf-8',
  '.css':  'text/css; charset=utf-8',
  '.png':  'image/png',
  '.svg':  'image/svg+xml',
  '.ico':  'image/x-icon',
  '.txt':  'text/plain; charset=utf-8'
};

// Serves only regular, non-hidden files with a whitelisted extension that
// resolve (after symlinks) to a path inside public/.
function serveStatic(req, res, pathname) {
  if (req.method !== 'GET' && req.method !== 'HEAD') return textResponse(res, 405, 'Method not allowed', { Allow: 'GET, HEAD' });
  let rel;
  try { rel = decodeURIComponent(pathname); } catch { return textResponse(res, 400, 'Bad request'); }
  if (rel.includes('\0')) return textResponse(res, 400, 'Bad request');
  if (rel === '/') rel = '/index.html';

  const full = path.resolve(PUBLIC_DIR, '.' + rel);
  const ext = path.extname(full).toLowerCase();
  if (!full.startsWith(PUBLIC_DIR + path.sep) || !MIME[ext] || path.basename(full).startsWith('.'))
    return textResponse(res, 404, 'Not found');

  fs.realpath(full, (err, real) => {
    if (err || !real.startsWith(PUBLIC_DIR + path.sep)) return textResponse(res, 404, 'Not found');
    fs.stat(real, (err2, st) => {
      if (err2 || !st.isFile()) return textResponse(res, 404, 'Not found');
      res.writeHead(200, {
        'Content-Type': MIME[ext],
        'Content-Length': st.size,
        'Cache-Control': ext === '.html' ? 'no-cache' : 'public, max-age=3600',
        ...SEC_HEADERS
      });
      if (req.method === 'HEAD') return res.end();
      const stream = fs.createReadStream(real);
      stream.on('error', () => res.destroy());
      stream.pipe(res);
    });
  });
}

// ─── Request handling ────────────────────────────────────────────────────────
async function handle(req, res) {
  let pathname;
  try { pathname = new URL(req.url, 'http://localhost').pathname; }
  catch { throw httpError(400, 'Bad request.'); }
  const method = req.method;

  if (!pathname.startsWith('/api/')) return serveStatic(req, res, pathname);

  // Tells the page whether THIS visitor may use the console without a password.
  if (pathname === '/api/config' && method === 'GET') return jsonResponse(res, 200, { openAccess: !!openSession(req), version: VERSION });

  // ── AUTH ──────────────────────────────────────────────────────────────────
  if (pathname === '/api/auth/login' && method === 'POST') {
    const ip = clientIp(req);
    if (loginIpFails.peek(ip)) return tooMany(res, loginIpFails.retryAfter(ip), 'Too many failed logins. Try again later.');
    const body = await readJson(req);
    const username = cleanStr(body.username, 64);
    const password = typeof body.password === 'string' ? body.password.slice(0, 200) : '';
    const ukey = username.toLowerCase();
    if (loginUserFails.peek(ukey)) return tooMany(res, loginUserFails.retryAfter(ukey), 'Too many failed logins for this account. Try again later.');

    const user = loadJSON(USERS_FILE, []).find(u => u.username.toLowerCase() === ukey);
    let ok = false;
    if (user) ok = await verifyPassword(user, password);
    else await verifyScryptHash(await dummyHash(), password);

    if (!ok) {
      loginIpFails.add(ip); loginUserFails.add(ukey);
      console.warn(`[auth] failed login for ${logStr(username)} from ${logStr(ip)}`);
      return jsonResponse(res, 401, { error: 'Invalid username or password' });
    }
    loginUserFails.clear(ukey);

    let mustChange = !!user.mustChange;
    if (isLegacyUser(user)) {                       // upgrade v2 sha256 hash → scrypt on first successful login
      const newHash = await hashPassword(password);
      if (password === 'Alpha') mustChange = true;  // the old shipped default
      mutateUsers(us => {
        const u = us.find(x => x.username === user.username);
        if (u) { u.passwordHash = newHash; delete u.salt; if (mustChange) u.mustChange = true; }
      });
      audit(user.username, 'upgraded legacy password hash');
    }
    const token = createSession(user.username, user.role === 'admin' ? 'admin' : 'agent', mustChange);
    audit(user.username, 'login', `from ${logStr(ip)}`);
    return jsonResponse(res, 200, { token, username: user.username, role: user.role === 'admin' ? 'admin' : 'agent', mustChange });
  }

  if (pathname === '/api/auth/logout' && method === 'POST') {
    const s = getSession(req);
    if (s) sessions.delete(s.token);
    return jsonResponse(res, 200, { ok: true });
  }

  // Change your own password (requires the current one). Allowed while mustChange is set.
  if (pathname === '/api/auth/password' && method === 'PUT') {
    const s = requireAuth(req, res, { allowMustChange: true });
    if (!s) return;
    if (s.open) return jsonResponse(res, 400, { error: 'Open access has no password to change. Log in with your own account first.' });
    const ip = clientIp(req), ukey = s.username.toLowerCase();
    if (loginIpFails.peek(ip) || loginUserFails.peek(ukey)) return tooMany(res, 300, 'Too many failed attempts. Try again later.');
    const body = await readJson(req);
    const current = typeof body.current === 'string' ? body.current.slice(0, 200) : '';
    const next = typeof body.password === 'string' ? body.password : '';
    const problem = passwordProblem(next, s.username);
    if (problem) return jsonResponse(res, 400, { error: problem });
    const user = loadJSON(USERS_FILE, []).find(u => u.username === s.username);
    if (!user || !(await verifyPassword(user, current))) {
      loginIpFails.add(ip); loginUserFails.add(ukey);
      return jsonResponse(res, 400, { error: 'Current password is incorrect.' });
    }
    if (next === current) return jsonResponse(res, 400, { error: 'New password must be different from the current one.' });
    const hash = await hashPassword(next);
    mutateUsers(us => {
      const u = us.find(x => x.username === s.username);
      if (u) { u.passwordHash = hash; delete u.salt; delete u.mustChange; }
    });
    s.mustChange = false;
    destroySessions(s.username, s.token);           // log out every other session
    audit(s.username, 'changed own password');
    return jsonResponse(res, 200, { ok: true });
  }

  // ── USERS ─────────────────────────────────────────────────────────────────
  if (pathname === '/api/assignees' && method === 'GET') {      // names only; any staff member
    if (!requireAuth(req, res)) return;
    return jsonResponse(res, 200, loadJSON(USERS_FILE, []).map(u => u.username));
  }

  if (pathname === '/api/users' && method === 'GET') {
    if (!requireAuth(req, res, { admin: true })) return;
    return jsonResponse(res, 200, loadJSON(USERS_FILE, []).map(u => ({
      username: u.username, role: u.role === 'admin' ? 'admin' : 'agent', email: u.email || '', created: u.created
    })));
  }

  if (pathname === '/api/users' && method === 'POST') {
    const s = requireAuth(req, res, { admin: true });
    if (!s) return;
    const body = await readJson(req);
    const username = cleanStr(body.username, 32);
    const email = cleanStr(body.email, LIMITS.email);
    const role = ROLES.includes(body.role) ? body.role : 'agent';
    if (!/^[A-Za-z0-9._-]{3,32}$/.test(username))
      return jsonResponse(res, 400, { error: 'Username must be 3–32 characters: letters, numbers, dot, dash, underscore.' });
    if (email && !validEmail(email)) return jsonResponse(res, 400, { error: 'Invalid email address.' });
    const problem = passwordProblem(body.password, username);
    if (problem) return jsonResponse(res, 400, { error: problem });
    const passwordHash = await hashPassword(body.password);
    const created = mutateUsers(us => {
      if (us.some(u => u.username.toLowerCase() === username.toLowerCase())) return false;
      us.push({ username, passwordHash, role, email, created: new Date().toISOString(), mustChange: true });
      return true;
    });
    if (!created) return jsonResponse(res, 409, { error: 'Username already exists.' });
    audit(s.username, 'created user', `${logStr(username)} role=${role}`);
    return jsonResponse(res, 201, { username, role, email });
  }

  const userPass = /^\/api\/users\/([^/]+)\/password$/.exec(pathname);
  if (userPass && method === 'PUT') {          // admin resets someone else's password
    const s = requireAuth(req, res, { admin: true });
    if (!s) return;
    const target = decodeURIComponent(userPass[1]);
    if (target === s.username) return jsonResponse(res, 400, { error: 'Use "change your own password" for your own account.' });
    const body = await readJson(req);
    const problem = passwordProblem(body.password, target);
    if (problem) return jsonResponse(res, 400, { error: problem });
    const hash = await hashPassword(body.password);
    const found = mutateUsers(us => {
      const u = us.find(x => x.username === target);
      if (!u) return false;
      u.passwordHash = hash; delete u.salt; u.mustChange = true;
      return true;
    });
    if (!found) return jsonResponse(res, 404, { error: 'User not found.' });
    destroySessions(target);
    audit(s.username, 'reset password for', logStr(target));
    return jsonResponse(res, 200, { ok: true });
  }

  const userEmail = /^\/api\/users\/([^/]+)\/email$/.exec(pathname);
  if (userEmail && method === 'PUT') {          // admin sets or clears a user's email address
    const s = requireAuth(req, res, { admin: true });
    if (!s) return;
    const target = decodeURIComponent(userEmail[1]);
    const body = await readJson(req);
    const email = cleanStr(body.email, LIMITS.email);
    if (email && !validEmail(email)) return jsonResponse(res, 400, { error: 'That does not look like a valid email address.' });
    const found = mutateUsers(us => {
      const u = us.find(x => x.username === target);
      if (!u) return false;
      u.email = email;
      return true;
    });
    if (!found) return jsonResponse(res, 404, { error: 'User not found.' });
    audit(s.username, 'set email for', logStr(target));
    return jsonResponse(res, 200, { ok: true, email });
  }

  const userOne = /^\/api\/users\/([^/]+)$/.exec(pathname);
  if (userOne && method === 'DELETE') {
    const s = requireAuth(req, res, { admin: true });
    if (!s) return;
    const target = decodeURIComponent(userOne[1]);
    if (target === s.username) return jsonResponse(res, 400, { error: 'You cannot delete your own account.' });
    const result = mutateUsers(us => {
      const u = us.find(x => x.username === target);
      if (!u) return 'missing';
      if (u.role === 'admin' && us.filter(x => x.role === 'admin').length <= 1) return 'last-admin';
      us.splice(us.indexOf(u), 1);
      return 'ok';
    });
    if (result === 'missing') return jsonResponse(res, 404, { error: 'User not found.' });
    if (result === 'last-admin') return jsonResponse(res, 400, { error: 'Cannot delete the last administrator.' });
    destroySessions(target);
    audit(s.username, 'deleted user', logStr(target));
    return jsonResponse(res, 200, { ok: true });
  }

  // ── EMAIL CONFIG (admin) ──────────────────────────────────────────────────
  if (pathname === '/api/email-config' && method === 'GET') {
    if (!requireAuth(req, res, { admin: true })) return;
    const cfg = emailConfig();
    return jsonResponse(res, 200, {
      enabled: !!cfg.enabled,
      fromEmail: cfg.fromEmail || '',
      adminEmail: cfg.adminEmail || '',
      notifyNewTicket: !!cfg.notifyNewTicket,
      notifyStatusChange: !!cfg.notifyStatusChange,
      notifyAssignee: cfg.notifyAssignee !== false,
      gmailAppPassword: cfg.gmailAppPassword && cfg.gmailAppPassword !== 'your-16-char-app-password-here' ? MASK : '',
      transporterReady: !!transporter
    });
  }

  if (pathname === '/api/email-config' && method === 'PUT') {
    const s = requireAuth(req, res, { admin: true });
    if (!s) return;
    const body = await readJson(req);
    const next = { ...loadJSON(EMAIL_FILE, {}) };
    for (const k of ['enabled', 'notifyNewTicket', 'notifyStatusChange', 'notifyAssignee']) if (typeof body[k] === 'boolean') next[k] = body[k];
    for (const k of ['fromEmail', 'adminEmail']) {
      if (body[k] === undefined) continue;
      const v = cleanStr(body[k], LIMITS.email);
      if (v && !validEmail(v)) return jsonResponse(res, 400, { error: `Invalid ${k === 'fromEmail' ? 'From' : 'Admin'} email address.` });
      next[k] = v;
    }
    if (typeof body.gmailAppPassword === 'string' && body.gmailAppPassword !== MASK) {
      const pw = body.gmailAppPassword.replace(/\s+/g, '');
      if (pw.length < 8 || pw.length > 64) return jsonResponse(res, 400, { error: 'App password looks wrong (expected 16 characters).' });
      next.gmailAppPassword = pw;
    }
    saveJSON(EMAIL_FILE, next);
    reloadEmail();
    audit(s.username, 'updated email settings');
    return jsonResponse(res, 200, { ok: true, transporterReady: !!transporter });
  }

  if (pathname === '/api/email-config/test' && method === 'POST') {
    if (!requireAuth(req, res, { admin: true })) return;
    if (!transporter) return jsonResponse(res, 400, { error: 'Email is not enabled yet. Tick "Enable", fill in the From address and App Password, click Save, then try again.' });
    const cfg = emailConfig();
    if (!validEmail(cfg.adminEmail)) return jsonResponse(res, 400, { error: 'Enter an Admin Notification Email and save the settings first.' });
    const started = Date.now();
    try {
      await deliverMail({ to: cfg.adminEmail, subject: 'Helpdesk — Test Email',
        html: `<div style="font-family:sans-serif;padding:20px"><h2>Email is working</h2>
       <p>Your Helpdesk email notifications are configured correctly.</p></div>` });
      logMail({ to: cfg.adminEmail, subject: 'Helpdesk — Test Email', status: 'sent', note: `${Date.now() - started} ms` });
      return jsonResponse(res, 200, { ok: true, ms: Date.now() - started });
    } catch (err) {
      const why = friendlyMailError(err);
      console.error('[email] Test send failed:', logStr(why));
      logMail({ to: cfg.adminEmail, subject: 'Helpdesk — Test Email', status: 'failed', note: why });
      return jsonResponse(res, 502, { ok: false, error: why });
    }
  }

  if (pathname === '/api/email-config/log' && method === 'GET') {
    if (!requireAuth(req, res, { admin: true })) return;
    return jsonResponse(res, 200, { waiting: mailQueue.length, entries: mailLog.slice().reverse() });
  }

  // ── TICKETS ───────────────────────────────────────────────────────────────
  // Public: submit a ticket. Returns only the ID.
  if (pathname === '/api/tickets' && method === 'POST') {
    const ip = clientIp(req);
    if (ticketCreate.peek(ip)) return tooMany(res, ticketCreate.retryAfter(ip), 'You have submitted several tickets recently. Please wait a few minutes.');
    const body = await readJson(req);
    const name = cleanStr(body.name, LIMITS.name);
    const email = cleanStr(body.email, LIMITS.email);
    const subject = cleanStr(body.subject, LIMITS.subject);
    const desc = cleanStr(body.desc, LIMITS.desc, true);
    if (!name || !subject || !desc) return jsonResponse(res, 400, { error: 'Name, subject and description are required.' });
    if (!validEmail(email)) return jsonResponse(res, 400, { error: 'Please enter a valid email address.' });
    ticketCreate.add(ip);
    const ticket = mutateTickets(data => {
      data.counter += 1;
      const t = {
        id: 'HD-' + String(data.counter).padStart(3, '0'),
        name, email, subject, desc,
        category: CATEGORIES.includes(body.category) ? body.category : 'other',
        priority: PRIORITIES.includes(body.priority) ? body.priority : 'low',
        status: 'open', assign: '', resolution: '',
        date: new Date().toISOString()
      };
      data.tickets.unshift(t);
      return t;
    });
    notifyNewTicket(ticket).catch(e => console.error('[email]', e.message));
    return jsonResponse(res, 201, { id: ticket.id });
  }

  // Public: look up one ticket. Needs the ID AND the email it was submitted with.
  if (pathname === '/api/track' && method === 'POST') {
    const ip = clientIp(req);
    if (!trackLookup.take(ip)) return tooMany(res, trackLookup.retryAfter(ip));
    const body = await readJson(req);
    const id = cleanStr(body.id, 20).toUpperCase();
    const email = cleanStr(body.email, LIMITS.email).toLowerCase();
    const t = loadJSON(DATA_FILE, { tickets: [] }).tickets.find(x => x.id === id);
    if (!t || !email || !t.email || t.email.toLowerCase() !== email)
      return jsonResponse(res, 404, { error: 'No ticket found matching that ID and email address.' });
    return jsonResponse(res, 200, {
      id: t.id, subject: t.subject, name: t.name, status: t.status, category: t.category,
      priority: t.priority, assign: t.assign, resolution: t.resolution, date: t.date
    });
  }

  if (pathname === '/api/tickets' && method === 'GET') {
    if (!requireAuth(req, res)) return;
    return jsonResponse(res, 200, loadJSON(DATA_FILE, { tickets: [] }).tickets);
  }

  const ticketMatch = /^\/api\/tickets\/(HD-\d{1,9})$/i.exec(pathname);
  if (ticketMatch) {
    const id = ticketMatch[1].toUpperCase();

    if (method === 'GET') {
      if (!requireAuth(req, res)) return;
      const t = loadJSON(DATA_FILE, { tickets: [] }).tickets.find(x => x.id === id);
      return t ? jsonResponse(res, 200, t) : jsonResponse(res, 404, { error: 'Not found' });
    }

    if (method === 'PUT') {
      const s = requireAuth(req, res);
      if (!s) return;
      const body = await readJson(req);
      const known = loadJSON(USERS_FILE, []).map(u => u.username);
      const patch = {};
      if (body.status !== undefined)   { if (!STATUSES.includes(body.status))     return jsonResponse(res, 400, { error: 'Invalid status.' });   patch.status = body.status; }
      if (body.category !== undefined) { if (!CATEGORIES.includes(body.category)) return jsonResponse(res, 400, { error: 'Invalid category.' }); patch.category = body.category; }
      if (body.priority !== undefined) { if (!PRIORITIES.includes(body.priority)) return jsonResponse(res, 400, { error: 'Invalid priority.' }); patch.priority = body.priority; }
      if (body.resolution !== undefined) patch.resolution = cleanStr(body.resolution, LIMITS.resolution, true);
      if (body.assign !== undefined) patch.assign = cleanStr(body.assign, 64);

      const result = mutateTickets(data => {
        const t = data.tickets.find(x => x.id === id);
        if (!t) return { missing: true };
        if (patch.assign && patch.assign !== t.assign && !known.includes(patch.assign)) return { badAssignee: true };
        const oldStatus = t.status;
        const oldAssign = t.assign || '';
        Object.assign(t, patch, { updated: new Date().toISOString(), updatedBy: s.username });
        return { ticket: { ...t }, oldStatus, oldAssign };
      });
      if (result.missing) return jsonResponse(res, 404, { error: 'Not found' });
      if (result.badAssignee) return jsonResponse(res, 400, { error: 'Unknown assignee.' });
      notifyStatusChange(result.ticket, result.oldStatus, s.username).catch(e => console.error('[email]', e.message));
      let notice = '';
      try { notice = await notifyAssignee(result.ticket, result.oldAssign, s.username); } catch (e) { console.error('[email]', e.message); }
      return jsonResponse(res, 200, notice ? { ...result.ticket, notice } : result.ticket);
    }

    if (method === 'DELETE') {
      const s = requireAuth(req, res, { admin: true });
      if (!s) return;
      mutateTickets(data => { data.tickets = data.tickets.filter(x => x.id !== id); });
      audit(s.username, 'deleted ticket', id);
      return jsonResponse(res, 200, { ok: true });
    }
  }

  return jsonResponse(res, 404, { error: 'Unknown route' });
}

const server = http.createServer(async (req, res) => {
  try {
    await handle(req, res);
  } catch (err) {
    if (res.headersSent) return res.destroy();
    if (err && err.status) {
      const extra = err.status === 413 ? { Connection: 'close' } : {};
      jsonResponse(res, err.status, { error: err.message }, extra);
      if (err.status === 413) res.once('finish', () => req.destroy());
      return;
    }
    console.error('[error]', req.method, logStr(req.url), err);
    jsonResponse(res, 500, { error: 'Internal server error' });
  }
});
server.requestTimeout = 30e3;
server.headersTimeout = 15e3;
server.keepAliveTimeout = 5e3;

// ─── Start-up ────────────────────────────────────────────────────────────────
async function initFiles() {
  if (!fs.existsSync(DATA_FILE)) saveJSON(DATA_FILE, { counter: 0, tickets: [] });

  if (!fs.existsSync(EMAIL_FILE)) saveJSON(EMAIL_FILE, {
    enabled: false,
    gmailAppPassword: 'your-16-char-app-password-here',
    fromEmail: '',
    adminEmail: '',
    notifyNewTicket: true,
    notifyStatusChange: true
  });

  if (!fs.existsSync(USERS_FILE)) {
    const pw = randomPassword();
    saveJSON(USERS_FILE, [{
      username: 'Beta', passwordHash: await hashPassword(pw), role: 'admin',
      email: '', created: new Date().toISOString(), mustChange: true
    }]);
    console.log('\n  ────────────────────────────────────────────────────────────');
    console.log('   First run: created administrator account');
    console.log('     username : Beta');
    console.log(`     password : ${pw}   (one time; you must change it at first login)`);
    console.log('   Lost it?  node server.js --reset-admin');
    console.log('  ────────────────────────────────────────────────────────────\n');
  }
}

async function resetAdmin(name) {
  const users = loadJSON(USERS_FILE, []);
  const u = users.find(x => name ? x.username.toLowerCase() === name.toLowerCase() : x.role === 'admin');
  if (!u) { console.error(name ? `No user named "${name}".` : 'No administrator found.'); process.exit(1); }
  const pw = randomPassword();
  u.passwordHash = await hashPassword(pw);
  delete u.salt;
  u.mustChange = true;
  u.role = u.role === 'agent' ? 'agent' : 'admin';
  saveJSON(USERS_FILE, users);
  console.log(`Password for "${u.username}" reset.\n  New one-time password: ${pw}\n  (You will be asked to change it at next login. Restart the service to end old sessions.)`);
}

// Only used for the start-up banner, so it must never be able to stop the server:
// some sandboxes (e.g. systemd without AF_NETLINK) forbid reading network interfaces.
function lanAddress() {
  try {
    for (const list of Object.values(os.networkInterfaces()))
      for (const a of list || []) if ((a.family === 'IPv4' || a.family === 4) && !a.internal) return a.address;
  } catch { /* not available here; the banner simply omits the network address */ }
  return null;
}

async function main() {
  const i = process.argv.indexOf('--reset-admin');
  if (i !== -1) { await resetAdmin(process.argv[i + 1]); return; }

  await initFiles();
  reloadEmail();
  warnOpenAccess();
  server.listen(PORT, HOST, () => {
    console.log(`\n  ✔  Helpdesk v${VERSION} running on http://${HOST}:${PORT}`);
    console.log(`     Local   →  http://localhost:${PORT}`);
    const ip = lanAddress();
    if (ip && HOST === '0.0.0.0') console.log(`     Network →  http://${ip}:${PORT}   (plain HTTP — keep it on your LAN)`);
    if (!transporter) console.log('\n  ⚠  Email notifications are DISABLED (see Admin → Users → Email).\n');
  });
}

for (const sig of ['SIGINT', 'SIGTERM']) process.on(sig, () => server.close(() => process.exit(0)));
process.on('unhandledRejection', e => console.error('[unhandledRejection]', e));
main().catch(e => { console.error(e); process.exit(1); });
