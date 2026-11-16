'use strict';
// Run with:  npm test   (Node 18+, no extra dependencies)
// Each group starts a real server on a random port with a temporary data folder.

const { describe, it, before, after } = require('node:test');
const assert = require('node:assert/strict');
const { spawn, spawnSync } = require('node:child_process');
const crypto = require('node:crypto');
const fs = require('node:fs');
const http = require('node:http');
const net = require('node:net');
const os = require('node:os');
const path = require('node:path');

const SERVER = path.join(__dirname, '..', 'server.js');

// ── helpers ─────────────────────────────────────────────────────────────────
function freePort() {
  return new Promise((resolve, reject) => {
    const s = net.createServer();
    s.on('error', reject);
    s.listen(0, '127.0.0.1', () => { const p = s.address().port; s.close(() => resolve(p)); });
  });
}

async function startServer({ dataDir, preseed, env = {} } = {}) {
  const dir = dataDir || fs.mkdtempSync(path.join(os.tmpdir(), 'helpdesk-test-'));
  if (preseed) preseed(dir);
  const port = await freePort();
  const proc = spawn(process.execPath, [SERVER], {
    env: { ...process.env, OPEN_ACCESS: '', PORT: String(port), HOST: '127.0.0.1', DATA_DIR: dir, ...env },
    stdio: ['ignore', 'pipe', 'pipe']
  });
  let out = '';
  proc.stdout.on('data', d => { out += d; });
  proc.stderr.on('data', d => { out += d; });
  await new Promise((resolve, reject) => {
    const timer = setTimeout(() => { clearInterval(iv); reject(new Error('server did not start:\n' + out)); }, 15000);
    const iv = setInterval(() => { if (out.includes('running on')) { clearTimeout(timer); clearInterval(iv); resolve(); } }, 40);
    proc.once('exit', () => { clearTimeout(timer); clearInterval(iv); reject(new Error('server exited early:\n' + out)); });
  });
  return {
    port, dir, base: `http://127.0.0.1:${port}`, output: () => out,
    async stop({ cleanup = true } = {}) {
      proc.removeAllListeners('exit');
      proc.kill('SIGTERM');
      await new Promise(r => proc.once('exit', r));
      if (cleanup) fs.rmSync(dir, { recursive: true, force: true });
    }
  };
}

async function call(base, method, p, { token, json, raw, headers = {} } = {}) {
  const h = { ...headers };
  if (token) h.Authorization = `Bearer ${token}`;
  let body;
  if (json !== undefined) { h['Content-Type'] = 'application/json'; body = JSON.stringify(json); }
  if (raw !== undefined) body = raw;
  const res = await fetch(base + p, { method, headers: h, body });
  const text = await res.text();
  let data; try { data = JSON.parse(text); } catch { data = text; }
  return { status: res.status, headers: res.headers, data };
}

// Sends the path exactly as given (no client-side normalisation of "..").
function rawGet(port, rawPath, headers = {}) {
  return new Promise((resolve, reject) => {
    http.get({ host: '127.0.0.1', port, path: rawPath, headers }, res => {
      let body = '';
      res.on('data', c => { body += c; });
      res.on('end', () => resolve({ status: res.statusCode, body }));
    }).on('error', reject);
  });
}

const firstPassword = out => /password\s*:\s*(\S+)/.exec(out)[1];
const login = (base, username, password) => call(base, 'POST', '/api/auth/login', { json: { username, password } });

// ── fresh install ───────────────────────────────────────────────────────────
describe('fresh install', () => {
  let srv, adminToken, ticketId;
  const ADMIN_PW = 'Correct-Horse-9x';

  before(async () => { srv = await startServer(); });
  after(async () => { await srv.stop(); });

  it('serves the page with security headers', async () => {
    const r = await call(srv.base, 'GET', '/');
    assert.equal(r.status, 200);
    assert.match(r.headers.get('content-type'), /text\/html/);
    assert.match(r.headers.get('content-security-policy'), /connect-src 'self'/);
    assert.equal(r.headers.get('x-content-type-options'), 'nosniff');
    assert.equal(r.headers.get('x-frame-options'), 'DENY');
    assert.equal(r.headers.get('access-control-allow-origin'), null);
  });

  it('blocks path traversal and direct access to data files', async () => {
    const paths = ['/../users.json', '/../email-config.json', '/../server.js', '/..%2fusers.json',
      '/%2e%2e/users.json', '/public/../../users.json', '/..%5cusers.json', '/.env', '/users.json', '/server.js', '/%00'];
    for (const p of paths) {
      const r = await rawGet(srv.port, p);
      assert.ok([400, 404].includes(r.status), `${p} → ${r.status}`);
      assert.ok(!r.body.includes('passwordHash') && !r.body.includes('gmailAppPassword') && !r.body.includes("require('http')"), `${p} leaked file content`);
    }
  });

  it('requires login for staff endpoints (ticket lookup is no longer public)', async () => {
    for (const p of ['/api/tickets', '/api/tickets/HD-001', '/api/users', '/api/email-config', '/api/assignees']) {
      assert.equal((await call(srv.base, 'GET', p)).status, 401, p);
    }
  });

  it('rejects the old default password', async () => {
    assert.equal((await login(srv.base, 'Beta', 'Alpha')).status, 401);
  });

  it('has the no-password mode OFF by default', async () => {
    const r = await call(srv.base, 'GET', '/api/config');
    assert.equal(r.status, 200);
    assert.equal(r.data.openAccess, false);
    assert.match(r.data.version, /^4\./);
    assert.equal(srv.output().includes('OPEN ACCESS is ON'), false);
  });

  it('forces a password change on first login, then enforces the policy', async () => {
    const first = firstPassword(srv.output());
    const r = await login(srv.base, 'Beta', first);
    assert.equal(r.status, 200);
    assert.equal(r.data.mustChange, true);
    assert.equal(r.data.role, 'admin');
    const t = r.data.token;

    const blocked = await call(srv.base, 'GET', '/api/tickets', { token: t });
    assert.equal(blocked.status, 403);
    assert.equal(blocked.data.mustChange, true);

    const put = body => call(srv.base, 'PUT', '/api/auth/password', { token: t, json: body });
    assert.equal((await put({ current: first, password: 'short' })).status, 400);
    assert.equal((await put({ current: first, password: 'Beta-is-my-name' })).status, 400);
    assert.equal((await put({ current: 'wrong-current-pw', password: ADMIN_PW })).status, 400);
    assert.equal((await put({ current: first, password: first })).status, 400);
    assert.equal((await put({ current: first, password: ADMIN_PW })).status, 200);

    assert.equal((await login(srv.base, 'Beta', first)).status, 401);
    const again = await login(srv.base, 'Beta', ADMIN_PW);
    assert.equal(again.status, 200);
    assert.equal(again.data.mustChange, false);
    adminToken = again.data.token;
    assert.equal((await call(srv.base, 'GET', '/api/tickets', { token: adminToken })).status, 200);
  });

  it('accepts a ticket and returns only its ID', async () => {
    const r = await call(srv.base, 'POST', '/api/tickets', {
      json: { name: 'Pat', email: 'pat@example.com', subject: 'Printer jam', desc: 'It is jammed.', category: 'hardware', priority: 'high' }
    });
    assert.equal(r.status, 201);
    assert.deepEqual(Object.keys(r.data), ['id']);
    assert.match(r.data.id, /^HD-\d{3}$/);
    ticketId = r.data.id;
  });

  it('validates ticket input and normalises bad enums', async () => {
    const bad = json => call(srv.base, 'POST', '/api/tickets', { json });
    assert.equal((await bad({ name: '', email: 'a@b.co', subject: 's', desc: 'd' })).status, 400);
    assert.equal((await bad({ name: 'n', email: 'not-an-email', subject: 's', desc: 'd' })).status, 400);
    assert.equal((await bad({ name: 'n', email: 'a@b.co,c@d.co', subject: 's', desc: 'd' })).status, 400);
    const ok = await bad({ name: 'n', email: 'a@b.co', subject: 's', desc: 'd', category: '<script>', priority: 'urgent!!' });
    assert.equal(ok.status, 201);
    const list = await call(srv.base, 'GET', '/api/tickets', { token: adminToken });
    const t = list.data.find(x => x.id === ok.data.id);
    assert.equal(t.category, 'other');
    assert.equal(t.priority, 'low');
  });

  it('rejects non-JSON and oversized request bodies', async () => {
    const wrongType = await call(srv.base, 'POST', '/api/tickets', { raw: 'name=x', headers: { 'Content-Type': 'text/plain' } });
    assert.equal(wrongType.status, 415);
    const big = await call(srv.base, 'POST', '/api/tickets', {
      json: { name: 'n', email: 'a@b.co', subject: 's', desc: 'x'.repeat(100 * 1024) }
    });
    assert.equal(big.status, 413);
  });

  it('ticket tracking needs the ID and the matching email', async () => {
    const track = json => call(srv.base, 'POST', '/api/track', { json });
    const ok = await track({ id: ticketId.toLowerCase(), email: 'PAT@example.com' });
    assert.equal(ok.status, 200);
    assert.equal(ok.data.subject, 'Printer jam');
    assert.equal(ok.data.desc, undefined);
    assert.equal(ok.data.email, undefined);
    const wrongEmail = await track({ id: ticketId, email: 'someone@else.com' });
    const unknownId = await track({ id: 'HD-999', email: 'pat@example.com' });
    assert.equal(wrongEmail.status, 404);
    assert.equal(unknownId.status, 404);
    assert.deepEqual(wrongEmail.data, unknownId.data);          // no way to tell "exists" from "doesn't"
  });

  it('validates ticket updates', async () => {
    const put = json => call(srv.base, 'PUT', `/api/tickets/${ticketId}`, { token: adminToken, json });
    assert.equal((await put({ status: 'hacked' })).status, 400);
    assert.equal((await put({ assign: 'nobody-here' })).status, 400);
    const ok = await put({ assign: 'Beta', status: 'assigned', resolution: 'Cleared the jam.', id: 'HD-777', date: '1999-01-01' });
    assert.equal(ok.status, 200);
    assert.equal(ok.data.id, ticketId);                          // id/date cannot be overwritten
    assert.notEqual(ok.data.date, '1999-01-01');
    assert.equal(ok.data.status, 'assigned');
  });

  it('agents can work tickets but not administer', async () => {
    const mk = json => call(srv.base, 'POST', '/api/users', { token: adminToken, json });
    assert.equal((await mk({ username: 'agent1', password: 'weak', role: 'agent' })).status, 400);
    assert.equal((await mk({ username: 'a b', password: 'Long-enough-pw1', role: 'agent' })).status, 400);
    assert.equal((await mk({ username: 'agent1', password: 'Temp-Password-1', role: 'agent' })).status, 201);
    assert.equal((await mk({ username: 'AGENT1', password: 'Temp-Password-1', role: 'agent' })).status, 409);

    const l = await login(srv.base, 'agent1', 'Temp-Password-1');
    assert.equal(l.data.mustChange, true);
    assert.equal(l.data.role, 'agent');
    const chg = await call(srv.base, 'PUT', '/api/auth/password', { token: l.data.token, json: { current: 'Temp-Password-1', password: 'Agent-Own-Pass-2' } });
    assert.equal(chg.status, 200);
    const t = (await login(srv.base, 'agent1', 'Agent-Own-Pass-2')).data.token;

    assert.equal((await call(srv.base, 'GET', '/api/tickets', { token: t })).status, 200);
    assert.equal((await call(srv.base, 'GET', '/api/assignees', { token: t })).status, 200);
    assert.equal((await call(srv.base, 'GET', '/api/users', { token: t })).status, 403);
    assert.equal((await call(srv.base, 'GET', '/api/email-config', { token: t })).status, 403);
    assert.equal((await call(srv.base, 'DELETE', `/api/tickets/${ticketId}`, { token: t })).status, 403);
    assert.equal((await call(srv.base, 'POST', '/api/users', { token: t, json: { username: 'sneaky', password: 'Sneaky-Pass-123' } })).status, 403);
  });

  it('admin cannot delete their own account; deleting a user ends their sessions', async () => {
    assert.equal((await call(srv.base, 'DELETE', '/api/users/Beta', { token: adminToken })).status, 400);
    const t = (await login(srv.base, 'agent1', 'Agent-Own-Pass-2')).data.token;
    assert.equal((await call(srv.base, 'DELETE', '/api/users/agent1', { token: adminToken })).status, 200);
    assert.equal((await call(srv.base, 'GET', '/api/tickets', { token: t })).status, 401);
  });

  it('never returns password hashes or the Gmail password', async () => {
    const users = await call(srv.base, 'GET', '/api/users', { token: adminToken });
    assert.ok(!JSON.stringify(users.data).includes('scrypt'));
    const cfg = await call(srv.base, 'GET', '/api/email-config', { token: adminToken });
    assert.ok(!JSON.stringify(cfg.data).includes('your-16-char'));
  });

  it('ships with no personal email addresses, and the email fields can be left blank', async () => {
    const cfg = await call(srv.base, 'GET', '/api/email-config', { token: adminToken });
    assert.equal(cfg.data.fromEmail, '');
    assert.equal(cfg.data.adminEmail, '');
    const users = await call(srv.base, 'GET', '/api/users', { token: adminToken });
    assert.equal(users.data.find(u => u.username === 'Beta').email, '');
    const put = json => call(srv.base, 'PUT', '/api/email-config', { token: adminToken, json });
    assert.equal((await put({ fromEmail: '', adminEmail: '' })).status, 200);
    assert.equal((await put({ fromEmail: 'not-an-email' })).status, 400);
    assert.equal((await call(srv.base, 'POST', '/api/email-config/test', { token: adminToken })).status, 400);
  });

  it('stores data files with owner-only permissions', () => {
    for (const f of ['users.json', 'tickets.json', 'email-config.json']) {
      const mode = fs.statSync(path.join(srv.dir, f)).mode & 0o777;
      assert.equal(mode, 0o600, `${f} is ${mode.toString(8)}`);
    }
  });

  it('rate-limits ticket submission', async () => {
    let limited = null;
    for (let i = 0; i < 8 && !limited; i++) {
      const r = await call(srv.base, 'POST', '/api/tickets', { json: { name: 'Spam', email: 'spam@example.com', subject: 's' + i, desc: 'd' } });
      if (r.status === 429) limited = r;
    }
    assert.ok(limited, 'expected a 429');
    assert.ok(Number(limited.headers.get('retry-after')) > 0);
  });
});

// ── optional "no password" mode ─────────────────────────────────────────────
describe('open access (optional no-password mode)', () => {
  let srv, ticketId;
  before(async () => {
    srv = await startServer({ env: { OPEN_ACCESS: 'on' } });
    const r = await call(srv.base, 'POST', '/api/tickets', { json: { name: 'Pat', email: 'pat@example.com', subject: 'Mouse', desc: 'Broken mouse' } });
    ticketId = r.data.id;
  });
  after(async () => { await srv.stop(); });

  it('warns loudly in the log', () => {
    assert.ok(srv.output().includes('OPEN ACCESS is ON'));
  });

  it('tells a local visitor that open access applies', async () => {
    assert.equal((await call(srv.base, 'GET', '/api/config')).data.openAccess, true);
  });

  it('lets a local visitor view and work tickets without logging in', async () => {
    const list = await call(srv.base, 'GET', '/api/tickets');
    assert.equal(list.status, 200);
    assert.equal(list.data.length, 1);
    assert.equal((await call(srv.base, 'GET', '/api/assignees')).status, 200);
    const upd = await call(srv.base, 'PUT', `/api/tickets/${ticketId}`, { json: { status: 'resolved', resolution: 'Swapped the mouse.' } });
    assert.equal(upd.status, 200);
    assert.equal(upd.data.updatedBy, 'open-access');
  });

  it('never grants admin powers', async () => {
    assert.equal((await call(srv.base, 'GET', '/api/users')).status, 403);
    assert.equal((await call(srv.base, 'GET', '/api/email-config')).status, 403);
    assert.equal((await call(srv.base, 'POST', '/api/users', { json: { username: 'sneaky', password: 'Sneaky-Pass-123', role: 'admin' } })).status, 403);
    assert.equal((await call(srv.base, 'DELETE', `/api/tickets/${ticketId}`)).status, 403);
    assert.equal((await call(srv.base, 'PUT', '/api/auth/password', { json: { current: 'x', password: 'Whatever-Pass-123' } })).status, 400);
  });

  it('does not apply to requests relayed by a proxy', async () => {
    const h = { 'X-Forwarded-For': '203.0.113.9' };
    assert.equal((await call(srv.base, 'GET', '/api/tickets', { headers: h })).status, 401);
    assert.equal((await call(srv.base, 'GET', '/api/config', { headers: h })).data.openAccess, false);
  });

  it('does not apply when the page was reached through a public-looking web name', async () => {
    const r = await rawGet(srv.port, '/api/tickets', { Host: 'evil.example.com' });
    assert.equal(r.status, 401);
    const ok = await rawGet(srv.port, '/api/tickets', { Host: 'pi4.local:3000' });
    assert.equal(ok.status, 200);
  });

  it('a wrong or expired login token is refused, not silently treated as open access', async () => {
    assert.equal((await call(srv.base, 'GET', '/api/tickets', { token: 'a'.repeat(64) })).status, 401);
  });

  it('a real admin can still log in normally while open access is on', async () => {
    const pw = firstPassword(srv.output());
    const r = await login(srv.base, 'Beta', pw);
    assert.equal(r.status, 200);
    assert.equal(r.data.role, 'admin');
  });
});

// ── hardened service sandbox ────────────────────────────────────────────────
describe('restricted sandbox', () => {
  it('still starts when the network-interface lookup is forbidden (systemd RestrictAddressFamilies)', async () => {
    const fixture = path.join(__dirname, '..', 'fixtures', 'no-netlink.js');
    const srv = await startServer({ env: { NODE_OPTIONS: `--require ${fixture}` } });
    try {
      assert.equal((await call(srv.base, 'GET', '/api/config')).status, 200);
    } finally { await srv.stop(); }
  });
});

// ── brute-force protection ──────────────────────────────────────────────────
describe('login throttling', () => {
  let srv;
  before(async () => { srv = await startServer(); });
  after(async () => { await srv.stop(); });

  it('locks out repeated failures, even before the right password is tried', async () => {
    const good = firstPassword(srv.output());
    for (let i = 0; i < 10; i++) assert.equal((await login(srv.base, 'Beta', 'guess-' + i)).status, 401);
    const r = await login(srv.base, 'Beta', good);
    assert.equal(r.status, 429);
    assert.ok(Number(r.headers.get('retry-after')) > 0);
  });
});

// ── upgrading a v2 install ──────────────────────────────────────────────────
describe('upgrade from v2', () => {
  let srv;
  before(async () => {
    srv = await startServer({
      preseed(dir) {
        const salt = crypto.randomBytes(16).toString('hex');
        fs.writeFileSync(path.join(dir, 'users.json'), JSON.stringify([{
          username: 'Beta', salt, passwordHash: crypto.createHash('sha256').update(salt + 'Alpha').digest('hex'),
          role: 'admin', email: 'x@example.com', created: new Date().toISOString()
        }]));
        fs.writeFileSync(path.join(dir, 'tickets.json'), JSON.stringify({
          counter: 1, tickets: [{ id: 'HD-001', name: '<b>old</b>', email: 'o@example.com', category: 'other', priority: 'low',
            subject: 'legacy', desc: 'legacy', status: 'open', assign: '', resolution: '', date: new Date().toISOString() }]
        }));
      }
    });
  });
  after(async () => { await srv.stop(); });

  it('accepts the legacy hash once, forces a change for the old default, and upgrades the hash', async () => {
    const r = await login(srv.base, 'Beta', 'Alpha');
    assert.equal(r.status, 200);
    assert.equal(r.data.mustChange, true);
    const stored = fs.readFileSync(path.join(srv.dir, 'users.json'), 'utf8');
    assert.match(stored, /scrypt\$/);
    assert.ok(!stored.includes('"salt"'));
    assert.equal((await login(srv.base, 'Beta', 'Alpha')).status, 200);   // still works until they change it
  });

  it('keeps existing tickets', async () => {
    const t = (await login(srv.base, 'Beta', 'Alpha')).data.token;
    // must change password first, so the list is blocked until then
    assert.equal((await call(srv.base, 'GET', '/api/tickets', { token: t })).status, 403);
    await call(srv.base, 'PUT', '/api/auth/password', { token: t, json: { current: 'Alpha', password: 'Brand-New-Pass-1' } });
    const t2 = (await login(srv.base, 'Beta', 'Brand-New-Pass-1')).data.token;
    const list = await call(srv.base, 'GET', '/api/tickets', { token: t2 });
    assert.equal(list.data[0].id, 'HD-001');
  });
});

// ── recovery ────────────────────────────────────────────────────────────────
describe('--reset-admin', () => {
  it('issues a new one-time password for the admin', async () => {
    const first = await startServer();
    await first.stop({ cleanup: false });
    const r = spawnSync(process.execPath, [SERVER, '--reset-admin'], { env: { ...process.env, DATA_DIR: first.dir }, encoding: 'utf8' });
    assert.equal(r.status, 0, r.stderr);
    const pw = /New one-time password:\s*(\S+)/.exec(r.stdout)[1];
    const second = await startServer({ dataDir: first.dir });
    try {
      const l = await login(second.base, 'Beta', pw);
      assert.equal(l.status, 200);
      assert.equal(l.data.mustChange, true);
    } finally { await second.stop(); }
  });
});

// ── email queue (fake mail transport: the real nodemailer is not needed) ────
describe('email sending', () => {
  const ADMIN_PW = 'Mail-Test-Pass-77';
  const FIXTURE = path.join(__dirname, '..', 'fixtures', 'fake-mail.js');
  const waitFor = async (fn, ms = 8000) => {
    const end = Date.now() + ms;
    while (Date.now() < end) { const v = await fn(); if (v) return v; await new Promise(r => setTimeout(r, 40)); }
    throw new Error('timed out waiting');
  };
  async function boot(extraEnv) {
    const outFile = path.join(os.tmpdir(), 'mail-out-' + crypto.randomBytes(4).toString('hex') + '.jsonl');
    fs.writeFileSync(outFile, '');
    const srv = await startServer({ env: { HELPDESK_MAIL_FIXTURE: FIXTURE, MAIL_FIXTURE_OUT: outFile, HELPDESK_MAIL_RETRY_MS: '100,100', ...extraEnv } });
    const first = firstPassword(srv.output());
    const t0 = (await login(srv.base, 'Beta', first)).data.token;
    await call(srv.base, 'PUT', '/api/auth/password', { token: t0, json: { current: first, password: ADMIN_PW } });
    const token = (await login(srv.base, 'Beta', ADMIN_PW)).data.token;
    const put = await call(srv.base, 'PUT', '/api/email-config', { token, json: {
      enabled: true, fromEmail: 'help@example.com', adminEmail: 'boss@example.com', gmailAppPassword: 'abcdabcdabcdabcd',
      notifyNewTicket: true, notifyStatusChange: true } });
    assert.equal(put.data.transporterReady, true);
    const lines = () => fs.readFileSync(outFile, 'utf8').split('\n').filter(Boolean).map(l => JSON.parse(l));
    return { srv, token, lines, outFile };
  }
  const ticket = (srv, email = 'pat@example.com') => call(srv.base, 'POST', '/api/tickets', {
    json: { name: 'Pat', email, subject: 'Printer', desc: 'jam', category: 'hardware', priority: 'low' } });

  it('does not make the ticket request wait for a slow mail server', async () => {
    const { srv, lines } = await boot({ MAIL_FIXTURE_DELAY: '1500' });
    try {
      const t = Date.now();
      const r = await ticket(srv);
      assert.equal(r.status, 201);
      assert.ok(Date.now() - t < 1000, 'request took ' + (Date.now() - t) + ' ms');
      await waitFor(() => lines().length === 2, 10000);     // admin notice + confirmation
    } finally { await srv.stop(); }
  });

  it('retries a failed send and records it in the activity log', async () => {
    const { srv, token, lines } = await boot({ MAIL_FIXTURE_FAIL_FIRST: '2' });
    try {
      await ticket(srv);
      await waitFor(() => lines().length >= 4);               // 2 failures + 2 successes
      const log = await waitFor(async () => {
        const l = (await call(srv.base, 'GET', '/api/email-config/log', { token })).data;
        return l.entries.some(e => e.status === 'sent') && l ;
      });
      assert.ok(log.entries.some(e => e.status === 'retrying'));
      assert.ok(log.entries.some(e => e.status === 'sent'));
      assert.equal((await call(srv.base, 'GET', '/api/email-config/log')).status, 401);
    } finally { await srv.stop(); }
  });

  it('does not retry a rejected login, and Send Test explains it in plain words', async () => {
    const { srv, token, lines } = await boot({ MAIL_FIXTURE_AUTH_FAIL: '1' });
    try {
      const r = await call(srv.base, 'POST', '/api/email-config/test', { token });
      assert.equal(r.status, 502);
      assert.match(r.data.error, /App Password/);
      await ticket(srv);
      await waitFor(async () => (await call(srv.base, 'GET', '/api/email-config/log', { token })).data.entries.filter(e => e.status === 'failed').length >= 3);
      await new Promise(r => setTimeout(r, 500));
      assert.equal(lines().length, 3);                         // 1 test + 2 ticket mails, no retries
    } finally { await srv.stop(); }
  });

  it('confirmation and status mails to one person are no longer cut off after three', async () => {
    const { srv, token, lines } = await boot();
    try {
      const id = (await ticket(srv)).data.id;
      for (const status of ['assigned', 'resolved', 'open', 'resolved']) {
        const u = await call(srv.base, 'PUT', `/api/tickets/${id}`, { token, json: { status, assign: 'Beta', resolution: 'done' } });
        assert.equal(u.status, 200, JSON.stringify(u.data));
      }
      await waitFor(() => lines().filter(l => l.to === 'pat@example.com').length === 5);
    } finally { await srv.stop(); }
  });
  it('emails the assignee when a ticket is assigned to them (not for self-assignment, not twice)', async () => {
    const { srv, token, lines } = await boot();
    try {
      const mk = await call(srv.base, 'POST', '/api/users', { token, json: { username: 'Gamma', password: 'Quiet-Harbor-Lamp-42', email: 'gamma@example.com', role: 'agent' } });
      assert.equal(mk.status, 201, JSON.stringify(mk.data));
      const id = (await ticket(srv)).data.id;
      await waitFor(() => lines().length === 2);                       // admin notice + confirmation
      const put = json => call(srv.base, 'PUT', `/api/tickets/${id}`, { token, json });
      assert.equal((await put({ assign: 'Gamma' })).status, 200);
      const sent = await waitFor(() => lines().find(l => l.to === 'gamma@example.com'));
      assert.match(sent.subject, new RegExp(`${id} assigned to you`));
      assert.equal((await put({ assign: 'Gamma', priority: 'high' })).status, 200);   // unchanged assignee
      assert.equal((await put({ assign: 'Beta' })).status, 200);                      // Beta is the one assigning
      await new Promise(r => setTimeout(r, 400));
      assert.equal(lines().filter(l => l.to === 'gamma@example.com').length, 1);
      assert.equal(lines().filter(l => /assigned to you/.test(l.subject)).length, 1);
    } finally { await srv.stop(); }
  });

  it('can be switched off, and notes in the activity log when the assignee has no email', async () => {
    const { srv, token, lines } = await boot();
    try {
      await call(srv.base, 'POST', '/api/users', { token, json: { username: 'Delta', password: 'Quiet-Harbor-Lamp-43', role: 'agent' } });
      const id = (await ticket(srv, 'x@example.com')).data.id;
      await waitFor(() => lines().length === 2);
      await call(srv.base, 'PUT', `/api/tickets/${id}`, { token, json: { assign: 'Delta' } });
      const log = await waitFor(async () => (await call(srv.base, 'GET', '/api/email-config/log', { token })).data.entries.find(e => e.status === 'dropped' && /No email address/.test(e.note)));
      assert.ok(log);
      await call(srv.base, 'PUT', '/api/email-config', { token, json: { notifyAssignee: false } });
      await call(srv.base, 'POST', '/api/users', { token, json: { username: 'Eps', password: 'Quiet-Harbor-Lamp-44', email: 'eps@example.com', role: 'agent' } });
      await call(srv.base, 'PUT', `/api/tickets/${id}`, { token, json: { assign: 'Eps' } });
      await new Promise(r => setTimeout(r, 400));
      assert.equal(lines().some(l => l.to === 'eps@example.com'), false);
    } finally { await srv.stop(); }
  });

  it('when a ticket is resolved, both the submitter and the assigned tech get an email', async () => {
    const { srv, token, lines } = await boot();
    try {
      await call(srv.base, 'POST', '/api/users', { token, json: { username: 'Zeta', password: 'Quiet-Harbor-Lamp-45', email: 'zeta@example.com', role: 'agent' } });
      const id = (await ticket(srv, 'sub@example.com')).data.id;
      await waitFor(() => lines().length === 2);
      await call(srv.base, 'PUT', `/api/tickets/${id}`, { token, json: { assign: 'Zeta' } });
      await waitFor(() => lines().some(l => l.to === 'zeta@example.com'));
      await call(srv.base, 'PUT', `/api/tickets/${id}`, { token, json: { status: 'resolved', resolution: 'Replaced toner' } });
      await waitFor(() => lines().some(l => l.to === 'sub@example.com' && /"Resolved"/.test(l.subject))
                       && lines().some(l => l.to === 'zeta@example.com' && /resolved/.test(l.subject)));
      await call(srv.base, 'PUT', `/api/tickets/${id}`, { token, json: { resolution: 'Edited note only' } });   // no status change
      await new Promise(r => setTimeout(r, 400));
      assert.equal(lines().filter(l => /resolved/i.test(l.subject)).length, 2);
    } finally { await srv.stop(); }
  });

  it('an admin can add an email to an existing user, and then assignment emails reach them', async () => {
    const { srv, token, lines } = await boot();
    try {
      await call(srv.base, 'POST', '/api/users', { token, json: { username: 'Theta', password: 'Quiet-Harbor-Lamp-46', role: 'agent' } });
      const id = (await ticket(srv, 'q@example.com')).data.id;
      await waitFor(() => lines().length === 2);
      const put = (name, json, tk = token) => call(srv.base, 'PUT', `/api/users/${name}/email`, { token: tk, json });
      assert.equal((await put('Theta', { email: 'not-an-email' })).status, 400);
      assert.equal((await put('Nobody', { email: 'a@b.co' })).status, 404);
      assert.equal((await call(srv.base, 'PUT', '/api/users/Theta/email', { json: { email: 'a@b.co' } })).status, 401);
      assert.equal((await put('Theta', { email: 'theta@example.com' })).status, 200);
      const users = (await call(srv.base, 'GET', '/api/users', { token })).data;
      assert.equal(users.find(u => u.username === 'Theta').email, 'theta@example.com');
      await call(srv.base, 'PUT', `/api/tickets/${id}`, { token, json: { assign: 'Theta' } });
      await waitFor(() => lines().some(l => l.to === 'theta@example.com'));
      assert.equal((await put('Theta', { email: '' })).status, 200);                  // clearing works too
    } finally { await srv.stop(); }
  });

  it('saving a ticket tells the admin what happened with the assignee email, and Open can be restored', async () => {
    const { srv, token } = await boot();
    try {
      await call(srv.base, 'POST', '/api/users', { token, json: { username: 'Iota', password: 'Quiet-Harbor-Lamp-47', role: 'agent' } });
      const id = (await ticket(srv, 'w@example.com')).data.id;
      const put = json => call(srv.base, 'PUT', `/api/tickets/${id}`, { token, json });
      const a = await put({ assign: 'Iota', status: 'assigned' });
      assert.match(a.data.notice, /Iota.*no email address/i);
      await call(srv.base, 'PUT', '/api/users/Iota/email', { token, json: { email: 'iota@example.com' } });
      await put({ assign: '' });
      const b = await put({ assign: 'Iota' });
      assert.match(b.data.notice, /Email queued to Iota/);
      assert.equal((await put({ status: 'resolved' })).data.status, 'resolved');
      const back = await put({ status: 'open' });
      assert.equal(back.data.status, 'open');                       // the server never blocked this
      assert.equal(back.data.assign, 'Iota');                       // and keeps the assignee
      const again = await call(srv.base, 'GET', `/api/tickets/${id}`, { token });
      assert.equal(again.data.status, 'open');
    } finally { await srv.stop(); }
  });
});
