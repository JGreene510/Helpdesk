'use strict';
// Test-only stand-in for nodemailer. Records every attempt in $MAIL_FIXTURE_OUT
// (one JSON line each), can fail the first N attempts, and can be slow.
const fs = require('fs');
let calls = 0;
exports.createTransport = () => ({
  async sendMail(msg) {
    calls++;
    fs.appendFileSync(process.env.MAIL_FIXTURE_OUT, JSON.stringify({ n: calls, to: msg.to, subject: msg.subject }) + '\n');
    const delay = Number(process.env.MAIL_FIXTURE_DELAY || 0);
    if (delay) await new Promise(r => setTimeout(r, delay));
    if (calls <= Number(process.env.MAIL_FIXTURE_FAIL_FIRST || 0)) {
      throw Object.assign(new Error('connect ETIMEDOUT 74.125.0.1:465'), { code: 'ETIMEDOUT' });
    }
    if (process.env.MAIL_FIXTURE_AUTH_FAIL) throw Object.assign(new Error('535 Invalid login'), { code: 'EAUTH', responseCode: 535 });
    return { accepted: [msg.to] };
  }
});
