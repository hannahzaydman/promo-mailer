'use strict';

const express    = require('express');
const multer     = require('multer');
const path       = require('path');
const crypto     = require('crypto');
const nodemailer = require('nodemailer');
const session    = require('express-session');
const https      = require('https');

const {
  escHtml, sanitizeMimeHeader, applyTemplate, parseRecipientList, partitionCodes,
  isFatalSmtpError, isFatalGmailError, validateColumns, RateLimiter,
  validateInputLengths, redactCredentials, readSpreadsheet, unsubToken,
  createSmtpCrypto, fetchWithTimeout,
} = require('./utils');

// ── createApp ──────────────────────────────────────────────────────────────
/**
 * Create and configure the Express app.
 *
 * @param {object} opts
 * @param {object} opts.db            - Firestore instance (or compatible mock)
 * @param {object} opts.sessionStore  - express-session store (FirestoreStore in prod,
 *                                      MemoryStore in tests)
 * @param {object} opts.config
 * @param {string} opts.config.baseUrl
 * @param {string} opts.config.sessionSecret
 * @param {string} [opts.config.allowedDomain]
 * @param {string} [opts.config.googleClientId]
 * @param {string} [opts.config.googleClientSecret]
 */
function createApp({ db, sessionStore, config }) {
  const {
    baseUrl           = 'http://localhost:5001',
    sessionSecret     = 'local-dev-secret-change-in-prod',
    allowedDomain     = '',
    googleClientId,
    googleClientSecret,
  } = config;

  const IS_PROD        = baseUrl.startsWith('https');
  const GMAIL_DAILY_LIMIT = 500;

  // ── Logging ──────────────────────────────────────────────────────────────
  // In production emit newline-delimited JSON for Cloud Run / Cloud Logging.
  // Locally emit readable text so the console stays scannable.
  function log(level, event, data = {}) {
    if (IS_PROD) {
      const severity = level === 'error' ? 'ERROR' : level === 'warn' ? 'WARNING' : 'INFO';
      process.stdout.write(JSON.stringify({ severity, event, ...data }) + '\n');
    } else {
      const prefix = level === 'error' ? '[ERROR]' : level === 'warn' ? '[WARN]' : '[INFO]';
      const extra = Object.keys(data).length ? ' ' + JSON.stringify(data) : '';
      console.log(`${prefix} ${event}${extra}`);
    }
  }

  // ── Startup validation ────────────────────────────────────────────────────
  // Fail fast in production rather than silently misbehaving.
  if (IS_PROD) {
    const missing = [
      sessionSecret === 'local-dev-secret-change-in-prod' && 'SESSION_SECRET',
    ].filter(Boolean);
    if (missing.length) {
      log('error', 'startup_validation_failed', { missing });
      process.exit(1);
    }
    if (!googleClientId || !googleClientSecret) {
      log('warn', 'google_oauth_not_configured', { note: 'Google sign-in disabled; SMTP login only' });
    }
  }

  // ── Domain restriction ────────────────────────────────────────────────────
  const allowedDomainRE = allowedDomain
    ? new RegExp('@' + allowedDomain.split('.').join('\\.') + '$', 'i')
    : null;

  // ── SMTP credential encryption ────────────────────────────────────────────
  const smtpEncKey = crypto.createHash('sha256').update(sessionSecret).digest();
  const { encrypt: encryptSmtpPassword, decrypt: decryptSmtpPassword } = createSmtpCrypto(smtpEncKey);

  // ── Unsubscribe helpers ───────────────────────────────────────────────────
  function makeUnsubToken(senderEmail, recipientEmail) {
    return unsubToken(sessionSecret, senderEmail, recipientEmail);
  }

  function unsubLink(senderEmail, recipientEmail) {
    const token = makeUnsubToken(senderEmail, recipientEmail);
    return `${baseUrl}/unsubscribe?sender=${encodeURIComponent(senderEmail)}&email=${encodeURIComponent(recipientEmail)}&token=${token}`;
  }

  async function getUnsubscribes(senderEmail) {
    const doc = await db.collection('unsubscribes').doc(senderEmail).get();
    if (!doc.exists) return new Set();
    return new Set(Object.keys(doc.data().emails || {}));
  }

  async function addUnsubscribe(senderEmail, recipientEmail) {
    await db.collection('unsubscribes').doc(senderEmail).set(
      { emails: { [recipientEmail]: true } },
      { merge: true }
    );
  }

  // ── Send count helpers ────────────────────────────────────────────────────
  async function getDailyCount(senderEmail) {
    const today = new Date().toISOString().slice(0, 10);
    const doc = await db.collection('sendCounts').doc(senderEmail).get();
    if (!doc.exists) return 0;
    const d = doc.data();
    return d.date === today ? (d.count || 0) : 0;
  }

  async function incrementDailyCount(senderEmail, n) {
    const today = new Date().toISOString().slice(0, 10);
    const ref = db.collection('sendCounts').doc(senderEmail);
    await db.runTransaction(async t => {
      const doc = await t.get(ref);
      const d = doc.exists ? doc.data() : {};
      const existing = d.date === today ? (d.count || 0) : 0;
      t.set(ref, { date: today, count: existing + n });
    });
  }

  // ── Rate limiters ─────────────────────────────────────────────────────────
  const sendRateLimiter  = new RateLimiter(200, 60_000);
  const loginRateLimiter = new RateLimiter(10, 15 * 60_000);
  setInterval(() => { sendRateLimiter.prune(); loginRateLimiter.prune(); }, 5 * 60_000).unref();

  // ── Express app ───────────────────────────────────────────────────────────
  const app = express();
  app.set('trust proxy', 1);

  // Security headers
  app.use((req, res, next) => {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
    res.setHeader('Content-Security-Policy', [
      "default-src 'self'",
      "script-src 'self' 'unsafe-inline'",
      "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com",
      "font-src https://fonts.gstatic.com",
      "connect-src 'self' https://accounts.google.com",
      "img-src 'self' data: https://f4.bcbits.com",
      "frame-ancestors 'none'",
      "object-src 'none'",
      "base-uri 'self'",
    ].join('; '));
    next();
  });

  // Session
  app.use(session({
    store:             sessionStore,
    secret:            sessionSecret,
    resave:            false,
    saveUninitialized: false,
    cookie: {
      secure:   IS_PROD,
      httpOnly: true,
      sameSite: 'lax',
      maxAge:   8 * 60 * 60 * 1000,
    },
  }));

  // Raise the JSON body limit to 5 MB so that large send batches are not
  // silently rejected with a 413.
  app.use(express.json({ limit: '5mb' }));

  // ── Auth middleware ───────────────────────────────────────────────────────
  function requireAuth(req, res, next) {
    if (req.path.startsWith('/auth/login')) return next();
    if (req.session?.user) return next();
    if (!googleClientId) return next();
    res.redirect('/auth/login');
  }

  // ── Login page ────────────────────────────────────────────────────────────
  const LOGIN_PAGE = (msg = '') => `<!DOCTYPE html>
<html><head><meta charset="UTF-8"><title>Promo Mailer</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Syne:wght@400;500;700;800&display=swap" rel="stylesheet">
<style>
  *{box-sizing:border-box;margin:0;padding:0}
  html{background:#0c0b10}
  body{background:transparent;color:#f0eef8;font-family:'Syne',sans-serif;
       display:flex;flex-direction:column;align-items:center;justify-content:center;min-height:100vh;margin:0;padding:40px 20px;gap:24px}
  #star-canvas{position:fixed;inset:0;width:100%;height:100%;z-index:-1;pointer-events:none}
  .card{background:#131118;border:1px solid #2a2635;padding:40px 36px;
        text-align:center;max-width:440px;width:100%}
  .logo{width:64px;height:64px;object-fit:cover;display:block;margin:0 auto 20px}
  h1{font-size:1.4rem;font-weight:800;letter-spacing:.06em;text-transform:uppercase;color:#f0eef8;margin-bottom:6px;line-height:1}
  .sub{color:#8a8499;font-size:.68rem;letter-spacing:.2em;text-transform:uppercase;font-weight:500;margin-bottom:28px}
  .features{list-style:none;margin-bottom:28px;display:flex;flex-direction:column;gap:10px;text-align:left}
  .features li{display:flex;align-items:flex-start;gap:10px;font-size:.8rem;color:#c8c3d8;line-height:1.5}
  .features li .icon{color:#4455ff;font-size:.85rem;flex-shrink:0;margin-top:2px}
  .features li strong{color:#f0eef8;font-weight:700}
  .divider{border:none;border-top:1px solid #2a2635;margin:24px 0}
  .section-label{font-size:.62rem;letter-spacing:.18em;text-transform:uppercase;color:#4d4a5a;font-weight:600;margin-bottom:14px;text-align:left}
  .field{margin-bottom:14px;text-align:left}
  label{display:block;font-size:.68rem;font-weight:600;letter-spacing:.08em;text-transform:uppercase;color:#8a8499;margin-bottom:6px}
  input,select{width:100%;background:#1b1922;border:1px solid #2a2635;border-radius:6px;color:#f0eef8;
    font-family:'Syne',sans-serif;font-size:.84rem;padding:9px 12px;outline:none;transition:border-color .15s,box-shadow .15s}
  input:focus,select:focus{border-color:#4455ff;box-shadow:0 0 0 3px rgba(68,85,255,.12)}
  input::placeholder{color:#4d4a5a}
  .row2{display:grid;grid-template-columns:1fr 1fr;gap:12px}
  .row3{display:grid;grid-template-columns:2fr 1fr 1fr;gap:12px}
  .presets{display:flex;gap:6px;flex-wrap:wrap;margin-bottom:16px}
  .chip{background:#1b1922;border:1px solid #2a2635;border-radius:6px;padding:5px 11px;
        font-size:.65rem;font-weight:600;letter-spacing:.04em;color:#8a8499;cursor:pointer;transition:border-color .15s,color .15s}
  .chip:hover{border-color:rgba(68,85,255,.4);color:#f0eef8}
  .chip.active{border-color:#4455ff;color:#f0eef8;background:rgba(68,85,255,.1)}
  .hint{font-size:.68rem;color:#8a8499;margin-top:5px;line-height:1.5}
  .btn-smtp{display:block;width:100%;background:#4455ff;border:none;border-radius:6px;color:#fff;
    cursor:pointer;font-family:'Syne',sans-serif;font-size:.72rem;font-weight:700;letter-spacing:.1em;
    text-transform:uppercase;padding:12px;transition:background .15s;margin-top:4px}
  .btn-smtp:hover{background:#6673ff}
  .btn-smtp:disabled{opacity:.4;cursor:not-allowed}
  .google-btn{display:flex;align-items:center;justify-content:center;gap:10px;width:100%;
    background:#1b1922;border:1px solid #2a2635;border-radius:6px;color:#f0eef8;
    font-family:'Syne',sans-serif;font-size:.78rem;font-weight:600;padding:11px;
    cursor:pointer;text-decoration:none;transition:border-color .15s,box-shadow .15s}
  .google-btn:hover{border-color:rgba(68,85,255,.35);box-shadow:0 0 0 3px rgba(68,85,255,.1)}
  .err{color:#ff4455;font-size:.75rem;margin-top:14px;letter-spacing:.04em;text-align:left}
  footer{font-size:.6rem;letter-spacing:.18em;text-transform:uppercase;color:#4d4a5a}
</style></head>
<body>
<canvas id="star-canvas"></canvas>
<div class="card">
  <img src="https://f4.bcbits.com/img/0042095815_10.jpg" class="logo" alt="Midnight Ecstasy" />
  <h1>Promo Mailer</h1>
  <div class="sub">Upload · Compose · Send</div>
  <ul class="features">
    <li><span class="icon">&#9675;</span><span><strong>Sends from your email account</strong> — every DJ gets a personal email straight from your address</span></li>
    <li><span class="icon">&#9675;</span><span><strong>Bandcamp download codes</strong> — one unique code per DJ, works with private pre-release albums</span></li>
    <li><span class="icon">&#9675;</span><span><strong>One link, one click</strong> — DJs redeem their code instantly, nothing to install</span></li>
    <li><span class="icon">&#9675;</span><span><strong>Your own contact list</strong> — bring your DJ list as a spreadsheet, you stay in control</span></li>
  </ul>
  <hr class="divider" />
  <p class="section-label">Connect your email</p>
  <div class="presets">
    <span class="chip" onclick="setPreset('gmail')">Gmail</span>
    <span class="chip" onclick="setPreset('outlook')">Outlook</span>
    <span class="chip" onclick="setPreset('yahoo')">Yahoo</span>
    <span class="chip" onclick="setPreset('proton')">Proton</span>
    <span class="chip" onclick="setPreset('icloud')">iCloud</span>
    <span class="chip" onclick="setPreset('fastmail')">Fastmail</span>
  </div>
  <form id="smtp-form" method="POST" action="/auth/login/smtp">
    <div class="row3">
      <div class="field">
        <label>SMTP Host</label>
        <input name="smtp_host" id="smtp_host" type="text" placeholder="smtp.example.com" required autocomplete="off" />
      </div>
      <div class="field">
        <label>Port</label>
        <input name="smtp_port" id="smtp_port" type="number" value="587" required />
      </div>
      <div class="field">
        <label>Security</label>
        <select name="smtp_security" id="smtp_security">
          <option value="starttls">STARTTLS</option>
          <option value="ssl">SSL/TLS</option>
          <option value="none">None</option>
        </select>
      </div>
    </div>
    <div class="row2">
      <div class="field">
        <label>Email / Username</label>
        <input name="smtp_user" id="smtp_user" type="email" placeholder="you@example.com" required autocomplete="username" />
      </div>
      <div class="field">
        <label>Password</label>
        <input name="smtp_pass" id="smtp_pass" type="password" placeholder="••••••••" required autocomplete="current-password" />
      </div>
    </div>
    <p id="preset-hint" class="hint" style="margin-bottom:12px;display:none"></p>
    <button class="btn-smtp" type="submit" id="smtp-btn">Connect &amp; Sign In</button>
  </form>
  ${msg ? `<p class="err">${escHtml(msg)}</p>` : ''}

  ${googleClientId ? `
  <div class="divider"></div>
  <p class="section-label">Or continue with Google</p>
  <a class="google-btn" href="/auth/login/google">
    <svg width="18" height="18" viewBox="0 0 24 24"><path d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z" fill="#4285F4"/><path d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z" fill="#34A853"/><path d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l3.66-2.84z" fill="#FBBC05"/><path d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z" fill="#EA4335"/></svg>
    Continue with Google
  </a>` : ''}
</div>
<footer>a tool by midnight ecstasy</footer>
<script src="/star-trails.js"></script>
<script>
  const presets = {
    gmail:    { host:'smtp.gmail.com',         port:587,  security:'starttls', hint:'Use an <strong>App Password</strong> — not your regular Google password. <a href="https://myaccount.google.com/apppasswords" target="_blank" rel="noopener" style="color:#4455ff">Generate one here</a>.' },
    outlook:  { host:'smtp.office365.com',     port:587,  security:'starttls', hint:null },
    yahoo:    { host:'smtp.mail.yahoo.com',    port:587,  security:'starttls', hint:'Requires an <strong>App Password</strong> from your Yahoo account security settings.' },
    proton:   { host:'127.0.0.1',              port:1025, security:'starttls', hint:'Requires <a href="https://proton.me/mail/bridge" target="_blank" rel="noopener" style="color:#4455ff">Proton Mail Bridge</a> running on this machine.' },
    icloud:   { host:'smtp.mail.me.com',       port:587,  security:'starttls', hint:'Use an <strong>App-Specific Password</strong> from your Apple ID settings.' },
    fastmail: { host:'smtp.fastmail.com',      port:465,  security:'ssl',      hint:null },
  };
  function setPreset(key) {
    document.querySelectorAll('.chip').forEach(c => c.classList.remove('active'));
    event.target.classList.add('active');
    const p = presets[key];
    document.getElementById('smtp_host').value     = p.host;
    document.getElementById('smtp_port').value     = p.port;
    document.getElementById('smtp_security').value = p.security;
    const hintEl = document.getElementById('preset-hint');
    if (p.hint) { hintEl.innerHTML = p.hint; hintEl.style.display = ''; }
    else        { hintEl.style.display = 'none'; }
  }
  document.getElementById('smtp-form').addEventListener('submit', () => {
    const btn = document.getElementById('smtp-btn');
    btn.disabled = true; btn.textContent = 'Connecting…';
  });
</script>
</body></html>`;

  // ── Login routes ──────────────────────────────────────────────────────────
  app.get('/auth/login', (req, res) => {
    res.send(LOGIN_PAGE(req.query.error || ''));
  });

  app.post('/auth/login/smtp', express.urlencoded({ extended: false }), async (req, res) => {
    if (!loginRateLimiter.isAllowed(req.ip)) {
      return res.redirect('/auth/login?error=' + encodeURIComponent('Too many login attempts. Please wait 15 minutes and try again.'));
    }
    const { smtp_host, smtp_port, smtp_security, smtp_user, smtp_pass } = req.body;
    if (!smtp_host || !smtp_port || !smtp_user || !smtp_pass) {
      return res.redirect('/auth/login?error=' + encodeURIComponent('All SMTP fields are required.'));
    }
    if (allowedDomainRE && !allowedDomainRE.test(smtp_user)) {
      return res.redirect(`/auth/login?error=${encodeURIComponent(`Access restricted to @${allowedDomain} accounts.`)}`);
    }
    const port       = parseInt(smtp_port, 10);
    const secure     = smtp_security === 'ssl';
    const requireTLS = smtp_security === 'starttls';
    const transporter = nodemailer.createTransport({
      host: smtp_host, port, secure, requireTLS,
      auth: { user: smtp_user, pass: smtp_pass },
      connectionTimeout: 10_000,
      greetingTimeout:   10_000,
    });
    try {
      await transporter.verify();
      req.session.user = { email: smtp_user, name: smtp_user };
      req.session.smtpConfig = { host: smtp_host, port, secure, requireTLS, user: smtp_user, pass: encryptSmtpPassword(smtp_pass) };
      log('info', 'user_login_smtp', { email: smtp_user });
      res.redirect('/');
    } catch (e) {
      const msg = e.message.replace(/\s+/g, ' ').slice(0, 200);
      log('warn', 'smtp_login_failed', { email: smtp_user, error: msg });
      res.redirect('/auth/login?error=' + encodeURIComponent('Could not connect: ' + msg));
    }
  });

  app.get('/auth/login/google', (req, res) => {
    if (!loginRateLimiter.isAllowed(req.ip)) {
      return res.redirect('/auth/login?error=' + encodeURIComponent('Too many login attempts. Please wait 15 minutes and try again.'));
    }
    if (!googleClientId) return res.send(LOGIN_PAGE('OAuth not configured. Set GOOGLE_CLIENT_ID env var.'));
    const state = crypto.randomBytes(32).toString('hex');
    req.session.oauthState = state;
    const params = new URLSearchParams({
      client_id:     googleClientId,
      redirect_uri:  `${baseUrl}/auth/login/callback`,
      response_type: 'code',
      scope:         'openid email profile https://www.googleapis.com/auth/gmail.send',
      access_type:   'offline',
      prompt:        'consent',
      state,
    });
    res.redirect(`https://accounts.google.com/o/oauth2/v2/auth?${params}`);
  });

  app.get('/auth/login/callback', async (req, res) => {
    const { code, error, state } = req.query;
    if (error) return res.redirect(`/auth/login?error=${encodeURIComponent(error)}`);
    const expectedState = req.session.oauthState;
    delete req.session.oauthState;
    if (!state || !expectedState || state !== expectedState) {
      return res.redirect('/auth/login?error=' + encodeURIComponent('Invalid login session. Please try again.'));
    }
    try {
      const tokenRes = await fetchWithTimeout('https://oauth2.googleapis.com/token', {
        method:  'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
          client_id:     googleClientId,
          client_secret: googleClientSecret,
          code,
          grant_type:    'authorization_code',
          redirect_uri:  `${baseUrl}/auth/login/callback`,
        }),
      });
      const tokens = await tokenRes.json();
      if (tokens.error) throw new Error(tokens.error_description || tokens.error);
      const userRes = await fetchWithTimeout('https://www.googleapis.com/oauth2/v3/userinfo', {
        headers: { 'Authorization': `Bearer ${tokens.access_token}` },
      });
      const user = await userRes.json();
      if (!user.email) {
        return res.redirect('/auth/login?error=' + encodeURIComponent('Could not retrieve your email address from Google.'));
      }
      if (allowedDomainRE && !allowedDomainRE.test(user.email)) {
        return res.redirect(`/auth/login?error=${encodeURIComponent(`Access restricted to @${allowedDomain} accounts.`)}`);
      }
      req.session.user = { email: user.email, name: user.name };
      req.session.gmailTokens = {
        access_token:  tokens.access_token,
        refresh_token: tokens.refresh_token,
        expiry:        Date.now() + (tokens.expires_in || 3600) * 1000,
      };
      log('info', 'user_login', { email: user.email });
      res.redirect('/');
    } catch (e) {
      const msg = e.name === 'AbortError' ? 'Google sign-in timed out. Please try again.' : e.message;
      log('error', 'auth_callback_error', { error: msg });
      res.redirect('/auth/login?error=' + encodeURIComponent(msg));
    }
  });

  app.get('/auth/logout', (req, res) => {
    log('info', 'user_logout', { email: req.session?.user?.email });
    req.session.destroy(() => res.redirect('/auth/login'));
  });

  // ── Unsubscribe (public — no auth required) ───────────────────────────────
  app.get('/unsubscribe', async (req, res) => {
    const { sender, email, token } = req.query;
    if (!sender || !email || !token) {
      return res.status(400).send(unsubPage('Invalid unsubscribe link.', false));
    }
    const expected = makeUnsubToken(sender, email);
    if (token.length !== expected.length ||
        !crypto.timingSafeEqual(Buffer.from(token), Buffer.from(expected))) {
      return res.status(400).send(unsubPage('Invalid or expired unsubscribe link.', false));
    }
    try {
      await addUnsubscribe(sender, email);
      res.send(unsubPage(`${email} has been unsubscribed from future emails from ${sender}.`, true));
    } catch (e) {
      log('error', 'unsubscribe_error', { error: e.message });
      res.status(500).send(unsubPage('Something went wrong. Please try again.', false));
    }
  });

  function unsubPage(message, success) {
    const color = success ? '#33cc88' : '#ff4455';
    return `<!DOCTYPE html>
<html><head><meta charset="UTF-8"><title>Unsubscribe - DJ Promo</title>
<link href="https://fonts.googleapis.com/css2?family=Syne:wght@400;700;800&display=swap" rel="stylesheet">
<style>
  *{box-sizing:border-box;margin:0;padding:0}
  html{background:#0c0b10}
  body{background:#0c0b10;color:#f0eef8;font-family:'Syne',sans-serif;
       display:flex;align-items:center;justify-content:center;min-height:100vh;padding:40px 20px}
  .card{background:#131118;border:1px solid #2a2635;padding:40px 36px;max-width:420px;width:100%;text-align:center}
  h1{font-size:1.2rem;font-weight:800;letter-spacing:.06em;text-transform:uppercase;margin-bottom:16px;color:${color}}
  p{color:#8a8499;font-size:.85rem;line-height:1.6}
</style></head>
<body><div class="card">
  <h1>${success ? 'Unsubscribed' : 'Error'}</h1>
  <p>${message}</p>
</div></body></html>`;
  }

  // Static assets served before auth so unauthenticated pages (login) can load them
  app.use(express.static(path.join(__dirname, 'public')));

  // ── Bandcamp releases proxy ───────────────────────────────────────────────
  const releasesCache = { data: null, fetchedAt: 0 };
  const RELEASES_TTL_MS = 10 * 60 * 1000;

  function httpsGet(url) {
    return new Promise((resolve, reject) => {
      https.get(url, { headers: { 'User-Agent': 'promo-mailer/1.0' } }, res => {
        const chunks = [];
        res.on('data', c => chunks.push(c));
        res.on('end', () => resolve(Buffer.concat(chunks).toString()));
      }).on('error', reject);
    });
  }

  app.get('/api/releases', async (req, res) => {
    const now = Date.now();
    if (releasesCache.data && now - releasesCache.fetchedAt < RELEASES_TTL_MS) {
      return res.json(releasesCache.data);
    }
    try {
      const musicHtml = await httpsGet('https://midnightecstasy.bandcamp.com/music');
      const urlMatches = [...musicHtml.matchAll(/href="(https?:\/\/[^"]+\/album\/[^"?]+)[^"]*"/g)];
      const albumUrls = [...new Set(urlMatches.map(m => m[1]))].slice(0, 6);
      const releases = await Promise.all(albumUrls.map(async link => {
        try {
          const html    = await httpsGet(link);
          const art     = (html.match(/<meta property="og:image" content="([^"]+)"/) || [])[1] || '';
          const ogTitle = (html.match(/<meta property="og:title" content="([^"]+)"/) || [])[1] || '';
          const title   = ogTitle.split(', by')[0].trim() || link.split('/album/')[1]?.replace(/-/g, ' ') || '';
          return { title, art, link };
        } catch {
          return { title: link.split('/album/')[1]?.replace(/-/g, ' ') || '', art: '', link };
        }
      }));
      releasesCache.data = releases.filter(r => r.title);
      releasesCache.fetchedAt = now;
      res.json(releasesCache.data);
    } catch (err) {
      log('error', 'releases_fetch_error', { message: err.message });
      res.status(502).json({ error: 'Failed to fetch releases' });
    }
  });

  // Apply auth middleware to all subsequent routes
  app.use(requireAuth);

  // ── Auth info ─────────────────────────────────────────────────────────────
  app.get('/auth/me', async (req, res) => {
    if (!req.session?.user) return res.status(401).json({ error: 'Not authenticated' });
    const email = req.session.user.email;
    let dailySent = 0;
    try { dailySent = await getDailyCount(email); } catch { /* non-fatal */ }
    res.json({ email, name: req.session.user.name, dailySent, gmailDailyLimit: GMAIL_DAILY_LIMIT });
  });

  // ── Gmail token helpers ───────────────────────────────────────────────────
  async function getGmailAccessToken(sess) {
    const t = sess.gmailTokens;
    if (!t) throw new Error('Gmail not authorized');
    if (Date.now() < t.expiry - 60_000) return t.access_token;
    if (!t.refresh_token) throw new Error('Gmail token expired — please sign in again');
    const r = await fetchWithTimeout('https://oauth2.googleapis.com/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        client_id:     googleClientId,
        client_secret: googleClientSecret,
        refresh_token: t.refresh_token,
        grant_type:    'refresh_token',
      }),
    });
    const data = await r.json();
    if (data.error) throw new Error(data.error_description || data.error);
    sess.gmailTokens = {
      access_token:  data.access_token,
      refresh_token: t.refresh_token,
      expiry:        Date.now() + (data.expires_in || 3600) * 1000,
    };
    log('warn', 'gmail_token_refreshed', { email: sess.user?.email });
    return data.access_token;
  }

  // ── Email send helpers ────────────────────────────────────────────────────
  async function sendViaSmtp(smtpConfig, from, to, subject, htmlBody) {
    const transporter = nodemailer.createTransport({
      host: smtpConfig.host, port: smtpConfig.port,
      secure: smtpConfig.secure, requireTLS: smtpConfig.requireTLS,
      auth: { user: smtpConfig.user, pass: smtpConfig.pass },
      connectionTimeout: 10_000, greetingTimeout: 10_000,
    });
    await transporter.sendMail({ from, to, subject, html: htmlBody, text: htmlBody.replace(/<[^>]*>/g, '') });
  }

  async function sendViaGmail(accessToken, from, to, subject, htmlBody) {
    const plain = htmlBody
      .replace(/<br\s*\/?>/gi, '\n')
      .replace(/<\/p>/gi, '\n\n')
      .replace(/<[^>]+>/g, '')
      .trim();
    const mime = [
      'MIME-Version: 1.0',
      `From: ${from}`, `To: ${to}`, `Subject: ${subject}`,
      'Content-Type: multipart/alternative; boundary="BOUNDARY"',
      '',
      '--BOUNDARY', 'Content-Type: text/plain; charset=UTF-8', '', plain,
      '--BOUNDARY', 'Content-Type: text/html; charset=UTF-8', '',
      `<!DOCTYPE html><html><body style="font-family:sans-serif;font-size:14px;line-height:1.6;color:#333;max-width:600px">${htmlBody}</body></html>`,
      '--BOUNDARY--',
    ].join('\r\n');
    const raw = Buffer.from(mime).toString('base64url');
    const resp = await fetchWithTimeout(
      'https://gmail.googleapis.com/gmail/v1/users/me/messages/send',
      {
        method:  'POST',
        headers: { 'Authorization': `Bearer ${accessToken}`, 'Content-Type': 'application/json' },
        body:    JSON.stringify({ raw }),
      }
    );
    const data = await resp.json();
    if (data.error) throw new Error(data.error.message || JSON.stringify(data.error));
    return data;
  }

  // ── Spreadsheet endpoints ─────────────────────────────────────────────────
  const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 10 * 1024 * 1024 } });

  app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));

  app.post('/get-columns', upload.single('recipient_file'), (req, res) => {
    try {
      if (!req.file) return res.status(400).json({ error: 'No file uploaded' });
      const rows = readSpreadsheet(req.file.buffer);
      if (!rows.length) return res.json({ error: 'File appears to be empty' });
      const columns = Object.keys(rows[0]);
      const PREVIEW_ROWS = 8;
      const preview = rows.slice(0, PREVIEW_ROWS).map(r => ({
        name:  r[columns.find(c => /name|artist|dj|recipient|first/i.test(c))] ?? '',
        email: r[columns.find(c => /email|e-mail|mail/i.test(c))] ?? '',
      }));
      res.json({ columns, preview, total: rows.length });
    } catch (e) {
      res.status(400).json({ error: `Could not read file: ${e.message}` });
    }
  });

  const previewUpload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 10 * 1024 * 1024 } }).fields([
    { name: 'recipient_file', maxCount: 1 },
    ...Array.from({ length: 10 }, (_, i) => ({ name: `codes_file_${i}`, maxCount: 1 })),
  ]);

  app.post('/preview', previewUpload, async (req, res) => {
    try {
      const { name_col, email_col, release_count } = req.body;
      const count = Math.min(parseInt(release_count) || 0, 10);
      if (count === 0) return res.status(400).json({ error: 'No releases provided' });

      const recipientFileInfo = req.files['recipient_file']?.[0];

      let extraRecipients = [];
      if (req.body.extra_recipients) {
        try {
          const parsed = JSON.parse(req.body.extra_recipients);
          if (Array.isArray(parsed)) {
            extraRecipients = parsed
              .filter(r => r && typeof r.email === 'string')
              .map(r => ({ name: typeof r.name === 'string' ? r.name.trim() : '', email: r.email.trim() }))
              .filter(r => r.email && r.email.includes('@'));
          }
        } catch { /* ignore malformed JSON */ }
      }

      if (!recipientFileInfo && extraRecipients.length === 0) {
        return res.status(400).json({ error: 'No recipients provided. Upload a recipient file or add recipients manually.' });
      }

      const warnings = [];
      let recipientList = [];

      if (recipientFileInfo) {
        const rawRecipientRows  = readSpreadsheet(recipientFileInfo.buffer);
        const resolvedNameCol   = name_col && name_col !== '__none__' ? name_col : null;
        const recipientColErr   = validateColumns(rawRecipientRows, [email_col]);
        if (recipientColErr) return res.status(400).json({ error: 'Recipient file: ' + recipientColErr });
        if (resolvedNameCol) {
          const nameColErr = validateColumns(rawRecipientRows, [resolvedNameCol]);
          if (nameColErr) return res.status(400).json({ error: 'Recipient file: ' + nameColErr });
        }
        const fromFile = parseRecipientList(rawRecipientRows, resolvedNameCol, email_col);
        const dropped  = rawRecipientRows.length - fromFile.length;
        if (dropped > 0) {
          warnings.push(`${dropped} recipient row${dropped !== 1 ? 's' : ''} were skipped (blank or missing/invalid email). If you prepared your codes file to align row-for-row, the assignment order may be off.`);
        }
        recipientList = fromFile;
      }

      recipientList = recipientList.concat(extraRecipients);
      if (!recipientList.length) return res.status(400).json({ error: 'No valid recipients found. Check that the correct email column is selected and that email addresses contain @.' });

      if (!req.session.user) return res.status(401).json({ error: 'Session expired. Please sign out and sign in again.' });
      const senderEmail = req.session.user.email;

      let unsubscribed = new Set();
      try { unsubscribed = await getUnsubscribes(senderEmail); } catch { /* non-fatal */ }
      if (unsubscribed.size > 0) {
        const before = recipientList.length;
        recipientList = recipientList.filter(r => !unsubscribed.has(r.email));
        const skipped = before - recipientList.length;
        if (skipped > 0) warnings.push(`${skipped} recipient${skipped !== 1 ? 's' : ''} skipped (previously unsubscribed).`);
      }
      if (!recipientList.length) return res.status(400).json({ error: 'No recipients remaining after filtering unsubscribed addresses.' });

      const seenEmails = new Set();
      const deduped = [];
      for (const r of recipientList) {
        if (!seenEmails.has(r.email)) { seenEmails.add(r.email); deduped.push(r); }
      }
      const dupCount = recipientList.length - deduped.length;
      if (dupCount > 0) {
        warnings.push(`${dupCount} duplicate email address${dupCount !== 1 ? 'es' : ''} removed. Each recipient will receive one email.`);
      }
      recipientList = deduped;

      const releases = [];
      for (let i = 0; i < count; i++) {
        const codesFile = req.files[`codes_file_${i}`]?.[0];
        if (!codesFile) return res.status(400).json({ error: `Missing codes file for release ${i + 1}` });

        const codesCol = req.body[`codes_col_${i}`];
        const subject  = req.body[`subject_${i}`] || '';
        const body     = req.body[`body_${i}`] || '';
        const name     = req.body[`release_name_${i}`] || `Release ${i + 1}`;

        const previewLenErr = validateInputLengths({
          [`release_name_${i}`]: { value: name,    max: 200      },
          [`subject_${i}`]:      { value: subject, max: 998      },
          [`body_${i}`]:         { value: body,    max: 512*1024 },
        });
        if (previewLenErr) return res.status(400).json({ error: previewLenErr });

        const rawCodeRows  = readSpreadsheet(codesFile.buffer);
        const codesColErr  = validateColumns(rawCodeRows, [codesCol], name);
        if (codesColErr) return res.status(400).json({ error: codesColErr });

        const codes = rawCodeRows
          .filter(r => r != null && typeof r === 'object')
          .map(r => String(r[codesCol] ?? '').trim())
          .filter(Boolean);

        const codesDropped = rawCodeRows.length - codes.length;
        if (codesDropped > 0) {
          warnings.push(`"${name}": ${codesDropped} empty row${codesDropped !== 1 ? 's' : ''} skipped in codes file — row order may not match your recipient list.`);
        }

        if (codes.length < recipientList.length) {
          return res.status(400).json({
            error: `"${name}": not enough codes (${codes.length}) for all recipients (${recipientList.length}).`,
          });
        }

        const { assigned: assignedCodes, unused: unusedCodes } = partitionCodes(codes, recipientList.length);

        releases.push({
          name,
          count: recipientList.length,
          unusedCodes,
          emails: recipientList.map((recipient, j) => {
            const code     = assignedCodes[j];
            const bodyHtml = applyTemplate(body, recipient.name, code);
            const link     = unsubLink(senderEmail, recipient.email);
            const footer   = `<p style="margin-top:24px;font-size:11px;color:#888">Don't want these emails? <a href="${link}" style="color:#888">Unsubscribe</a></p>`;
            return {
              name:    recipient.name,
              email:   recipient.email,
              code,
              subject: applyTemplate(subject, recipient.name, code),
              body:    bodyHtml + footer,
              release: name,
            };
          }),
        });
      }

      const allEmails = releases.flatMap(r => r.emails);
      const unusedCodesByRelease = Object.fromEntries(releases.map(r => [r.name, r.unusedCodes]));
      res.json({ releases, allEmails, total: allEmails.length, warnings, unusedCodesByRelease });
    } catch (e) {
      res.status(400).json({ error: e.message });
    }
  });

  // ── Send ──────────────────────────────────────────────────────────────────
  app.post('/send', async (req, res) => {
    const rlKey = req.session?.id || req.ip;
    if (!sendRateLimiter.isAllowed(rlKey)) {
      return res.status(429).json({ error: 'Too many requests. Please wait a moment before sending again.' });
    }

    const useSmtp  = !!req.session.smtpConfig;
    const useGmail = !!req.session.gmailTokens;
    if (!useSmtp && !useGmail)
      return res.status(401).json({ error: 'Not authorized. Please sign in again.' });

    const { from_name, emails } = req.body;
    if (!emails?.length) return res.status(400).json({ error: 'No emails to send' });

    const lenErr = validateInputLengths({ 'from_name': { value: from_name, max: 200 } });
    if (lenErr) return res.status(400).json({ error: lenErr });

    if (!req.session.user) return res.status(401).json({ error: 'Session expired. Please sign out and sign in again.' });
    const fromEmail = req.session.user.email;
    const fromAddr  = from_name?.trim()
      ? `"${from_name.trim().replace(/"/g, "'")}" <${fromEmail}>`
      : fromEmail;

    const resolvedSmtpConfig = useSmtp
      ? { ...req.session.smtpConfig, pass: decryptSmtpPassword(req.session.smtpConfig.pass) }
      : null;

    const sent = [], failed = [];

    for (let i = 0; i < emails.length; i++) {
      const item = emails[i];
      try {
        if (useSmtp) {
          await sendViaSmtp(resolvedSmtpConfig, fromAddr, sanitizeMimeHeader(item.email), sanitizeMimeHeader(item.subject), item.body);
        } else {
          const token = await getGmailAccessToken(req.session);
          await sendViaGmail(token, fromAddr, sanitizeMimeHeader(item.email), sanitizeMimeHeader(item.subject), item.body);
        }
        sent.push(item.email);
      } catch (e) {
        const errMsg = useSmtp
          ? redactCredentials(e.message, resolvedSmtpConfig.pass)
          : redactCredentials(e.message, googleClientSecret);
        failed.push({ email: item.email, error: errMsg });
        const fatal = useSmtp ? isFatalSmtpError(e.message) : isFatalGmailError(e.message);
        if (fatal) {
          for (let j = i + 1; j < emails.length; j++)
            failed.push({ email: emails[j].email, error: 'Aborted — see previous error' });
          log('error', 'send_aborted', { sender: fromEmail, sent: sent.length, failed: failed.length, reason: errMsg });
          return res.json({ sent, failed, aborted: true, abortReason: errMsg });
        }
      }
    }

    log('info', 'send_complete', { sender: fromEmail, sent: sent.length, failed: failed.length });
    if (sent.length > 0) {
      incrementDailyCount(fromEmail, sent.length).catch(e => log('error', 'send_count_error', { error: e.message }));
    }
    res.json({ sent, failed });
  });

  return app;
}

// ── Boot ───────────────────────────────────────────────────────────────────
if (require.main === module) {
  const { Firestore }  = require('@google-cloud/firestore');
  const FirestoreStore = require('./firestoreSessionStore')(session);
  const PORT   = process.env.PORT || 5001;
  const config = {
    baseUrl:           process.env.BASE_URL           || `http://localhost:${PORT}`,
    sessionSecret:     process.env.SESSION_SECRET     || 'local-dev-secret-change-in-prod',
    allowedDomain:     process.env.ALLOWED_DOMAIN     || '',
    googleClientId:    process.env.GOOGLE_CLIENT_ID,
    googleClientSecret: process.env.GOOGLE_CLIENT_SECRET,
  };
  const db           = new Firestore();
  const sessionStore = new FirestoreStore();
  sessionStore.on('error', err => console.error('[ERROR] session_store_error', err.message));
  const app = createApp({ db, sessionStore, config });
  app.listen(PORT, () => console.log(`[INFO] server_start {"url":"${config.baseUrl}"}`));
}

module.exports = { createApp };
