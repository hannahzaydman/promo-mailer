const express = require('express');
const multer  = require('multer');
const XLSX    = require('@e965/xlsx');
const path    = require('path');
const crypto  = require('crypto');
const session        = require('express-session');
const FirestoreStore = require('./firestoreSessionStore')(session);
const { Firestore }  = require('@google-cloud/firestore');
const db = new Firestore();

const app = express();
app.set('trust proxy', 1); // Required for secure cookies behind Cloud Run

// ── Security headers ───────────────────────────────────────────────────────
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  // CSP: inline scripts/styles are required by the single-file frontend.
  // frame-ancestors, object-src, and base-uri still provide meaningful protection.
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

const { escHtml, sanitizeMimeHeader, htmlToPlainText, applyTemplate, parseRecipientList, partitionCodes, isFatalSmtpError, validateColumns, RateLimiter, validateInputLengths, redactCredentials } = require('./utils');

const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 10 * 1024 * 1024 } });

// ── Config ─────────────────────────────────────────────────────────────────
const PORT           = process.env.PORT           || 5001;
const BASE_URL       = process.env.BASE_URL        || `http://localhost:${PORT}`;
// Optional: set ALLOWED_DOMAIN=midnightecstasy.com to restrict sign-in to one domain.
// Omit (or leave empty) to allow any Google account — required for multi-tenant use.
const ALLOWED_DOMAIN = process.env.ALLOWED_DOMAIN  || '';
const SESSION_SECRET = process.env.SESSION_SECRET  || 'local-dev-secret-change-in-prod';

// Build domain-restriction regex only when a domain is configured.
const ALLOWED_DOMAIN_RE = ALLOWED_DOMAIN
  ? new RegExp('@' + ALLOWED_DOMAIN.split('.').join('\\.') + '$', 'i')
  : null;
// OAuth credentials — from Secret Manager env vars in prod, config file locally
const GOOGLE_CLIENT_ID     = process.env.GOOGLE_CLIENT_ID;
const GOOGLE_CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET;

// ── Structured logging ─────────────────────────────────────────────────────
// In production (https) emit newline-delimited JSON for Cloud Run / Cloud Logging.
// Locally emit readable text so the console stays scannable.
const IS_PROD = BASE_URL.startsWith('https');

function log(level, event, data = {}) {
  if (IS_PROD) {
    // Cloud Logging severity mapping
    const severity = level === 'error' ? 'ERROR' : level === 'warn' ? 'WARNING' : 'INFO';
    process.stdout.write(JSON.stringify({ severity, event, ...data }) + '\n');
  } else {
    const prefix = level === 'error' ? '[ERROR]' : level === 'warn' ? '[WARN]' : '[INFO]';
    const extra = Object.keys(data).length ? ' ' + JSON.stringify(data) : '';
    console.log(`${prefix} ${event}${extra}`);
  }
}

// ── Startup validation ─────────────────────────────────────────────────────
// Fail fast in production rather than silently misbehaving.
if (BASE_URL.startsWith('https')) {
  const missing = [
    SESSION_SECRET === 'local-dev-secret-change-in-prod' && 'SESSION_SECRET',
    !GOOGLE_CLIENT_ID     && 'GOOGLE_CLIENT_ID',
    !GOOGLE_CLIENT_SECRET && 'GOOGLE_CLIENT_SECRET',
  ].filter(Boolean);
  if (missing.length) {
    log('error', 'startup_validation_failed', { missing });
    process.exit(1);
  }
}

// ── Unsubscribe helpers ────────────────────────────────────────────────────
function unsubToken(senderEmail, recipientEmail) {
  return crypto.createHmac('sha256', SESSION_SECRET)
    .update(senderEmail + '\x00' + recipientEmail)
    .digest('hex')
    .slice(0, 24);
}

function unsubLink(baseUrl, senderEmail, recipientEmail) {
  const token = unsubToken(senderEmail, recipientEmail);
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

// ── Send count helpers (daily Gmail quota tracking) ────────────────────────
const GMAIL_DAILY_LIMIT = 500;

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

// ── Rate limiters ──────────────────────────────────────────────────────────
// 200 send requests per session per minute.  Keyed on session ID so each
// authenticated user has an independent quota.
const sendRateLimiter = new RateLimiter(200, 60_000);
// Prune stale entries every 5 minutes to prevent unbounded Map growth.
setInterval(() => sendRateLimiter.prune(), 5 * 60_000).unref();

// ── Session ────────────────────────────────────────────────────────────────
const sessionStore = new FirestoreStore();
// Log Firestore session store errors so they surface in Cloud Run logs
// instead of silently failing (which would cause every request to appear
// unauthenticated and flood the login page with confusing redirects).
sessionStore.on('error', err => log('error', 'session_store_error', { error: err.message }));
app.use(session({
  store:             sessionStore,
  secret:            SESSION_SECRET,
  resave:            false,
  saveUninitialized: false,
  cookie: {
    secure:   BASE_URL.startsWith('https'),
    httpOnly: true,
    sameSite: 'lax',
    maxAge:   8 * 60 * 60 * 1000, // 8 hours
  },
}));

// Raise the JSON body limit to 5 MB so that large send batches (many
// recipients × HTML body) are not silently rejected with a 413.
app.use(express.json({ limit: '5mb' }));

// ── Google login middleware ────────────────────────────────────────────────
function requireAuth(req, res, next) {
  // Allow login flow through unauthenticated
  if (req.path.startsWith('/auth/login')) return next();
  if (req.session?.user) return next();

  // No Google credentials configured — let through so app is accessible
  if (!GOOGLE_CLIENT_ID) return next();

  res.redirect('/auth/login');
}

// fetch() with an AbortController timeout — prevents Google OAuth calls from hanging
// indefinitely and exhausting Cloud Run connections.
function fetchWithTimeout(url, options, ms) {
  if (ms === undefined) ms = 10000;
  const ctrl = new AbortController();
  const t = setTimeout(function() { ctrl.abort(); }, ms);
  return fetch(url, Object.assign({}, options || {}, { signal: ctrl.signal }))
    .finally(function() { clearTimeout(t); });
}

// ── Google login routes ────────────────────────────────────────────────────
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
        text-align:center;max-width:360px;width:100%}
  .logo{width:64px;height:64px;object-fit:cover;display:block;margin:0 auto 20px}
  h1{font-size:1.4rem;font-weight:800;letter-spacing:.06em;text-transform:uppercase;color:#f0eef8;margin-bottom:6px;line-height:1}
  .sub{color:#8a8499;font-size:.68rem;letter-spacing:.2em;text-transform:uppercase;font-weight:500;margin-bottom:24px}
  p{color:#8a8499;font-size:.82rem;margin-bottom:28px;line-height:1.6}
  a{display:inline-flex;align-items:center;gap:10px;background:#4455ff;color:#ffffff;
    font-weight:700;font-size:.68rem;letter-spacing:.14em;text-transform:uppercase;
    border-radius:0;padding:13px 28px;text-decoration:none;font-family:'Syne',sans-serif;
    transition:background .15s}
  a:hover{background:#6673ff}
  .err{color:#ff4455;font-size:.78rem;margin-top:16px;letter-spacing:.04em}
  footer{font-size:.6rem;letter-spacing:.18em;text-transform:uppercase;color:#4d4a5a}
</style></head>
<body>
<canvas id="star-canvas"></canvas>
<div class="card">
  <img src="https://f4.bcbits.com/img/0042095815_10.jpg" class="logo" alt="Midnight Ecstasy" />
  <h1>Promo Mailer</h1>
  <div class="sub">Upload · Compose · Send</div>
  <p>${ALLOWED_DOMAIN ? `Sign in with your ${ALLOWED_DOMAIN} account to continue.` : 'Sign in with Google to continue. You\'ll also authorize sending email from your account.'}</p>
  <a href="/auth/login/google">Sign in with Google</a>
  ${msg ? `<p class="err">${escHtml(msg)}</p>` : ''}
</div>
<footer>a tool by midnight ecstasy</footer>
<script src="/star-trails.js"></script>
</body></html>`;

app.get('/auth/login', (req, res) => {
  res.send(LOGIN_PAGE(req.query.error || ''));
});

app.get('/auth/login/google', (req, res) => {
  if (!GOOGLE_CLIENT_ID) return res.send(LOGIN_PAGE('OAuth not configured. Set GOOGLE_CLIENT_ID env var.'));

  // CSRF protection: store a random state token in the session before
  // redirecting to Google; validate it on return to prevent CSRF attacks.
  const state = crypto.randomBytes(32).toString('hex');
  req.session.oauthState = state;

  // Request gmail.send alongside identity scopes so users authorize sending
  // in a single step rather than needing a second "Connect Gmail" flow.
  // offline access_type + prompt:consent ensures we get a refresh token every time.
  const params = new URLSearchParams({
    client_id:     GOOGLE_CLIENT_ID,
    redirect_uri:  `${BASE_URL}/auth/login/callback`,
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

  // Validate state to prevent CSRF — consume immediately (one-time use).
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
        client_id:     GOOGLE_CLIENT_ID,
        client_secret: GOOGLE_CLIENT_SECRET,
        code,
        grant_type:    'authorization_code',
        redirect_uri:  `${BASE_URL}/auth/login/callback`,
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
    if (ALLOWED_DOMAIN_RE && !ALLOWED_DOMAIN_RE.test(user.email)) {
      return res.redirect(`/auth/login?error=${encodeURIComponent(`Access restricted to @${ALLOWED_DOMAIN} accounts.`)}`);
    }

    // Store Gmail send tokens in session at login time — no separate auth step needed.
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

// ── Unsubscribe (public — no auth required) ────────────────────────────────
app.get('/unsubscribe', async (req, res) => {
  const { sender, email, token } = req.query;
  if (!sender || !email || !token) {
    return res.status(400).send(unsubPage('Invalid unsubscribe link.', false));
  }
  const expected = unsubToken(sender, email);
  if (!crypto.timingSafeEqual(Buffer.from(token), Buffer.from(expected))) {
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

// Apply auth middleware to all subsequent routes
app.use(requireAuth);

// ── Auth info ──────────────────────────────────────────────────────────────
app.get('/auth/me', async (req, res) => {
  if (!req.session?.user) return res.status(401).json({ error: 'Not authenticated' });
  const email = req.session.user.email;
  let dailySent = 0;
  try { dailySent = await getDailyCount(email); } catch { /* non-fatal */ }
  res.json({ email, name: req.session.user.name, dailySent, gmailDailyLimit: GMAIL_DAILY_LIMIT });
});

async function getGmailAccessToken(session) {
  const t = session.gmailTokens;
  if (!t) throw new Error('Gmail not authorized');
  if (Date.now() < t.expiry - 60_000) return t.access_token;
  if (!t.refresh_token) throw new Error('Gmail token expired — please sign in again');
  const r = await fetchWithTimeout('https://oauth2.googleapis.com/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      client_id:     GOOGLE_CLIENT_ID,
      client_secret: GOOGLE_CLIENT_SECRET,
      refresh_token: t.refresh_token,
      grant_type:    'refresh_token',
    }),
  });
  const data = await r.json();
  if (data.error) throw new Error(data.error_description || data.error);
  session.gmailTokens = {
    access_token:  data.access_token,
    refresh_token: t.refresh_token,
    expiry:        Date.now() + (data.expires_in || 3600) * 1000,
  };
  log('warn', 'gmail_token_refreshed', { email: session.user?.email });
  return data.access_token;
}

async function sendViaGmail(accessToken, from, to, subject, htmlBody) {
  const plain = htmlBody
    .replace(/<br\s*\/?>/gi, '\n')
    .replace(/<\/p>/gi, '\n\n')
    .replace(/<[^>]+>/g, '')
    .trim();

  const mime = [
    'MIME-Version: 1.0',
    `From: ${from}`,
    `To: ${to}`,
    `Subject: ${subject}`,
    'Content-Type: multipart/alternative; boundary="BOUNDARY"',
    '',
    '--BOUNDARY',
    'Content-Type: text/plain; charset=UTF-8',
    '',
    plain,
    '--BOUNDARY',
    'Content-Type: text/html; charset=UTF-8',
    '',
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

const FATAL_GMAIL_ERRORS = [
  'invalid_grant',
  'token has been expired or revoked',
  'invalid credentials',
  'daily sending limit exceeded',
  'user rate limit exceeded',
];
function isFatalGmailError(message) {
  const lower = String(message).toLowerCase();
  return FATAL_GMAIL_ERRORS.some(p => lower.includes(p));
}

// ── Spreadsheet endpoints ──────────────────────────────────────────────────
function readSpreadsheet(buffer) {
  const wb    = XLSX.read(buffer, { type: 'buffer' });
  const sheet = wb.Sheets[wb.SheetNames[0]];
  // blankrows: true preserves blank rows so callers can warn when they're
  // skipped — blank rows in a codes file shift code-to-recipient alignment.
  // Filter out any null/undefined entries that some XLSX edge cases can produce.
  const rows  = XLSX.utils.sheet_to_json(sheet, { defval: '', blankrows: true })
    .filter(r => r != null && typeof r === 'object');
  // Strip UTF-8 BOM from column names — common in Windows/Excel CSV exports.
  // Without this, the first column is named '\uFEFFname' instead of 'name',
  // breaking auto-detection and column matching silently.
  if (rows.length === 0) return rows;
  const hasBom = Object.keys(rows[0]).some(k => k.startsWith('\uFEFF'));
  if (!hasBom) return rows;
  return rows.map(row => {
    const cleaned = {};
    for (const [key, val] of Object.entries(row)) {
      cleaned[key.replace(/^\uFEFF/, '')] = val;
    }
    return cleaned;
  });
}

app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));

app.post('/get-columns', upload.single('recipient_file'), (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ error: 'No file uploaded' });
    const rows = readSpreadsheet(req.file.buffer);
    if (!rows.length) return res.json({ error: 'File appears to be empty' });
    const columns = Object.keys(rows[0]);
    // Return a small preview so the UI can show a recipient list
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
    // Cap at 10 to match the UI limit and prevent runaway iteration
    const count = Math.min(parseInt(release_count) || 0, 10);
    if (count === 0) return res.status(400).json({ error: 'No releases provided' });

    const recipientFileInfo = req.files['recipient_file']?.[0];

    // Parse extra (manually entered) recipients sent as JSON
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
      // Parse recipient list and warn if rows were silently dropped
      const rawRecipientRows = readSpreadsheet(recipientFileInfo.buffer);

      const resolvedNameCol = name_col && name_col !== '__none__' ? name_col : null;

      const recipientColErr = validateColumns(rawRecipientRows, [email_col]);
      if (recipientColErr) return res.status(400).json({ error: 'Recipient file: ' + recipientColErr });
      if (resolvedNameCol) {
        const nameColErr = validateColumns(rawRecipientRows, [resolvedNameCol]);
        if (nameColErr) return res.status(400).json({ error: 'Recipient file: ' + nameColErr });
      }

      const fromFile = parseRecipientList(rawRecipientRows, resolvedNameCol, email_col);

      const dropped = rawRecipientRows.length - fromFile.length;
      if (dropped > 0) {
        warnings.push(`${dropped} recipient row${dropped !== 1 ? 's' : ''} were skipped (blank or missing/invalid email). If you prepared your codes file to align row-for-row, the assignment order may be off.`);
      }

      recipientList = fromFile;
    }

    // Append manually entered recipients
    recipientList = recipientList.concat(extraRecipients);

    if (!recipientList.length) return res.status(400).json({ error: 'No valid recipients found. Check that the correct email column is selected and that email addresses contain @.' });

    // Filter out unsubscribed recipients
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

    // Deduplicate by email address — keep first occurrence
    const seenEmails = new Set();
    const deduped = [];
    for (const r of recipientList) {
      if (!seenEmails.has(r.email)) {
        seenEmails.add(r.email);
        deduped.push(r);
      }
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

      const rawCodeRows = readSpreadsheet(codesFile.buffer);

      const codesColErr = validateColumns(rawCodeRows, [codesCol], name);
      if (codesColErr) return res.status(400).json({ error: codesColErr });

      const codes = rawCodeRows.filter(r => r != null && typeof r === 'object').map(r => String(r[codesCol] ?? '').trim()).filter(Boolean);

      // Warn if blank rows were dropped from the codes file (row-alignment risk)
      const codesDropped = rawCodeRows.length - codes.length;
      if (codesDropped > 0) {
        warnings.push(`"${name}": ${codesDropped} empty row${codesDropped !== 1 ? 's' : ''} skipped in codes file — row order may not match your recipient list.`);
      }

      if (codes.length < recipientList.length) {
        return res.status(400).json({
          error: `"${name}": not enough codes (${codes.length}) for all recipients (${recipientList.length}).`
        });
      }

      const { assigned: assignedCodes, unused: unusedCodes } = partitionCodes(codes, recipientList.length);

      releases.push({
        name,
        count: recipientList.length,
        unusedCodes,
        emails: recipientList.map((recipient, j) => {
          const code = assignedCodes[j];
          const bodyHtml = applyTemplate(body, recipient.name, code);
          const link = unsubLink(BASE_URL, senderEmail, recipient.email);
          const footer = `<p style="margin-top:24px;font-size:11px;color:#888">Don't want these emails? <a href="${link}" style="color:#888">Unsubscribe</a></p>`;
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

// ── Send ───────────────────────────────────────────────────────────────────
app.post('/send', async (req, res) => {
  // Rate limit: 5 sends per minute per session to prevent accidental or
  // malicious spam bursts.
  const rlKey = req.session?.id || req.ip;
  if (!sendRateLimiter.isAllowed(rlKey)) {
    return res.status(429).json({ error: 'Too many requests. Please wait a moment before sending again.' });
  }

  if (!req.session.gmailTokens)
    return res.status(401).json({ error: 'Gmail not authorized. Please sign out and sign in again.' });

  const { from_name, emails } = req.body;
  if (!emails?.length) return res.status(400).json({ error: 'No emails to send' });

  const lenErr = validateInputLengths({ 'from_name': { value: from_name, max: 200 } });
  if (lenErr) return res.status(400).json({ error: lenErr });

  const fromEmail = req.session.user.email;
  const fromAddr  = from_name?.trim()
    ? `"${from_name.trim().replace(/"/g, "'")}" <${fromEmail}>`
    : fromEmail;

  const sent = [], failed = [];

  for (let i = 0; i < emails.length; i++) {
    const item = emails[i];
    try {
      const token = await getGmailAccessToken(req.session);
      await sendViaGmail(token, fromAddr, sanitizeMimeHeader(item.email), sanitizeMimeHeader(item.subject), item.body);
      sent.push(item.email);
    } catch (e) {
      failed.push({ email: item.email, error: redactCredentials(e.message, GOOGLE_CLIENT_SECRET) });
      if (isFatalGmailError(e.message)) {
        for (let j = i + 1; j < emails.length; j++)
          failed.push({ email: emails[j].email, error: 'Aborted — see previous error' });
        const abortReason = redactCredentials(e.message, GOOGLE_CLIENT_SECRET);
        log('error', 'send_aborted', { sender: fromEmail, sent: sent.length, failed: failed.length, reason: abortReason });
        return res.json({ sent, failed, aborted: true, abortReason });
      }
    }
  }
  log('info', 'send_complete', { sender: fromEmail, sent: sent.length, failed: failed.length });
  if (sent.length > 0) {
    incrementDailyCount(fromEmail, sent.length).catch(e => log('error', 'send_count_error', { error: e.message }));
  }
  res.json({ sent, failed });
});

app.listen(PORT, () => log('info', 'server_start', { url: BASE_URL }));
