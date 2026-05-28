const express = require('express');
const multer  = require('multer');
const XLSX    = require('xlsx');
const path    = require('path');
const fs      = require('fs');
const crypto  = require('crypto');
const nodemailer     = require('nodemailer');
const session        = require('express-session');
const FirestoreStore = require('./firestoreSessionStore')(session);

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

const { escHtml, sanitizeMimeHeader, htmlToPlainText, applyTemplate, parseRecipientList, isFatalSmtpError, validateColumns, RateLimiter, validateInputLengths, redactCredentials } = require('./utils');

const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 10 * 1024 * 1024 } });

// ── Config ─────────────────────────────────────────────────────────────────
const PORT           = process.env.PORT           || 5001;
const BASE_URL       = process.env.BASE_URL        || `http://localhost:${PORT}`;
const ALLOWED_DOMAIN = process.env.ALLOWED_DOMAIN  || 'midnightecstasy.com';
const SESSION_SECRET = process.env.SESSION_SECRET  || 'local-dev-secret-change-in-prod';

// Escape literal dots so the domain name doesn't act as a wildcard in the regex.
const ALLOWED_DOMAIN_RE = new RegExp('@' + ALLOWED_DOMAIN.split('.').join('\\.') + '$', 'i');
if (BASE_URL.startsWith('https') && SESSION_SECRET === 'local-dev-secret-change-in-prod') {
  console.error('FATAL: SESSION_SECRET env var is not set. Refusing to start in production.');
  process.exit(1);
}

// OAuth credentials — from Secret Manager env vars in prod, config file locally
const GOOGLE_CLIENT_ID     = process.env.GOOGLE_CLIENT_ID;
const GOOGLE_CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET;

// ── Rate limiters ──────────────────────────────────────────────────────────
// 5 send requests per session per minute.  Keyed on session ID so each
// authenticated user has an independent quota.
const sendRateLimiter = new RateLimiter(5, 60_000);
// Prune stale entries every 5 minutes to prevent unbounded Map growth.
setInterval(() => sendRateLimiter.prune(), 5 * 60_000).unref();

// ── Session ────────────────────────────────────────────────────────────────
const sessionStore = new FirestoreStore();
// Log Firestore session store errors so they surface in Cloud Run logs
// instead of silently failing (which would cause every request to appear
// unauthenticated and flood the login page with confusing redirects).
sessionStore.on('error', err => console.error('[session store error]', err));
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
  body{background:#0c0b10;color:#f0eef8;font-family:'Syne',sans-serif;
       display:flex;flex-direction:column;align-items:center;justify-content:center;min-height:100vh;margin:0;padding:40px 20px;gap:24px}
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
<body><div class="card">
  <img src="https://f4.bcbits.com/img/0042095815_10.jpg" class="logo" alt="Midnight Ecstasy" />
  <h1>Promo Mailer</h1>
  <div class="sub">Upload · Compose · Send</div>
  <p>Sign in with your ${ALLOWED_DOMAIN} account to continue.</p>
  <a href="/auth/login/google">Sign in with Google</a>
  ${msg ? `<p class="err">${escHtml(msg)}</p>` : ''}
</div>
<footer>a tool by midnight ecstasy</footer>
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

  const params = new URLSearchParams({
    client_id:     GOOGLE_CLIENT_ID,
    redirect_uri:  `${BASE_URL}/auth/login/callback`,
    response_type: 'code',
    scope:         'openid email profile',
    access_type:   'online',
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

    if (!user.email || !ALLOWED_DOMAIN_RE.test(user.email)) {
      return res.redirect(`/auth/login?error=${encodeURIComponent(`Access restricted to @${ALLOWED_DOMAIN} accounts.`)}`);
    }

    req.session.user = { email: user.email, name: user.name };
    res.redirect('/');
  } catch (e) {
    const msg = e.name === 'AbortError' ? 'Google sign-in timed out. Please try again.' : e.message;
    res.redirect('/auth/login?error=' + encodeURIComponent(msg));
  }
});

app.get('/auth/logout', (req, res) => {
  req.session.destroy(() => res.redirect('/auth/login'));
});

// Apply auth middleware to all subsequent routes
app.use(requireAuth);
app.use(express.static(path.join(__dirname, 'public')));

// ── Gmail send OAuth ───────────────────────────────────────────────────────
// Separate OAuth flow for gmail.send scope — tokens live in the session only.
// The same Google Cloud OAuth client is reused; add /auth/gmail/callback to
// the "Authorized redirect URIs" in Google Cloud Console.

app.post('/auth/gmail/setup', (req, res) => {
  if (!GOOGLE_CLIENT_ID)
    return res.status(501).json({ error: 'Google OAuth not configured.' });
  const state = crypto.randomBytes(32).toString('hex');
  req.session.gmailOAuthState = state;
  const params = new URLSearchParams({
    client_id:     GOOGLE_CLIENT_ID,
    redirect_uri:  `${BASE_URL}/auth/gmail/callback`,
    response_type: 'code',
    scope:         'https://www.googleapis.com/auth/gmail.send',
    access_type:   'offline',
    prompt:        'consent',
    state,
  });
  res.json({ authUrl: `https://accounts.google.com/o/oauth2/v2/auth?${params}` });
});

app.get('/auth/gmail/callback', async (req, res) => {
  const { code, error, state } = req.query;
  if (error) return res.send(`<script>window.opener?.postMessage('gmail-error','*');window.close();</script>`);

  const expectedState = req.session.gmailOAuthState;
  delete req.session.gmailOAuthState;
  if (!state || !expectedState || state !== expectedState)
    return res.send(`<script>window.opener?.postMessage('gmail-error','*');window.close();</script>`);

  try {
    const tokenRes = await fetchWithTimeout('https://oauth2.googleapis.com/token', {
      method:  'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        client_id:     GOOGLE_CLIENT_ID,
        client_secret: GOOGLE_CLIENT_SECRET,
        code,
        grant_type:    'authorization_code',
        redirect_uri:  `${BASE_URL}/auth/gmail/callback`,
      }),
    });
    const tokens = await tokenRes.json();
    if (tokens.error) throw new Error(tokens.error_description || tokens.error);
    req.session.gmailTokens = {
      access_token:  tokens.access_token,
      refresh_token: tokens.refresh_token,
      expiry:        Date.now() + (tokens.expires_in || 3600) * 1000,
    };
    res.send(`<script>window.opener?.postMessage('gmail-authorized','*');window.close();</script>`);
  } catch (e) {
    res.send(`<script>window.opener?.postMessage('gmail-error','*');window.close();</script>`);
  }
});

app.get('/auth/gmail/status', (req, res) => {
  res.json({
    authorized: !!(req.session.gmailTokens?.access_token),
    hasOAuth:   !!GOOGLE_CLIENT_ID,
  });
});

app.post('/auth/gmail/revoke', (req, res) => {
  delete req.session.gmailTokens;
  res.json({ ok: true });
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
  const rows  = XLSX.utils.sheet_to_json(sheet, { defval: '', blankrows: true });
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
    const rows = readSpreadsheet(req.file.buffer);
    if (!rows.length) return res.json({ error: 'File appears to be empty' });
    res.json({ columns: Object.keys(rows[0]) });
  } catch (e) {
    res.status(400).json({ error: `Could not read file: ${e.message}` });
  }
});

const previewUpload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 10 * 1024 * 1024 } }).fields([
  { name: 'recipient_file', maxCount: 1 },
  ...Array.from({ length: 10 }, (_, i) => ({ name: `codes_file_${i}`, maxCount: 1 })),
]);

app.post('/preview', previewUpload, (req, res) => {
  try {
    const { name_col, email_col, release_count } = req.body;
    // Cap at 10 to match the UI limit and prevent runaway iteration
    const count = Math.min(parseInt(release_count) || 0, 10);
    if (count === 0) return res.status(400).json({ error: 'No releases provided' });

    const recipientFileInfo = req.files['recipient_file']?.[0];
    if (!recipientFileInfo) return res.status(400).json({ error: 'Recipient file missing' });

    const warnings = [];

    // Parse recipient list and warn if rows were silently dropped
    const rawRecipientRows = readSpreadsheet(recipientFileInfo.buffer);

    const recipientColErr = validateColumns(rawRecipientRows, [name_col, email_col]);
    if (recipientColErr) return res.status(400).json({ error: 'Recipient file: ' + recipientColErr });

    const recipientList = parseRecipientList(rawRecipientRows, name_col, email_col);

    if (!recipientList.length) return res.status(400).json({ error: 'No valid recipients found. Check that the correct name and email columns are selected, and that email addresses contain @.' });

    const dropped = rawRecipientRows.length - recipientList.length;
    if (dropped > 0) {
      warnings.push(`${dropped} recipient row${dropped !== 1 ? 's' : ''} were skipped (blank, missing name/email, or invalid email format). If you prepared your codes file to align row-for-row, the assignment order may be off.`);
    }

    // Warn about duplicate email addresses in the recipient list
    const emailCount = {};
    recipientList.forEach(recipient => { emailCount[recipient.email] = (emailCount[recipient.email] || 0) + 1; });
    const dupes = Object.keys(emailCount).filter(e => emailCount[e] > 1);
    if (dupes.length > 0) {
      const preview = dupes.slice(0, 3).join(', ') + (dupes.length > 3 ? '…' : '');
      warnings.push(`${dupes.length} duplicate email address${dupes.length !== 1 ? 'es' : ''} found — those recipients will receive multiple emails: ${preview}`);
    }

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

      const codes = rawCodeRows.map(r => String(r[codesCol] ?? '').trim()).filter(Boolean);

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

      releases.push({
        name,
        count: recipientList.length,
        emails: recipientList.map((recipient, j) => {
          const code = codes[j];
          return {
            name:    recipient.name,
            email:   recipient.email,
            code,
            subject: applyTemplate(subject, recipient.name, code),
            body:    applyTemplate(body,    recipient.name, code),
            release: name,
          };
        }),
      });
    }

    const allEmails = releases.flatMap(r => r.emails);
    res.json({ releases, allEmails, total: allEmails.length, warnings });
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

  const { smtp_host, smtp_port, smtp_user, smtp_pass, from_name, emails } = req.body;
  if (!smtp_user)      return res.status(400).json({ error: 'Email address is required' });
  if (!emails?.length) return res.status(400).json({ error: 'No emails to send' });

  // Input length validation — prevents oversized strings from reaching the
  // SMTP transport or appearing in logs.
  const lenErr = validateInputLengths({
    'from_name': { value: from_name, max: 200 },
    'smtp_host': { value: smtp_host, max: 253 },
    'smtp_user': { value: smtp_user, max: 254 },
    'smtp_pass': { value: smtp_pass, max: 256 },
  });
  if (lenErr) return res.status(400).json({ error: lenErr });

  const fromAddr = from_name?.trim()
    ? `"${from_name.trim().replace(/"/g, "'")}" <${smtp_user}>`
    : smtp_user;

  const sent = [], failed = [];

  // ── Gmail API path (when user has authorized via Sign in with Google) ──────
  if (req.session.gmailTokens) {
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
          return res.json({ sent, failed, aborted: true, abortReason: e.message });
        }
      }
    }
    return res.json({ sent, failed });
  }

  // ── SMTP path ─────────────────────────────────────────────────────────────
  if (!smtp_host || !smtp_pass)
    return res.status(400).json({ error: 'SMTP host and password are required' });

  const transport = nodemailer.createTransport({
    host:              smtp_host,
    port:              parseInt(smtp_port) || 587,
    secure:            false,
    auth:              { user: smtp_user, pass: smtp_pass },
    connectionTimeout: 10_000, // abort if TCP connect takes > 10s (e.g. unrouteable IP)
    greetingTimeout:   10_000, // abort if server doesn't send SMTP greeting within 10s
  });

  for (let i = 0; i < emails.length; i++) {
    const item = emails[i];
    try {
      await transport.sendMail({
        from:    fromAddr,
        to:      sanitizeMimeHeader(item.email),
        subject: sanitizeMimeHeader(item.subject),
        text:    htmlToPlainText(item.body),
        html:    `<!DOCTYPE html><html><body style="font-family:sans-serif;font-size:14px;line-height:1.6;color:#333;max-width:600px">${item.body}</body></html>`,
      });
      sent.push(item.email);
    } catch (e) {
      failed.push({ email: item.email, error: redactCredentials(e.message, smtp_pass) });
      if (isFatalSmtpError(e.message)) {
        for (let j = i + 1; j < emails.length; j++)
          failed.push({ email: emails[j].email, error: 'Aborted — see previous error' });
        return res.json({ sent, failed, aborted: true, abortReason: e.message });
      }
    }
  }
  res.json({ sent, failed });
});

app.listen(PORT, () => console.log(`Promo Mailer running at ${BASE_URL}`));
