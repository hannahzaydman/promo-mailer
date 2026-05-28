const express = require('express');
const multer  = require('multer');
const XLSX    = require('xlsx');
const path    = require('path');
const fs      = require('fs');
const session = require('express-session');

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
    "img-src 'self' data:",
    "frame-ancestors 'none'",
    "object-src 'none'",
    "base-uri 'self'",
  ].join('; '));
  next();
});

const { escHtml, sanitizeMimeHeader, htmlToPlainText, applyTemplate, parseDjList } = require('./utils');

const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 10 * 1024 * 1024 } });

// ── Config ─────────────────────────────────────────────────────────────────
const PORT           = process.env.PORT           || 5001;
const BASE_URL       = process.env.BASE_URL        || `http://localhost:${PORT}`;
const BUCKET_NAME    = process.env.BUCKET_NAME;
const ALLOWED_DOMAIN = process.env.ALLOWED_DOMAIN  || 'midnightecstasy.com';
const SESSION_SECRET = process.env.SESSION_SECRET  || 'local-dev-secret-change-in-prod';

if (BASE_URL.startsWith('https') && SESSION_SECRET === 'local-dev-secret-change-in-prod') {
  console.error('FATAL: SESSION_SECRET env var is not set. Refusing to start in production.');
  process.exit(1);
}

// OAuth credentials — from Secret Manager env vars in prod, config file locally
const GOOGLE_CLIENT_ID     = process.env.GOOGLE_CLIENT_ID;
const GOOGLE_CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET;

// ── Session ────────────────────────────────────────────────────────────────
app.use(session({
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

app.use(express.json());

// ── Google login middleware ────────────────────────────────────────────────
function requireAuth(req, res, next) {
  // Allow login flow through unauthenticated
  if (req.path.startsWith('/auth/login')) return next();
  if (req.session?.user) return next();

  // No Google credentials configured yet — let through so user can set up
  if (!GOOGLE_CLIENT_ID && !oauthConfig.clientId) return next();

  res.redirect('/auth/login');
}

// ── GCS or local config persistence (tokens only) ─────────────────────────
let gcsStorage, gcsBucket;
if (BUCKET_NAME) {
  const { Storage } = require('@google-cloud/storage');
  gcsStorage = new Storage();
  gcsBucket  = gcsStorage.bucket(BUCKET_NAME);
}

const CONFIG_PATH = path.join(__dirname, 'config.json');

// oauthConfig holds Gmail tokens (and credentials as fallback for local dev)
let oauthConfig = { clientId: null, clientSecret: null, tokens: null };

async function loadConfig() {
  try {
    let raw;
    if (gcsBucket) {
      const [contents] = await gcsBucket.file('config.json').download();
      raw = contents.toString();
    } else {
      raw = fs.readFileSync(CONFIG_PATH, 'utf8');
    }
    const saved = JSON.parse(raw);
    oauthConfig.clientId     = saved.clientId     || null;
    oauthConfig.clientSecret = saved.clientSecret || null;
    oauthConfig.tokens       = saved.tokens       || null;
    if (oauthConfig.tokens) console.log('Loaded saved Gmail authorization.');
  } catch (e) {
    if (e.code !== 404 && e.code !== 'ENOENT') console.error('Config load error:', e.message);
  }
}

async function saveConfig() {
  const data = JSON.stringify({
    clientId:     oauthConfig.clientId,
    clientSecret: oauthConfig.clientSecret,
    tokens:       oauthConfig.tokens,
  }, null, 2);
  if (gcsBucket) {
    await gcsBucket.file('config.json').save(data);
  } else {
    fs.writeFileSync(CONFIG_PATH, data);
  }
}

// Use Secret Manager env vars in prod, fall back to config file for local dev
function getClientId()     { return GOOGLE_CLIENT_ID     || oauthConfig.clientId; }
function getClientSecret() { return GOOGLE_CLIENT_SECRET || oauthConfig.clientSecret; }

loadConfig();

// ── Google login routes ────────────────────────────────────────────────────
const LOGIN_PAGE = (msg = '') => `<!DOCTYPE html>
<html><head><meta charset="UTF-8"><title>Promo Mailer</title>
<style>
  body{background:#0e0e0e;color:#f0f0f0;font-family:'Helvetica Neue',sans-serif;
       display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0}
  .card{background:#1a1a1a;border:1px solid #2e2e2e;border-radius:8px;padding:40px;
        text-align:center;max-width:360px;width:100%}
  h1{font-size:1.2rem;letter-spacing:.12em;text-transform:uppercase;color:#c8f135;margin-bottom:8px}
  p{color:#888;font-size:.85rem;margin-bottom:28px;line-height:1.5}
  a{display:inline-flex;align-items:center;gap:10px;background:#c8f135;color:#0e0e0e;
    font-weight:700;font-size:.8rem;letter-spacing:.1em;text-transform:uppercase;
    border-radius:5px;padding:12px 24px;text-decoration:none}
  a:hover{background:#d9ff4a}
  .err{color:#ff5c5c;font-size:.8rem;margin-top:16px}
</style></head>
<body><div class="card">
  <h1>Promo Mailer</h1>
  <p>Sign in with your ${ALLOWED_DOMAIN} account to continue.</p>
  <a href="/auth/login/google">Sign in with Google</a>
  ${msg ? `<p class="err">${escHtml(msg)}</p>` : ''}
</div></body></html>`;

app.get('/auth/login', (req, res) => {
  res.send(LOGIN_PAGE(req.query.error || ''));
});

app.get('/auth/login/google', (req, res) => {
  const clientId = getClientId();
  if (!clientId) return res.send(LOGIN_PAGE('OAuth not configured. Set GOOGLE_CLIENT_ID env var.'));

  const params = new URLSearchParams({
    client_id:     clientId,
    redirect_uri:  `${BASE_URL}/auth/login/callback`,
    response_type: 'code',
    scope:         'openid email profile',
    access_type:   'online',
  });
  res.redirect(`https://accounts.google.com/o/oauth2/v2/auth?${params}`);
});

app.get('/auth/login/callback', async (req, res) => {
  const { code, error } = req.query;
  if (error) return res.redirect(`/auth/login?error=${encodeURIComponent(error)}`);

  try {
    const tokenRes = await fetch('https://oauth2.googleapis.com/token', {
      method:  'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        client_id:     getClientId(),
        client_secret: getClientSecret(),
        code,
        grant_type:    'authorization_code',
        redirect_uri:  `${BASE_URL}/auth/login/callback`,
      }),
    });
    const tokens = await tokenRes.json();
    if (tokens.error) throw new Error(tokens.error_description || tokens.error);

    const userRes = await fetch('https://www.googleapis.com/oauth2/v3/userinfo', {
      headers: { 'Authorization': `Bearer ${tokens.access_token}` },
    });
    const user = await userRes.json();

    if (!user.email?.endsWith(`@${ALLOWED_DOMAIN}`)) {
      return res.redirect(`/auth/login?error=${encodeURIComponent(`Access restricted to @${ALLOWED_DOMAIN} accounts.`)}`);
    }

    req.session.user = { email: user.email, name: user.name };
    res.redirect('/');
  } catch (e) {
    res.redirect(`/auth/login?error=${encodeURIComponent(e.message)}`);
  }
});

app.get('/auth/logout', (req, res) => {
  req.session.destroy(() => res.redirect('/auth/login'));
});

// Apply auth middleware to all subsequent routes
app.use(requireAuth);
app.use(express.static(path.join(__dirname, 'public')));

// ── Gmail OAuth endpoints ──────────────────────────────────────────────────
app.post('/auth/setup', async (req, res) => {
  const client_id     = getClientId()     || req.body.client_id?.trim();
  const client_secret = getClientSecret() || req.body.client_secret?.trim();
  if (!client_id || !client_secret)
    return res.status(400).json({ error: 'client_id and client_secret are required' });

  // Only persist to config if not coming from Secret Manager
  if (!GOOGLE_CLIENT_ID) {
    oauthConfig.clientId     = client_id;
    oauthConfig.clientSecret = client_secret;
    oauthConfig.tokens       = null;
    await saveConfig();
  }

  const params = new URLSearchParams({
    client_id,
    redirect_uri:  `${BASE_URL}/auth/callback`,
    response_type: 'code',
    scope:         'https://www.googleapis.com/auth/gmail.send',
    access_type:   'offline',
    prompt:        'consent',
  });
  res.json({ authUrl: `https://accounts.google.com/o/oauth2/v2/auth?${params}` });
});

app.get('/auth/callback', async (req, res) => {
  const { code, error } = req.query;
  const style = 'font-family:sans-serif;padding:32px;background:#0e0e0e;color:';

  if (error) {
    return res.send(`<html><body style="${style}#ff5c5c">
      <p>Authorization failed: ${escHtml(error)}</p><p>Close this tab and try again.</p>
    </body></html>`);
  }

  try {
    const tokenRes = await fetch('https://oauth2.googleapis.com/token', {
      method:  'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        client_id:     getClientId(),
        client_secret: getClientSecret(),
        code,
        grant_type:    'authorization_code',
        redirect_uri:  `${BASE_URL}/auth/callback`,
      }),
    });
    const tokens = await tokenRes.json();
    if (tokens.error) throw new Error(tokens.error_description || tokens.error);

    oauthConfig.tokens = {
      access_token:  tokens.access_token,
      refresh_token: tokens.refresh_token,
      expiry:        Date.now() + (tokens.expires_in - 60) * 1000,
    };
    await saveConfig();

    res.send(`<html><body style="${style}#c8f135">
      <p>&#10003; Authorized! You can close this tab.</p>
      <script>window.opener?.postMessage('gmail-authorized', window.location.origin);window.close();</script>
    </body></html>`);
  } catch (e) {
    res.send(`<html><body style="${style}#ff5c5c">
      <p>Token exchange failed: ${e.message}</p><p>Close this tab and try again.</p>
    </body></html>`);
  }
});

app.get('/auth/status', (_req, res) => res.json({ authorized: !!oauthConfig.tokens }));

app.get('/auth/config', (_req, res) => res.json({
  clientId:          getClientId()     || '',
  // Never expose the client secret to the browser — return only whether it's set
  hasClientSecret:   !!(getClientSecret()),
  credentialsLocked: !!(GOOGLE_CLIENT_ID && GOOGLE_CLIENT_SECRET),
  authorized:        !!oauthConfig.tokens,
}));

// ── Gmail API helpers ──────────────────────────────────────────────────────
async function getAccessToken() {
  if (!oauthConfig.tokens) throw new Error('Not authorized with Gmail');
  if (Date.now() < oauthConfig.tokens.expiry) return oauthConfig.tokens.access_token;

  const res = await fetch('https://oauth2.googleapis.com/token', {
    method:  'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      client_id:     getClientId(),
      client_secret: getClientSecret(),
      refresh_token: oauthConfig.tokens.refresh_token,
      grant_type:    'refresh_token',
    }),
  });
  const data = await res.json();
  if (data.error) throw new Error(`Token refresh failed: ${data.error_description || data.error}`);

  oauthConfig.tokens.access_token = data.access_token;
  oauthConfig.tokens.expiry       = Date.now() + (data.expires_in - 60) * 1000;
  await saveConfig();
  return oauthConfig.tokens.access_token;
}

async function sendGmail(accessToken, from, to, subject, htmlBody) {
  // Strip newlines from header values to prevent MIME header injection
  from    = sanitizeMimeHeader(from);
  to      = sanitizeMimeHeader(to);
  subject = sanitizeMimeHeader(subject);

  const boundary = 'mp_' + Date.now().toString(36);

  const textBody = htmlToPlainText(htmlBody);

  const mime = [
    `From: ${from}`,
    `To: ${to}`,
    `Subject: ${subject}`,
    'MIME-Version: 1.0',
    `Content-Type: multipart/alternative; boundary="${boundary}"`,
    '',
    `--${boundary}`,
    'Content-Type: text/plain; charset=UTF-8',
    '',
    textBody,
    '',
    `--${boundary}`,
    'Content-Type: text/html; charset=UTF-8',
    '',
    `<!DOCTYPE html><html><body style="font-family:sans-serif;font-size:14px;line-height:1.6;color:#333;max-width:600px">${htmlBody}</body></html>`,
    '',
    `--${boundary}--`,
  ].join('\r\n');

  const raw = Buffer.from(mime).toString('base64url');

  const res = await fetch('https://gmail.googleapis.com/gmail/v1/users/me/messages/send', {
    method:  'POST',
    headers: { 'Authorization': `Bearer ${accessToken}`, 'Content-Type': 'application/json' },
    body:    JSON.stringify({ raw }),
  });

  if (!res.ok) {
    const err = await res.json();
    throw new Error(err.error?.message || `HTTP ${res.status}`);
  }
}

// ── Spreadsheet endpoints ──────────────────────────────────────────────────
function readSpreadsheet(buffer) {
  const wb    = XLSX.read(buffer, { type: 'buffer' });
  const sheet = wb.Sheets[wb.SheetNames[0]];
  const rows  = XLSX.utils.sheet_to_json(sheet, { defval: '' });
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

app.post('/get-columns', upload.single('dj_file'), (req, res) => {
  try {
    const rows = readSpreadsheet(req.file.buffer);
    if (!rows.length) return res.json({ error: 'File appears to be empty' });
    res.json({ columns: Object.keys(rows[0]) });
  } catch (e) {
    res.status(400).json({ error: `Could not read file: ${e.message}` });
  }
});

const previewUpload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 10 * 1024 * 1024 } }).fields([
  { name: 'dj_file', maxCount: 1 },
  ...Array.from({ length: 10 }, (_, i) => ({ name: `codes_file_${i}`, maxCount: 1 })),
]);

app.post('/preview', previewUpload, (req, res) => {
  try {
    const { name_col, email_col, release_count } = req.body;
    // Cap at 10 to match the UI limit and prevent runaway iteration
    const count = Math.min(parseInt(release_count) || 0, 10);
    if (count === 0) return res.status(400).json({ error: 'No releases provided' });

    const djFileInfo = req.files['dj_file']?.[0];
    if (!djFileInfo) return res.status(400).json({ error: 'DJ file missing' });

    const warnings = [];

    // Parse DJ list and warn if rows were silently dropped
    const rawDjRows = readSpreadsheet(djFileInfo.buffer);
    const djList    = parseDjList(rawDjRows, name_col, email_col);

    if (!djList.length) return res.status(400).json({ error: 'No valid DJ rows found. Check that the correct name and email columns are selected, and that email addresses contain @.' });

    const dropped = rawDjRows.length - djList.length;
    if (dropped > 0) {
      warnings.push(`${dropped} DJ row${dropped !== 1 ? 's' : ''} were skipped (blank, missing name/email, or invalid email format). If you prepared your codes file to align row-for-row, the assignment order may be off.`);
    }

    // Warn about duplicate email addresses in the DJ list
    const emailCount = {};
    djList.forEach(dj => { emailCount[dj.email] = (emailCount[dj.email] || 0) + 1; });
    const dupes = Object.keys(emailCount).filter(e => emailCount[e] > 1);
    if (dupes.length > 0) {
      const preview = dupes.slice(0, 3).join(', ') + (dupes.length > 3 ? '…' : '');
      warnings.push(`${dupes.length} duplicate email address${dupes.length !== 1 ? 'es' : ''} found — those DJs will receive multiple emails: ${preview}`);
    }

    const releases = [];
    for (let i = 0; i < count; i++) {
      const codesFile = req.files[`codes_file_${i}`]?.[0];
      if (!codesFile) return res.status(400).json({ error: `Missing codes file for release ${i + 1}` });

      const codesCol = req.body[`codes_col_${i}`];
      const subject  = req.body[`subject_${i}`] || '';
      const body     = req.body[`body_${i}`] || '';
      const name     = req.body[`release_name_${i}`] || `Release ${i + 1}`;

      const rawCodeRows = readSpreadsheet(codesFile.buffer);
      const codes = rawCodeRows.map(r => String(r[codesCol] ?? '').trim()).filter(Boolean);

      // Warn if blank rows were dropped from the codes file (row-alignment risk)
      const codesDropped = rawCodeRows.length - codes.length;
      if (codesDropped > 0) {
        warnings.push(`"${name}": ${codesDropped} empty row${codesDropped !== 1 ? 's' : ''} skipped in codes file — row order may not match your DJ list.`);
      }

      if (codes.length < djList.length) {
        return res.status(400).json({
          error: `"${name}": not enough codes (${codes.length}) for all DJs (${djList.length}).`
        });
      }

      releases.push({
        name,
        count: djList.length,
        emails: djList.map((dj, j) => {
          const code = codes[j];
          return {
            name:    dj.name,
            email:   dj.email,
            code,
            subject: applyTemplate(subject, dj.name, code),
            body:    applyTemplate(body,    dj.name, code),
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

// Errors that mean retrying further emails won't help — abort the batch.
const FATAL_SEND_ERRORS = [
  'token refresh failed',
  'not authorized with gmail',
  'invalid_grant',
  'daily limit exceeded',
  'user rate limit exceeded',
  'insufficient authentication scopes',
  'request had invalid authentication credentials',
];

function isFatalSendError(message) {
  const lower = message.toLowerCase();
  return FATAL_SEND_ERRORS.some(pat => lower.includes(pat));
}

// ── Send ───────────────────────────────────────────────────────────────────
app.post('/send', async (req, res) => {
  const { gmail_user, from_name, emails } = req.body;
  if (!gmail_user)     return res.status(400).json({ error: 'Gmail address is required' });
  if (!oauthConfig.tokens) return res.status(401).json({ error: 'Not authorized with Gmail. Complete the OAuth setup first.' });
  if (!emails?.length) return res.status(400).json({ error: 'No emails to send' });

  // Construct From header: "Display Name" <email> or just email
  const fromAddr = from_name?.trim()
    ? `"${from_name.trim().replace(/"/g, "'")}" <${gmail_user}>`
    : gmail_user;

  const sent = [], failed = [];
  for (let i = 0; i < emails.length; i++) {
    const item = emails[i];
    try {
      const token = await getAccessToken();
      await sendGmail(token, fromAddr, item.email, item.subject, item.body);
      sent.push(item.email);
    } catch (e) {
      failed.push({ email: item.email, error: e.message });
      // Auth failures and quota errors won't resolve by retrying — abort the
      // rest of the batch immediately rather than accumulating identical failures.
      if (isFatalSendError(e.message)) {
        for (let j = i + 1; j < emails.length; j++) {
          failed.push({ email: emails[j].email, error: 'Aborted — see previous error' });
        }
        return res.json({ sent, failed, aborted: true, abortReason: e.message });
      }
    }
  }
  res.json({ sent, failed });
});

app.listen(PORT, () => console.log(`Promo Mailer running at ${BASE_URL}`));
