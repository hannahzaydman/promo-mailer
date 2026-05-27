const express = require('express');
const multer  = require('multer');
const XLSX    = require('xlsx');
const path    = require('path');
const fs      = require('fs');
const session = require('express-session');

const app = express();
app.set('trust proxy', 1); // Required for secure cookies behind Cloud Run

const upload = multer({ storage: multer.memoryStorage() });

// ── Config ─────────────────────────────────────────────────────────────────
const PORT           = process.env.PORT           || 5001;
const BASE_URL       = process.env.BASE_URL        || `http://localhost:${PORT}`;
const BUCKET_NAME    = process.env.BUCKET_NAME;
const ALLOWED_DOMAIN = process.env.ALLOWED_DOMAIN  || 'midnightecstasy.com';
const SESSION_SECRET = process.env.SESSION_SECRET  || 'local-dev-secret-change-in-prod';

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
  ${msg ? `<p class="err">${msg}</p>` : ''}
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
      <p>Authorization failed: ${error}</p><p>Close this tab and try again.</p>
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
      <script>window.opener?.postMessage('gmail-authorized','*');window.close();</script>
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
  clientSecret:      getClientSecret() || '',
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

async function sendGmail(accessToken, from, to, subject, body) {
  const raw = Buffer.from(
    [`From: ${from}`, `To: ${to}`, `Subject: ${subject}`,
     'MIME-Version: 1.0', 'Content-Type: text/plain; charset=UTF-8', '', body]
    .join('\r\n')
  ).toString('base64url');

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
  return XLSX.utils.sheet_to_json(sheet, { defval: '' });
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

const previewUpload = multer({ storage: multer.memoryStorage() }).fields([
  { name: 'dj_file', maxCount: 1 },
  ...Array.from({ length: 10 }, (_, i) => ({ name: `codes_file_${i}`, maxCount: 1 })),
]);

app.post('/preview', previewUpload, (req, res) => {
  try {
    const { name_col, email_col, release_count } = req.body;
    const count = parseInt(release_count) || 0;
    if (count === 0) return res.status(400).json({ error: 'No releases provided' });

    const djFileInfo = req.files['dj_file']?.[0];
    if (!djFileInfo) return res.status(400).json({ error: 'DJ file missing' });

    const djList = readSpreadsheet(djFileInfo.buffer)
      .map(r => ({ name: String(r[name_col] ?? '').trim(), email: String(r[email_col] ?? '').trim() }))
      .filter(r => r.name && r.email);

    if (!djList.length) return res.status(400).json({ error: 'No valid DJ rows found' });

    const releases = [];
    for (let i = 0; i < count; i++) {
      const codesFile = req.files[`codes_file_${i}`]?.[0];
      if (!codesFile) return res.status(400).json({ error: `Missing codes file for release ${i + 1}` });

      const codesCol = req.body[`codes_col_${i}`];
      const subject  = req.body[`subject_${i}`] || '';
      const body     = req.body[`body_${i}`] || '';
      const name     = req.body[`release_name_${i}`] || `Release ${i + 1}`;

      const codes = readSpreadsheet(codesFile.buffer)
        .map(r => String(r[codesCol] ?? '').trim())
        .filter(Boolean);

      if (codes.length < djList.length) {
        return res.status(400).json({
          error: `"${name}": not enough codes (${codes.length}) for all DJs (${djList.length}).`
        });
      }

      releases.push({
        name,
        count: djList.length,
        emails: djList.map((dj, j) => {
          const code    = codes[j];
          const replace = s => s.replace(/\{name\}/g, dj.name).replace(/\{code\}/g, code);
          return { name: dj.name, email: dj.email, code, subject: replace(subject), body: replace(body), release: name };
        }),
      });
    }

    const allEmails = releases.flatMap(r => r.emails);
    res.json({ releases, allEmails, total: allEmails.length });
  } catch (e) {
    res.status(400).json({ error: e.message });
  }
});

// ── Send ───────────────────────────────────────────────────────────────────
app.post('/send', async (req, res) => {
  const { gmail_user, emails } = req.body;
  if (!gmail_user)     return res.status(400).json({ error: 'Gmail address is required' });
  if (!oauthConfig.tokens) return res.status(401).json({ error: 'Not authorized with Gmail. Complete the OAuth setup first.' });
  if (!emails?.length) return res.status(400).json({ error: 'No emails to send' });

  const sent = [], failed = [];
  for (const item of emails) {
    try {
      const token = await getAccessToken();
      await sendGmail(token, gmail_user, item.email, item.subject, item.body);
      sent.push(item.email);
    } catch (e) {
      failed.push({ email: item.email, error: e.message });
    }
  }
  res.json({ sent, failed });
});

app.listen(PORT, () => console.log(`Promo Mailer running at ${BASE_URL}`));
