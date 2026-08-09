# Promo Mailer

A web app for sending personalized promo emails to DJ lists with Bandcamp download codes. Available at [djpromo.net](https://djpromo.net).

---

## What It Does

1. Upload a DJ list (`.xlsx` or `.csv`) with names and email addresses — or enter recipients manually
2. Add one or more releases, each with its own download codes (`.csv`) and email template
3. Preview every personalized email before anything is sent
4. Sign in with your email account and send in real-time with live progress

Email templates support two placeholders:
- `{name}` — replaced with the DJ's name
- `{code}` — replaced with their unique download code

Codes are assigned one-to-one in spreadsheet order (row 1 DJ → row 1 code, etc).

### Features
- **Template library** — save and load email templates locally (localStorage, no server needed)
- **Test email** — send the first email in the batch to yourself before the full send
- **Real-time progress** — live per-email progress bar and result list as sends complete
- **Retry failed** — after a batch, retry only the emails that errored without re-running the flow
- **Export CSV** — download a spreadsheet of all previewed emails (release, name, email, code, subject) for verification
- **Export unused codes** — after a send, download the codes that weren't used
- **Custom From name** — set a display name so emails arrive as `Label Name <you@domain.com>`
- **Embargo note** — optionally append a "don't share until release day" note to each email
- **Attribution footer** — "Sent with djpromo.net, a tool by Midnight Ecstasy" appended to every email
- **Unsubscribe links** — every email includes a signed unsubscribe link; opt-outs are stored in Firestore and honored on future sends
- **Bandcamp releases picker** — browse your label's recent releases directly in the app to fill in release details
- **Manual recipient entry** — add DJs without uploading a spreadsheet
- **Name column optional** — recipients can be email-only (no name required)
- **Recipient deduplication** — duplicate emails flagged and removed at preview time
- **Daily send limit warning** — soft warning when approaching Gmail's daily send cap
- **Warnings** — flags duplicate emails, skipped DJ rows, and misaligned codes files before sending
- **Bandcamp slug warning** — shown below codes upload if the slug looks wrong

---

## Tech Stack

| Layer | Tool |
|---|---|
| Runtime | Node.js 20 |
| Framework | Express |
| File parsing | @e965/xlsx (SheetJS fork) — handles `.xlsx` and `.csv` |
| File uploads | multer (memory storage, 10 MB limit) |
| Email sending | Gmail API (OAuth2) **or** any SMTP server (via nodemailer) |
| Session auth | express-session + Google OAuth or SMTP credentials |
| Session store | Firestore — survives Cloud Run restarts, scales across instances |
| Secret storage | Google Cloud Secret Manager |
| Token storage | Local `config.json` (dev) / Google Cloud Storage (production) |
| Hosting | Google Cloud Run |
| Tests | Node.js built-in `node:test` (no extra dependencies) |
| Template storage | `localStorage` (client-side, no database) |

---

## Project Structure

```
promo-mailer/
├── server.js                  # Express backend — all API routes and auth
├── utils.js                   # Pure helper functions (escaping, template, parsing)
├── firestoreSessionStore.js   # Custom Firestore-backed session store
├── public/
│   ├── index.html             # Single-page frontend (HTML + CSS + JS)
│   ├── star-trails.js         # Star trail canvas animation (login page background)
│   ├── privacy.html           # Privacy policy (required for OAuth verification)
│   └── terms.html             # Terms of service
├── test/
│   ├── utils.test.js          # Unit tests for helper functions
│   ├── security.test.js       # Security-focused tests
│   ├── features.test.js       # Feature integration tests
│   ├── startup.test.js        # Server startup validation tests
│   └── logging.test.js        # Structured logging tests
├── test-data/
│   ├── dj-list.csv            # 10 fake DJs all pointing to hannahzaydman@gmail.com
│   └── download-codes.csv
├── Dockerfile
├── .dockerignore
├── package.json
└── config.json                # Auto-generated locally — stores Gmail tokens only (never commit this)
```

Templates are saved in browser `localStorage` under the key `promo-mailer-templates` and persist across sessions with no server involvement.

---

## Running Tests

```bash
cd ~/promo-mailer
npm test
```

Uses Node's built-in test runner — no `npm install` required for tests. Covers helper functions, security, features, startup validation, and structured logging.

---

## Access & Authentication

### Logging in (production)
Visit `https://djpromo.net` and sign in with either:
- **SMTP** — enter your mail server settings directly (Gmail, Outlook, Yahoo, Proton, iCloud, Fastmail presets available)
- **Google OAuth** — click "Continue with Google" (any Google account)

Sessions last 8 hours. After expiry, API calls silently fail — the app will show "Your session has expired. Please sign out and sign in again." Two improvements are deferred: (1) rolling sessions (`rolling: true` in session config) so any activity resets the 8-hour clock, and (2) an in-page "session expired" modal that prompts re-auth without losing the user's current work.

### Logging in (local dev)
No login required locally — the app opens directly unless `GOOGLE_CLIENT_ID` is set as an env var.

---

## Running Locally

```bash
cd ~/promo-mailer
node server.js
```

Open `http://localhost:5001` in your browser.

`config.json` is created automatically the first time you authorize Gmail. It stores only the Gmail send tokens — credentials live in Secret Manager in prod, and are entered via the app UI locally.

---

## Environment Variables & Secrets

Set on Cloud Run. Secrets are stored in Secret Manager — not plaintext env vars.

| Variable | Source | Value |
|---|---|---|
| `PORT` | Cloud Run (auto) | `8080` (set automatically) |
| `BASE_URL` | Env var | `https://djpromo.net` |
| `BUCKET_NAME` | Env var | `your-label-promo-config` |
| `GOOGLE_CLIENT_ID` | Secret Manager → `google-client-id` | OAuth client ID |
| `GOOGLE_CLIENT_SECRET` | Secret Manager → `google-client-secret` | OAuth client secret |
| `SESSION_SECRET` | Secret Manager → `session-secret` | Random 32-byte hex, signs session cookies and unsubscribe tokens |
| `ALLOWED_DOMAIN` | Env var (optional) | If set, restricts sign-in to a single email domain (e.g. `midnightecstasy.com`). Omit to allow any account. |

### Rotating the client secret
If the OAuth client secret is ever compromised or reset in Google Cloud Console:
```bash
echo -n "NEW_SECRET" | gcloud secrets versions add google-client-secret \
  --project=elegant-cipher-497621-m4 --data-file=-
```
Then redeploy.

---

## Google Cloud Setup (one-time, already done)

### Project details
- **Project ID:** `elegant-cipher-497621-m4`
- **Project number:** `626783271182`
- **Organization ID:** `1097860000437`
- **Cloud Run URL:** `https://promo-mailer-626783271182.us-central1.run.app`
- **Custom domain:** `https://djpromo.net`
- **GCS bucket:** `your-label-promo-config`

### OAuth credentials
Created in **APIs & Services → Credentials** as a Web application OAuth client.

Authorized redirect URIs registered:
- `http://localhost:5001/auth/callback` (Gmail send auth, local)
- `http://localhost:5001/auth/login/callback` (Google login, local)
- `https://djpromo.net/auth/callback` (Gmail send auth, prod)
- `https://djpromo.net/auth/login/callback` (Google login, prod)
- `https://promo-mailer-626783271182.us-central1.run.app/auth/callback` (Gmail send auth, direct Cloud Run URL)
- `https://promo-mailer-626783271182.us-central1.run.app/auth/login/callback` (Google login, direct Cloud Run URL)

### Secret Manager secrets created
```bash
# Secrets already created — use these commands only to recreate if needed
echo -n "YOUR_CLIENT_ID" | gcloud secrets create google-client-id \
  --project=elegant-cipher-497621-m4 --data-file=-

echo -n "YOUR_CLIENT_SECRET" | gcloud secrets create google-client-secret \
  --project=elegant-cipher-497621-m4 --data-file=-

echo -n "$(openssl rand -hex 32)" | gcloud secrets create session-secret \
  --project=elegant-cipher-497621-m4 --data-file=-
```

### IAM permissions granted
```bash
# Cloud Build and Storage access for deployment
gcloud projects add-iam-policy-binding elegant-cipher-497621-m4 \
  --member="serviceAccount:626783271182-compute@developer.gserviceaccount.com" \
  --role="roles/cloudbuild.builds.builder"

gcloud projects add-iam-policy-binding elegant-cipher-497621-m4 \
  --member="serviceAccount:626783271182-compute@developer.gserviceaccount.com" \
  --role="roles/storage.admin"

# Secret Manager access
for SECRET in google-client-id google-client-secret session-secret; do
  gcloud secrets add-iam-policy-binding $SECRET \
    --project=elegant-cipher-497621-m4 \
    --member="serviceAccount:626783271182-compute@developer.gserviceaccount.com" \
    --role="roles/secretmanager.secretAccessor"
done

# Public Cloud Run access (org policy override applied at project level)
gcloud run services add-iam-policy-binding promo-mailer \
  --region=us-central1 \
  --member="allUsers" \
  --role="roles/run.invoker"
```

### Org policy override
The Workspace org blocks `allUsers` on Cloud Run by default. An override was applied at the project level to allow public access (the app handles its own auth via Google sign-in):
```bash
gcloud services enable orgpolicy.googleapis.com --project=elegant-cipher-497621-m4

gcloud organizations add-iam-policy-binding 1097860000437 \
  --member="user:admin@midnightecstasy.com" \
  --role="roles/orgpolicy.policyAdmin"

cat > /tmp/allow-all-members.yaml << 'EOF'
name: projects/elegant-cipher-497621-m4/policies/iam.allowedPolicyMemberDomains
spec:
  inheritFromParent: false
  rules:
  - allowAll: true
EOF
gcloud org-policies set-policy /tmp/allow-all-members.yaml
```

---

## Deploying

### Redeploy after code changes
```bash
cd ~/promo-mailer
gcloud run deploy promo-mailer --source . --region us-central1
```

Env vars and secrets are remembered between deploys — no need to pass them again unless changing a value.

### Redeploy and update an env var
```bash
gcloud run deploy promo-mailer \
  --source . \
  --region us-central1 \
  --update-env-vars="KEY=value"
```

### Redeploy and remove an env var
```bash
gcloud run deploy promo-mailer \
  --source . \
  --region us-central1 \
  --update-env-vars="KEY=value" \
  --remove-env-vars="OTHER_KEY"
```

Note: `--set-env-vars` and `--remove-env-vars` cannot be used together — use `--update-env-vars` when also removing.

---

## Spreadsheet Format

**DJ list** (`.xlsx` or `.csv`) — needs at minimum an email column. Name column is optional.

| name | email |
|---|---|
| DJ Phantom | dj@example.com |

**Download codes** (`.csv`) — one code per row. Any column name works; you select it in the app.

| code |
|---|
| XK9F-2MQT-7RVL |

The app supports up to **10 releases** in a single session. Each release needs its own codes CSV.

---

## Troubleshooting

**Redirected to login but sign-in fails**
Make sure `https://djpromo.net/auth/login/callback` is listed as an authorized redirect URI in your OAuth client (APIs & Services → Credentials).

**SMTP login fails with "invalid credentials"**
For Gmail, use an [App Password](https://myaccount.google.com/apppasswords) — not your regular Google password. For Yahoo and iCloud, use an app-specific password from your account security settings. For Proton, Proton Mail Bridge must be running locally.

**"Not enough codes" error**
The codes CSV has fewer rows than the DJ list. Add more codes or reduce the DJ list.

**`gcloud run deploy` crashes with a `FileNotFoundError` on a macOS News path**
gcloud is scanning the wrong directory. Run the deploy from inside the project folder, or pass the path explicitly:
```bash
cd ~/promo-mailer && gcloud run deploy promo-mailer --source . --region us-central1
# or
gcloud run deploy promo-mailer --source ~/promo-mailer --region us-central1
```
If it persists, run `gcloud components update` first.

**"MulterError: Unexpected field"**
Server wasn't restarted after a code change. Stop and restart `node server.js`.

**Gmail auth fails after redeploy**
Re-authorization is only needed if the domain/URL changes or access is revoked. Tokens are stored in GCS and reused automatically on restart.

**`gcloud run deploy` permission error**
Re-run the `gcloud projects add-iam-policy-binding` commands in the IAM section above.

**Preview shows an error message**
Check the terminal running `node server.js` for the actual server-side error.

**`--set-env-vars` and `--remove-env-vars` conflict error**
Use `--update-env-vars` instead of `--set-env-vars` when also using `--remove-env-vars` in the same command.

**Session lost after Cloud Run restart**
Sessions are stored in Firestore and survive restarts automatically. If sessions are dropping, check that the Firestore API is enabled in the GCP project and the service account has Firestore access.
