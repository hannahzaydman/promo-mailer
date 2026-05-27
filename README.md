# Promo Mailer

A web app for sending personalized promo emails to DJ lists with Bandcamp download codes. Built for internal use at the label.

---

## What It Does

1. Upload a DJ list (`.xlsx` or `.csv`) with names and email addresses
2. Add one or more releases, each with its own download codes (`.csv`) and email template
3. Preview every personalized email before anything is sent
4. Authorize with Gmail via OAuth and send everything in one click

Email templates support two placeholders:
- `{name}` — replaced with the DJ's name
- `{code}` — replaced with their unique download code

Codes are assigned one-to-one in spreadsheet order (row 1 DJ → row 1 code, etc).

---

## Tech Stack

| Layer | Tool |
|---|---|
| Runtime | Node.js 20 |
| Framework | Express |
| File parsing | xlsx (SheetJS) — handles `.xlsx` and `.csv` |
| File uploads | multer (memory storage) |
| Email sending | Gmail API (via OAuth2, no SMTP) |
| Session auth | express-session + Google OAuth (restricted to `@midnightecstasy.com`) |
| Secret storage | Google Cloud Secret Manager |
| Token storage | Local `config.json` (dev) / Google Cloud Storage (production) |
| Hosting | Google Cloud Run |

---

## Project Structure

```
promo-mailer/
├── server.js           # Express backend — all API routes and auth
├── public/
│   └── index.html      # Single-page frontend (HTML + CSS + JS)
├── test-data/
│   ├── dj-list.csv     # 10 fake DJs all pointing to hannahzaydman@gmail.com
│   └── download-codes.csv
├── Dockerfile
├── .dockerignore
├── package.json
└── config.json         # Auto-generated locally — stores Gmail tokens only (never commit this)
```

---

## Access & Authentication

### Logging in (production)
Visit `https://djpromo.net` and click **Sign in with Google**. Only `@midnightecstasy.com` accounts are allowed in. Sessions last 8 hours.

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
| `BASE_URL` | Env var | `https://promo-mailer-wgqszg7kfq-uc.a.run.app` |
| `BUCKET_NAME` | Env var | `your-label-promo-config` |
| `GOOGLE_CLIENT_ID` | Secret Manager → `google-client-id` | OAuth client ID |
| `GOOGLE_CLIENT_SECRET` | Secret Manager → `google-client-secret` | OAuth client secret |
| `SESSION_SECRET` | Secret Manager → `session-secret` | Random 32-byte hex, signs session cookies |
| `ALLOWED_DOMAIN` | Env var (optional) | Defaults to `midnightecstasy.com` |

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

**DJ list** (`.xlsx` or `.csv`) — needs at minimum a name column and an email column. Column names are auto-detected but can be overridden in the app.

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
Make sure `https://promo-mailer-wgqszg7kfq-uc.a.run.app/auth/login/callback` is listed as an authorized redirect URI in your OAuth client (APIs & Services → Credentials).

**"Not enough codes" error**
The codes CSV has fewer rows than the DJ list. Add more codes or reduce the DJ list.

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
