'use strict';

const crypto = require('crypto');
const XLSX   = require('@e965/xlsx');

/**
 * Escape HTML special characters to prevent XSS when inserting untrusted
 * strings into HTML content.
 */
function escHtml(s) {
  return String(s)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

/**
 * Strip CR and LF characters from a string to prevent MIME header injection.
 * Must be applied to every value placed in a MIME header (From, To, Subject).
 */
function sanitizeMimeHeader(s) {
  return String(s).replace(/[\r\n]/g, '');
}

/**
 * Convert an HTML email body to a plain-text fallback.
 *   - <br> / <br/> → newline
 *   - </p>         → double newline
 *   - all other tags stripped
 *   - common HTML entities unescaped
 *   - leading/trailing whitespace trimmed
 */
function htmlToPlainText(html) {
  return html
    .replace(/<br\s*\/?>/gi, '\n')
    .replace(/<\/p>/gi, '\n\n')
    .replace(/<[^>]+>/g, '')
    .replace(/&amp;/g,  '&')
    .replace(/&lt;/g,   '<')
    .replace(/&gt;/g,   '>')
    .replace(/&quot;/g, '"')
    .replace(/&#39;/g,  "'")
    .replace(/&nbsp;/g, ' ')
    .trim();
}

/**
 * Substitute {name} and {code} placeholders in a template string.
 *
 * Values inside href/src attribute values are URL-encoded (so that names or
 * codes with spaces or special characters don't break URLs in links).
 * All remaining occurrences are HTML-escaped to prevent injection into the
 * email body text.
 *
 * @param {string} template - HTML template string (may contain {name}/{code})
 * @param {string} name     - DJ display name
 * @param {string} code     - Bandcamp download code
 * @returns {string}
 */
function applyTemplate(template, name, code) {
  // First pass: replace placeholders inside href/src="..." with URL-encoded values
  const urlEncoded = template.replace(/(href|src)="([^"]*)"/gi, (match, attr, urlVal) => {
    const replaced = urlVal
      .replace(/\{name\}/g, encodeURIComponent(name))
      .replace(/\{code\}/g, encodeURIComponent(code));
    return `${attr}="${replaced}"`;
  });
  // Second pass: replace remaining occurrences with HTML-escaped values
  return urlEncoded
    .replace(/\{name\}/g, escHtml(name))
    .replace(/\{code\}/g, escHtml(code));
}

/**
 * Map spreadsheet rows to {name, email} objects and filter out any row that is
 * missing either value after trimming whitespace, or whose email doesn't
 * contain '@' (catches Excel number/date-formatted cells misconstrued as emails).
 *
 * @param {object[]} rows     - Parsed spreadsheet rows (from XLSX.utils.sheet_to_json)
 * @param {string}   nameCol  - Column name to use as the recipient's display name
 * @param {string}   emailCol - Column name to use as the recipient's email address
 * @returns {{ name: string, email: string }[]}
 */
function parseRecipientList(rows, nameCol, emailCol) {
  const useNameCol = nameCol && nameCol !== '__none__';
  return rows
    .filter(r => r != null && typeof r === 'object')   // drop blank/undefined rows XLSX can produce
    .map(r => ({
      name:  useNameCol ? String(r[nameCol] ?? '').trim() : '',
      email: String(r[emailCol] ?? '').trim(),
    }))
    .filter(r => r.email && r.email.includes('@'));
}

/**
 * Partition a flat codes array into the slice assigned to recipients and the
 * leftover (unused) slice.
 *
 * @param {string[]} codes          - Full list of codes from the uploaded file
 * @param {number}   recipientCount - Number of recipients who will receive codes
 * @returns {{ assigned: string[], unused: string[] }}
 */
function partitionCodes(codes, recipientCount) {
  return {
    assigned: codes.slice(0, recipientCount),
    unused:   codes.slice(recipientCount),
  };
}

/**
 * Sliding-window in-memory rate limiter.
 *
 * Keeps a list of request timestamps per key, prunes those outside the window,
 * and rejects when the count reaches maxRequests. Safe to use with session IDs
 * or IP addresses as the key.
 */
class RateLimiter {
  constructor(maxRequests, windowMs) {
    this.maxRequests = maxRequests;
    this.windowMs    = windowMs;
    this._store      = new Map(); // key → [timestamp, ...]
  }

  /** Returns true if the request is allowed; false if the caller is rate-limited. */
  isAllowed(key) {
    const now    = Date.now();
    const cutoff = now - this.windowMs;
    const hits   = (this._store.get(key) || []).filter(t => t > cutoff);
    if (hits.length >= this.maxRequests) {
      this._store.set(key, hits);
      return false;
    }
    hits.push(now);
    this._store.set(key, hits);
    return true;
  }

  /** Remove expired entries for all keys. Call periodically to prevent unbounded growth. */
  prune() {
    const cutoff = Date.now() - this.windowMs;
    for (const [key, hits] of this._store) {
      const fresh = hits.filter(t => t > cutoff);
      if (fresh.length === 0) this._store.delete(key);
      else this._store.set(key, fresh);
    }
  }
}

/**
 * Validate that string fields do not exceed their maximum allowed lengths.
 *
 * @param {object} fields - { label: { value, max } }
 * @returns {string|null}  First violation as an error message, or null.
 */
function validateInputLengths(fields) {
  for (const [label, { value, max }] of Object.entries(fields)) {
    if (value != null && String(value).length > max) {
      return `"${label}" exceeds the maximum length of ${max} characters (got ${String(value).length}).`;
    }
  }
  return null;
}

/**
 * Redact sensitive values (passwords, tokens) from an error message before it
 * is logged or returned to the client.
 *
 * Uses split/join rather than a regex so that regex-special characters in
 * passwords (e.g. `.`, `*`, `(`) cannot cause a RegExp error.
 *
 * @param {string}    msg     - Error message that may contain a secret
 * @param {...string} secrets - Values to redact (falsy values are skipped)
 * @returns {string}
 */
function redactCredentials(msg, ...secrets) {
  let s = String(msg);
  for (const secret of secrets) {
    if (secret && String(secret).length > 0) {
      s = s.split(String(secret)).join('[REDACTED]');
    }
  }
  return s;
}

// Errors that mean retrying further emails won't help — abort the batch.
const FATAL_SMTP_ERRORS = [
  'invalid login',
  'authentication failed',
  'authentication unsuccessful',
  'too many login attempts',
  'daily sending limit exceeded',
  'daily limit exceeded',
  'user rate limit exceeded',
];

/**
 * Returns true if the SMTP error message indicates a fatal condition where
 * retrying remaining emails in the batch won't help (auth failures, quota).
 */
function isFatalSmtpError(message) {
  const lower = String(message).toLowerCase();
  return FATAL_SMTP_ERRORS.some(pat => lower.includes(pat));
}

const FATAL_GMAIL_ERRORS = [
  'invalid_grant',
  'token has been expired or revoked',
  'invalid credentials',
  'daily sending limit exceeded',
  'user rate limit exceeded',
];

/**
 * Returns true if the Gmail API error message indicates a fatal condition where
 * retrying remaining emails in the batch won't help.
 */
function isFatalGmailError(message) {
  const lower = String(message).toLowerCase();
  return FATAL_GMAIL_ERRORS.some(p => lower.includes(p));
}

/**
 * Verify that every required column name exists in spreadsheet rows.
 * Returns null on success, or an error string naming the first missing column.
 */
function validateColumns(rows, required, context) {
  if (!rows || rows.length === 0) return null;
  const available = Object.keys(rows[0]);
  for (const col of required) {
    if (!available.includes(col)) {
      const prefix = context ? ('"' + context + '": ') : '';
      return prefix + 'column "' + col + '" not found. Available columns: ' + available.join(', ');
    }
  }
  return null;
}

/**
 * Parse an XLSX or CSV buffer into an array of row objects.
 *
 * - blankrows:true preserves blank rows so callers can warn when they're
 *   skipped (blank rows in a codes file shift code-to-recipient alignment).
 * - Strips UTF-8 BOM from column names — common in Windows/Excel CSV exports.
 *   Without this, the first column is named '\uFEFFname' instead of 'name',
 *   breaking auto-detection and column matching silently.
 *
 * @param {Buffer} buffer
 * @returns {object[]}
 */
function readSpreadsheet(buffer) {
  const wb    = XLSX.read(buffer, { type: 'buffer' });
  const sheet = wb.Sheets[wb.SheetNames[0]];
  const rows  = XLSX.utils.sheet_to_json(sheet, { defval: '', blankrows: true })
    .filter(r => r != null && typeof r === 'object');
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

/**
 * Compute a short HMAC token for use in unsubscribe links.
 * Scoped to a specific sender+recipient pair so tokens can't be reused
 * across senders or recipients.
 *
 * @param {string} secret         - HMAC key (SESSION_SECRET in production)
 * @param {string} senderEmail
 * @param {string} recipientEmail
 * @returns {string} 24-char hex token
 */
function unsubToken(secret, senderEmail, recipientEmail) {
  return crypto.createHmac('sha256', secret)
    .update(senderEmail + '\x00' + recipientEmail)
    .digest('hex')
    .slice(0, 24);
}

/**
 * fetch() with an AbortController timeout — prevents external API calls from
 * hanging indefinitely and exhausting Cloud Run connections.
 *
 * @param {string} url
 * @param {object} [options]
 * @param {number} [ms=10000]
 * @returns {Promise<Response>}
 */
function fetchWithTimeout(url, options, ms) {
  if (ms === undefined) ms = 10000;
  const ctrl = new AbortController();
  const t = setTimeout(function() { ctrl.abort(); }, ms);
  return fetch(url, Object.assign({}, options || {}, { signal: ctrl.signal }))
    .finally(function() { clearTimeout(t); });
}

/**
 * Factory that returns encrypt/decrypt functions for SMTP passwords stored in
 * sessions. Uses AES-256-GCM so a Firestore data leak alone is not sufficient
 * to recover plaintext passwords — the server key is also required.
 *
 * @param {Buffer} key - 32-byte AES key (derive from SESSION_SECRET via SHA-256)
 * @returns {{ encrypt(plaintext: string): string, decrypt(encrypted: string): string }}
 */
function createSmtpCrypto(key) {
  function encrypt(plaintext) {
    const iv         = crypto.randomBytes(12);
    const cipher     = crypto.createCipheriv('aes-256-gcm', key, iv);
    const ciphertext = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
    const authTag    = cipher.getAuthTag();
    return [iv, authTag, ciphertext].map(b => b.toString('hex')).join('.');
  }

  function decrypt(encrypted) {
    const [ivHex, authTagHex, ciphertextHex] = encrypted.split('.');
    const iv         = Buffer.from(ivHex, 'hex');
    const authTag    = Buffer.from(authTagHex, 'hex');
    const ciphertext = Buffer.from(ciphertextHex, 'hex');
    const decipher   = crypto.createDecipheriv('aes-256-gcm', key, iv);
    decipher.setAuthTag(authTag);
    return decipher.update(ciphertext, undefined, 'utf8') + decipher.final('utf8');
  }

  return { encrypt, decrypt };
}

module.exports = {
  escHtml, sanitizeMimeHeader, htmlToPlainText, applyTemplate,
  parseRecipientList, partitionCodes,
  isFatalSmtpError, isFatalGmailError,
  validateColumns, validateInputLengths, redactCredentials,
  RateLimiter,
  readSpreadsheet, unsubToken, createSmtpCrypto, fetchWithTimeout,
};
