'use strict';

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
  return rows
    .map(r => ({
      name:  String(r[nameCol]  ?? '').trim(),
      email: String(r[emailCol] ?? '').trim(),
    }))
    .filter(r => r.name && r.email && r.email.includes('@'));
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

module.exports = { escHtml, sanitizeMimeHeader, htmlToPlainText, applyTemplate, parseRecipientList, isFatalSmtpError , validateColumns };
