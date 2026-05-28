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
 * Both values are HTML-escaped before insertion to prevent injection
 * into the email body.
 */
function applyTemplate(template, name, code) {
  return template
    .replace(/\{name\}/g, escHtml(name))
    .replace(/\{code\}/g, escHtml(code));
}

/**
 * Map spreadsheet rows to {name, email} objects and filter out any row
 * that is missing either value after trimming whitespace.
 *
 * @param {object[]} rows     - Parsed spreadsheet rows (from XLSX.utils.sheet_to_json)
 * @param {string}   nameCol  - Column name to use as the DJ's display name
 * @param {string}   emailCol - Column name to use as the DJ's email address
 * @returns {{ name: string, email: string }[]}
 */
function parseDjList(rows, nameCol, emailCol) {
  return rows
    .map(r => ({
      name:  String(r[nameCol]  ?? '').trim(),
      email: String(r[emailCol] ?? '').trim(),
    }))
    .filter(r => r.name && r.email);
}

module.exports = { escHtml, sanitizeMimeHeader, htmlToPlainText, applyTemplate, parseDjList };
