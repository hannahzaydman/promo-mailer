'use strict';

const { describe, test } = require('node:test');
const assert = require('node:assert/strict');
const { escHtml, sanitizeMimeHeader, htmlToPlainText, applyTemplate, parseRecipientList, isFatalSmtpError } = require('../utils');

// ── escHtml ──────────────────────────────────────────────────────────────────

describe('escHtml', () => {
  test('escapes < and >', () => {
    assert.equal(escHtml('<script>'), '&lt;script&gt;');
  });

  test('escapes &', () => {
    assert.equal(escHtml('AT&T'), 'AT&amp;T');
  });

  test('escapes double quotes', () => {
    assert.equal(escHtml('"value"'), '&quot;value&quot;');
  });

  test('leaves single quotes unchanged', () => {
    assert.equal(escHtml("it's fine"), "it's fine");
  });

  test('handles a full XSS payload', () => {
    assert.equal(
      escHtml('<img src=x onerror=alert(1)>'),
      '&lt;img src=x onerror=alert(1)&gt;'
    );
  });

  test('handles attribute-injection payload', () => {
    assert.equal(
      escHtml('" onmouseover="alert(1)'),
      '&quot; onmouseover=&quot;alert(1)'
    );
  });

  test('coerces non-string types', () => {
    assert.equal(escHtml(42),        '42');
    assert.equal(escHtml(null),      'null');
    assert.equal(escHtml(undefined), 'undefined');
  });

  test('does not double-escape on a second call (not idempotent by design)', () => {
    assert.equal(escHtml('&amp;'), '&amp;amp;');
  });

  test('empty string stays empty', () => {
    assert.equal(escHtml(''), '');
  });
});

// ── sanitizeMimeHeader ────────────────────────────────────────────────────────

describe('sanitizeMimeHeader', () => {
  test('strips CRLF (classic header injection sequence)', () => {
    assert.equal(
      sanitizeMimeHeader('Subject\r\nBcc: attacker@evil.com'),
      'SubjectBcc: attacker@evil.com'
    );
  });

  test('strips bare LF', () => {
    assert.equal(sanitizeMimeHeader('line1\nline2'), 'line1line2');
  });

  test('strips bare CR', () => {
    assert.equal(sanitizeMimeHeader('line1\rline2'), 'line1line2');
  });

  test('strips multiple injected newlines', () => {
    assert.equal(sanitizeMimeHeader('a\r\nb\r\nc'), 'abc');
  });

  test('leaves a normal subject line unchanged', () => {
    assert.equal(
      sanitizeMimeHeader('New Promo: Artist – Title [2025]'),
      'New Promo: Artist – Title [2025]'
    );
  });

  test('empty string stays empty', () => {
    assert.equal(sanitizeMimeHeader(''), '');
  });

  test('coerces numbers', () => {
    assert.equal(sanitizeMimeHeader(42), '42');
  });
});

// ── htmlToPlainText ───────────────────────────────────────────────────────────

describe('htmlToPlainText', () => {
  test('converts <br> to newline', () => {
    assert.equal(htmlToPlainText('Hello<br>World'), 'Hello\nWorld');
  });

  test('converts self-closing <br/>', () => {
    assert.equal(htmlToPlainText('Hello<br/>World'), 'Hello\nWorld');
  });

  test('converts <br /> (with space)', () => {
    assert.equal(htmlToPlainText('Hello<br />World'), 'Hello\nWorld');
  });

  test('is case-insensitive for <BR>', () => {
    assert.equal(htmlToPlainText('Hello<BR>World'), 'Hello\nWorld');
  });

  test('converts </p> to double newline and strips <p> opening tag', () => {
    assert.equal(htmlToPlainText('<p>First</p><p>Second</p>'), 'First\n\nSecond');
  });

  test('strips <b> / <strong> tags, keeps text', () => {
    assert.equal(htmlToPlainText('<b>bold</b> and <strong>stronger</strong>'), 'bold and stronger');
  });

  test('strips anchor tags but keeps link text', () => {
    assert.equal(
      htmlToPlainText('<a href="https://example.com">click here</a>'),
      'click here'
    );
  });

  test('unescapes &amp;', () => {
    assert.equal(htmlToPlainText('AT&amp;T'), 'AT&T');
  });

  test('unescapes &lt; and &gt;', () => {
    assert.equal(htmlToPlainText('&lt;tag&gt;'), '<tag>');
  });

  test('unescapes &quot;', () => {
    assert.equal(htmlToPlainText('say &quot;hello&quot;'), 'say "hello"');
  });

  test("unescapes &#39; (single quote)", () => {
    assert.equal(htmlToPlainText("it&#39;s"), "it's");
  });

  test('replaces &nbsp; with a regular space', () => {
    assert.equal(htmlToPlainText('a&nbsp;b'), 'a b');
  });

  test('trims leading and trailing whitespace', () => {
    assert.equal(htmlToPlainText('   plain text   '), 'plain text');
  });

  test('handles already-plain text unchanged', () => {
    assert.equal(htmlToPlainText('just some text'), 'just some text');
  });

  test('handles empty string', () => {
    assert.equal(htmlToPlainText(''), '');
  });

  test('handles a realistic rich-text email body', () => {
    const html = '<p>Hi there,</p><p>Your code is <b>XK9F-2MQT</b>.<br>Enjoy!</p>';
    assert.equal(htmlToPlainText(html), 'Hi there,\n\nYour code is XK9F-2MQT.\nEnjoy!');
  });
});

// ── applyTemplate ─────────────────────────────────────────────────────────────

describe('applyTemplate', () => {
  test('substitutes {name}', () => {
    assert.equal(applyTemplate('Hi {name}!', 'DJ Phantom', 'CODE1'), 'Hi DJ Phantom!');
  });

  test('substitutes {code}', () => {
    assert.equal(applyTemplate('Your code: {code}', 'DJ', 'XK9F-2MQT'), 'Your code: XK9F-2MQT');
  });

  test('substitutes both placeholders in one template', () => {
    assert.equal(
      applyTemplate('Hi {name}, your code is {code}.', 'DJ Phantom', 'ABC123'),
      'Hi DJ Phantom, your code is ABC123.'
    );
  });

  test('replaces all occurrences of {name}', () => {
    assert.equal(applyTemplate('{name} — {name}', 'DJ', 'X'), 'DJ — DJ');
  });

  test('HTML-escapes name to prevent XSS injection', () => {
    assert.equal(
      applyTemplate('Hi {name}!', '<script>alert(1)</script>', 'CODE'),
      'Hi &lt;script&gt;alert(1)&lt;/script&gt;!'
    );
  });

  test('HTML-escapes code to prevent XSS injection', () => {
    assert.equal(
      applyTemplate('Code: {code}', 'DJ', '<evil>'),
      'Code: &lt;evil&gt;'
    );
  });

  test('HTML-escapes & in name', () => {
    assert.equal(
      applyTemplate('Hi {name}!', 'Rock & Roll DJ', 'CODE'),
      'Hi Rock &amp; Roll DJ!'
    );
  });

  test('HTML-escapes " in name', () => {
    assert.equal(
      applyTemplate('Hi {name}!', 'DJ "Specter"', 'CODE'),
      'Hi DJ &quot;Specter&quot;!'
    );
  });

  test('passes through a template with no placeholders unchanged', () => {
    assert.equal(applyTemplate('No placeholders here.', 'DJ', 'CODE'), 'No placeholders here.');
  });

  test('handles empty template', () => {
    assert.equal(applyTemplate('', 'DJ', 'CODE'), '');
  });

  test('URL-encodes {code} inside an href attribute', () => {
    assert.equal(
      applyTemplate('<a href="https://bandcamp.com/redeem/{code}">link</a>', 'DJ', 'XK9F&2MQT'),
      '<a href="https://bandcamp.com/redeem/XK9F%262MQT">link</a>'
    );
  });

  test('URL-encodes {name} with spaces inside an href attribute', () => {
    assert.equal(
      applyTemplate('<a href="https://example.com/{name}">click</a>', 'DJ Phantom', 'CODE'),
      '<a href="https://example.com/DJ%20Phantom">click</a>'
    );
  });

  test('URL-encodes href but still HTML-escapes the link text', () => {
    assert.equal(
      applyTemplate('<a href="https://example.com/{code}">{name}</a>', 'Rock & Roll', 'X&Y'),
      '<a href="https://example.com/X%26Y">Rock &amp; Roll</a>'
    );
  });

  test('href without placeholders is left unchanged', () => {
    assert.equal(
      applyTemplate('<a href="https://example.com">visit {name}</a>', 'DJ', 'CODE'),
      '<a href="https://example.com">visit DJ</a>'
    );
  });
});

// ── parseDjList ───────────────────────────────────────────────────────────────

describe('parseRecipientList', () => {
  test('maps name and email from the given columns', () => {
    const rows = [{ name: 'DJ Phantom', email: 'dj@test.com' }];
    assert.deepEqual(parseRecipientList(rows, 'name', 'email'), [
      { name: 'DJ Phantom', email: 'dj@test.com' },
    ]);
  });

  test('filters out rows with a missing email', () => {
    const rows = [
      { name: 'DJ One', email: '' },
      { name: 'DJ Two', email: 'two@test.com' },
    ];
    assert.deepEqual(parseRecipientList(rows, 'name', 'email'), [
      { name: 'DJ Two', email: 'two@test.com' },
    ]);
  });

  test('keeps rows with a missing name (name is optional)', () => {
    const rows = [
      { name: '',       email: 'one@test.com' },
      { name: 'DJ Two', email: 'two@test.com' },
    ];
    assert.deepEqual(parseRecipientList(rows, 'name', 'email'), [
      { name: '',       email: 'one@test.com' },
      { name: 'DJ Two', email: 'two@test.com' },
    ]);
  });

  test('trims whitespace from both name and email', () => {
    const rows = [{ name: '  DJ Phantom  ', email: '  dj@test.com  ' }];
    assert.deepEqual(parseRecipientList(rows, 'name', 'email'), [
      { name: 'DJ Phantom', email: 'dj@test.com' },
    ]);
  });

  test('keeps rows where name is whitespace-only after trim (name is optional)', () => {
    const rows = [{ name: '   ', email: 'dj@test.com' }];
    assert.deepEqual(parseRecipientList(rows, 'name', 'email'), [
      { name: '', email: 'dj@test.com' },
    ]);
  });

  test('handles null and undefined cell values without throwing', () => {
    const rows = [{ name: null, email: undefined }];
    assert.deepEqual(parseRecipientList(rows, 'name', 'email'), []);
  });

  test('returns empty array when all rows are invalid', () => {
    const rows = [{ name: '', email: '' }, { name: '  ', email: '  ' }];
    assert.deepEqual(parseRecipientList(rows, 'name', 'email'), []);
  });

  test('returns empty array for empty input', () => {
    assert.deepEqual(parseRecipientList([], 'name', 'email'), []);
  });

  test('works with non-standard column names', () => {
    const rows = [{ artist: 'DJ Phantom', contact: 'dj@test.com' }];
    assert.deepEqual(parseRecipientList(rows, 'artist', 'contact'), [
      { name: 'DJ Phantom', email: 'dj@test.com' },
    ]);
  });

  test('keeps rows when name column does not exist (name defaults to empty)', () => {
    const rows = [{ name: 'DJ Phantom', email: 'dj@test.com' }];
    assert.deepEqual(parseRecipientList(rows, 'wrong_col', 'email'), [
      { name: '', email: 'dj@test.com' },
    ]);
  });

  test('filters out rows where email has no @ (e.g. Excel number-formatted cell)', () => {
    const rows = [
      { name: 'DJ One', email: '45292' },      // Excel date serial number
      { name: 'DJ Two', email: 'dj@test.com' },
    ];
    assert.deepEqual(parseRecipientList(rows, 'name', 'email'), [
      { name: 'DJ Two', email: 'dj@test.com' },
    ]);
  });

  test('filters out rows where email is a plain word with no @', () => {
    const rows = [{ name: 'DJ Phantom', email: 'notanemail' }];
    assert.deepEqual(parseRecipientList(rows, 'name', 'email'), []);
  });

  test('preserves order and handles multiple valid rows', () => {
    const rows = [
      { name: 'DJ One',   email: 'one@test.com' },
      { name: 'DJ Two',   email: 'two@test.com' },
      { name: 'DJ Three', email: 'three@test.com' },
    ];
    assert.deepEqual(parseRecipientList(rows, 'name', 'email'), [
      { name: 'DJ One',   email: 'one@test.com' },
      { name: 'DJ Two',   email: 'two@test.com' },
      { name: 'DJ Three', email: 'three@test.com' },
    ]);
  });
});

// ── isFatalSmtpError ──────────────────────────────────────────────────────────

describe('isFatalSmtpError', () => {
  // Each fatal pattern
  test('detects "invalid login"', () => {
    assert.equal(isFatalSmtpError('535 5.7.8 Error: authentication failed: Invalid login'), true);
  });

  test('detects "authentication failed"', () => {
    assert.equal(isFatalSmtpError('Authentication failed: bad credentials'), true);
  });

  test('detects "authentication unsuccessful"', () => {
    assert.equal(isFatalSmtpError('454 4.7.0 Authentication unsuccessful'), true);
  });

  test('detects "too many login attempts"', () => {
    assert.equal(isFatalSmtpError('Too many login attempts, please try again later'), true);
  });

  test('detects "daily sending limit exceeded"', () => {
    assert.equal(isFatalSmtpError('Daily sending limit exceeded'), true);
  });

  test('detects "daily limit exceeded"', () => {
    assert.equal(isFatalSmtpError('You have exceeded your daily limit exceeded for this account'), true);
  });

  test('detects "user rate limit exceeded"', () => {
    assert.equal(isFatalSmtpError('User rate limit exceeded'), true);
  });

  // Case-insensitivity
  test('is case-insensitive (all-caps)', () => {
    assert.equal(isFatalSmtpError('AUTHENTICATION FAILED'), true);
  });

  test('is case-insensitive (mixed case)', () => {
    assert.equal(isFatalSmtpError('Invalid Login: bad password'), true);
  });

  // Non-fatal errors should return false
  test('returns false for a transient connection error', () => {
    assert.equal(isFatalSmtpError('Connection timeout'), false);
  });

  test('returns false for a single recipient rejection', () => {
    assert.equal(isFatalSmtpError('550 5.1.1 The email account does not exist'), false);
  });

  test('returns false for an empty string', () => {
    assert.equal(isFatalSmtpError(''), false);
  });

  test('coerces non-string message without throwing', () => {
    assert.equal(isFatalSmtpError(null), false);
    assert.equal(isFatalSmtpError(undefined), false);
  });
});
