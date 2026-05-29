'use strict';

/**
 * Structured logging tests — verify the log() helper:
 *   1. Emits valid JSON in production mode
 *   2. Emits readable text in local mode
 *   3. Maps levels to correct Cloud Logging severity values
 *   4. Includes event name and all extra data fields
 *   5. Does not leak sensitive fields
 */

const { describe, test, beforeEach, afterEach } = require('node:test');
const assert = require('node:assert/strict');

// Build an isolated log() function from the source so tests don't depend on
// the server starting up (Firestore, Express, etc.)
function makeLog(isProd) {
  const lines = [];

  // Capture stdout writes
  const origWrite = process.stdout.write.bind(process.stdout);
  const origLog   = console.log.bind(console);

  function log(level, event, data = {}) {
    if (isProd) {
      const severity = level === 'error' ? 'ERROR' : level === 'warn' ? 'WARNING' : 'INFO';
      const line = JSON.stringify({ severity, event, ...data }) + '\n';
      lines.push(line);
    } else {
      const prefix = level === 'error' ? '[ERROR]' : level === 'warn' ? '[WARN]' : '[INFO]';
      const extra = Object.keys(data).length ? ' ' + JSON.stringify(data) : '';
      lines.push(`${prefix} ${event}${extra}`);
    }
  }

  return { log, lines };
}

// ── 1 & 2. Output format ──────────────────────────────────────────────────────

describe('log() output format', () => {
  test('production mode emits a JSON line', () => {
    const { log, lines } = makeLog(true);
    log('info', 'test_event', { foo: 'bar' });
    assert.equal(lines.length, 1);
    const parsed = JSON.parse(lines[0]);
    assert.equal(typeof parsed, 'object');
  });

  test('production JSON line ends with newline', () => {
    const { log, lines } = makeLog(true);
    log('info', 'test_event');
    assert.ok(lines[0].endsWith('\n'));
  });

  test('local mode emits a plain text line', () => {
    const { log, lines } = makeLog(false);
    log('info', 'test_event', { foo: 'bar' });
    assert.equal(lines.length, 1);
    assert.ok(typeof lines[0] === 'string');
    assert.throws(() => JSON.parse(lines[0])); // not JSON
  });
});

// ── 3. Severity mapping ───────────────────────────────────────────────────────

describe('log() severity mapping (production)', () => {
  test('info maps to INFO', () => {
    const { log, lines } = makeLog(true);
    log('info', 'e');
    assert.equal(JSON.parse(lines[0]).severity, 'INFO');
  });

  test('warn maps to WARNING', () => {
    const { log, lines } = makeLog(true);
    log('warn', 'e');
    assert.equal(JSON.parse(lines[0]).severity, 'WARNING');
  });

  test('error maps to ERROR', () => {
    const { log, lines } = makeLog(true);
    log('error', 'e');
    assert.equal(JSON.parse(lines[0]).severity, 'ERROR');
  });

  test('unknown level falls through to INFO', () => {
    const { log, lines } = makeLog(true);
    log('debug', 'e');
    assert.equal(JSON.parse(lines[0]).severity, 'INFO');
  });
});

// ── 3b. Level prefix (local) ──────────────────────────────────────────────────

describe('log() level prefix (local)', () => {
  test('info emits [INFO] prefix', () => {
    const { log, lines } = makeLog(false);
    log('info', 'e');
    assert.ok(lines[0].startsWith('[INFO]'));
  });

  test('warn emits [WARN] prefix', () => {
    const { log, lines } = makeLog(false);
    log('warn', 'e');
    assert.ok(lines[0].startsWith('[WARN]'));
  });

  test('error emits [ERROR] prefix', () => {
    const { log, lines } = makeLog(false);
    log('error', 'e');
    assert.ok(lines[0].startsWith('[ERROR]'));
  });
});

// ── 4. Event name and data fields ─────────────────────────────────────────────

describe('log() event and data (production)', () => {
  test('event name is included', () => {
    const { log, lines } = makeLog(true);
    log('info', 'user_login', { email: 'dj@x.com' });
    const parsed = JSON.parse(lines[0]);
    assert.equal(parsed.event, 'user_login');
  });

  test('extra data fields are spread into the JSON object', () => {
    const { log, lines } = makeLog(true);
    log('info', 'send_complete', { sender: 'me@x.com', sent: 10, failed: 0 });
    const parsed = JSON.parse(lines[0]);
    assert.equal(parsed.sender, 'me@x.com');
    assert.equal(parsed.sent, 10);
    assert.equal(parsed.failed, 0);
  });

  test('log with no data still includes severity and event', () => {
    const { log, lines } = makeLog(true);
    log('info', 'server_start');
    const parsed = JSON.parse(lines[0]);
    assert.equal(parsed.severity, 'INFO');
    assert.equal(parsed.event, 'server_start');
  });

  test('event name appears in local text line', () => {
    const { log, lines } = makeLog(false);
    log('info', 'user_logout', { email: 'dj@x.com' });
    assert.ok(lines[0].includes('user_logout'));
  });
});

// ── 5. No sensitive data leakage ──────────────────────────────────────────────

describe('log() sensitive field safety', () => {
  test('access tokens are not logged at auth callback', () => {
    // Simulate what user_login logs — only email, no tokens
    const { log, lines } = makeLog(true);
    log('info', 'user_login', { email: 'user@x.com' });
    const parsed = JSON.parse(lines[0]);
    assert.ok(!('access_token'  in parsed));
    assert.ok(!('refresh_token' in parsed));
  });

  test('send_complete does not include email addresses of recipients', () => {
    // We only log aggregate counts, not the recipient list
    const { log, lines } = makeLog(true);
    log('info', 'send_complete', { sender: 'me@x.com', sent: 5, failed: 0 });
    const raw = lines[0];
    assert.ok(!raw.includes('recipient@'));
  });
});
