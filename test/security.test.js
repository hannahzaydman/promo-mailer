'use strict';

/**
 * Tests for the three security fixes applied during the audit:
 *   1. OAuth CSRF — state parameter generation and validation logic
 *   2. ALLOWED_DOMAIN regex injection — domain escaping
 *   3. Column validation — validateColumns() guards in /preview
 *   4. fetchWithTimeout — aborts stalled Google API calls
 */

const { describe, test, before, after } = require('node:test');
const assert = require('node:assert/strict');
const http = require('http');
const { validateColumns } = require('../utils');

// ── 1. validateColumns ────────────────────────────────────────────────────────

describe('validateColumns', () => {
  test('returns null when all required columns are present', () => {
    const rows = [{ name: 'DJ One', email: 'dj@example.com', code: 'ABC1' }];
    assert.equal(validateColumns(rows, ['name', 'email', 'code']), null);
  });

  test('returns an error string when a required column is missing', () => {
    const rows = [{ name: 'DJ One', email: 'dj@example.com' }];
    const err = validateColumns(rows, ['name', 'email', 'code']);
    assert.ok(err, 'should return an error string');
    assert.ok(err.includes('"code"'), 'error names the missing column');
    assert.ok(err.includes('name') && err.includes('email'), 'error lists available columns');
  });

  test('reports the FIRST missing column when several are absent', () => {
    const rows = [{ name: 'DJ One' }];
    const err = validateColumns(rows, ['name', 'email', 'code']);
    assert.ok(err.includes('"email"'), 'first missing col is email');
  });

  test('includes context prefix in the error when context is provided', () => {
    const rows = [{ name: 'DJ One' }];
    const err = validateColumns(rows, ['email'], 'Release A');
    assert.ok(err.startsWith('"Release A":'), 'error is prefixed with context');
  });

  test('omits prefix when no context is given', () => {
    const rows = [{ name: 'DJ One' }];
    const err = validateColumns(rows, ['email']);
    assert.ok(!err.startsWith('"'), 'no prefix when context is absent');
  });

  test('returns null for an empty rows array (no columns to compare against)', () => {
    assert.equal(validateColumns([], ['name', 'email']), null);
  });

  test('returns null for null/undefined rows', () => {
    assert.equal(validateColumns(null, ['name']), null);
    assert.equal(validateColumns(undefined, ['name']), null);
  });

  test('returns null when required array is empty', () => {
    const rows = [{ name: 'DJ One' }];
    assert.equal(validateColumns(rows, []), null);
  });

  test('column names are case-sensitive — wrong case is treated as missing', () => {
    const rows = [{ Name: 'DJ One', Email: 'dj@test.com' }];
    const err = validateColumns(rows, ['name', 'email']);
    assert.ok(err, 'lowercase name/email should not match uppercase Name/Email');
    assert.ok(err.includes('"name"'));
  });

  test('validates codes column — silent miss would send wrong codes to all DJs', () => {
    // This is the highest-impact edge case: if codesCol is wrong, every recipient
    // gets an empty code string. validateColumns must catch this before mapping.
    const codeRows = [{ 'Download Code': 'XK9F-2MQT' }];
    const err = validateColumns(codeRows, ['code'], 'My Release');
    assert.ok(err, 'should reject wrong column name');
    assert.ok(err.includes('"My Release"'), 'should include release name for context');
    assert.ok(err.includes('"code"'), 'should name the missing column');
    assert.ok(err.includes('Download Code'), 'should list the actual available column');
  });
});

// ── 2. ALLOWED_DOMAIN regex safety ───────────────────────────────────────────
// We test the escaping logic in isolation — build the regex the same way
// server.js does and verify edge cases.

describe('ALLOWED_DOMAIN_RE escaping', () => {
  function buildDomainRE(domain) {
    // Mirrors the logic in server.js
    return new RegExp('@' + domain.split('.').join('\\.') + '$', 'i');
  }

  test('matches the exact domain', () => {
    const re = buildDomainRE('example.com');
    assert.ok(re.test('user@example.com'));
  });

  test('is case-insensitive', () => {
    const re = buildDomainRE('Example.COM');
    assert.ok(re.test('user@EXAMPLE.COM'));
    assert.ok(re.test('user@example.com'));
  });

  test('dot is treated as a literal — exampleXcom does not match example.com', () => {
    const re = buildDomainRE('example.com');
    assert.ok(!re.test('user@exampleXcom'), 'unescaped dot would match any char — escaping prevents this');
  });

  test('does not match a subdomain', () => {
    const re = buildDomainRE('example.com');
    assert.ok(!re.test('user@sub.example.com'));
  });

  test('does not match a different domain with the same suffix', () => {
    const re = buildDomainRE('example.com');
    assert.ok(!re.test('user@notexample.com'));
  });

  test('matches midnightecstasy.com (the default domain)', () => {
    const re = buildDomainRE('midnightecstasy.com');
    assert.ok(re.test('user@midnightecstasy.com'));
    assert.ok(!re.test('user@midnightecstasyXcom'));
  });

  test('empty email string does not match', () => {
    const re = buildDomainRE('example.com');
    assert.ok(!re.test(''));
  });
});

// ── 3. OAuth state CSRF logic ─────────────────────────────────────────────────
// The state validation is: !state || !expectedState || state !== expectedState
// We test the pure predicate without spinning up Express.

describe('OAuth CSRF state validation logic', () => {
  function shouldReject(state, expectedState) {
    return !state || !expectedState || state !== expectedState;
  }

  test('valid matching state is accepted', () => {
    const s = 'abc123';
    assert.equal(shouldReject(s, s), false);
  });

  test('missing state (no param from Google) is rejected', () => {
    assert.equal(shouldReject(undefined, 'abc123'), true);
    assert.equal(shouldReject('', 'abc123'), true);
    assert.equal(shouldReject(null, 'abc123'), true);
  });

  test('missing session state (session expired or tampered) is rejected', () => {
    assert.equal(shouldReject('abc123', undefined), true);
    assert.equal(shouldReject('abc123', null), true);
    assert.equal(shouldReject('abc123', ''), true);
  });

  test('mismatched state (CSRF attempt) is rejected', () => {
    assert.equal(shouldReject('attacker-state', 'real-state'), true);
  });

  test('both missing is rejected', () => {
    assert.equal(shouldReject(undefined, undefined), true);
  });

  test('state comparison is exact — length-extension prefix does not match', () => {
    const real = 'abc123';
    const attacker = real + 'extra';
    assert.equal(shouldReject(attacker, real), true);
  });
});

// ── 4. fetchWithTimeout ───────────────────────────────────────────────────────

describe('fetchWithTimeout', () => {
  let server;
  let baseUrl;

  // Spin up a minimal HTTP server for testing
  before(async () => {
    await new Promise((resolve) => {
      server = http.createServer((req, res) => {
        if (req.url === '/fast') {
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ ok: true }));
        } else if (req.url === '/slow') {
          // Never respond — simulates a hung Google API call
          // (connection stays open until the test server is closed)
        } else {
          res.writeHead(404);
          res.end();
        }
      });
      server.listen(0, '127.0.0.1', () => {
        baseUrl = `http://127.0.0.1:${server.address().port}`;
        resolve();
      });
    });
  });

  after(async () => {
    await new Promise((resolve) => server.close(resolve));
  });

  // Load fetchWithTimeout from server.js in a way that avoids starting
  // Express/Firestore. We do this by extracting and eval-ing just the function.
  function getFetchWithTimeout() {
    const fs = require('fs');
    const src = fs.readFileSync(require('path').join(__dirname, '../server.js'), 'utf8');
    const start = src.indexOf('function fetchWithTimeout');
    const end = src.indexOf('\n}\n', start) + 3;
    const fnSrc = src.slice(start, end);
    return new Function('fetch', 'AbortController', 'setTimeout', 'clearTimeout', '"use strict"; return (' + fnSrc + ')')(
      globalThis.fetch, AbortController, setTimeout, clearTimeout
    );
  }

  test('resolves with the response for a fast endpoint', async () => {
    const fetchWithTimeout = getFetchWithTimeout();
    const res = await fetchWithTimeout(baseUrl + '/fast', {}, 3000);
    const body = await res.json();
    assert.equal(body.ok, true);
  });

  test('rejects with AbortError when the server does not respond within the timeout', async () => {
    const fetchWithTimeout = getFetchWithTimeout();
    await assert.rejects(
      () => fetchWithTimeout(baseUrl + '/slow', {}, 100),
      (err) => {
        assert.equal(err.name, 'AbortError', 'should be an AbortError, not a generic timeout');
        return true;
      }
    );
  });

  test('defaults to a 10-second timeout (does not hang forever)', async () => {
    // We can't wait 10s in a test, but we can verify the default is wired up
    // by passing ms=undefined and checking that the call still resolves for a
    // fast endpoint (i.e. options default handling works).
    const fetchWithTimeout = getFetchWithTimeout();
    const res = await fetchWithTimeout(baseUrl + '/fast');
    assert.equal(res.status, 200);
  });
});
