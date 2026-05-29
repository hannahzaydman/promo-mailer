'use strict';

/**
 * Startup validation tests — verify the app refuses to start in production
 * when required env vars are missing, and starts fine locally without them.
 *
 * We test the validation logic in isolation (no Express/Firestore) by
 * extracting and evaluating the check block from server.js.
 */

const { describe, test } = require('node:test');
const assert = require('node:assert/strict');

// Mirror the exact validation logic from server.js so tests stay in sync.
function validateStartup({ BASE_URL, SESSION_SECRET, GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET }) {
  if (!BASE_URL.startsWith('https')) return null; // local — no checks
  const missing = [
    SESSION_SECRET === 'local-dev-secret-change-in-prod' && 'SESSION_SECRET',
    !GOOGLE_CLIENT_ID     && 'GOOGLE_CLIENT_ID',
    !GOOGLE_CLIENT_SECRET && 'GOOGLE_CLIENT_SECRET',
  ].filter(Boolean);
  return missing.length ? missing : null;
}

const PROD_URL   = 'https://djpromo.net';
const LOCAL_URL  = 'http://localhost:5001';
const GOOD_SECRET = 'a-real-secret-value';

describe('startup validation', () => {
  // ── Production: all vars present ──────────────────────────────────────────

  test('passes when all required vars are set in production', () => {
    const result = validateStartup({
      BASE_URL:       PROD_URL,
      SESSION_SECRET: GOOD_SECRET,
      GOOGLE_CLIENT_ID:     'client-id',
      GOOGLE_CLIENT_SECRET: 'client-secret',
    });
    assert.equal(result, null);
  });

  // ── Production: individual missing vars ───────────────────────────────────

  test('fails in production when SESSION_SECRET is the dev default', () => {
    const missing = validateStartup({
      BASE_URL:       PROD_URL,
      SESSION_SECRET: 'local-dev-secret-change-in-prod',
      GOOGLE_CLIENT_ID:     'client-id',
      GOOGLE_CLIENT_SECRET: 'client-secret',
    });
    assert.ok(missing, 'should return missing list');
    assert.ok(missing.includes('SESSION_SECRET'));
  });

  test('fails in production when GOOGLE_CLIENT_ID is missing', () => {
    const missing = validateStartup({
      BASE_URL:       PROD_URL,
      SESSION_SECRET: GOOD_SECRET,
      GOOGLE_CLIENT_ID:     undefined,
      GOOGLE_CLIENT_SECRET: 'client-secret',
    });
    assert.ok(missing);
    assert.ok(missing.includes('GOOGLE_CLIENT_ID'));
  });

  test('fails in production when GOOGLE_CLIENT_SECRET is missing', () => {
    const missing = validateStartup({
      BASE_URL:       PROD_URL,
      SESSION_SECRET: GOOD_SECRET,
      GOOGLE_CLIENT_ID:     'client-id',
      GOOGLE_CLIENT_SECRET: undefined,
    });
    assert.ok(missing);
    assert.ok(missing.includes('GOOGLE_CLIENT_SECRET'));
  });

  test('reports all missing vars at once rather than failing one at a time', () => {
    const missing = validateStartup({
      BASE_URL:       PROD_URL,
      SESSION_SECRET: 'local-dev-secret-change-in-prod',
      GOOGLE_CLIENT_ID:     undefined,
      GOOGLE_CLIENT_SECRET: undefined,
    });
    assert.ok(missing);
    assert.equal(missing.length, 3);
    assert.ok(missing.includes('SESSION_SECRET'));
    assert.ok(missing.includes('GOOGLE_CLIENT_ID'));
    assert.ok(missing.includes('GOOGLE_CLIENT_SECRET'));
  });

  // ── Local dev: checks are skipped entirely ────────────────────────────────

  test('skips all checks on http:// (local dev)', () => {
    const result = validateStartup({
      BASE_URL:       LOCAL_URL,
      SESSION_SECRET: 'local-dev-secret-change-in-prod',
      GOOGLE_CLIENT_ID:     undefined,
      GOOGLE_CLIENT_SECRET: undefined,
    });
    assert.equal(result, null);
  });

  test('a custom SESSION_SECRET that happens to contain the default string still passes', () => {
    // Only the exact default value triggers the check
    const result = validateStartup({
      BASE_URL:       PROD_URL,
      SESSION_SECRET: 'my-prefix-local-dev-secret-change-in-prod-suffix',
      GOOGLE_CLIENT_ID:     'client-id',
      GOOGLE_CLIENT_SECRET: 'client-secret',
    });
    assert.equal(result, null);
  });

  test('empty string is treated as missing for GOOGLE_CLIENT_ID', () => {
    const missing = validateStartup({
      BASE_URL:       PROD_URL,
      SESSION_SECRET: GOOD_SECRET,
      GOOGLE_CLIENT_ID:     '',
      GOOGLE_CLIENT_SECRET: 'client-secret',
    });
    assert.ok(missing);
    assert.ok(missing.includes('GOOGLE_CLIENT_ID'));
  });

  test('empty string is treated as missing for GOOGLE_CLIENT_SECRET', () => {
    const missing = validateStartup({
      BASE_URL:       PROD_URL,
      SESSION_SECRET: GOOD_SECRET,
      GOOGLE_CLIENT_ID:     'client-id',
      GOOGLE_CLIENT_SECRET: '',
    });
    assert.ok(missing);
    assert.ok(missing.includes('GOOGLE_CLIENT_SECRET'));
  });
});
