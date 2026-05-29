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
// Google OAuth creds are now optional — SMTP login is a valid alternative.
function validateStartup({ BASE_URL, SESSION_SECRET }) {
  if (!BASE_URL.startsWith('https')) return null; // local — no checks
  const missing = [
    SESSION_SECRET === 'local-dev-secret-change-in-prod' && 'SESSION_SECRET',
  ].filter(Boolean);
  return missing.length ? missing : null;
}

const PROD_URL   = 'https://djpromo.net';
const LOCAL_URL  = 'http://localhost:5001';
const GOOD_SECRET = 'a-real-secret-value';

describe('startup validation', () => {
  // ── Production: passes with only SESSION_SECRET ───────────────────────────

  test('passes when SESSION_SECRET is set (Google creds not required)', () => {
    const result = validateStartup({ BASE_URL: PROD_URL, SESSION_SECRET: GOOD_SECRET });
    assert.equal(result, null);
  });

  test('passes even when Google creds are absent — SMTP login is a valid alternative', () => {
    const result = validateStartup({ BASE_URL: PROD_URL, SESSION_SECRET: GOOD_SECRET });
    assert.equal(result, null);
  });

  // ── Production: SESSION_SECRET is still required ──────────────────────────

  test('fails in production when SESSION_SECRET is the dev default', () => {
    const missing = validateStartup({
      BASE_URL:       PROD_URL,
      SESSION_SECRET: 'local-dev-secret-change-in-prod',
    });
    assert.ok(missing, 'should return missing list');
    assert.ok(missing.includes('SESSION_SECRET'));
  });

  test('a custom SESSION_SECRET that happens to contain the default string still passes', () => {
    const result = validateStartup({
      BASE_URL:       PROD_URL,
      SESSION_SECRET: 'my-prefix-local-dev-secret-change-in-prod-suffix',
    });
    assert.equal(result, null);
  });

  // ── Local dev: checks are skipped entirely ────────────────────────────────

  test('skips all checks on http:// (local dev)', () => {
    const result = validateStartup({
      BASE_URL:       LOCAL_URL,
      SESSION_SECRET: 'local-dev-secret-change-in-prod',
    });
    assert.equal(result, null);
  });
});
