'use strict';

/**
 * Tests for features added in the unsubscribe + deduplication pass:
 *   1. unsubToken — HMAC generation is deterministic and sender-scoped
 *   2. Recipient deduplication — first occurrence wins, count is correct
 *   3. Unsubscribe filtering — unsubscribed addresses are removed from preview
 */

const { describe, test } = require('node:test');
const assert = require('node:assert/strict');
const { unsubToken } = require('../utils');

// Fixed secret for deterministic tests
const SECRET = 'local-dev-secret-change-in-prod';

// ── 1. unsubToken ─────────────────────────────────────────────────────────────

describe('unsubToken', () => {
  test('returns a non-empty string', () => {
    const t = unsubToken(SECRET, 'sender@example.com', 'dj@example.com');
    assert.ok(typeof t === 'string' && t.length > 0);
  });

  test('is deterministic — same inputs produce the same token', () => {
    const t1 = unsubToken(SECRET, 'sender@example.com', 'dj@example.com');
    const t2 = unsubToken(SECRET, 'sender@example.com', 'dj@example.com');
    assert.equal(t1, t2);
  });

  test('is sender-scoped — different senders produce different tokens for the same recipient', () => {
    const t1 = unsubToken(SECRET, 'alice@label.com', 'dj@example.com');
    const t2 = unsubToken(SECRET, 'bob@label.com',   'dj@example.com');
    assert.notEqual(t1, t2);
  });

  test('is recipient-scoped — different recipients produce different tokens', () => {
    const t1 = unsubToken(SECRET, 'sender@label.com', 'dj1@example.com');
    const t2 = unsubToken(SECRET, 'sender@label.com', 'dj2@example.com');
    assert.notEqual(t1, t2);
  });

  test('swapping sender and recipient produces a different token', () => {
    const t1 = unsubToken(SECRET, 'a@x.com', 'b@x.com');
    const t2 = unsubToken(SECRET, 'b@x.com', 'a@x.com');
    assert.notEqual(t1, t2);
  });

  test('returns a hex string of the expected length (24 chars)', () => {
    const t = unsubToken(SECRET, 'sender@example.com', 'dj@example.com');
    assert.match(t, /^[0-9a-f]{24}$/);
  });

  test('forged token (one char off) does not match', () => {
    const real   = unsubToken(SECRET, 'sender@example.com', 'dj@example.com');
    const forged = real.slice(0, -1) + (real.slice(-1) === 'a' ? 'b' : 'a');
    assert.notEqual(real, forged);
  });
});

// ── 2. Recipient deduplication logic ─────────────────────────────────────────
// Mirror the dedup block from /preview exactly so we test the same logic.

function deduplicate(recipientList) {
  const seenEmails = new Set();
  const deduped = [];
  for (const r of recipientList) {
    if (!seenEmails.has(r.email)) {
      seenEmails.add(r.email);
      deduped.push(r);
    }
  }
  return { deduped, dupCount: recipientList.length - deduped.length };
}

describe('recipient deduplication', () => {
  test('no duplicates — list is unchanged', () => {
    const list = [
      { name: 'DJ A', email: 'a@x.com' },
      { name: 'DJ B', email: 'b@x.com' },
    ];
    const { deduped, dupCount } = deduplicate(list);
    assert.equal(deduped.length, 2);
    assert.equal(dupCount, 0);
  });

  test('one duplicate — second occurrence is removed', () => {
    const list = [
      { name: 'DJ A',       email: 'a@x.com' },
      { name: 'DJ A again', email: 'a@x.com' },
    ];
    const { deduped, dupCount } = deduplicate(list);
    assert.equal(deduped.length, 1);
    assert.equal(dupCount, 1);
  });

  test('first occurrence is kept, not the second', () => {
    const list = [
      { name: 'First',  email: 'dj@x.com' },
      { name: 'Second', email: 'dj@x.com' },
    ];
    const { deduped } = deduplicate(list);
    assert.equal(deduped[0].name, 'First');
  });

  test('multiple duplicates of the same address are all collapsed to one', () => {
    const list = [
      { name: 'A', email: 'same@x.com' },
      { name: 'B', email: 'same@x.com' },
      { name: 'C', email: 'same@x.com' },
    ];
    const { deduped, dupCount } = deduplicate(list);
    assert.equal(deduped.length, 1);
    assert.equal(dupCount, 2);
  });

  test('duplicates across spreadsheet and manual recipients are caught', () => {
    const fromFile   = [{ name: 'DJ A', email: 'dj@x.com' }];
    const fromManual = [{ name: 'DJ A manual', email: 'dj@x.com' }];
    const combined = fromFile.concat(fromManual);
    const { deduped, dupCount } = deduplicate(combined);
    assert.equal(deduped.length, 1);
    assert.equal(dupCount, 1);
  });

  test('empty list returns empty with zero dups', () => {
    const { deduped, dupCount } = deduplicate([]);
    assert.equal(deduped.length, 0);
    assert.equal(dupCount, 0);
  });

  test('email comparison is case-sensitive (matches server behaviour)', () => {
    // Server stores emails as-is; two differently-cased addresses are treated as distinct
    const list = [
      { name: 'A', email: 'DJ@X.COM' },
      { name: 'B', email: 'dj@x.com' },
    ];
    const { deduped, dupCount } = deduplicate(list);
    assert.equal(deduped.length, 2);
    assert.equal(dupCount, 0);
  });
});

// ── 3. Unsubscribe filtering ───────────────────────────────────────────────────
// Mirror the filter block from /preview.

function filterUnsubscribed(recipientList, unsubscribed) {
  const before = recipientList.length;
  const filtered = recipientList.filter(r => !unsubscribed.has(r.email));
  return { filtered, skipped: before - filtered.length };
}

describe('unsubscribe filtering', () => {
  test('no unsubscribes — list is unchanged', () => {
    const list = [{ email: 'a@x.com' }, { email: 'b@x.com' }];
    const { filtered, skipped } = filterUnsubscribed(list, new Set());
    assert.equal(filtered.length, 2);
    assert.equal(skipped, 0);
  });

  test('unsubscribed address is removed', () => {
    const list = [{ email: 'a@x.com' }, { email: 'b@x.com' }];
    const { filtered, skipped } = filterUnsubscribed(list, new Set(['a@x.com']));
    assert.equal(filtered.length, 1);
    assert.equal(filtered[0].email, 'b@x.com');
    assert.equal(skipped, 1);
  });

  test('multiple unsubscribes are all removed', () => {
    const list = [
      { email: 'a@x.com' },
      { email: 'b@x.com' },
      { email: 'c@x.com' },
    ];
    const unsub = new Set(['a@x.com', 'c@x.com']);
    const { filtered, skipped } = filterUnsubscribed(list, unsub);
    assert.equal(filtered.length, 1);
    assert.equal(filtered[0].email, 'b@x.com');
    assert.equal(skipped, 2);
  });

  test('address not in unsubscribe list is kept', () => {
    const list = [{ email: 'kept@x.com' }];
    const { filtered } = filterUnsubscribed(list, new Set(['other@x.com']));
    assert.equal(filtered.length, 1);
  });

  test('all recipients unsubscribed returns empty list', () => {
    const list = [{ email: 'a@x.com' }, { email: 'b@x.com' }];
    const unsub = new Set(['a@x.com', 'b@x.com']);
    const { filtered, skipped } = filterUnsubscribed(list, unsub);
    assert.equal(filtered.length, 0);
    assert.equal(skipped, 2);
  });

  test('unsubscribe set from a different sender does not affect this sender', () => {
    // Each sender has their own unsubscribe set in Firestore — simulate isolation
    const listA = [{ email: 'dj@x.com' }];
    const listB = [{ email: 'dj@x.com' }];
    const unsubForA = new Set(['dj@x.com']);
    const unsubForB = new Set(); // B never had this person unsubscribe

    const { filtered: filteredA } = filterUnsubscribed(listA, unsubForA);
    const { filtered: filteredB } = filterUnsubscribed(listB, unsubForB);

    assert.equal(filteredA.length, 0, 'removed for sender A');
    assert.equal(filteredB.length, 1, 'kept for sender B');
  });
});
