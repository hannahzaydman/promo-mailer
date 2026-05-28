'use strict';

const { describe, test, beforeEach } = require('node:test');
const assert  = require('node:assert/strict');
const session = require('express-session');
const FirestoreStore = require('../firestoreSessionStore')(session);

// ── In-memory Firestore stub ──────────────────────────────────────────────────

/**
 * Minimal stub for a Firestore DocumentReference / CollectionReference.
 * Stores documents in a plain object so tests run without a real GCP project.
 */
function makeFirestoreStub() {
  const docs = {};

  function makeDoc(id) {
    return {
      get() {
        const data = docs[id];
        return Promise.resolve({
          exists: data !== undefined,
          data: () => data,
        });
      },
      set(val) {
        docs[id] = val;
        return Promise.resolve();
      },
      delete() {
        delete docs[id];
        return Promise.resolve();
      },
    };
  }

  return {
    _docs: docs,
    collection() {
      return {
        doc: (id) => makeDoc(id),
      };
    },
  };
}

/**
 * Returns a Firestore stub where every operation rejects with the given error.
 */
function makeFailingFirestoreStub(err) {
  const failingDoc = {
    get:    () => Promise.reject(err),
    set:    () => Promise.reject(err),
    delete: () => Promise.reject(err),
  };
  return {
    collection() {
      return { doc: () => failingDoc };
    },
  };
}

function makeExpiry(msFromNow) {
  const ms = Date.now() + msFromNow;
  return { toMillis: () => ms };
}

// ── Helpers ───────────────────────────────────────────────────────────────────

function promisify(fn) {
  return (...args) =>
    new Promise((resolve, reject) =>
      fn(...args, (err, result) => (err ? reject(err) : resolve(result)))
    );
}

// ── Tests ─────────────────────────────────────────────────────────────────────

describe('FirestoreStore', () => {
  let store;
  let firestore;

  beforeEach(() => {
    firestore = makeFirestoreStub();
    store = new FirestoreStore({ firestore });
  });

  // ── set / get ───────────────────────────────────────────────────────────────

  describe('set + get round-trip', () => {
    test('stores a session and retrieves it', async () => {
      const sess = { cookie: { maxAge: 3600000 }, user: { email: 'dj@test.com' } };
      await promisify(store.set.bind(store))('sid1', sess);
      const retrieved = await promisify(store.get.bind(store))('sid1');
      assert.deepEqual(retrieved, sess);
    });

    test('returns null for an unknown session id', async () => {
      const result = await promisify(store.get.bind(store))('nonexistent');
      assert.equal(result, null);
    });

    test('overwrites an existing session on a second set', async () => {
      const sess1 = { cookie: { maxAge: 3600000 }, user: { email: 'a@test.com' } };
      const sess2 = { cookie: { maxAge: 3600000 }, user: { email: 'b@test.com' } };
      await promisify(store.set.bind(store))('sid2', sess1);
      await promisify(store.set.bind(store))('sid2', sess2);
      const result = await promisify(store.get.bind(store))('sid2');
      assert.deepEqual(result, sess2);
    });

    test('persists the correct expiry timestamp', async () => {
      const maxAge = 8 * 60 * 60 * 1000; // 8 hours
      const before = Date.now();
      await promisify(store.set.bind(store))('sid3', { cookie: { maxAge } });
      const after = Date.now();
      const stored = firestore._docs['sid3'];
      assert.ok(stored.expires.toMillis() >= before + maxAge);
      assert.ok(stored.expires.toMillis() <= after  + maxAge);
    });

    test('falls back to 8-hour maxAge when cookie.maxAge is absent', async () => {
      const before = Date.now();
      await promisify(store.set.bind(store))('sid4', { cookie: {} });
      const stored = firestore._docs['sid4'];
      const eightHours = 8 * 60 * 60 * 1000;
      assert.ok(stored.expires.toMillis() >= before + eightHours);
    });
  });

  // ── destroy ─────────────────────────────────────────────────────────────────

  describe('destroy', () => {
    test('removes an existing session', async () => {
      await promisify(store.set.bind(store))('sid5', { cookie: { maxAge: 3600000 }, user: {} });
      await promisify(store.destroy.bind(store))('sid5');
      const result = await promisify(store.get.bind(store))('sid5');
      assert.equal(result, null);
    });

    test('does not throw when destroying a non-existent session', async () => {
      await assert.doesNotReject(() =>
        promisify(store.destroy.bind(store))('ghost-session')
      );
    });
  });

  // ── expiry / lazy-delete ─────────────────────────────────────────────────────

  describe('expired sessions', () => {
    test('returns null for an expired session', async () => {
      // Write directly to the stub with a past expiry
      firestore._docs['expired-sid'] = {
        data:    JSON.stringify({ user: 'old' }),
        expires: makeExpiry(-1000), // 1 second in the past
      };
      const result = await promisify(store.get.bind(store))('expired-sid');
      assert.equal(result, null);
    });

    test('lazy-deletes the expired document from Firestore', async () => {
      firestore._docs['expired-sid2'] = {
        data:    JSON.stringify({ user: 'old' }),
        expires: makeExpiry(-1000),
      };
      await promisify(store.get.bind(store))('expired-sid2');
      // Give the fire-and-forget delete a tick to run
      await new Promise(r => setImmediate(r));
      assert.equal(firestore._docs['expired-sid2'], undefined);
    });

    test('returns a valid session that has not yet expired', async () => {
      firestore._docs['live-sid'] = {
        data:    JSON.stringify({ user: 'active' }),
        expires: makeExpiry(60000), // 60 seconds from now
      };
      const result = await promisify(store.get.bind(store))('live-sid');
      assert.deepEqual(result, { user: 'active' });
    });
  });

  // ── touch ────────────────────────────────────────────────────────────────────

  describe('touch', () => {
    test('refreshes the expiry of an existing session', async () => {
      const sess = { cookie: { maxAge: 3600000 }, user: {} };
      await promisify(store.set.bind(store))('sid6', sess);
      const expiryBefore = firestore._docs['sid6'].expires.toMillis();

      // Small delay so the refreshed timestamp is strictly later
      await new Promise(r => setTimeout(r, 5));

      await promisify(store.touch.bind(store))('sid6', sess);
      const expiryAfter = firestore._docs['sid6'].expires.toMillis();
      assert.ok(expiryAfter >= expiryBefore);
    });

    test('touch on an unknown sid creates the document', async () => {
      const sess = { cookie: { maxAge: 3600000 }, user: { email: 'x@test.com' } };
      await promisify(store.touch.bind(store))('new-sid', sess);
      assert.ok(firestore._docs['new-sid'] !== undefined);
    });
  });

  // ── Firestore error propagation ───────────────────────────────────────────────

  describe('Firestore errors propagate to callback', () => {
    const dbError = new Error('Firestore unavailable');

    test('get forwards a Firestore read error', async () => {
      const failStore = new FirestoreStore({ firestore: makeFailingFirestoreStub(dbError) });
      await assert.rejects(
        promisify(failStore.get.bind(failStore))('sid'),
        dbError
      );
    });

    test('set forwards a Firestore write error', async () => {
      const failStore = new FirestoreStore({ firestore: makeFailingFirestoreStub(dbError) });
      await assert.rejects(
        promisify(failStore.set.bind(failStore))('sid', { cookie: { maxAge: 3600000 } }),
        dbError
      );
    });

    test('destroy forwards a Firestore delete error', async () => {
      const failStore = new FirestoreStore({ firestore: makeFailingFirestoreStub(dbError) });
      await assert.rejects(
        promisify(failStore.destroy.bind(failStore))('sid'),
        dbError
      );
    });
  });

  // ── Corrupted stored data ─────────────────────────────────────────────────────

  describe('corrupted data field', () => {
    test('get forwards a JSON parse error via callback', async () => {
      firestore._docs['bad-sid'] = {
        data:    'not valid json {{{{',
        expires: makeExpiry(60000),
      };
      await assert.rejects(
        promisify(store.get.bind(store))('bad-sid'),
        SyntaxError
      );
    });
  });

  // ── Missing expires field ─────────────────────────────────────────────────────

  describe('document with no expires field', () => {
    test('get returns the session when expires is undefined (treated as non-expiring)', async () => {
      firestore._docs['no-expiry-sid'] = {
        data:    JSON.stringify({ user: 'forever' }),
        expires: undefined,
      };
      const result = await promisify(store.get.bind(store))('no-expiry-sid');
      assert.deepEqual(result, { user: 'forever' });
    });
  });

  // ── Missing cookie on session ─────────────────────────────────────────────────

  describe('session without cookie property', () => {
    test('set falls back to 8-hour expiry when sess.cookie is absent', async () => {
      const before = Date.now();
      await promisify(store.set.bind(store))('no-cookie-sid', { user: 'x' });
      const stored = firestore._docs['no-cookie-sid'];
      const eightHours = 8 * 60 * 60 * 1000;
      assert.ok(stored.expires.toMillis() >= before + eightHours);
    });

    test('stored session can be retrieved after set with no cookie', async () => {
      const sess = { user: { email: 'dj@test.com' } };
      await promisify(store.set.bind(store))('no-cookie-sid2', sess);
      const result = await promisify(store.get.bind(store))('no-cookie-sid2');
      assert.deepEqual(result, sess);
    });
  });
});
