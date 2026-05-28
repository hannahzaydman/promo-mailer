/**
 * Minimal express-session store backed by Firestore.
 * Uses @google-cloud/firestore (pure-JS gRPC, no native compilation).
 *
 * Documents live at sessions/{sessionId} with fields:
 *   data    — JSON-serialised session object
 *   expires — Firestore Timestamp (used for TTL)
 */
'use strict';

const { Firestore } = require('@google-cloud/firestore');

module.exports = function (session) {
  const Store = session.Store;

  class FirestoreStore extends Store {
    /**
     * @param {object} [options]
     * @param {string} [options.collection='sessions']  Firestore collection name
     * @param {Firestore} [options.firestore]            Existing Firestore client
     */
    constructor(options = {}) {
      super();
      this.db  = options.firestore || new Firestore();
      this.col = this.db.collection(options.collection || 'sessions');
    }

    get(sid, cb) {
      this.col.doc(sid).get()
        .then(doc => {
          if (!doc.exists) return cb(null, null);
          const { data, expires } = doc.data();
          if (expires && expires.toMillis() < Date.now()) {
            // Expired — lazy-delete and return nothing
            this.col.doc(sid).delete().catch(() => {});
            return cb(null, null);
          }
          cb(null, JSON.parse(data));
        })
        .catch(cb);
    }

    set(sid, sess, cb) {
      const maxAge  = sess.cookie?.maxAge ?? 8 * 60 * 60 * 1000;
      const expires = Firestore.Timestamp.fromMillis(Date.now() + maxAge);
      this.col.doc(sid).set({ data: JSON.stringify(sess), expires })
        .then(() => cb(null))
        .catch(cb);
    }

    destroy(sid, cb) {
      this.col.doc(sid).delete()
        .then(() => cb(null))
        .catch(cb);
    }

    touch(sid, sess, cb) {
      // Refresh the expiry without touching session data
      this.set(sid, sess, cb);
    }
  }

  return FirestoreStore;
};
