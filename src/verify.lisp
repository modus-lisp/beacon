;;;; src/verify.lisp — BIP340 signature verification, with a decoded-pubkey cache.
;;;;
;;;; secp256k1-fast's SCHNORR-VERIFY spends more than half its time (and ~175 KB
;;;; of garbage, measured) in LIFT-X: recovering the curve point from the x-only
;;;; pubkey with a 256-bit bignum MOD-EXPT.  A relay sees the same authors over
;;;; and over, so we lift each pubkey once and keep the point.  What is left per
;;;; event is the double-scalar multiply SECP-MUL-2 (~80 us, ~11 KB) and one
;;;; SHA-256 whose first block is a precomputed midstate.
;;;;
;;;; Allocation matters as much as time here: SBCL's collector stops every
;;;; thread, so garbage made by the verify pool is latency paid by everyone.

(in-package #:beacon)

(defvar *challenge-midstate*
  (let* ((tag-hash (sha256 (ascii-octets "BIP0340/challenge")))
         (ctx (make-sha256-ctx)))
    (sha256-update ctx tag-hash)
    (sha256-update ctx tag-hash)
    ctx)
  "SHA-256 state after absorbing SHA256(tag) || SHA256(tag) for BIP0340/challenge.")

(defun bytes->int (octets &optional (start 0) (end (length octets)))
  (let ((n 0))
    (loop for i from start below end do (setf n (logior (ash n 8) (aref octets i))))
    n))

;;; ---- the pubkey -> point cache ------------------------------------------------

(defconstant +point-shards+ 64)
(defvar *point-shard-cap* 8192)

(defstruct (point-shard (:constructor make-point-shard ()))
  (table (make-hash-table :test 'eql) :type hash-table)
  (lock (sb-thread:make-mutex :name "point-cache")))

(defvar *point-cache*
  (let ((v (make-array +point-shards+)))
    (dotimes (i +point-shards+ v) (setf (svref v i) (make-point-shard)))))

(defvar *point-cache-hits* 0)
(defvar *point-cache-misses* 0)

(defun pubkey-point (pubkey)
  "The even-Y curve point for x-only PUBKEY (32 octets), or NIL if none exists."
  (let* ((h (keyed-hash pubkey))
         (shard (svref *point-cache* (logand h (1- +point-shards+))))
         (key (ldb (byte 62 0) h)))
    (let ((hit (sb-thread:with-mutex ((point-shard-lock shard))
                 (gethash key (point-shard-table shard)))))
      ;; The hash is keyed, but compare the pubkey anyway: a cache must never
      ;; hand one author's point to another.
      (when (and hit (octets-string= (car hit) pubkey))
        (incf *point-cache-hits*)
        (return-from pubkey-point (cdr hit))))
    (incf *point-cache-misses*)
    (let ((pt (schnorr:lift-x (bytes->int pubkey))))
      (when pt
        (sb-thread:with-mutex ((point-shard-lock shard))
          (let ((tab (point-shard-table shard)))
            (when (>= (hash-table-count tab) *point-shard-cap*) (clrhash tab))
            (setf (gethash key tab) (cons (copy-seq pubkey) pt)))))
      pt)))

;;; ---- BIP340 verify -------------------------------------------------------------

(defun verify-signature (pubkey msg32 sig64)
  "T iff SIG64 is a valid BIP340 signature of MSG32 under x-only PUBKEY.  Safe
to call from many threads at once."
  (declare (type octets pubkey msg32 sig64))
  (secp:secp-init)
  (let ((p secp:*secp256k1-p*) (n secp:*secp256k1-n*))
    (let ((r (bytes->int sig64 0 32))
          (s (bytes->int sig64 32 64)))
      (unless (and (< r p) (< s n)) (return-from verify-signature nil))
      (let ((pt (pubkey-point pubkey)))
        (unless pt (return-from verify-signature nil))
        (let* ((ctx (sha256-copy-state *challenge-midstate* (make-sha256-ctx)))
               (e (progn (sha256-update ctx sig64 0 32)
                         (sha256-update ctx pubkey)
                         (sha256-update ctx msg32)
                         (mod (bytes->int (sha256-final ctx)) n)))
               ;; R = s*G - e*P = s*G + (n-e)*P
               (rr (secp:secp-mul-2 s (secp:secp-generator) (mod (- n e) n) pt)))
          (and (not (secp:secp-inf-p rr))
               (evenp (secp:secp-y rr))
               (= (secp:secp-x rr) r)))))))

(defun verify-event-signature (e)
  (handler-case (verify-signature (event-pubkey e) (event-id e) (event-sig e))
    (error () nil)))
