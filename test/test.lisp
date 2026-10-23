;;;; test/test.lisp — beacon's test suite.
;;;;
;;;; Three layers:
;;;;   1. primitives against published vectors (SHA-256, SHA-1, SipHash, CRC32,
;;;;      BIP340), and the JSON reader on hostile input;
;;;;   2. the store against a brute-force REFERENCE MODEL: random events and
;;;;      random filters, where the expected answer is computed by filtering a
;;;;      plain list — the index must agree exactly, before and after a restart;
;;;;   3. the relay over real sockets, driven by cl-nostr — an independent client
;;;;      implementation — when it is loadable (see RUN-NETWORK-TESTS).

(defpackage #:beacon.test
  (:use #:cl #:beacon)
  (:import-from #:beacon
                #:make-octets #:ascii-octets #:octets-string= #:hex-encode #:hex-decode
                #:make-obuf #:obuf-data #:obuf-fill #:obuf-reset
                #:json-parse #:json-parse-string #:json-get #:json-error
                #:compute-event-id #:parse-event #:parse-event-json #:invalid-event
                #:event-id #:event-pubkey #:event-kind #:event-created-at #:event-json #:event-tags
                #:event-content #:verify-event-signature #:verify-signature
                #:parse-filter #:filter-matches-event-p
                #:store-index #:index-count #:store-insert-batch #:store-delete-ids
                #:read-event-json #:unix-now #:sha256 #:siphash64 #:crc32 #:sha1 #:base64-encode)
  (:export #:run #:make-test-key #:sign-event-json))

(in-package #:beacon.test)

(defvar *pass* 0)
(defvar *fail* 0)

(defmacro check (name form)
  `(handler-case
       (if ,form
           (incf *pass*)
           (progn (incf *fail*) (format t "~&FAIL: ~a~%" ,name)))
     (error (c) (incf *fail*) (format t "~&FAIL: ~a (signalled ~a)~%" ,name c))))

;;; ---- signing test events -------------------------------------------------------

(defun make-test-key (&optional (seed (random (ash 1 250))))
  "(secret . pubkey-octets): the secret a fixed 32-byte buffer, as the signer takes it.
Test keys come from CL:RANDOM and are not secret."
  (let ((d (gossamer:pooled-copy
            (secp256k1-fast:int-to-bytes32 (1+ (mod seed (1- secp256k1-fast:*secp256k1-n*)))))))
    (cons d (secp256k1-fast.schnorr:pubkey-xonly d))))

(defun json-escape (s)
  (let ((b (make-obuf 64)))
    (beacon::obuf-json-string b s)
    (sb-ext:octets-to-string (subseq (obuf-data b) 0 (obuf-fill b)) :external-format :utf-8)))

(defun sign-event-json (key kind content &key (tags '()) (created-at (unix-now)) (fake-sig nil))
  "A signed event as a JSON string.  TAGS is a list of lists of strings.
FAKE-SIG skips signing (for store tests, which do not verify)."
  (let* ((tv (coerce (mapcar (lambda (tg) (coerce tg 'simple-vector)) tags) 'simple-vector))
         (id (compute-event-id (cdr key) created-at kind tv content))
         (sig (if fake-sig (make-octets 64) (secp256k1-fast.schnorr:schnorr-sign (car key) id))))
    (format nil "{\"id\":\"~a\",\"pubkey\":\"~a\",\"created_at\":~d,\"kind\":~d,\"tags\":[~{~a~^,~}],\"content\":~a,\"sig\":\"~a\"}"
            (hex-encode id) (hex-encode (cdr key)) created-at kind
            (mapcar (lambda (tg) (format nil "[~{~a~^,~}]" (mapcar #'json-escape tg))) tags)
            (json-escape content) (hex-encode (coerce sig '(simple-array (unsigned-byte 8) (*)))))))

;;; ---- 1. primitives ---------------------------------------------------------------

(defun test-primitives ()
  (check "sha256 abc" (string= (hex-encode (sha256 (ascii-octets "abc")))
                               "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"))
  (check "sha256 two-block" (string= (hex-encode (sha256 (ascii-octets "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq")))
                                     "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"))
  (check "sha256 1M a"
         (let ((o (make-octets 1000000))) (fill o 97)
           (string= (hex-encode (sha256 o)) "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0")))
  (check "sha1 abc" (string= (hex-encode (sha1 (ascii-octets "abc"))) "a9993e364706816aba3e25717850c26c9cd0d89d"))
  (check "ws accept key" (string= (base64-encode (sha1 (ascii-octets "dGhlIHNhbXBsZSBub25jZQ==258EAFA5-E914-47DA-95CA-C5AB0DC85B11")))
                                  "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="))
  (check "siphash reference"
         (let ((m (make-octets 15))) (dotimes (i 15) (setf (aref m i) i))
           (= (siphash64 m 0 15 nil #x0706050403020100 #x0f0e0d0c0b0a0908) #xa129ca6149be45e5)))
  (check "crc32" (= (crc32 (ascii-octets "123456789")) #xCBF43926))
  ;; BIP340 vectors 0 and 1, and a corrupted copy
  (let ((pk (hex-decode "f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9"))
        (msg (make-octets 32))
        (sig (hex-decode "e907831f80848d1069a5371b402410364bdf1c5f8307b0084c55f1ce2dca821525f66a4a85ea8b71e482a74f382d2ce5ebeee8fdb2172f477df4900d310536c0")))
    (check "bip340 vector 0" (verify-signature pk msg sig))
    (let ((bad (copy-seq sig))) (setf (aref bad 63) (logxor (aref bad 63) 1))
      (check "bip340 vector 0 corrupted" (not (verify-signature pk msg bad)))))
  (let ((pk (hex-decode "dff1d77f2a671c5f36183726db2341be58feae1da2deced843240f7b502ba659"))
        (msg (hex-decode "243f6a8885a308d313198a2e03707344a4093822299f31d0082efa98ec4e6c89"))
        (sig (hex-decode "6896bd60eeae296db48a229ff71dfe071bde413e6d43f917dc8dcf8c78de33418906d11ac976abccb20b091292bff4ea897efcb639ea871cfa95f6de339e4b0a")))
    (check "bip340 vector 1" (verify-signature pk msg sig))
    (check "bip340 vector 1 twice (cached point)" (verify-signature pk msg sig)))
  ;; JSON
  (check "json basic" (equalp (json-parse-string "{\"a\":[1,-2,\"x\\u00e9\\ud83d\\ude00\",true,null]}")
                              (list (cons "a" (vector 1 -2 (format nil "x~a~a" (code-char #xe9) (code-char #x1f600)) :true :null)))))
  (dolist (bad '("{" "[1,]" "{\"a\" 1}" "\"\\ud800\"" "\"\\udc00\"" "[1] x" "\"a" "01x" "{\"a\":tru}"))
    (check (format nil "json rejects ~s" bad)
           (handler-case (progn (json-parse-string bad) nil) (json-error () t))))
  (check "json rejects raw control char"
         (handler-case (progn (json-parse (coerce #(34 1 34) '(simple-array (unsigned-byte 8) (*)))) nil)
           (json-error () t)))
  (check "json rejects overlong utf-8"
         (handler-case (progn (json-parse (coerce #(34 #xC0 #x80 34) '(simple-array (unsigned-byte 8) (*)))) nil)
           (json-error () t)))
  (check "json depth limit"
         (handler-case (progn (json-parse-string (make-string 200 :initial-element #\[)) nil)
           (json-error () t))))

;;; ---- index structures across chunk and resize boundaries ---------------------------

(defun test-index-structures ()
  ;; chunked vector: past several 64K chunks, and chunk 0's doubling
  (let ((cv (beacon::make-cvec '(unsigned-byte 32) 4)) (n 300000))
    (dotimes (i n) (beacon::cvec-ensure cv i) (setf (beacon::cvref cv i (unsigned-byte 32)) (* 7 i)))
    (check "cvec holds 300k values across chunks"
           (loop for i below n always (= (beacon::cvref cv i (unsigned-byte 32)) (* 7 i)))))
  ;; incremental-resize table: every key findable at every point, overwrites win
  (let ((tb (beacon::make-table 16)) (n 500000) (bad 0) (checked-mid nil))
    (dotimes (i n)
      (beacon::table-put tb (+ 1000 (* 3 i)) (1+ i))
      ;; while a migration is in progress, look up a spread of earlier keys
      (when (and (beacon::table-old tb) (zerop (mod i 997)))
        (setf checked-mid t)
        (loop for j from 0 to i by (max 1 (floor i 50))
              unless (= (beacon::table-get tb (+ 1000 (* 3 j))) (1+ j)) do (incf bad))))
    (check "table: lookups correct DURING migrations" (and checked-mid (zerop bad)))
    (check "table: all 500k keys after growth"
           (loop for i below n always (= (beacon::table-get tb (+ 1000 (* 3 i))) (1+ i))))
    (check "table: absent keys absent" (loop for i below 1000 always (zerop (beacon::table-get tb (+ 1001 (* 3 i))))))
    ;; overwrite keys that may still sit only in the OLD table
    (let ((tb (beacon::make-table 16)) (ok t))
      (dotimes (i 70000)
        (beacon::table-put tb i 5)
        (when (beacon::table-old tb) (beacon::table-put tb (floor i 2) 9)))
      (dotimes (i 70000)
        (let ((v (beacon::table-get tb i)))
          (unless (member v '(5 9)) (setf ok nil))))
      (check "table: overwrite during migration never resurrects nothing" ok)
      (let ((tb (beacon::make-table 16)))
        (dotimes (i 40000) (beacon::table-put tb i 1))
        (dotimes (i 40000) (beacon::table-put tb i 2))   ; overwrite everything, migrations included
        (dotimes (i 1000) (beacon::table-put tb (+ 100000 i) 3))
        (check "table: overwrite always wins" (loop for i below 40000 always (= 2 (beacon::table-get tb i))))))))

;;; ---- event parsing ------------------------------------------------------------------

(defun test-events ()
  (let* ((k (make-test-key 12345))
         (json (sign-event-json k 1 (format nil "hello ~a \"q\" \\ ~a tab	nl
" (code-char #x2603) (code-char 1))
                                :tags '(("e" "aa") ("p" "bb" "wss://x") ("t" "nostr")))))
    (let ((e (parse-event-json json)))
      (check "parse signed event" (eql 1 (event-kind e)))
      (check "signature verifies" (verify-event-signature e))
      (check "stored JSON re-parses to the same event"
             (let ((e2 (parse-event-json (event-json e))))
               (and (octets-string= (event-id e) (event-id e2))
                    (string= (event-content e) (event-content e2))))))
    ;; tampering
    (let ((tampered (cl-ppcre-free-replace json "hello" "jello")))
      (check "tampered content fails the id check"
             (handler-case (progn (parse-event-json tampered) nil) (invalid-event () t))))
    (check "uppercase hex id rejected"
           (handler-case (progn (parse-event-json (string-upcase-id json)) nil) (invalid-event () t)))
    (check "missing field rejected"
           (handler-case (progn (parse-event-json "{\"id\":\"00\"}") nil) (invalid-event () t)))))

(defun cl-ppcre-free-replace (s old new)
  (let ((p (search old s))) (concatenate 'string (subseq s 0 p) new (subseq s (+ p (length old))))))

(defun string-upcase-id (json)
  (let* ((p (+ (search "\"id\":\"" json) 6)))
    (concatenate 'string (subseq json 0 p) (string-upcase (subseq json p (+ p 64))) (subseq json (+ p 64)))))

;;; ---- 2. the store against a reference model --------------------------------------------

(defvar *scratch-dir* #p"/tmp/beacon-test/")

(defun fresh-dir (name)
  (let ((d (merge-pathnames (format nil "~a/" name) *scratch-dir*)))
    (uiop:delete-directory-tree d :validate t :if-does-not-exist :ignore)
    (ensure-directories-exist d)
    d))

(defun insert-json (store jsons &optional (now (unix-now)))
  (store-insert-batch store (mapcar #'parse-event-json jsons) :now now))

(defun result-ids (store serials)
  (mapcar (lambda (s) (multiple-value-bind (buf start end) (read-event-json store s)
                        (json-get (json-parse buf start end) "id")))
          serials))

(defun q (store filter-json)
  (result-ids store (store-query store (list (parse-filter (json-parse-string filter-json))))))

(defun model-query (events filter-json)
  "Brute force: EVENTS is the list of live parsed events."
  (let* ((f (parse-filter (json-parse-string filter-json)))
         (limit (min beacon::*max-limit* (or (beacon::filter-limit f) beacon::*default-limit*)))
         (hits (remove-if-not (lambda (e) (filter-matches-event-p f e)) events)))
    (setf hits (stable-sort (copy-list hits) #'> :key #'event-created-at))
    (mapcar (lambda (e) (hex-encode (event-id e))) (subseq hits 0 (min limit (length hits))))))

(defun test-store-semantics ()
  (let* ((dir (fresh-dir "semantics"))
         (store (open-store dir :sync nil))
         (a (make-test-key 1)) (b (make-test-key 2))
         (now (unix-now)))
    (unwind-protect
         (progn
           (let ((r (insert-json store (list (sign-event-json a 1 "first" :created-at (- now 100) :fake-sig t)))))
             (check "insert stores" (eq :stored (car (first r)))))
           (let* ((j (sign-event-json a 1 "dup" :created-at (- now 99) :fake-sig t))
                  (r (insert-json store (list j j))))
             (check "in-batch duplicate" (equal (mapcar #'car r) '(:stored :duplicate)))
             (check "later duplicate" (eq :duplicate (car (first (insert-json store (list j)))))))
           ;; replaceable: kind 0, newer wins, older is rejected afterwards
           (insert-json store (list (sign-event-json a 0 "profile v1" :created-at (- now 50) :fake-sig t)))
           (insert-json store (list (sign-event-json a 0 "profile v2" :created-at (- now 40) :fake-sig t)))
           (check "replaceable: one survives" (= 1 (length (q store (format nil "{\"kinds\":[0],\"authors\":[\"~a\"]}" (hex-encode (cdr a)))))))
           (check "replaceable: older version rejected"
                  (eq :rejected (car (first (insert-json store (list (sign-event-json a 0 "profile v0" :created-at (- now 60) :fake-sig t)))))))
           (check "replaceable: newest content"
                  (let ((ids (q store (format nil "{\"kinds\":[0],\"authors\":[\"~a\"]}" (hex-encode (cdr a))))))
                    (search "profile v2" (multiple-value-bind (buf s e)
                                             (read-event-json store (first (store-query store (list (parse-filter (json-parse-string (format nil "{\"ids\":[\"~a\"]}" (first ids))))))))
                                           (sb-ext:octets-to-string buf :start s :end e :external-format :utf-8)))))
           ;; addressable: keyed by d
           (insert-json store (list (sign-event-json a 30023 "post x1" :tags '(("d" "x")) :created-at (- now 30) :fake-sig t)
                                    (sign-event-json a 30023 "post y1" :tags '(("d" "y")) :created-at (- now 30) :fake-sig t)
                                    (sign-event-json a 30023 "post x2" :tags '(("d" "x")) :created-at (- now 20) :fake-sig t)))
           (check "addressable: two slots" (= 2 (length (q store (format nil "{\"kinds\":[30023],\"authors\":[\"~a\"]}" (hex-encode (cdr a)))))))
           (check "addressable: #d lookup" (= 1 (length (q store (format nil "{\"kinds\":[30023],\"authors\":[\"~a\"],\"#d\":[\"x\"]}" (hex-encode (cdr a)))))))
           ;; deletion
           (let* ((victim (sign-event-json b 1 "delete me" :created-at (- now 10) :fake-sig t))
                  (vid (json-get (json-parse-string victim) "id")))
             (insert-json store (list victim))
             (check "victim present" (equal (q store (format nil "{\"ids\":[\"~a\"]}" vid)) (list vid)))
             ;; someone else cannot delete it
             (insert-json store (list (sign-event-json a 5 "" :tags `(("e" ,vid)) :created-at (- now 5) :fake-sig t)))
             (check "foreign deletion ignored" (equal (q store (format nil "{\"ids\":[\"~a\"]}" vid)) (list vid)))
             (insert-json store (list (sign-event-json b 5 "" :tags `(("e" ,vid)) :created-at (- now 4) :fake-sig t)))
             (check "author deletion hides the event" (null (q store (format nil "{\"ids\":[\"~a\"]}" vid))))
             (check "deleted event cannot be re-published"
                    (eq :rejected (car (first (insert-json store (list victim)))))))
           ;; expiration
           (let ((exp (sign-event-json a 1 "short-lived" :tags `(("expiration" ,(princ-to-string (+ now 2)))) :created-at (- now 3) :fake-sig t)))
             (insert-json store (list exp))
             (check "not yet expired"
                    (= 1 (length (q store (format nil "{\"ids\":[\"~a\"]}" (json-get (json-parse-string exp) "id"))))))
             (check "search filter matches nothing" (null (q store "{\"search\":\"x\"}")))
             (check "expired event hidden later"
                    (null (result-ids store (store-query store (list (parse-filter (json-parse-string
                                                                                   (format nil "{\"ids\":[\"~a\"]}" (json-get (json-parse-string exp) "id")))))
                                                         :now (+ now 10)))))))
      (close-store store))
    ;; restart: replay must reproduce the same answers
    (let ((store (open-store dir :sync nil)))
      (unwind-protect
           (progn
             (check "replay: replaceable" (= 1 (length (q store (format nil "{\"kinds\":[0],\"authors\":[\"~a\"]}" (hex-encode (cdr a)))))))
             (check "replay: addressable" (= 2 (length (q store (format nil "{\"kinds\":[30023],\"authors\":[\"~a\"]}" (hex-encode (cdr a)))))))
             (check "replay: deletion" (zerop (length (q store (format nil "{\"kinds\":[1],\"authors\":[\"~a\"]}" (hex-encode (cdr b))))))))
        (close-store store)))))

(defun random-event-json (keys now)
  (let* ((key (elt keys (random (length keys))))
         (kind (elt '(1 1 1 7 6 1111 30023 0 3 10002) (random 10)))
         (tags (loop repeat (random 4)
                     collect (list (elt '("e" "p" "t" "a" "x" "expiration2") (random 6))
                                   (format nil "v~d" (random 12))))))
    (when (and (= kind 30023) (zerop (random 2))) (push (list "d" (format nil "d~d" (random 3))) tags))
    (sign-event-json key kind (format nil "c~d" (random 1000000)) :tags tags
                     :created-at (- now (random 5000)) :fake-sig t)))

(defun random-filter-json (keys)
  (let ((parts '()))
    (when (< (random 10) 4)
      (push (format nil "\"authors\":[~{\"~a\"~^,~}]"
                    (loop repeat (1+ (random 3)) collect (hex-encode (cdr (elt keys (random (length keys)))))))
            parts))
    (when (< (random 10) 5)
      (push (format nil "\"kinds\":[~{~d~^,~}]" (loop repeat (1+ (random 2)) collect (elt '(1 7 6 0 3 30023 10002 4) (random 8))))
            parts))
    (when (< (random 10) 4)
      (push (format nil "\"#~a\":[~{\"v~d\"~^,~}]" (elt '("e" "p" "t") (random 3))
                    (loop repeat (1+ (random 3)) collect (random 12)))
            parts))
    (when (< (random 10) 2)
      (push (format nil "\"#~a\":[\"v~d\"]" (elt '("e" "p" "t") (random 3)) (random 12)) parts))
    (when (< (random 10) 3) (push (format nil "\"since\":~d" (- (unix-now) (random 5000))) parts))
    (when (< (random 10) 3) (push (format nil "\"until\":~d" (- (unix-now) (random 5000))) parts))
    (when (< (random 10) 5) (push (format nil "\"limit\":~d" (random 40)) parts))
    (format nil "{~{~a~^,~}}" parts)))

(defun live-events (store)
  "Every live event, parsed from what the store would send."
  (let ((idx (store-index store)) (out '()))
    (dotimes (s (index-count idx) out)
      (unless (beacon::serial-deleted-p (beacon::index-columns idx) s)
        (multiple-value-bind (buf start end) (read-event-json store s)
          (push (parse-event (json-parse buf start end)) out))))))

(defun test-store-model (&key (n 3000) (queries 400))
  (let* ((dir (fresh-dir "model"))
         (store (open-store dir :sync nil))
         (keys (loop for i below 12 collect (make-test-key (+ 100 i))))
         (now (unix-now))
         (mismatches 0))
    (unwind-protect
         (loop repeat (ceiling n 50)
               do (insert-json store (loop repeat 50 collect (random-event-json keys now))))
      nil)
    (flet ((compare (label)
             (let ((events (live-events store)))
               (dotimes (i queries)
                 (let* ((fj (random-filter-json keys))
                        (got (q store fj)) (want (model-query events fj)))
                   ;; Same created_at sequence, and the same ids strictly above the
                   ;; LIMIT boundary — which of several events TIED at the boundary
                   ;; gets in is not specified, so it is not compared.
                   (unless (let* ((ct (let ((h (make-hash-table :test 'equal)))
                                        (dolist (e events h) (setf (gethash (hex-encode (event-id e)) h) (event-created-at e)))))
                                  (cg (mapcar (lambda (i) (gethash i ct)) got))
                                  (cw (mapcar (lambda (i) (gethash i ct)) want))
                                  (edge (car (last cw))))
                             (and (equal cg cw)
                                  (null (set-exclusive-or (remove-if (lambda (i) (eql (gethash i ct) edge)) got)
                                                          (remove-if (lambda (i) (eql (gethash i ct) edge)) want)
                                                          :test #'string=))))
                     (when (< mismatches 5)
                       (format t "~&~a mismatch for ~a~%  got ~d want ~d~%" label fj (length got) (length want)))
                     (incf mismatches)))))))
      (compare "live")
      (close-store store)
      (setf store (open-store dir :sync nil))
      (compare "replayed")
      (close-store store))
    (check (format nil "store agrees with the model (~d mismatches)" mismatches) (zerop mismatches))))

(defun test-big-replay ()
  "Replay with a 4 KB read chunk: hundreds of refills, records straddling every
boundary, and records (10 KB, 200 KB) larger than a chunk."
  (let* ((dir (fresh-dir "big-replay"))
         (store (open-store dir :sync nil))
         (k (make-test-key 77)) (now (unix-now)) (n 0))
    (loop for batch below 12
          do (incf n (count :stored (insert-json store (loop for i below 100
                                                             collect (sign-event-json k 1 (make-string (+ 9000 (random 3000)) :initial-element #\x)
                                                                                      :created-at (- now (random 100000)) :fake-sig t)))
                            :key #'car)))
    (insert-json store (list (sign-event-json k 1 (make-string 200000 :initial-element #\y) :created-at now :fake-sig t)))
    (incf n)
    (close-store store)
    (let ((store (let ((beacon::*replay-chunk* 4096)) (open-store dir :sync nil))))
      (check (format nil "big replay: ~d events back" n) (= n (store-event-count store)))
      (check "big replay: the huge record reads back"
             (= 1 (length (q store "{\"kinds\":[1],\"limit\":1}"))))
      (close-store store))))

(defun run-store-tests ()
  (test-big-replay)
  (test-store-semantics)
  (test-store-model))

;;; ---- NIP-44 v2 decryption ---------------------------------------------------------------
;;; The official vectors (test/nip44.vectors.json, from paulmillr/nip44) for the decryption
;;; side, and the RFC primitives beneath it against values computed with Python's
;;; cryptography library -- not with this code, and not from memory.

(defun base64-decode-octets (string)
  "RFC 4648 base64 to octets.  Test-side only: the relay itself never sees base64."
  (let ((alphabet "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/")
        (bits 0) (nbits 0)
        (out (make-array 0 :element-type '(unsigned-byte 8) :adjustable t :fill-pointer 0)))
    (loop for ch across string
          for v = (position ch alphabet)
          when v do (setf bits (logior (ash bits 6) v)) (incf nbits 6)
          when (>= nbits 8)
            do (decf nbits 8)
               (vector-push-extend (ldb (byte 8 nbits) bits) out)
               (setf bits (ldb (byte nbits 0) bits)))
    (coerce out '(simple-array (unsigned-byte 8) (*)))))

(defun nip44-vectors-section (name &optional (kind "valid"))
  "The NAME section of the KIND (\"valid\" or \"invalid\") v2 official vectors."
  (json-get (json-get (json-get (json-parse-string
                                 (uiop:read-file-string (asdf:system-relative-pathname "beacon" "test/nip44.vectors.json")))
                                "v2")
                      kind)
            name))

(defun run-nip44-tests ()
  (progn
    ;; RFC 8439 2.4.2: ChaCha20 with block counter 1
    (let ((key (coerce (loop for i below 32 collect i) '(simple-array (unsigned-byte 8) (*))))
          (nonce (hex-decode "000000000000004a00000000"))
          (pt (ascii-octets "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.")))
      (check "chacha20 RFC 8439 2.4.2 keystream"
             (equalp (beacon::chacha20-xor key nonce pt :counter 1)
                     (hex-decode "6e2e359a2568f98041ba0728dd0d6981e97e7aec1d4360c20a27afccfd9fae0bf91b65c5524733ab8f593dabcd62b3571639d624e65152ab8f530c359f0861d807ca0dbf500d6a6156a38e088a22b65e52bc514d16ccf806818ce91ab77937365af90bbf74a35be6b40b8eedf2785e42874d"))))
    ;; RFC 4231 test case 1, RFC 5869 test case 1
    (check "hmac-sha256 RFC 4231 test 1"
           (equalp (beacon::hmac-sha256 (make-array 20 :element-type '(unsigned-byte 8) :initial-element #x0b)
                                (ascii-octets "Hi There"))
                   (hex-decode "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7")))
    (let* ((ikm (make-array 22 :element-type '(unsigned-byte 8) :initial-element #x0b))
           (salt (coerce (loop for i below 13 collect i) '(simple-array (unsigned-byte 8) (*))))
           (info (coerce (loop for i from #xf0 below #xfa collect i) '(simple-array (unsigned-byte 8) (*))))
           (prk (beacon::hkdf-extract salt ikm)))
      (check "hkdf-extract RFC 5869 test 1"
             (equalp prk (hex-decode "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5")))
      (check "hkdf-expand RFC 5869 test 1"
             (equalp (beacon::hkdf-expand prk info 42)
                     (hex-decode "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"))))
    ;; the official vectors
    (let ((bad 0))
      (loop for pair across (nip44-vectors-section "calc_padded_len")
            unless (= (aref pair 1) (beacon::nip44-calc-padded-len (aref pair 0)))
              do (incf bad))
      (check "calc_padded_len matches the official vectors" (zerop bad)))
    (let ((bad 0) (n 0))
      (loop for e across (nip44-vectors-section "get_conversation_key")
            do (incf n)
               (unless (equalp (beacon::nip44-conversation-key (gossamer:pooled-copy (hex-decode (json-get e "sec1")))
                                                       (hex-decode (json-get e "pub2")))
                               (hex-decode (json-get e "conversation_key")))
                 (incf bad)))
      (check (format nil "conversation keys match the official vectors (~d)" n) (and (plusp n) (zerop bad))))
    (let ((bad 0) (n 0))
      (let* ((section (nip44-vectors-section "get_message_keys"))
             (ck (hex-decode (json-get section "conversation_key"))))
            (progn
                 (loop for k across (json-get section "keys")
                       do (incf n)
                          (let* ((okm (beacon::hkdf-expand ck (hex-decode (json-get k "nonce")) 76)))
                            (unless (and (equalp (subseq okm 0 32) (hex-decode (json-get k "chacha_key")))
                                         (equalp (subseq okm 32 44) (hex-decode (json-get k "chacha_nonce")))
                                         (equalp (subseq okm 44 76) (hex-decode (json-get k "hmac_key"))))
                              (incf bad))))))
      (check (format nil "message keys match the official vectors (~d)" n) (and (plusp n) (zerop bad))))
    (let ((bad 0) (n 0))
      (loop for e across (nip44-vectors-section "encrypt_decrypt")
            do (incf n)
               (let* ((ck (hex-decode (json-get e "conversation_key")))
                      (plain (sb-ext:string-to-octets (json-get e "plaintext") :external-format :utf-8))
                      (payload (base64-decode-octets (json-get e "payload"))))
                 (unless (equalp (beacon::nip44-decrypt ck payload) plain) (incf bad))))
      (check (format nil "decrypt the official encrypt/decrypt vectors (~d)" n) (and (plusp n) (zerop bad))))
    ;; the key that opens them is derived from the two private keys, too
    (let ((bad 0))
      (loop for e across (nip44-vectors-section "encrypt_decrypt")
            unless (equalp (beacon::nip44-conversation-key (gossamer:pooled-copy (hex-decode (json-get e "sec1")))
                                                   (secp256k1-fast.schnorr:pubkey-xonly
                                                    (gossamer:pooled-copy (hex-decode (json-get e "sec2")))))
                           (hex-decode (json-get e "conversation_key")))
              do (incf bad))
      (check "conversation keys from the two private keys (encrypt_decrypt)" (zerop bad)))
    ;; every invalid payload must be refused
    (let ((refused 0) (n 0))
      (loop for e across (nip44-vectors-section "decrypt" "invalid")
            do (incf n)
               (when (handler-case (progn (beacon::nip44-decrypt (hex-decode (json-get e "conversation_key"))
                                                         (base64-decode-octets (json-get e "payload")))
                                          nil)
                       (error () t))
                 (incf refused)))
      (check (format nil "all ~d invalid payloads refused" n) (and (plusp n) (= refused n))))))

;;; ---- entry ------------------------------------------------------------------------------

(defun run-section (name fn)
  "A section that dies is a failure, not the end of the run."
  (handler-case (funcall fn)
    (error (c) (incf *fail*) (format t "~&FAIL: section ~a died: ~a~%" name c))))

(defun test-huge-limit ()
  "A LIMIT far above the result size costs the result, not the limit (the top-k grows)."
  (let* ((dir (fresh-dir "huge-limit")) (store (open-store dir :sync nil)) (a (make-test-key 7)) (now (unix-now))
         (jsons (loop for i below 5000 collect (sign-event-json a 1 (format nil "e~d" i) :created-at (- now i) :fake-sig t))))
    (unwind-protect
         (let ((beacon::*max-limit* 100000000) (beacon::*default-limit* 100000000))
           (insert-json store jsons)
           (let ((events (mapcar #'parse-event-json jsons))
                 (bytes-before (sb-ext:get-bytes-consed)))
             (let ((got (q store "{\"kinds\":[1]}")))
               (check "huge limit: every event, newest first" (equal got (model-query events "{\"kinds\":[1]}")))
               (check "huge limit: allocation is not the limit's size"
                      (< (- (sb-ext:get-bytes-consed) bytes-before) (* 50 1024 1024))))))
      (close-store store))))

(defun run (&key (network t))
  (setf *pass* 0 *fail* 0)
  (run-section "primitives" #'test-primitives)
  (run-section "events" #'test-events)
  (run-section "big replay" #'test-big-replay)
  (run-section "store semantics" #'test-store-semantics)
  (run-section "index structures" #'test-index-structures)
  (run-section "store model" #'test-store-model)
  (run-section "huge limit" #'test-huge-limit)
  (run-section "nip44 v2" #'run-nip44-tests)
  (run-section "store model, 100k events (crosses chunk + resize boundaries)"
               (lambda () (test-store-model :n 100000 :queries 120)))
  (when (and network (fboundp 'run-network-tests)) (run-section "network" 'run-network-tests))
  (when (and network (fboundp 'run-policy-tests)) (run-section "policy" 'run-policy-tests))
  (when (and network (fboundp 'run-udp-tests)) (run-section "udp" 'run-udp-tests))
  (format t "~&~d passed, ~d failed~%" *pass* *fail*)
  (zerop *fail*))
