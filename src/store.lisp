;;;; src/store.lisp — the store: replay at startup, batched inserts, deletion.
;;;;
;;;; STORE-INSERT-BATCH is the group commit.  It decides every event in the batch
;;;; (duplicate? replaced? deleted? expired?), encodes the accepted ones into one
;;;; buffer, writes it with ONE fsync, and only then makes them visible in the
;;;; index.  So an event is never visible before it is durable, and under load
;;;; the fsync cost is shared by everything that arrived while the last one ran.
;;;;
;;;; Replaceable / addressable events (NIP-01) and deletions (NIP-09) are not
;;;; persisted as separate state: the log holds the events, and replay re-derives
;;;; who replaced whom and what was deleted.  Only operator deletions write a
;;;; tombstone record, because nothing else would remember them.

(in-package #:beacon)

(defstruct (store (:constructor %make-store))
  (dir nil)
  (log nil)
  (index (make-index) :type index)
  (write-lock (sb-thread:make-mutex :name "store-writer"))
  (readers (make-hash-table :test 'eq :weakness :key :synchronized t))
  (sync t)                        ; fsync each batch
  (wbuf (make-obuf 65536))        ; the writer's encode buffer, reused across batches
  (key nil))                      ; the 16-byte SipHash secret

(defun store-log-path (dir) (merge-pathnames "events.log" dir))
(defun store-key-path (dir) (merge-pathnames "hash.key" dir))

(defun store-event-count (store) (index-live (store-index store)))

(defun store-reader (store)
  "This thread's private reader on the store's log."
  (let ((tab (store-readers store)) (th sb-thread:*current-thread*))
    (or (gethash th tab)
        (setf (gethash th tab) (open-log-reader (store-log-path (store-dir store)))))))

(defun read-event-json (store serial &optional (reader (store-reader store)))
  "Returns (values octets start end) — the stored JSON of SERIAL, in a buffer
that the next read on READER will overwrite."
  (let* ((cols (index-columns (store-index store)))
         (buf (read-record reader (col-off cols serial) (col-len cols serial)))
         (start (rec-json-start buf 0)))
    (values buf start (+ start (rec-json-length buf 0)))))

;;; ---- the hash key ---------------------------------------------------------------

(defun random-octets (n)
  (with-open-file (in "/dev/urandom" :element-type '(unsigned-byte 8))
    (let ((o (make-octets n))) (read-sequence o in) o)))

(defun load-or-create-key (dir)
  (let ((path (store-key-path dir)))
    (if (probe-file path)
        (with-open-file (in path :element-type '(unsigned-byte 8))
          (let ((k (make-octets 16)))
            (unless (= 16 (read-sequence k in)) (error "~a is not a 16-byte key" path))
            k))
        (let ((k (random-octets 16)))
          (with-open-file (out path :element-type '(unsigned-byte 8) :direction :output)
            (write-sequence k out))
          k))))

;;; ---- deletion (NIP-09) -------------------------------------------------------------

(defun parse-address (string)
  "\"<kind>:<pubkey-hex>:<d-tag>\" -> (values kind pubkey-octets d-tag), or NIL."
  (let* ((c1 (position #\: string))
         (c2 (and c1 (position #\: string :start (1+ c1)))))
    (when c2
      (let ((kind (ignore-errors (parse-integer string :end c1)))
            (pk (hex-decode (subseq string (1+ c1) c2) 32)))
        (when (and kind pk (<= 0 kind 65535))
          (values kind pk (subseq string (1+ c2))))))))

(defun deletion-targets (pubkey tags)
  "What a kind-5 event by PUBKEY asks to delete: (values id-octets-list
address-list) where each address is (kind . rkey-without-author)."
  (let ((ids '()) (addrs '()))
    (loop for tag across tags
          when (>= (length tag) 2) do
            (let ((name (svref tag 0)) (v (svref tag 1)))
              (cond ((string= name "e")
                     (let ((id (hex-decode v 32))) (when id (push id ids))))
                    ((string= name "a")
                     (multiple-value-bind (kind pk d) (parse-address v)
                       ;; only the author may delete their own addressable events
                       (when (and kind (octets-string= pk pubkey)
                                  (or (replaceable-kind-p kind) (addressable-kind-p kind)))
                         (push (cons kind (if (addressable-kind-p kind) (d-string-hash d) 0)) addrs)))))))
    (values ids addrs)))

;;; DELETED-IDS values: who may no longer publish this id.  An author's deletion
;;; blocks only that author's event; an operator tombstone blocks everyone.
(defconstant +deleted-by-operator+ (1- (ash 1 61)))
(defun deleter-code (author-hash) (1+ (ldb (byte 60 0) author-hash)))

(defun apply-deletion (store author-hash created ids addrs)
  "Apply a kind-5 event's effects to the index (writer only)."
  (let* ((idx (store-index store)) (cols (index-columns idx)))
    (dolist (id ids)
      (table-put (index-deleted-ids idx) (keyed-hash id) (deleter-code author-hash))
      (let ((s (index-find-id idx id)))
        (when (and s (= (col-author cols s) author-hash)
                   (/= (col-kind cols s) 5))
          (index-delete idx s))))
    (loop for (kind . dhash) in addrs
          for rkey = (replaceable-key author-hash kind dhash)
          do (let ((prior (table-get (index-deleted-addrs idx) rkey)))
               (when (> (1+ created) prior)
                 (table-put (index-deleted-addrs idx) rkey (1+ created))))
             (let ((v (table-get (index-replaceable idx) rkey)))
               (when (and (plusp v) (<= (col-created cols (1- v)) created))
                 (index-delete idx (1- v)))))))

;;; ---- replaceable slots ---------------------------------------------------------------

(defun newer-p (created-a idpre-a created-b idpre-b)
  "Does A supersede B?  Newer created_at wins; on a tie the LOWER id wins (NIP-01)."
  (or (> created-a created-b)
      (and (= created-a created-b) (< idpre-a idpre-b))))

(defun settle-replaceable (store serial rkey)
  "SERIAL (just added) occupies replaceable slot RKEY.  Keep whichever of it and
the slot's previous holder is newer; delete the other."
  (let* ((idx (store-index store)) (cols (index-columns idx))
         (v (table-get (index-replaceable idx) rkey)))
    (if (zerop v)
        (table-put (index-replaceable idx) rkey (1+ serial))
        (let ((old (1- v)))
          (if (newer-p (col-created cols serial) (col-idpre cols serial)
                       (col-created cols old) (col-idpre cols old))
              (progn (index-delete idx old)
                     (table-put (index-replaceable idx) rkey (1+ serial)))
              (index-delete idx serial))))))

;;; ---- opening: replay -------------------------------------------------------------------

(defun open-store (dir &key (sync t))
  "Open (creating if needed) the store in directory DIR and rebuild the indexes
from its log."
  (let* ((dir (uiop:ensure-directory-pathname dir))
         (_ (ensure-directories-exist dir))
         (key (load-or-create-key dir))
         (store (%make-store :dir dir :sync sync :key key))
         (path (store-log-path dir))
         (t0 (now-us)))
    (declare (ignore _))
    (set-hash-key key)
    ;; gather headers
    (let ((n 0) (cap 4096)
          (off (u64-vector 4096)) (len (u32-vector 4096)) (created (u32-vector 4096))
          (kind (make-array 4096 :element-type '(unsigned-byte 16)))
          (expire (u32-vector 4096)) (dhash (u64-vector 4096))
          (ids (make-octets (* 32 4096))) (authors (u64-vector 4096))
          (tagstart (u32-vector 4097)) (tags (u64-vector 4096)) (ntags 0)
          (tombstones '()))
      (let ((valid
              (replay-log path
                (lambda (buf o file-off rec-len)
                  (if (= (rec-type buf o) +rec-tombstone+)
                      (push (subseq buf (+ o 24) (+ o 56)) tombstones)
                      (progn
                        (when (>= n cap)
                          (setf cap (* 2 cap)
                                off (grow-vector off cap) len (grow-vector len cap)
                                created (grow-vector created cap) kind (grow-vector kind cap)
                                expire (grow-vector expire cap) dhash (grow-vector dhash cap)
                                ids (grow-vector ids (* 32 cap)) authors (grow-vector authors cap)
                                tagstart (grow-vector tagstart (1+ cap))))
                        (setf (aref off n) file-off (aref len n) rec-len
                              (aref created n) (rec-created-at buf o) (aref kind n) (rec-kind buf o)
                              (aref expire n) (rec-expiration buf o) (aref dhash n) (rec-dhash buf o)
                              (aref authors n) (keyed-hash buf (+ o 56) (+ o 88)))
                        (replace ids buf :start1 (* 32 n) :start2 (+ o 24) :end2 (+ o 56))
                        (let ((k (rec-ntags buf o)))
                          (when (> (+ ntags k) (length tags))
                            (setf tags (grow-vector tags (max (* 2 (length tags)) (+ ntags k)))))
                          (dotimes (i k) (setf (aref tags (+ ntags i)) (rec-tag-hash buf o i)))
                          (setf (aref tagstart n) ntags)
                          (incf ntags k)
                          (setf (aref tagstart (1+ n)) ntags))
                        (incf n)))))))
        (when (and (probe-file path) (< valid (with-open-file (s path :element-type '(unsigned-byte 8)) (file-length s))))
          (log-msg 0 "event log: torn tail, truncating to ~d bytes" valid)
          (truncate-file path valid)))
      ;; assign serials in created_at order (ties: log order)
      (let ((order (make-array n :element-type 'fixnum)))
        (dotimes (i n) (setf (aref order i) i))
        (setf order (sort order (lambda (a b)
                                  (or (< (aref created a) (aref created b))
                                      (and (= (aref created a) (aref created b))
                                           (< (aref off a) (aref off b)))))))
        (let ((idx (store-index store)) (kind5 '()))
          (loop for i across order
                for ts = (subseq tags (aref tagstart i) (aref tagstart (1+ i)))
                for s = (index-add idx :off (aref off i) :len (aref len i) :created (aref created i)
                                       :kind (aref kind i) :author-hash (aref authors i)
                                       :id ids :id-start (* 32 i) :expire (aref expire i)
                                       :tag-hashes ts)
                for k = (aref kind i)
                do (cond ((replaceable-kind-p k)
                          (settle-replaceable store s (replaceable-key (aref authors i) k 0)))
                         ((addressable-kind-p k)
                          (settle-replaceable store s (replaceable-key (aref authors i) k (aref dhash i))))
                         ((= k 5) (push s kind5))))
          (setf (store-log store) (open-event-log path))
          ;; deletions are re-derived from the kind-5 events themselves
          (dolist (s (nreverse kind5))
            (multiple-value-bind (buf start end) (read-event-json store s)
              (let* ((obj (json-parse buf start end))
                     (pk (hex-decode (json-get obj "pubkey") 32)))
                (multiple-value-bind (dids daddrs) (deletion-targets pk (json-get obj "tags"))
                  (apply-deletion store (col-author (index-columns idx) s)
                                  (col-created (index-columns idx) s) dids daddrs)))))
          (dolist (id tombstones)
            (table-put (index-deleted-ids idx) (keyed-hash id) +deleted-by-operator+)
            (let ((s (index-find-id idx id))) (when s (index-delete idx s))))
          (log-msg 1 "store ~a: ~:d events (~:d live) loaded in ~,2f s"
                   (namestring dir) n (index-live idx) (/ (- (now-us) t0) 1e6)))))
    store))

(defun close-store (store)
  (sb-thread:with-mutex ((store-write-lock store))
    (when (store-log store) (close-event-log (store-log store)) (setf (store-log store) nil))
    (loop for r being the hash-values of (store-readers store) do (ignore-errors (close-log-reader r)))
    (clrhash (store-readers store))))

;;; ---- inserting -----------------------------------------------------------------------

(defvar *future-slack* 900
  "Reject events dated more than this many seconds in the future.")

(defun store-insert-batch (store events &key (now (unix-now)))
  "Insert EVENTS (signatures already verified) as one durable group commit.
Returns a list parallel to EVENTS of (STATUS . DETAIL):
  (:stored . serial) (:duplicate . nil) (:ephemeral . nil) (:rejected . reason)."
  (sb-thread:with-mutex ((store-write-lock store))
    (let* ((idx (store-index store))
           (results (make-array (length events) :initial-element nil))
           (accepted '())                          ; (position event author-hash rkey del-ids del-addrs)
           (batch-ids (make-hash-table :test 'eql))
           (batch-deleted (make-hash-table :test 'eql))   ; id hash -> author hash
           (buf (obuf-reset (store-wbuf store))))
      (loop for e in events for pos from 0 do
        (let* ((id-hash (keyed-hash (event-id e)))
               (author (keyed-hash (event-pubkey e)))
               (kind (event-kind e))
               (rkey (cond ((replaceable-kind-p kind) (replaceable-key author kind 0))
                           ((addressable-kind-p kind) (replaceable-key author kind (d-tag-hash e)))))
               (existing (index-find-id idx (event-id e)))
               (deleter (let ((v (table-get (index-deleted-ids idx) id-hash)))
                          (or (gethash id-hash batch-deleted) (and (plusp v) v)))))
          (declare (type (or null fixnum) deleter))
          (setf (svref results pos)
                (cond
                  ((ephemeral-kind-p kind) '(:ephemeral))
                  ((or (gethash id-hash batch-ids)
                       (and existing (not (serial-deleted-p (index-columns idx) existing))))
                   '(:duplicate))
                  ((or existing (and deleter (or (= deleter +deleted-by-operator+)
                                                 (= deleter (deleter-code author)))))
                   '(:rejected . "blocked: this event has been deleted"))
                  ((and (plusp (event-expiration e)) (<= (event-expiration e) now))
                   '(:rejected . "invalid: event has expired"))
                  ((> (event-created-at e) (+ now *future-slack*))
                   '(:rejected . "invalid: created_at is too far in the future"))
                  ((and rkey (> (table-get (index-deleted-addrs idx) rkey) (event-created-at e)))
                   '(:rejected . "blocked: this address has been deleted"))
                  ((and rkey
                        (let ((v (table-get (index-replaceable idx) rkey)) (cols (index-columns idx)))
                          (and (plusp v) (not (serial-deleted-p cols (1- v)))
                               (not (newer-p (event-created-at e) (id-prefix (event-id e))
                                             (col-created cols (1- v))
                                             (col-idpre cols (1- v)))))))
                   '(:rejected . "duplicate: have a newer version of this event"))
                  (t
                   (setf (gethash id-hash batch-ids) t)
                   (multiple-value-bind (dids daddrs)
                       (if (= kind 5) (deletion-targets (event-pubkey e) (event-tags e)) (values nil nil))
                     (dolist (d dids) (setf (gethash (keyed-hash d) batch-deleted) (deleter-code author)))
                     (let ((start (obuf-fill buf)))
                       (encode-event-record buf e)
                       (push (list pos e author rkey dids daddrs start (- (obuf-fill buf) start)) accepted)))
                   :pending)))))
      ;; one write, one fsync
      (setf accepted (nreverse accepted))
      (when accepted
        (let ((base (event-log-size (store-log store))))
          (log-append (store-log store) buf :sync (store-sync store))
          ;; now make them visible, in order
          (loop for (pos e author rkey dids daddrs start len) in accepted do
            (let ((s (index-add idx :off (+ base start) :len len :created (event-created-at e)
                                    :kind (event-kind e) :author-hash author :id (event-id e) :id-start 0
                                    :expire (event-expiration e) :tag-hashes (event-tag-hashes e))))
              (when rkey (settle-replaceable store s rkey))
              (when (= (event-kind e) 5)
                (apply-deletion store author (event-created-at e) dids daddrs))
              (setf (svref results pos) (cons :stored s))))))
      ;; don't keep a huge buffer around after one huge batch
      (when (> (length (obuf-data buf)) (* 64 1024 1024)) (setf (store-wbuf store) (make-obuf 65536)))
      (coerce results 'list))))

(defun store-insert (store event)
  "Insert one verified EVENT.  See STORE-INSERT-BATCH."
  (first (store-insert-batch store (list event))))

(defun store-delete-ids (store ids)
  "Operator deletion: tombstone each id (octets) durably, then hide it."
  (sb-thread:with-mutex ((store-write-lock store))
    (let ((buf (make-obuf 256)) (idx (store-index store)))
      (dolist (id ids) (encode-tombstone-record buf id))
      (log-append (store-log store) buf :sync (store-sync store))
      (dolist (id ids)
        (table-put (index-deleted-ids idx) (keyed-hash id) +deleted-by-operator+)
        (let ((s (index-find-id idx id))) (when s (index-delete idx s)))))))

;;; ---- compaction ---------------------------------------------------------------------------

(defun compact-store (dir)
  "Rewrite DIR's log keeping only live events (offline: the store must not be
open elsewhere).  Replaced, deleted and expired events are dropped; kind-5
deletion events are kept so their effect survives."
  (let* ((store (open-store dir))
         (idx (store-index store))
         (cols (index-columns idx))
         (now (unix-now))
         (tmp (merge-pathnames "events.log.compact" (store-dir store)))
         (kept 0))
    (with-open-file (out tmp :element-type '(unsigned-byte 8) :direction :output :if-exists :supersede)
      ;; operator tombstones must outlive the events they removed: they also
      ;; stop the event being published again
      (replay-log (store-log-path (store-dir store))
                  (lambda (buf o off len)
                    (declare (ignore off))
                    (when (= (rec-type buf o) +rec-tombstone+)
                      (write-sequence buf out :start o :end (+ o len)))))
      (let ((reader (store-reader store)))
        (dotimes (s (index-count idx))
          (unless (or (serial-deleted-p cols s)
                      (let ((x (col-expire cols s))) (and (plusp x) (<= x now))))
            (let ((rec (read-record reader (col-off cols s) (col-len cols s))))
              (write-sequence rec out :end (col-len cols s))
              (incf kept)))))
      (finish-output out)
      (sb-posix:fsync (fd-of out)))
    (close-store store)
    (rename-file tmp (store-log-path (uiop:ensure-directory-pathname dir)))
    kept))
