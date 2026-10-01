;;;; src/relay.lisp — the Nostr protocol, and the pipeline behind it.
;;;;
;;;;   I/O threads ──EVENT──▶ verify pool ──▶ writer (group commit) ──▶ fanout
;;;;        │                                     │ OK                    │ live EVENTs
;;;;        └──REQ/COUNT──▶ query pool ──stored EVENTs, EOSE──────────────┘
;;;;
;;;; Every stage is a thread (or pool) with a bounded queue in front of it, so a
;;;; burst of one kind of work cannot starve another: a flood of EVENTs saturates
;;;; the verify pool while queries keep running on theirs, and an expensive
;;;; query occupies one query worker, not an I/O thread.  When a queue is full
;;;; the client is told "rate-limited:" at once rather than made to wait.
;;;;
;;;; GAP-FREE SUBSCRIPTIONS.  A REQ must deliver every matching event exactly
;;;; once: stored ones, EOSE, then live ones.  The fanout thread processes stored
;;;; events in serial order and FANNED is the first serial it has not processed.
;;;; A query worker registers the subscription and reads FANNED under the same
;;;; lock, then queries the snapshot BELOW FANNED; everything at or above it will
;;;; come through fanout.  While the query runs, fanout parks matches in the
;;;; subscription's PENDING list; after EOSE the worker flushes it and flips the
;;;; subscription to :LIVE, again under the lock.

(in-package #:beacon)

;;; ---- configuration ------------------------------------------------------------------

(defstruct (config (:constructor make-config
                       (&key (host "127.0.0.1") (port 7777) (dir "./beacon-data/")
                             (io-threads 4) (verify-threads 4) (query-threads 4)
                             (sync t) (max-message (* 512 1024)) (max-subscriptions 50)
                             (max-filters 20) (max-connections 20000)
                             (events-per-second 50) (event-burst 200)
                             (reqs-per-second 50) (req-burst 200)
                             (verify-queue 4096) (query-queue 4096)
                             (name "beacon") (description "A Nostr relay in pure Common Lisp.")
                             (pubkey nil) (contact nil))))
  host port dir io-threads verify-threads query-threads sync max-message max-subscriptions
  max-filters max-connections events-per-second event-burst reqs-per-second req-burst
  verify-queue query-queue name description pubkey contact)

;;; ---- statistics ----------------------------------------------------------------------

(defconstant +hist-buckets+ 32)   ; bucket i: latency in [2^i, 2^(i+1)) microseconds

(defstruct (stats (:constructor make-stats))
  (received 0 :type sb-ext:word) (stored 0 :type sb-ext:word) (duplicates 0 :type sb-ext:word)
  (rejected 0 :type sb-ext:word) (invalid 0 :type sb-ext:word) (busy 0 :type sb-ext:word)
  (reqs 0 :type sb-ext:word) (counts 0 :type sb-ext:word) (delivered 0 :type sb-ext:word)
  (ingest-hist (make-array +hist-buckets+ :element-type 'sb-ext:word :initial-element 0)
   :type (simple-array sb-ext:word (*)))
  (query-hist (make-array +hist-buckets+ :element-type 'sb-ext:word :initial-element 0)
   :type (simple-array sb-ext:word (*)))
  ;; where ingest time goes: queued for verify, verifying, queued for the writer, committing
  (stage-hists (loop repeat 4 collect (make-array +hist-buckets+ :element-type 'sb-ext:word :initial-element 0))))

(defun record-latency (hist t0)
  (let ((us (max 1 (- (now-us) t0))))
    (sb-ext:atomic-incf (aref hist (min (1- +hist-buckets+) (1- (integer-length us)))))))

(defun hist-percentile (hist p)
  "Upper bound (us) of the bucket holding the P-th percentile."
  (let* ((total (reduce #'+ hist)) (want (* p total)) (acc 0))
    (if (zerop total) 0
        (dotimes (i +hist-buckets+ (ash 1 +hist-buckets+))
          (incf acc (aref hist i))
          (when (>= acc want) (return (ash 1 (1+ i))))))))

;;; ---- GC pauses ------------------------------------------------------------------------
;;; SBCL's collector stops every thread, so a pause is latency paid by every
;;; request in flight.  The relay reports them rather than leaving it a guess.

(defvar *gc-count* 0)
(defvar *gc-max-ms* 0)
(defvar *gc-total-ms* 0)
(defvar *gc-last-run-time* 0)
(defvar *gc-pauses* (make-array 32 :element-type 'sb-ext:word :initial-element 0)
  "Histogram of pause lengths: bucket i is [2^i, 2^(i+1)) microseconds.")

(defun note-gc ()
  (let* ((now sb-ext:*gc-run-time*)
         (us (round (* 1000000 (- now *gc-last-run-time*)) internal-time-units-per-second)))
    (setf *gc-last-run-time* now)
    (incf *gc-count*)
    (incf *gc-total-ms* (round us 1000))
    (setf *gc-max-ms* (max *gc-max-ms* (round us 1000)))
    (incf (aref *gc-pauses* (min 31 (integer-length (max 1 us)))))))

(defun install-gc-monitor ()
  (setf *gc-last-run-time* sb-ext:*gc-run-time*)
  (pushnew 'note-gc sb-ext:*after-gc-hooks*))

;;; ---- the relay -------------------------------------------------------------------------

(defstruct (relay (:constructor %make-relay))
  config store server
  (stats (make-stats))
  verify-q writer-q query-q fanout-q
  (threads '())
  (running t)
  ;; the live-subscription index, all under SUBS-LOCK
  (subs-lock (sb-thread:make-mutex :name "subs"))
  (by-id (make-hash-table :test 'eql))
  (by-author (make-hash-table :test 'eql))
  (by-tag (make-hash-table :test 'eql))
  (by-kind (make-array 65536 :initial-element nil))
  (wildcard '())
  (fanned 0 :type fixnum)
  (fanout-seq 0 :type fixnum))

(defstruct (cstate (:constructor make-cstate))
  (subs (make-hash-table :test 'equal))
  (event-tokens 0.0d0 :type double-float)
  (req-tokens 0.0d0 :type double-float)
  (refilled 0 :type fixnum))               ; microseconds

(defstruct (sub (:constructor %make-sub))
  conn id id-json filters
  (state :querying)                        ; :querying :live :closed
  (pending '())
  (npending 0 :type fixnum)
  (regs '())                               ; (table-or-:kind key entry) for unregistering
  (seen 0 :type fixnum)                    ; last fanout sequence delivered (dedupe)
  (t0 0))

(defvar *max-pending* 10000 "Live events buffered for one subscription while its query runs.")

;;; ---- framing ------------------------------------------------------------------------------

(defun msg-frame (fn)
  "A text frame whose payload FN writes into an obuf."
  (let ((b (make-obuf 128)))
    (funcall fn b)
    (ws-text-frame-from-obuf b)))

(defun send-notice (c text)
  (conn-send c (msg-frame (lambda (b) (obuf-ascii b "[\"NOTICE\",") (obuf-json-string b text) (obuf-byte b 93)))))

(defun send-ok (c id-hex ok message)
  (conn-send c (msg-frame (lambda (b)
                            (obuf-ascii b "[\"OK\",") (obuf-json-string b id-hex)
                            (obuf-ascii b (if ok ",true," ",false,"))
                            (obuf-json-string b message) (obuf-byte b 93)))))

(defun send-closed (c sub-id message)
  (conn-send c (msg-frame (lambda (b)
                            (obuf-ascii b "[\"CLOSED\",") (obuf-json-string b sub-id)
                            (obuf-byte b 44) (obuf-json-string b message) (obuf-byte b 93)))))

(defun eose-frame (sub)
  (msg-frame (lambda (b) (obuf-ascii b "[\"EOSE\",") (obuf-octets b (sub-id-json sub)) (obuf-byte b 93))))

(defun event-frame (sub-id-json json start end)
  "[\"EVENT\",<sub>,<json>] as one frame, built with a single allocation."
  (declare (type octets sub-id-json json) (type ufix start end))
  (let* ((plen (+ 9 (length sub-id-json) 1 (- end start) 1))
         (out (make-octets (+ (ws-frame-header-length plen) plen)))
         (p (write-ws-frame-header out 0 +op-text+ plen)))
    (replace out #.(ascii-octets "[\"EVENT\",") :start1 p) (incf p 9)
    (replace out sub-id-json :start1 p) (incf p (length sub-id-json))
    (setf (aref out p) 44) (incf p)
    (replace out json :start1 p :start2 start :end2 end) (incf p (- end start))
    (setf (aref out p) 93)
    out))

;;; ---- rate limiting -------------------------------------------------------------------------

(defun take-token (relay cs kind)
  "Token buckets per connection.  KIND is :event or :req."
  (let* ((cfg (relay-config relay))
         (now (now-us))
         (dt (/ (- now (cstate-refilled cs)) 1d6)))
    (setf (cstate-refilled cs) now)
    (flet ((refill (tokens rate burst) (min (float burst 1d0) (+ tokens (* dt rate)))))
      (setf (cstate-event-tokens cs) (refill (cstate-event-tokens cs) (config-events-per-second cfg) (config-event-burst cfg))
            (cstate-req-tokens cs) (refill (cstate-req-tokens cs) (config-reqs-per-second cfg) (config-req-burst cfg))))
    (ecase kind
      (:event (when (>= (cstate-event-tokens cs) 1d0) (decf (cstate-event-tokens cs) 1d0) t))
      (:req (when (>= (cstate-req-tokens cs) 1d0) (decf (cstate-req-tokens cs) 1d0) t)))))

;;; ---- the subscription index ----------------------------------------------------------------

(declaim (inline hkey))
(defun hkey (h) h)                      ; hashes are already fixnums

(defun register-sub (relay sub)
  "Index SUB's filters for fanout.  Caller holds SUBS-LOCK."
  (dolist (f (sub-filters sub))
    (unless (filter-impossible f)
      (let ((entry (cons f sub)))
        (flet ((add (table key)
                 (push entry (gethash key table))
                 (push (list table key entry) (sub-regs sub))))
          (cond
            ((filter-ids f) (dolist (id (filter-ids f)) (add (relay-by-id relay) (hkey (keyed-hash id)))))
            ((filter-tags f) (loop for h across (cdr (first (filter-tags f))) do (add (relay-by-tag relay) (hkey h))))
            ((filter-authors f) (dolist (a (filter-authors f)) (add (relay-by-author relay) (hkey (keyed-hash a)))))
            ((filter-kinds f)
             (dolist (k (filter-kinds f))
               (push entry (svref (relay-by-kind relay) k))
               (push (list :kind k entry) (sub-regs sub))))
            (t (push entry (relay-wildcard relay))
               (push (list :wildcard nil entry) (sub-regs sub)))))))))

(defun unregister-sub (relay sub)
  "Caller holds SUBS-LOCK."
  (loop for (table key entry) in (sub-regs sub) do
    (case table
      (:kind (setf (svref (relay-by-kind relay) key) (delete entry (svref (relay-by-kind relay) key) :test #'eq)))
      (:wildcard (setf (relay-wildcard relay) (delete entry (relay-wildcard relay) :test #'eq)))
      (t (let ((rest (delete entry (gethash key table) :test #'eq)))
           (if rest (setf (gethash key table) rest) (remhash key table))))))
  (setf (sub-regs sub) '() (sub-state sub) :closed (sub-pending sub) '()))

(defun matching-subs (relay e)
  "Subscriptions with a filter matching E, each once.  Caller holds SUBS-LOCK."
  (let ((seq (incf (relay-fanout-seq relay))) (out '()))
    (flet ((try (entries)
             (dolist (entry entries)
               (let ((sub (cdr entry)))
                 (when (and (/= (sub-seen sub) seq) (filter-matches-event-p (car entry) e))
                   (setf (sub-seen sub) seq)
                   (push sub out))))))
      (try (gethash (hkey (keyed-hash (event-id e))) (relay-by-id relay)))
      (try (gethash (hkey (keyed-hash (event-pubkey e))) (relay-by-author relay)))
      (loop for h across (event-tag-hashes e) do (try (gethash (hkey h) (relay-by-tag relay))))
      (try (svref (relay-by-kind relay) (event-kind e)))
      (try (relay-wildcard relay)))
    out))

;;; ---- protocol: the I/O-thread side --------------------------------------------------------

(defun close-sub (relay c sub-id)
  (let* ((cs (conn-user c)) (sub (gethash sub-id (cstate-subs cs))))
    (when sub
      (remhash sub-id (cstate-subs cs))
      (sb-thread:with-mutex ((relay-subs-lock relay)) (unregister-sub relay sub)))))

(defun handle-event-msg (relay c msg)
  (let ((st (relay-stats relay)) (t0 (now-us)))
    (sb-ext:atomic-incf (stats-received st))
    (let* ((raw (and (> (length msg) 1) (svref msg 1)))
           (raw-id (or (and (listp raw) (let ((v (json-get raw "id"))) (and (stringp v) v))) "")))
      (unless (take-token relay (conn-user c) :event)
        (sb-ext:atomic-incf (stats-busy st))
        (return-from handle-event-msg (send-ok c raw-id nil "rate-limited: slow down")))
      (let ((e (handler-case (parse-event raw)
                 (invalid-event (err)
                   (sb-ext:atomic-incf (stats-invalid st))
                   (return-from handle-event-msg
                     (send-ok c raw-id nil (format nil "invalid: ~a" (invalid-event-reason err))))))))
        ;; cheap early answer for the commonest case: we already have it
        (let* ((idx (store-index (relay-store relay))) (s (index-find-id idx (event-id e))))
          (when (and s (not (serial-deleted-p (index-columns idx) s)))
            (sb-ext:atomic-incf (stats-duplicates st))
            (return-from handle-event-msg (send-ok c raw-id t "duplicate: already have this event"))))
        (unless (bqueue-push (relay-verify-q relay) (list c e t0))
          (sb-ext:atomic-incf (stats-busy st))
          (send-ok c raw-id nil "rate-limited: relay is busy, try again"))))))

(defun valid-sub-id-p (x) (and (stringp x) (<= 1 (length x) 64)))

(defun handle-req-msg (relay c msg count-p)
  (let ((cfg (relay-config relay)) (cs (conn-user c)) (t0 (now-us)))
    (let ((sub-id (and (> (length msg) 1) (svref msg 1))))
      (unless (valid-sub-id-p sub-id)
        (return-from handle-req-msg (send-notice c "invalid: subscription id must be a string of 1-64 characters")))
      (let ((filters (handler-case
                         (progn
                           (when (< (length msg) 3) (bad-filter "at least one filter is required"))
                           (when (> (- (length msg) 2) (config-max-filters cfg)) (bad-filter "too many filters"))
                           (loop for i from 2 below (length msg) collect (parse-filter (svref msg i))))
                       (invalid-filter (err)
                         (return-from handle-req-msg
                           (send-closed c sub-id (format nil "invalid: ~a" (invalid-filter-reason err))))))))
        (unless (take-token relay cs :req)
          (return-from handle-req-msg (send-closed c sub-id "rate-limited: slow down")))
        (close-sub relay c sub-id)
        (when (and (not count-p) (>= (hash-table-count (cstate-subs cs)) (config-max-subscriptions cfg)))
          (return-from handle-req-msg (send-closed c sub-id "rate-limited: too many open subscriptions")))
        (let ((b (make-obuf 80)))
          (obuf-json-string b sub-id)
          (let ((sub (%make-sub :conn c :id sub-id :id-json (obuf-copy b) :filters filters :t0 t0)))
            (unless count-p (setf (gethash sub-id (cstate-subs cs)) sub))
            (unless (bqueue-push (relay-query-q relay) (list (if count-p :count :req) sub))
              (unless count-p (remhash sub-id (cstate-subs cs)))
              (send-closed c sub-id "rate-limited: relay is busy, try again"))))))))

(defun relay-on-message (relay c buf start end)
  (let ((msg (handler-case (json-parse buf start end)
               (json-error (e) (return-from relay-on-message
                                 (send-notice c (format nil "invalid: ~a" (json-error-message e))))))))
    (unless (and (simple-vector-p msg) (plusp (length msg)) (stringp (svref msg 0)))
      (return-from relay-on-message (send-notice c "invalid: expected a JSON array starting with a message type")))
    (let ((type (svref msg 0)))
      (cond ((string= type "EVENT") (handle-event-msg relay c msg))
            ((string= type "REQ") (handle-req-msg relay c msg nil))
            ((string= type "COUNT") (handle-req-msg relay c msg t))
            ((string= type "CLOSE")
             (when (and (> (length msg) 1) (stringp (svref msg 1))) (close-sub relay c (svref msg 1))))
            (t (send-notice c (format nil "unsupported: message type ~a" type)))))))

(defun relay-on-open (relay c)
  (let ((cfg (relay-config relay)))
    (setf (conn-user c) (make-cstate :event-tokens (float (config-event-burst cfg) 1d0)
                                     :req-tokens (float (config-req-burst cfg) 1d0)
                                     :refilled (now-us)))))

(defun relay-on-close (relay c)
  (let ((cs (conn-user c)))
    (when cs
      (sb-thread:with-mutex ((relay-subs-lock relay))
        (loop for sub being the hash-values of (cstate-subs cs) do (unregister-sub relay sub)))
      (clrhash (cstate-subs cs)))))

;;; ---- HTTP: NIP-11 and stats ------------------------------------------------------------------

(defun relay-info-json (relay)
  (let ((cfg (relay-config relay)) (b (make-obuf 512)))
    (flet ((kv (k v &optional (comma t))
             (obuf-json-string b k) (obuf-byte b 58)
             (etypecase v
               (string (obuf-json-string b v))
               (integer (obuf-int b v))
               ((member t) (obuf-ascii b "true"))
               ((member :false) (obuf-ascii b "false")))
             (when comma (obuf-byte b 44))))
      (obuf-byte b 123)
      (kv "name" (config-name cfg))
      (kv "description" (config-description cfg))
      (when (config-pubkey cfg) (kv "pubkey" (config-pubkey cfg)))
      (when (config-contact cfg) (kv "contact" (config-contact cfg)))
      (obuf-ascii b "\"supported_nips\":[1,9,11,40,45],")
      (kv "software" "https://github.com/modus-lisp/beacon")
      (kv "version" "0.1.0")
      (obuf-ascii b "\"limitation\":{")
      (kv "max_message_length" (config-max-message cfg))
      (kv "max_subscriptions" (config-max-subscriptions cfg))
      (kv "max_filters" (config-max-filters cfg))
      (kv "max_limit" *max-limit*)
      (kv "default_limit" *default-limit*)
      (kv "max_subid_length" 64)
      (kv "max_event_tags" *max-tags*)
      (kv "max_content_length" *max-content-chars*)
      (kv "created_at_upper_limit" *future-slack*)
      (kv "auth_required" :false)
      (kv "payment_required" :false nil)
      (obuf-ascii b "}}"))
    (obuf-copy b)))

(defun relay-stats-json (relay)
  (let ((st (relay-stats relay)) (store (relay-store relay)))
    (string-utf8
     (format nil "{\"events\":~d,\"received\":~d,\"stored\":~d,\"duplicates\":~d,\"rejected\":~d,\"invalid\":~d,\"busy\":~d,\"reqs\":~d,\"counts\":~d,\"delivered\":~d,\"connections\":~d,\"verify_queue\":~d,\"query_queue\":~d,\"ingest_p50_us\":~d,\"ingest_p99_us\":~d,\"query_p50_us\":~d,\"query_p99_us\":~d,\"point_cache_hits\":~d,\"point_cache_misses\":~d,\"gc_count\":~d,\"gc_total_ms\":~d,\"gc_max_ms\":~d,\"gc_p99_ms\":~d,\"heap_mb\":~d,\"stage_p99_us\":[~{~d~^,~}],\"stage_max_us\":[~{~d~^,~}]}"
             (store-event-count store) (stats-received st) (stats-stored st) (stats-duplicates st)
             (stats-rejected st) (stats-invalid st) (stats-busy st) (stats-reqs st) (stats-counts st)
             (stats-delivered st) (server-connections (relay-server relay))
             (bqueue-count (relay-verify-q relay)) (bqueue-count (relay-query-q relay))
             (hist-percentile (stats-ingest-hist st) 0.5) (hist-percentile (stats-ingest-hist st) 0.99)
             (hist-percentile (stats-query-hist st) 0.5) (hist-percentile (stats-query-hist st) 0.99)
             *point-cache-hits* *point-cache-misses*
             *gc-count* *gc-total-ms* *gc-max-ms* (round (hist-percentile *gc-pauses* 0.99) 1000)
             (round (sb-kernel:dynamic-usage) 1048576)
             (mapcar (lambda (h) (hist-percentile h 0.99)) (stats-stage-hists st))
             (mapcar (lambda (h) (hist-percentile h 1.0)) (stats-stage-hists st))))))

(defparameter +cors+ '(("Access-Control-Allow-Origin" . "*")
                       ("Access-Control-Allow-Headers" . "*")
                       ("Access-Control-Allow-Methods" . "GET, OPTIONS")))

(defun relay-on-http (relay c method target headers)
  (declare (ignore c))
  (cond ((string-equal method "OPTIONS") (http-response 204 "No Content" :content-type nil :headers +cors+))
        ((and (string-equal method "GET") (search "application/nostr+json" (or (header headers "accept") "")))
         (http-response 200 "OK" :content-type "application/nostr+json" :body (relay-info-json relay) :headers +cors+))
        ((and (string-equal method "GET") (string= target "/stats"))
         (http-response 200 "OK" :content-type "application/json" :body (relay-stats-json relay)))
        ((string-equal method "GET")
         (http-response 200 "OK" :body (format nil "~a — a Nostr relay. Connect with a Nostr client.~%" (config-name (relay-config relay)))))
        (t (http-response 405 "Method Not Allowed" :body "method not allowed"))))

;;; ---- pipeline stages ----------------------------------------------------------------------

(defun verify-worker (relay)
  (loop while (relay-running relay) do
    (dolist (job (bqueue-pop-batch (relay-verify-q relay) :max 32 :timeout 0.5))
      (destructuring-bind (c e t0 &rest _) job
        (declare (ignore _))
        (let ((t1 (now-us)) (sh (stats-stage-hists (relay-stats relay))))
          (record-latency (first sh) t0)
          (setf (cdr (last job)) (list t1 (now-us))))
        (if (prog1 (verify-event-signature e)
              (record-latency (second (stats-stage-hists (relay-stats relay))) (fourth job)))
            (progn (setf (fifth job) (now-us))
                   (bqueue-push (relay-writer-q relay) job))    ; unbounded: never refuses
            (progn
              (sb-ext:atomic-incf (stats-invalid (relay-stats relay)))
              (send-ok c (event-id-hex e) nil "invalid: bad signature")))))))

(defun writer-loop (relay)
  (let ((store (relay-store relay)) (st (relay-stats relay)))
    (loop while (or (relay-running relay) (plusp (bqueue-count (relay-writer-q relay)))) do
      (let ((jobs (bqueue-pop-batch (relay-writer-q relay) :max 4096 :timeout 0.5))
            (tc (now-us)))
        (dolist (j jobs) (record-latency (third (stats-stage-hists st)) (fifth j)))
        (when jobs
          (let ((results (handler-case (store-insert-batch store (mapcar #'second jobs))
                           (error (err)
                             (log-msg 0 "writer: insert failed: ~a" err)
                             (mapcar (lambda (j) (declare (ignore j)) '(:rejected . "error: could not store the event")) jobs)))))
            (record-latency (fourth (stats-stage-hists st)) tc)
            (loop for (c e t0) in jobs
                  for (status . detail) in results
                  do (ecase status
                       (:stored (sb-ext:atomic-incf (stats-stored st))
                        (bqueue-push (relay-fanout-q relay) (cons e detail))
                        (send-ok c (event-id-hex e) t ""))
                       (:ephemeral (bqueue-push (relay-fanout-q relay) (cons e nil))
                        (send-ok c (event-id-hex e) t ""))
                       (:duplicate (sb-ext:atomic-incf (stats-duplicates st))
                        (send-ok c (event-id-hex e) t "duplicate: already have this event"))
                       (:rejected (sb-ext:atomic-incf (stats-rejected st))
                        (send-ok c (event-id-hex e) nil detail)))
                     (record-latency (stats-ingest-hist st) t0))))))))

(defun fanout-loop (relay)
  (let ((st (relay-stats relay)))
    (loop while (or (relay-running relay) (plusp (bqueue-count (relay-fanout-q relay)))) do
      (dolist (item (bqueue-pop-batch (relay-fanout-q relay) :max 1024 :timeout 0.5))
        (destructuring-bind (e . serial) item
          (sb-thread:with-mutex ((relay-subs-lock relay))
            (dolist (sub (matching-subs relay e))
              (let ((frame (event-frame (sub-id-json sub) (event-json e) 0 (length (event-json e)))))
                (ecase (sub-state sub)
                  (:live (conn-send (sub-conn sub) frame) (sb-ext:atomic-incf (stats-delivered st)))
                  (:querying
                   (if (< (sub-npending sub) *max-pending*)
                       (progn (push frame (sub-pending sub)) (incf (sub-npending sub)))
                       (conn-kill-now (sub-conn sub))))
                  (:closed nil))))
            (when serial (setf (relay-fanned relay) (1+ serial)))))))))

(defun query-worker (relay)
  (let ((store (relay-store relay)) (st (relay-stats relay)))
    (loop while (relay-running relay) do
      (let ((job (bqueue-pop (relay-query-q relay) :timeout 0.5)))
        (when job
          (destructuring-bind (kind sub) job
            (let ((c (sub-conn sub)))
              (handler-case
                  (ecase kind
                    (:count
                     (sb-ext:atomic-incf (stats-counts st))
                     (let ((n (store-count store (sub-filters sub))))
                       (conn-send c (msg-frame (lambda (b)
                                                 (obuf-ascii b "[\"COUNT\",") (obuf-octets b (sub-id-json sub))
                                                 (obuf-ascii b ",{\"count\":") (obuf-uint b n) (obuf-ascii b "}]"))))))
                    (:req
                     (sb-ext:atomic-incf (stats-reqs st))
                     (let ((snapshot nil))
                       (sb-thread:with-mutex ((relay-subs-lock relay))
                         (unless (eq (sub-state sub) :closed)
                           (register-sub relay sub)
                           (setf snapshot (relay-fanned relay))))
                       (when snapshot
                         (let ((reader (store-reader store)))
                           (dolist (s (store-query store (sub-filters sub) :snapshot snapshot))
                             (when (or (eq (sub-state sub) :closed) (conn-closed c)) (return))
                             (multiple-value-bind (buf start end) (read-event-json store s reader)
                               (conn-send-throttled c (event-frame (sub-id-json sub) buf start end)))))
                         (conn-send c (eose-frame sub))
                         (record-latency (stats-query-hist st) (sub-t0 sub))
                         (sb-thread:with-mutex ((relay-subs-lock relay))
                           (unless (eq (sub-state sub) :closed)
                             (dolist (frame (nreverse (sub-pending sub))) (conn-send c frame))
                             (setf (sub-pending sub) '() (sub-npending sub) 0 (sub-state sub) :live)))))))
                (error (err)
                  (log-msg 0 "query failed: ~a" err)
                  (send-closed c (sub-id sub) "error: query failed"))))))))))

;;; ---- starting and stopping ------------------------------------------------------------------

(defun start-relay (&optional (config (make-config)))
  "Open the store and start serving.  Returns the relay."
  (let* ((store (open-store (config-dir config) :sync (config-sync config)))
         (relay (%make-relay :config config :store store
                             :verify-q (make-bqueue :limit (config-verify-queue config))
                             :writer-q (make-bqueue)
                             :query-q (make-bqueue :limit (config-query-queue config))
                             :fanout-q (make-bqueue))))
    (setf (relay-fanned relay) (index-count (store-index store)))
    ;; count pauses from here on, not the ones the startup replay caused
    (setf *gc-count* 0 *gc-max-ms* 0 *gc-total-ms* 0)
    (fill *gc-pauses* 0)
    (install-gc-monitor)
    (flet ((spawn (name fn) (push (sb-thread:make-thread fn :arguments (list relay) :name name) (relay-threads relay))))
      (dotimes (i (config-verify-threads config)) (spawn (format nil "beacon-verify-~d" i) #'verify-worker))
      (dotimes (i (config-query-threads config)) (spawn (format nil "beacon-query-~d" i) #'query-worker))
      (spawn "beacon-writer" #'writer-loop)
      (spawn "beacon-fanout" #'fanout-loop))
    (setf (relay-server relay)
          (start-server :host (config-host config) :port (config-port config)
                        :io-threads (config-io-threads config)
                        :max-message (config-max-message config)
                        :max-connections (config-max-connections config)
                        :on-open (lambda (c) (relay-on-open relay c))
                        :on-message (lambda (c buf s e) (relay-on-message relay c buf s e))
                        :on-close (lambda (c) (relay-on-close relay c))
                        :on-http (lambda (c m tg h) (relay-on-http relay c m tg h))))
    (log-msg 1 "beacon listening on ~a:~d (~d events)" (config-host config) (relay-port relay)
             (store-event-count store))
    relay))

(defun relay-port (relay) (server-port (relay-server relay)))

(defun stop-relay (relay)
  (stop-server (relay-server relay))
  (setf (relay-running relay) nil)
  (dolist (q (list (relay-verify-q relay) (relay-query-q relay))) (bqueue-close q))
  ;; let the writer and fanout drain what was already accepted
  (dolist (th (relay-threads relay)) (ignore-errors (sb-thread:join-thread th :timeout 10)))
  (bqueue-close (relay-writer-q relay)) (bqueue-close (relay-fanout-q relay))
  (close-store (relay-store relay))
  relay)
