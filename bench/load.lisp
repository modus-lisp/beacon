;;;; bench/load.lisp — a network load generator for a Nostr relay.
;;;;
;;;; Runs in its OWN process (so its garbage is not the relay's GC pauses) and
;;;; drives three kinds of traffic at once, timing each from the client side:
;;;;
;;;;   publishers   open-loop: send signed EVENTs on a fixed schedule; time to OK
;;;;   listeners    hold live subscriptions; time from EVENT sent to EVENT received
;;;;   queriers     closed-loop REQs against the stored data; time from REQ to EOSE
;;;;
;;;; Open-loop publishing matters: a closed-loop client slows down when the server
;;;; does, which hides queueing delay ("coordinated omission").  Here the send
;;;; time is the SCHEDULED time, so a stall shows up in the latency it caused.

(in-package #:beacon.bench)

;;; ---- a minimal blocking WebSocket client ---------------------------------------------

(defstruct (wsc (:constructor %make-wsc))
  socket stream
  (lock (sb-thread:make-mutex :name "wsc")))

(defun ws-connect (host port)
  (let ((s (make-instance 'sb-bsd-sockets:inet-socket :type :stream :protocol :tcp)))
    (sb-bsd-sockets:socket-connect s (beacon::parse-ipv4 host) port)
    (setf (sb-bsd-sockets:sockopt-tcp-nodelay s) t)
    (let ((st (sb-bsd-sockets:socket-make-stream s :input t :output t :element-type '(unsigned-byte 8)
                                                   :buffering :full)))
      (write-sequence (beacon::ascii-octets
                       (format nil "GET / HTTP/1.1~c~cHost: ~a~c~cUpgrade: websocket~c~cConnection: Upgrade~c~cSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==~c~cSec-WebSocket-Version: 13~c~c~c~c"
                               #\Return #\Newline host #\Return #\Newline #\Return #\Newline #\Return #\Newline
                               #\Return #\Newline #\Return #\Newline #\Return #\Newline))
                      st)
      (force-output st)
      ;; read the 101 response header
      (let ((last4 0))
        (loop for b = (read-byte st)
              do (setf last4 (logand #xffffffff (logior (ash last4 8) b)))
              until (= last4 #x0d0a0d0a)))
      (%make-wsc :socket s :stream st))))

(defun ws-send (c payload &optional (start 0) (end (length payload)))
  "Send a masked text frame.  The mask is all zeros: legal framing, no XOR cost."
  (let* ((n (- end start))
         (hdr (make-array 14 :element-type '(unsigned-byte 8) :initial-element 0))
         (hl (cond ((< n 126) (setf (aref hdr 1) (logior #x80 n)) 2)
                   ((< n 65536) (setf (aref hdr 1) (logior #x80 126)
                                      (aref hdr 2) (ldb (byte 8 8) n) (aref hdr 3) (ldb (byte 8 0) n)) 4)
                   (t (setf (aref hdr 1) (logior #x80 127))
                      (dotimes (i 8) (setf (aref hdr (+ 2 i)) (ldb (byte 8 (* 8 (- 7 i))) n))) 10))))
    (setf (aref hdr 0) #x81)
    (sb-thread:with-mutex ((wsc-lock c))
      (write-sequence hdr (wsc-stream c) :end (+ hl 4))  ; + 4 zero mask bytes
      (write-sequence payload (wsc-stream c) :start start :end end)
      (force-output (wsc-stream c)))))

(defun ws-send-string (c string) (ws-send c (beacon::string-utf8 string)))

(defun ws-receive (c)
  "The next text message's payload (octets), or NIL at end of stream."
  (let ((st (wsc-stream c)))
    (handler-case
        (loop
          (let* ((b0 (read-byte st)) (b1 (read-byte st))
                 (op (logand b0 15)) (n (logand b1 127)))
            (cond ((= n 126) (setf n (logior (ash (read-byte st) 8) (read-byte st))))
                  ((= n 127) (setf n 0) (dotimes (i 8) (setf n (logior (ash n 8) (read-byte st))))))
            (let ((payload (make-array n :element-type '(unsigned-byte 8))))
              (read-sequence payload st)
              (case op
                (1 (return payload))
                (9 (sb-thread:with-mutex ((wsc-lock c))
                     (write-sequence (make-array 6 :element-type '(unsigned-byte 8)
                                                   :initial-contents '(#x8a #x80 0 0 0 0)) st)
                     (force-output st)))
                (8 (return nil))))))
      (error () nil))))

(defun ws-close (c) (ignore-errors (sb-bsd-sockets:socket-close (wsc-socket c))))

;;; ---- latency recording --------------------------------------------------------------------

(defstruct (rec (:constructor make-rec (name)))
  name
  (lock (sb-thread:make-mutex))
  (samples (make-array 100000 :element-type 'fixnum :adjustable t :fill-pointer 0)))

(defun rec-add (r us)
  (sb-thread:with-mutex ((rec-lock r)) (vector-push-extend us (rec-samples r))))

(defun rec-report (r seconds)
  (let* ((v (sort (copy-seq (rec-samples r)) #'<)) (n (length v)))
    (flet ((p (q) (if (zerop n) 0 (aref v (min (1- n) (floor (* q n)))))))
      (format t "~&  ~22a n=~8:d (~7,0f/s)  p50 ~7:d  p90 ~7:d  p99 ~8:d  p99.9 ~8:d  max ~9:d  us~%"
              (rec-name r) n (/ n seconds) (p 0.5) (p 0.9) (p 0.99) (p 0.999) (if (zerop n) 0 (aref v (1- n)))))))

;;; ---- signing events (for real) ----------------------------------------------------------------

(defun sign-batch (keys count &key (threads 64) (kind 1))
  "COUNT signed event JSON strings, each with an embedded unique number, made
on THREADS threads.  Returns a simple-vector of (id-hex . json-octets)."
  (let ((out (make-array count)) (per (ceiling count threads)))
    (mapc #'sb-thread:join-thread
          (loop for k below threads
                collect (let ((k k))
                          (sb-thread:make-thread
                           (lambda ()
                             (loop for i from (* k per) below (min count (* (1+ k) per))
                                   do (let* ((key (svref keys (mod i (length keys))))
                                             (tags (if (zerop (mod i 5)) '(("t" "bench")) '()))
                                             (json (beacon.test:sign-event-json
                                                    key kind (format nil "load test note ~d: the quick brown fox jumps over the lazy dog" i)
                                                    :tags tags))
                                             (p (search "\"id\":\"" json)))
                                        (setf (svref out i) (cons (subseq json (+ p 6) (+ p 70))
                                                                  (beacon::string-utf8 (format nil "[\"EVENT\",~a]" json)))))))))))
    out))

;;; The load generator's own pauses inflate what it measures; report them.
(defvar *client-gcs* 0)
(defvar *client-gc-max* 0)
(defvar *client-gc-last* 0)
(defun note-client-gc ()
  (let ((ms (/ (* 1000 (- sb-ext:*gc-run-time* *client-gc-last*)) internal-time-units-per-second)))
    (setf *client-gc-last* sb-ext:*gc-run-time*)
    (incf *client-gcs*)
    (setf *client-gc-max* (max *client-gc-max* ms))))
(setf *client-gc-last* sb-ext:*gc-run-time*)
(pushnew 'note-client-gc sb-ext:*after-gc-hooks*)

;;; ---- the load run --------------------------------------------------------------------------------

(defun message-type (payload)
  ;; ["OK"  ["EVENT"  ["EOSE"  ["CLOSED"  ["NOTICE"
  (case (aref payload 2) (79 :ok) (69 (if (= (aref payload 3) 86) :event :eose)) (67 (if (= (aref payload 3) 76) :closed :count))
        (78 :notice) (t :other)))

(defun ok-id (payload) (map 'string #'code-char (subseq payload 7 71)))

(defun event-id-in (payload)
  (let ((p (search #.(beacon::ascii-octets "\"id\":\"") payload)))
    (and p (map 'string #'code-char (subseq payload (+ p 6) (+ p 70))))))

(defun load-run (&key (host "127.0.0.1") (port 7777)
                      (publishers 8) (publish-rate 500) (listeners 50) (queriers 16)
                      (seconds 30) (keys 2000) (authors 200000) (query-mix :default) (firehose 1/2))
  "Total publish rate is PUBLISHERS x PUBLISH-RATE events/s."
  (let* ((nevents (* publishers publish-rate (+ seconds 2)))
         (t-sign (now-us))
         (keyv (coerce (loop for i below keys collect (beacon.test:make-test-key (+ 5000 i))) 'simple-vector))
         (events (sign-batch keyv nevents))
         (sent-at (make-hash-table :test 'equal :synchronized t))
         (r-ok (make-rec "publish -> OK"))
         (r-live (make-rec "publish -> live EVENT"))
         (r-query (make-rec "REQ -> EOSE"))
         (r-lag (make-rec "client send lag"))
         (rejected 0) (stop nil) (threads '()) (conns '())
         (author-vec (world-authors (make-world :authors authors)))
         (note-ids #()))
    (format t "~&signed ~:d events in ~,1f s~%" nevents (/ (- (now-us) t-sign) 1d6))
    ;; the generator must not be what it measures: settle the signed events into
    ;; an old generation and collect rarely
    (sb-ext:gc :full t)
    (setf (sb-ext:bytes-consed-between-gcs) (* 2 1024 1024 1024))
    ;; some real note ids from the store, for thread queries
    (let ((c (ws-connect host port)))
      (ws-send-string c "[\"REQ\",\"ids\",{\"kinds\":[1],\"limit\":2000}]")
      (setf note-ids (coerce (loop for m = (ws-receive c) while (and m (eq (message-type m) :event))
                                   collect (event-id-in m))
                             'simple-vector))
      (ws-close c))
    (flet ((spawn (fn) (push (sb-thread:make-thread fn) threads))
           (open-conn () (let ((c (ws-connect host port))) (push c conns) c)))
      ;; listeners: half firehose, half on a slice of the publishing authors
      (dotimes (i listeners)
        (let ((c (open-conn)) (i i))
          (ws-send-string c (if (< (mod (* i firehose) 1) firehose)
                                (format nil "[\"REQ\",\"live\",{\"kinds\":[1],\"limit\":0}]")
                                (format nil "[\"REQ\",\"live\",{\"authors\":[~{\"~a\"~^,~}],\"limit\":0}]"
                                        (loop for k from 0 below 50
                                              collect (beacon:hex-encode (cdr (svref keyv (mod (+ k (* i 50)) keys))))))))
          (spawn (lambda ()
                   (loop for m = (ws-receive c) while m
                         do (when (eq (message-type m) :event)
                              (let ((t0 (gethash (event-id-in m) sent-at)))
                                (when t0 (rec-add r-live (- (now-us) t0))))))))))
      (sleep 0.5)
      ;; queriers
      (dotimes (i queriers)
        (let ((c (open-conn)) (rng (sb-ext:seed-random-state (+ 77 i))))
          (spawn (lambda ()
                   (flet ((pk () (beacon:hex-encode (svref author-vec (skewed (length author-vec) rng)))))
                     (loop until stop do
                       (let* ((r (random 100 rng))
                              (filter
                                (cond ((< r 30) (format nil "{\"authors\":[\"~a\"],\"kinds\":[0]}" (pk)))
                                      ((< r 45) (format nil "{\"authors\":[\"~a\"],\"kinds\":[1],\"limit\":20}" (pk)))
                                      ((< r 55) (format nil "{\"authors\":[~{\"~a\"~^,~}],\"kinds\":[1,6],\"limit\":100}"
                                                        (loop repeat 300 collect (pk))))
                                      ((< r 70) (format nil "{\"#e\":[\"~a\"],\"kinds\":[1,7,9735]}"
                                                        (if (plusp (length note-ids)) (svref note-ids (random (length note-ids) rng)) (pk))))
                                      ((< r 85) (format nil "{\"#p\":[\"~a\"],\"limit\":50}" (pk)))
                                      ((< r 95) (format nil "{\"#t\":[\"tag~d\"],\"kinds\":[1],\"limit\":50}" (skewed 2000 rng)))
                                      (t "{\"kinds\":[1],\"limit\":50}")))
                              (t0 (now-us)))
                         (declare (ignorable query-mix))
                         (ws-send-string c (format nil "[\"REQ\",\"q\",~a]" filter))
                         (loop for m = (ws-receive c)
                               while m
                               until (member (message-type m) '(:eose :closed)))
                         (rec-add r-query (- (now-us) t0))
                         (ws-send-string c "[\"CLOSE\",\"q\"]"))))))))
      ;; publishers, open loop
      (let* ((per (floor nevents publishers))
             (start (+ (now-us) 200000))
             (interval (/ 1d6 publish-rate)))
        (dotimes (p publishers)
          (let ((c (open-conn)) (p p))
            (spawn (lambda ()
                     (loop for m = (ws-receive c) while m
                           do (when (eq (message-type m) :ok)
                                (let* ((id (ok-id m)) (t0 (gethash id sent-at)))
                                  (when t0 (rec-add r-ok (- (now-us) t0)))
                                  (unless (search #.(beacon::ascii-octets "true") m :end2 (min (length m) 80))
                                    (incf rejected)))))))
            (spawn (lambda ()
                     (loop for j from 0 below per
                           for i = (+ (* p per) j)
                           for due = (+ start (round (* j interval)))
                           until stop
                           do (let ((now (now-us)))
                                (when (> due now) (sleep (/ (- due now) 1d6))))
                              (destructuring-bind (id . frame) (svref events i)
                                (setf (gethash id sent-at) due)   ; the SCHEDULED time
                                (ws-send c frame)
                                (rec-add r-lag (max 0 (- (now-us) due)))))))))
        (let ((gc0 sb-ext:*gc-run-time*) (n0 *client-gcs*) (max0 (setf *client-gc-max* 0)))
          (declare (ignore max0))
          (sleep seconds)
          (setf stop t)
          (format t "~&load generator's own GC: ~d collections, ~,0f ms total, longest ~,0f ms~%"
                  (- *client-gcs* n0)
                  (/ (* 1000 (- sb-ext:*gc-run-time* gc0)) internal-time-units-per-second)
                  *client-gc-max*))
        (sleep 2)
        (format t "~&~d publishers x ~d/s = ~:d events/s offered, ~d listeners, ~d queriers, ~d s~%"
                publishers publish-rate (* publishers publish-rate) listeners queriers seconds)
        (rec-report r-ok seconds)
        (rec-report r-live seconds)
        (rec-report r-query seconds)
        (rec-report r-lag seconds)
        (format t "  rejected/failed publishes: ~d~%" rejected)
        (finish-output)
        (mapc #'ws-close conns)
        ;; reader threads blocked in read-byte do not all notice a closed socket; don't wait on them
        (sb-ext:exit :code 0 :abort t)))))
