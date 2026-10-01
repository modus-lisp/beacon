;;;; src/server.lisp — I/O threads and connections.
;;;;
;;;; N I/O threads each own a set of non-blocking connections and sit in poll(2).
;;;; An I/O thread reads, frames, and hands complete messages to the relay's
;;;; ON-MESSAGE — which must be quick: anything expensive (signature checks,
;;;; queries, the disk) is passed to another stage.
;;;;
;;;; SENDING is allowed from ANY thread (query workers, the writer, fanout).  A
;;;; sender takes the connection's OUT-LOCK and, if nothing is queued, WRITES
;;;; DIRECTLY to the socket — so a live event reaches the wire from the fanout
;;;; thread without waiting for an I/O thread to wake.  Only bytes the kernel
;;;; would not take are queued, and the owning I/O thread is woken to finish
;;;; them when the socket drains.
;;;;
;;;; A closed connection's fd number is reused by the kernel for the next accept,
;;;; so "closed" is decided under OUT-LOCK and every sender checks it there: no
;;;; thread can write a stale connection's bytes into a new client's socket.

(in-package #:beacon)

(defstruct (server (:constructor %make-server))
  (listener nil)
  (iothreads #() :type simple-vector)
  (acceptor nil)
  (running t)
  (on-open nil) (on-message nil) (on-close nil) (on-http nil)
  (max-message (* 1024 1024))          ; largest WebSocket message accepted
  (max-out-bytes (* 32 1024 1024))     ; queued output beyond this = slow consumer, dropped
  (max-connections 20000)
  (idle-timeout 600)                   ; seconds without traffic before a ping / close
  (connections 0 :type sb-ext:word)
  (next-id 0 :type sb-ext:word)
  (next-io 0 :type sb-ext:word))

(defstruct (iothread (:constructor %make-iothread))
  (server nil)
  (thread nil)
  (waker (make-waker))
  (pollset (make-pollset))
  (conns (make-array 64 :adjustable t :fill-pointer 0))
  (lock (sb-thread:make-mutex :name "iothread"))
  (incoming '())                       ; new connections to adopt
  (dirty '()))                         ; connections with queued output / a pending close

(defstruct (conn (:constructor %make-conn))
  (id 0 :type fixnum)
  (socket nil)
  (fd -1 :type fixnum)
  (io nil)
  (peer nil)
  (state :http)                        ; :http :ws
  (inbuf (make-octets 16384) :type octets)
  (in-fill 0 :type ufix)
  (frag nil)                           ; obuf while a fragmented message arrives
  (out-lock (sb-thread:make-mutex :name "conn-out"))
  (out-head nil :type list)            ; queued octet vectors
  (out-tail nil :type list)
  (out-pos 0 :type ufix)               ; bytes of the head already written
  (out-bytes 0 :type fixnum)
  (on-dirty nil)                       ; already in the I/O thread's dirty list
  (closing nil)                        ; close once output drains
  (kill nil)                           ; close now (another thread decided)
  (closed nil)
  (last-active 0 :type fixnum)
  (pinged nil)
  (user nil))                          ; the relay's per-connection state

;;; ---- sending (any thread) ------------------------------------------------------

(defun %mark-dirty (c)
  (unless (conn-on-dirty c)
    (setf (conn-on-dirty c) t)
    (let ((io (conn-io c)))
      (sb-thread:with-mutex ((iothread-lock io)) (push c (iothread-dirty io)))
      (wake (iothread-waker io)))))

(defun %write-queue (c)
  "Write as much queued output as the socket takes.  Caller holds OUT-LOCK.
Returns NIL if the connection failed."
  (loop while (conn-out-head c) do
    (let* ((chunk (car (conn-out-head c)))
           (n (fd-write (conn-fd c) chunk (conn-out-pos c) (length chunk))))
      (cond ((eq n :again) (return t))
            ((eq n :error) (return nil))
            (t (incf (conn-out-pos c) n)
               (decf (conn-out-bytes c) n)
               (when (= (conn-out-pos c) (length chunk))
                 (pop (conn-out-head c))
                 (setf (conn-out-pos c) 0)
                 (unless (conn-out-head c) (setf (conn-out-tail c) nil))))))
        finally (return t)))

(defun conn-send (c octets)
  "Queue OCTETS (a complete frame or HTTP response) for C, writing immediately
when possible.  Returns NIL if C is closed.  Safe from any thread."
  (declare (type octets octets))
  (sb-thread:with-mutex ((conn-out-lock c))
    (when (or (conn-closed c) (conn-kill c)) (return-from conn-send nil))
    (let ((cell (list octets)))
      (if (conn-out-tail c)
          (setf (cdr (conn-out-tail c)) cell (conn-out-tail c) cell)
          (setf (conn-out-head c) cell (conn-out-tail c) cell)))
    (incf (conn-out-bytes c) (length octets))
    (let ((was-only (null (cdr (conn-out-head c)))))
      ;; nothing ahead of us: go straight to the socket
      (when (and was-only (not (%write-queue c)))
        (setf (conn-kill c) t)))
    (cond ((> (conn-out-bytes c) (server-max-out-bytes (iothread-server (conn-io c))))
           (setf (conn-kill c) t)
           (%mark-dirty c))
          ((or (conn-out-head c) (conn-kill c)) (%mark-dirty c)))
    t))

(defun conn-send-throttled (c octets &key (high-water (* 4 1024 1024)) (timeout 30))
  "CONN-SEND for bulk output (query results): first wait, briefly, for the
client to drain below HIGH-WATER, instead of buffering without bound."
  (let ((deadline (+ (get-internal-real-time) (* timeout internal-time-units-per-second))))
    (loop while (and (> (conn-out-bytes c) high-water) (not (conn-closed c)) (not (conn-kill c)))
          do (when (> (get-internal-real-time) deadline)
               (sb-thread:with-mutex ((conn-out-lock c)) (setf (conn-kill c) t))
               (%mark-dirty c)
               (return-from conn-send-throttled nil))
             (sleep 0.001)))
  (conn-send c octets))

(defun conn-close-after-flush (c)
  (sb-thread:with-mutex ((conn-out-lock c)) (setf (conn-closing c) t))
  (%mark-dirty c))

(defun conn-kill-now (c)
  (sb-thread:with-mutex ((conn-out-lock c)) (setf (conn-kill c) t))
  (%mark-dirty c))

;;; ---- the I/O thread ---------------------------------------------------------------

(defun %close-conn (io c reason)
  (declare (ignore io))
  (let ((was-open nil))
    (sb-thread:with-mutex ((conn-out-lock c))
      (unless (conn-closed c)
        (setf (conn-closed c) t was-open t
              (conn-out-head c) nil (conn-out-tail c) nil (conn-out-bytes c) 0)
        (close-socket (conn-socket c))))
    (when was-open
      (let ((s (conn-io c)))
        (sb-ext:atomic-decf (server-connections (iothread-server s))))
      (log-msg 2 "conn ~d closed: ~a" (conn-id c) reason)
      (let ((h (server-on-close (iothread-server (conn-io c)))))
        (when h (ignore-errors (funcall h c)))))))

(defun %flush (io c)
  (let ((ok (sb-thread:with-mutex ((conn-out-lock c))
              (setf (conn-on-dirty c) nil)
              (and (not (conn-kill c)) (%write-queue c)))))
    (cond ((not ok) (%close-conn io c (if (conn-kill c) "dropped (slow consumer or error)" "write error")))
          ((and (conn-closing c) (null (conn-out-head c))) (%close-conn io c "closed")))))

(defun %compact-input (c consumed)
  (let ((rest (- (conn-in-fill c) consumed)))
    (when (plusp consumed)
      (replace (conn-inbuf c) (conn-inbuf c) :start2 consumed :end2 (conn-in-fill c))
      (setf (conn-in-fill c) rest))))

(defun %handle-http (io c)
  (let* ((buf (conn-inbuf c))
         (hend (find-header-end buf 0 (conn-in-fill c))))
    (cond
      ((null hend)
       (when (> (conn-in-fill c) *max-http-header-bytes*) (%close-conn io c "oversized HTTP header"))
       nil)
      (t
       (multiple-value-bind (method target headers) (parse-http-request buf 0 hend)
         (let ((server (iothread-server io)))
           (cond
             ((and (string-equal method "GET")
                   (header-has-token-p headers "upgrade" "websocket")
                   (header headers "sec-websocket-key"))
              (conn-send c (websocket-upgrade-response (header headers "sec-websocket-key")))
              (setf (conn-state c) :ws)
              (%compact-input c hend)
              (when (server-on-open server) (funcall (server-on-open server) c))
              t)
             (t
              (let ((resp (and (server-on-http server) (funcall (server-on-http server) c method target headers))))
                (conn-send c (or resp (http-response 404 "Not Found" :body "not found")))
                (conn-close-after-flush c)
                (setf (conn-in-fill c) 0)
                nil)))))))))

(defun %dispatch-message (io c buf start end)
  (let ((h (server-on-message (iothread-server io))))
    (handler-case (funcall h c buf start end)
      (error (e) (log-msg 0 "conn ~d: handler error: ~a" (conn-id c) e)))))

(defun %handle-frames (io c)
  (let ((buf (conn-inbuf c)) (pos 0) (max (server-max-message (iothread-server io))))
    (handler-case
        (loop
          (when (or (conn-closed c) (conn-closing c)) (return))
          (multiple-value-bind (fin opcode ps pe fe) (ws-parse-frame buf pos (conn-in-fill c) max)
            (when (null opcode) (return))        ; incomplete frame
            (setf pos fe)
            (case opcode
              ((#.+op-text+ #.+op-binary+)
               (when (conn-frag c) (protocol-fail "new message inside a fragmented one"))
               (if fin
                   (%dispatch-message io c buf ps pe)
                   (setf (conn-frag c) (obuf-octets (make-obuf (max 1024 (- pe ps))) buf ps pe))))
              (#.+op-continuation+
               (unless (conn-frag c) (protocol-fail "continuation without a message"))
               (obuf-octets (conn-frag c) buf ps pe)
               (when (> (obuf-fill (conn-frag c)) max) (protocol-fail "message too large"))
               (when fin
                 (let ((m (conn-frag c)))
                   (setf (conn-frag c) nil)
                   (%dispatch-message io c (obuf-data m) 0 (obuf-fill m)))))
              (#.+op-ping+ (conn-send c (ws-frame +op-pong+ buf ps pe)))
              (#.+op-pong+ (setf (conn-pinged c) nil))
              (#.+op-close+
               (conn-send c (ws-frame +op-close+ buf ps (min pe (+ ps 2))))
               (conn-close-after-flush c)
               (return))
              (t (protocol-fail "unknown opcode ~d" opcode)))))
      (protocol-error (e)
        (conn-send c (ws-close-frame 1002 (protocol-error-message e)))
        (conn-close-after-flush c)))
    (%compact-input c pos)))

(defun %handle-readable (io c)
  (let ((max-buf (+ (server-max-message (iothread-server io)) 16)))
    (loop repeat 32 do
      (when (>= (conn-in-fill c) (length (conn-inbuf c)))
        (if (>= (length (conn-inbuf c)) max-buf)
            (progn (%close-conn io c "input overflow") (return))
            (setf (conn-inbuf c) (grow-vector (conn-inbuf c) (min max-buf (* 2 (length (conn-inbuf c))))))))
      (let ((n (fd-read (conn-fd c) (conn-inbuf c) (conn-in-fill c) (length (conn-inbuf c)))))
        (cond ((eq n :again) (return))
              ((or (eq n :error) (eql n 0)) (%close-conn io c "peer closed") (return))
              (t (incf (conn-in-fill c) n)
                 (setf (conn-last-active c) (get-universal-time) (conn-pinged c) nil)
                 (when (eq (conn-state c) :http)
                   (unless (%handle-http io c) (return)))
                 (when (eq (conn-state c) :ws) (%handle-frames io c))
                 (when (conn-closed c) (return))))))
    ;; shrink a buffer that a big message grew
    (when (and (> (length (conn-inbuf c)) 65536) (< (conn-in-fill c) 16384))
      (setf (conn-inbuf c) (subseq (conn-inbuf c) 0 (max 16384 (conn-in-fill c)))))))

(defun %housekeeping (io)
  (let ((now (get-universal-time)) (timeout (server-idle-timeout (iothread-server io))))
    (loop for c across (iothread-conns io)
          unless (conn-closed c)
            do (let ((idle (- now (conn-last-active c))))
                 (cond ((and (conn-pinged c) (> idle (+ timeout 30))) (%close-conn io c "idle"))
                       ((and (> idle timeout) (not (conn-pinged c)) (eq (conn-state c) :ws))
                        (setf (conn-pinged c) t)
                        (conn-send c (ws-frame +op-ping+ (make-octets 0))))
                       ((and (eq (conn-state c) :http) (> idle 30)) (%close-conn io c "http timeout")))))
    ;; drop closed connections from the poll set
    (let ((live (remove-if #'conn-closed (iothread-conns io))))
      (setf (fill-pointer (iothread-conns io)) 0)
      (loop for c across live do (vector-push-extend c (iothread-conns io))))))

(defun iothread-loop (io)
  (let ((ps (iothread-pollset io))
        (slots (make-array 64 :adjustable t :fill-pointer 0))
        (server (iothread-server io))
        (last-housekeeping (get-universal-time)))
    (loop while (server-running server) do
      (pollset-clear ps)
      (setf (fill-pointer slots) 0)
      (pollset-add ps (waker-rfd (iothread-waker io)) +pollin+)
      (loop for c across (iothread-conns io)
            unless (conn-closed c)
              do (pollset-add ps (conn-fd c) (if (conn-out-head c) (logior +pollin+ +pollout+) +pollin+))
                 (vector-push-extend c slots))
      (pollset-wait ps 1000)
      (unless (zerop (pollset-revents ps 0)) (drain-waker (iothread-waker io)))
      ;; adopt new connections, finish others' sends
      (let (incoming dirty)
        (sb-thread:with-mutex ((iothread-lock io))
          (setf incoming (iothread-incoming io) (iothread-incoming io) '()
                dirty (iothread-dirty io) (iothread-dirty io) '()))
        (dolist (c incoming) (vector-push-extend c (iothread-conns io)))
        (dolist (c dirty)
          (unless (conn-closed c)
            (if (conn-kill c)
                (%close-conn io c "dropped (slow consumer or error)")
                (%flush io c)))))
      (loop for c across slots for i from 1
            for re = (pollset-revents ps i)
            unless (or (zerop re) (conn-closed c))
              do (handler-case
                     (progn
                       (when (logtest re +pollout+) (%flush io c))
                       (when (and (not (conn-closed c)) (logtest re (logior +pollin+ +pollhup+ +pollerr+)))
                         (%handle-readable io c))
                       (when (and (not (conn-closed c)) (logtest re +pollnval+))
                         (%close-conn io c "invalid fd")))
                   (error (e) (log-msg 0 "conn ~d: ~a" (conn-id c) e) (%close-conn io c "internal error"))))
      (when (/= last-housekeeping (get-universal-time))
        (setf last-housekeeping (get-universal-time))
        (%housekeeping io)))
    ;; shutting down
    (loop for c across (iothread-conns io) do (%close-conn io c "server stopping"))))

;;; ---- accepting -----------------------------------------------------------------------

(defun acceptor-loop (server)
  (let ((ps (make-pollset)) (lfd (socket-fd (server-listener server))))
    (loop while (server-running server) do
      (pollset-clear ps)
      (pollset-add ps lfd +pollin+)
      (when (plusp (pollset-wait ps 250))
        (loop for s = (accept-connection (server-listener server))
              while s
              do (if (>= (server-connections server) (server-max-connections server))
                     (close-socket s)
                     (let* ((ios (server-iothreads server))
                            (io (svref ios (mod (sb-ext:atomic-incf (server-next-io server)) (length ios))))
                            (c (%make-conn :id (sb-ext:atomic-incf (server-next-id server))
                                           :socket s :fd (socket-fd s) :io io :peer (socket-peer s)
                                           :last-active (get-universal-time))))
                       (sb-ext:atomic-incf (server-connections server))
                       (sb-thread:with-mutex ((iothread-lock io)) (push c (iothread-incoming io)))
                       (wake (iothread-waker io)))))))))

(defun start-server (&key (host "127.0.0.1") (port 7777) (io-threads 4)
                          on-open on-message on-close on-http
                          (max-message (* 1024 1024)) (max-connections 20000)
                          (idle-timeout 600))
  (ignore-sigpipe)
  (let* ((server (%make-server :listener (make-listener host port)
                               :on-open on-open :on-message on-message :on-close on-close :on-http on-http
                               :max-message max-message :max-connections max-connections
                               :idle-timeout idle-timeout)))
    (setf (server-iothreads server)
          (coerce (loop for i below io-threads
                        collect (let ((io (%make-iothread :server server)))
                                  (setf (iothread-thread io)
                                        (sb-thread:make-thread #'iothread-loop :arguments (list io)
                                                                              :name (format nil "beacon-io-~d" i)))
                                  io))
                  'simple-vector))
    (setf (server-acceptor server)
          (sb-thread:make-thread #'acceptor-loop :arguments (list server) :name "beacon-accept"))
    server))

(defun server-port (server) (listener-port (server-listener server)))

(defun stop-server (server)
  (setf (server-running server) nil)
  (ignore-errors (sb-thread:join-thread (server-acceptor server) :timeout 5))
  (loop for io across (server-iothreads server)
        do (wake (iothread-waker io))
           (ignore-errors (sb-thread:join-thread (iothread-thread io) :timeout 5))
           (close-waker (iothread-waker io)))
  (close-socket (server-listener server)))
