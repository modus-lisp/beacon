;;;; src/platform.lisp — the operating-system seam: sockets, poll(2), raw I/O.
;;;;
;;;; Everything platform-specific in the relay is in this file, in the spirit of
;;;; pagetree's block-device layer: a modus port replaces these few functions and
;;;; nothing above them changes.  On SBCL they are SBCL's own interfaces —
;;;; sb-bsd-sockets for the listener, sb-unix for poll/read/write on raw file
;;;; descriptors.  There is no FFI of our own and no foreign library.
;;;;
;;;; Connections are NON-BLOCKING file descriptors driven by poll(2).  An I/O
;;;; thread therefore never parks on one slow client, and thousands of
;;;; connections need a handful of threads, not thousands.

(in-package #:beacon)

(defun ignore-sigpipe ()
  ;; a write to a peer that has gone away must be an error code, not a signal
  (sb-sys:enable-interrupt sb-unix:sigpipe :ignore))

;;; ---- the listener ---------------------------------------------------------------

(defun parse-ipv4 (host)
  (let ((parts (mapcar #'parse-integer (uiop:split-string host :separator "."))))
    (coerce parts '(vector (unsigned-byte 8)))))

(defun make-listener (host port &key (backlog 1024))
  "A non-blocking listening TCP socket on HOST:PORT (port 0 = ephemeral)."
  (let ((s (make-instance 'sb-bsd-sockets:inet-socket :type :stream :protocol :tcp)))
    (setf (sb-bsd-sockets:sockopt-reuse-address s) t)
    (sb-bsd-sockets:socket-bind s (parse-ipv4 host) port)
    (sb-bsd-sockets:socket-listen s backlog)
    (setf (sb-bsd-sockets:non-blocking-mode s) t)
    s))

(defun listener-port (s) (nth-value 1 (sb-bsd-sockets:socket-name s)))
(defun socket-fd (s) (sb-bsd-sockets:socket-file-descriptor s))

(defun accept-connection (listener)
  "A newly accepted socket, configured for the relay (non-blocking, NODELAY),
or NIL if none is waiting.  The socket OBJECT must be kept alive while its fd
is in use: sb-bsd-sockets closes the fd when the object is collected."
  (let ((s (handler-case (sb-bsd-sockets:socket-accept listener)
             (sb-bsd-sockets:socket-error () nil))))
    (when s
      (setf (sb-bsd-sockets:non-blocking-mode s) t)
      (ignore-errors (setf (sb-bsd-sockets:sockopt-tcp-nodelay s) t))
      s)))

(defun socket-peer (s)
  (ignore-errors
   (multiple-value-bind (addr port) (sb-bsd-sockets:socket-peername s)
     (format nil "~{~d~^.~}:~d" (coerce addr 'list) port))))

(defun close-socket (s) (ignore-errors (sb-bsd-sockets:socket-close s)))

;;; ---- raw non-blocking I/O ----------------------------------------------------------

(defun fd-read (fd buf start end)
  "Read into BUF[START,END).  Returns the byte count, 0 at end of stream, :AGAIN
when nothing is available, or :ERROR."
  (declare (type octets buf) (type ufix start end))
  (multiple-value-bind (n errno)
      (sb-sys:with-pinned-objects (buf)
        (sb-unix:unix-read fd (sb-sys:sap+ (sb-sys:vector-sap buf) start) (- end start)))
    (cond (n n)
          ((or (= errno sb-unix:ewouldblock) (= errno sb-unix:eintr)) :again)
          (t :error))))

(defun fd-write (fd buf start end)
  "Write BUF[START,END).  Returns the byte count written (possibly short),
:AGAIN when the socket buffer is full, or :ERROR."
  (declare (type octets buf) (type ufix start end))
  (multiple-value-bind (n errno) (sb-unix:unix-write fd buf start (- end start))
    (cond (n n)
          ((or (= errno sb-unix:ewouldblock) (= errno sb-unix:eintr)) :again)
          (t :error))))

;;; ---- poll(2) ----------------------------------------------------------------------
;;; A POLLSET is a Lisp (unsigned-byte 32) vector laid out as struct pollfd[]:
;;; word 2i = fd, word 2i+1 = events (low 16 bits) | revents (high 16 bits).

(defconstant +pollin+ 1)
(defconstant +pollout+ 4)
(defconstant +pollerr+ 8)
(defconstant +pollhup+ 16)
(defconstant +pollnval+ 32)

(defstruct (pollset (:constructor %make-pollset))
  (words (make-array 512 :element-type '(unsigned-byte 32) :initial-element 0)
   :type (simple-array (unsigned-byte 32) (*)))
  (n 0 :type fixnum))

(defun make-pollset () (%make-pollset))

(defun pollset-clear (ps) (setf (pollset-n ps) 0))

(defun pollset-add (ps fd events)
  "Add FD; returns its slot."
  (let ((i (pollset-n ps)))
    (when (>= (* 2 (1+ i)) (length (pollset-words ps)))
      (setf (pollset-words ps) (grow-vector (pollset-words ps) (* 2 (length (pollset-words ps))))))
    (setf (aref (pollset-words ps) (* 2 i)) fd
          (aref (pollset-words ps) (1+ (* 2 i))) events)
    (setf (pollset-n ps) (1+ i))
    i))

(declaim (inline pollset-revents))
(defun pollset-revents (ps i) (ash (aref (pollset-words ps) (1+ (* 2 i))) -16))

(defun pollset-wait (ps timeout-ms)
  "poll(2).  Returns the number of ready descriptors (0 on timeout or EINTR)."
  (let ((words (pollset-words ps)))
    (multiple-value-bind (n errno)
        (sb-sys:with-pinned-objects (words)
          (sb-unix:unix-poll (sb-alien:sap-alien (sb-sys:vector-sap words)
                                                 (* (sb-alien:struct sb-unix:pollfd)))
                             (pollset-n ps) timeout-ms))
      (declare (ignore errno))
      (or n 0))))

;;; ---- a wakeup pipe ---------------------------------------------------------------
;;; Other threads hand an I/O thread work (bytes to send, a new connection) and
;;; then write one byte here so its poll(2) returns.

(defstruct (waker (:constructor %make-waker (rfd wfd)))
  rfd wfd
  (armed 0 :type fixnum))           ; 1 while a wake byte is in flight

(defun make-waker ()
  (multiple-value-bind (r w) (sb-unix:unix-pipe)
    (sb-posix:fcntl r sb-posix:f-setfl (logior (sb-posix:fcntl r sb-posix:f-getfl) sb-posix:o-nonblock))
    (sb-posix:fcntl w sb-posix:f-setfl (logior (sb-posix:fcntl w sb-posix:f-getfl) sb-posix:o-nonblock))
    (%make-waker r w)))

(defvar *wake-byte* (make-octets 1))

(defun wake (w)
  "Make the owner's poll return.  Coalesced: one byte in flight at a time."
  (when (zerop (sb-ext:compare-and-swap (waker-armed w) 0 1))
    (sb-unix:unix-write (waker-wfd w) *wake-byte* 0 1)))

(defun drain-waker (w)
  "Consume pending wake bytes and re-arm.  The caller must look at its work
queues AFTER this returns: work enqueued before the re-arm is seen by that
look, work enqueued after it writes a fresh byte."
  (let ((buf (make-octets 64)))
    (loop while (eql 64 (fd-read (waker-rfd w) buf 0 64))))
  (setf (waker-armed w) 0)
  (sb-thread:barrier (:memory)))   ; store-load: the re-arm before the queue look

(defun close-waker (w)
  (sb-unix:unix-close (waker-rfd w))
  (sb-unix:unix-close (waker-wfd w)))
