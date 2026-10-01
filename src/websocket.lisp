;;;; src/websocket.lisp — RFC 6455 server side, and the HTTP it starts from.
;;;;
;;;; Pure functions over octet buffers; the connection state machine that calls
;;;; them is in server.lisp.  Frames from a client MUST be masked (RFC 6455
;;;; 5.1); frames we send are not.  Payloads are unmasked in place, so a message
;;;; is handed to the relay without a copy unless it was fragmented.

(in-package #:beacon)

(define-condition protocol-error (error)
  ((message :initarg :message :reader protocol-error-message))
  (:report (lambda (c s) (format s "protocol error: ~a" (protocol-error-message c)))))

(defun protocol-fail (fmt &rest args)
  (error 'protocol-error :message (apply #'format nil fmt args)))

;;; ---- HTTP -------------------------------------------------------------------

(defvar *max-http-header-bytes* 16384)

(defun find-header-end (buf start end)
  "Index just past the CRLFCRLF ending an HTTP header in BUF[START,END), or NIL."
  (declare (type octets buf) (type ufix start end))
  (loop for i from (+ start 3) below end
        when (and (= (aref buf i) 10) (= (aref buf (- i 1)) 13)
                  (= (aref buf (- i 2)) 10) (= (aref buf (- i 3)) 13))
          do (return (1+ i))))

(defun parse-http-request (buf start end)
  "-> (values method target headers) where HEADERS is an alist with lowercased
names.  BUF[START,END) is exactly the header block."
  (let* ((text (map 'string #'code-char (subseq buf start end)))
         (lines (uiop:split-string (string-right-trim '(#\Return #\Newline) text) :separator '(#\Newline)))
         (request (string-right-trim '(#\Return) (first lines)))
         (parts (uiop:split-string request :separator " ")))
    (unless (>= (length parts) 3) (protocol-fail "bad request line"))
    (values (first parts) (second parts)
            (loop for line in (rest lines)
                  for l = (string-right-trim '(#\Return) line)
                  for colon = (position #\: l)
                  when colon
                    collect (cons (string-downcase (subseq l 0 colon))
                                  (string-trim " " (subseq l (1+ colon))))))))

(defun header (headers name) (cdr (assoc name headers :test #'string=)))

(defun header-has-token-p (headers name token)
  (let ((v (header headers name)))
    (and v (some (lambda (x) (string-equal (string-trim " " x) token))
                 (uiop:split-string v :separator ",")))))

(defun http-response (status reason &key (content-type "text/plain") (body "") headers)
  (let ((b (make-obuf 256))
        (body-octets (if (stringp body) (string-utf8 body) body)))
    (obuf-ascii b (format nil "HTTP/1.1 ~d ~a~c~c" status reason #\Return #\Newline))
    (dolist (h (append (when content-type `(("Content-Type" . ,content-type)))
                       `(("Content-Length" . ,(princ-to-string (length body-octets)))
                         ("Connection" . "close"))
                       headers))
      (obuf-ascii b (format nil "~a: ~a~c~c" (car h) (cdr h) #\Return #\Newline)))
    (obuf-ascii b (format nil "~c~c" #\Return #\Newline))
    (obuf-octets b body-octets)
    (obuf-copy b)))

(defun websocket-accept-key (key)
  (base64-encode (sha1 (ascii-octets (concatenate 'string key "258EAFA5-E914-47DA-95CA-C5AB0DC85B11")))))

(defun websocket-upgrade-response (key)
  (ascii-octets
   (format nil "HTTP/1.1 101 Switching Protocols~c~cUpgrade: websocket~c~cConnection: Upgrade~c~cSec-WebSocket-Accept: ~a~c~c~c~c"
           #\Return #\Newline #\Return #\Newline #\Return #\Newline
           (websocket-accept-key key) #\Return #\Newline #\Return #\Newline)))

;;; ---- frames -----------------------------------------------------------------

(defconstant +op-continuation+ 0)
(defconstant +op-text+ 1)
(defconstant +op-binary+ 2)
(defconstant +op-close+ 8)
(defconstant +op-ping+ 9)
(defconstant +op-pong+ 10)

(defun ws-parse-frame (buf start end max-payload)
  "Parse one client frame in BUF[START,END).  Returns NIL if it is incomplete,
else (values fin opcode payload-start payload-end frame-end) with the payload
unmasked in place."
  (declare (type octets buf) (type ufix start end max-payload))
  (when (< (- end start) 2) (return-from ws-parse-frame nil))
  (let* ((b0 (aref buf start)) (b1 (aref buf (1+ start)))
         (fin (logbitp 7 b0)) (opcode (logand b0 15))
         (masked (logbitp 7 b1)) (len (logand b1 127))
         (pos (+ start 2)))
    (declare (type ufix pos len))
    (unless (zerop (logand b0 #x70)) (protocol-fail "reserved bits set"))
    (unless masked (protocol-fail "client frames must be masked"))
    (cond ((= len 126)
           (when (< (- end pos) 2) (return-from ws-parse-frame nil))
           (setf len (logior (ash (aref buf pos) 8) (aref buf (1+ pos))) pos (+ pos 2)))
          ((= len 127)
           (when (< (- end pos) 8) (return-from ws-parse-frame nil))
           (let ((l 0)) (dotimes (i 8) (setf l (logior (ash l 8) (aref buf (+ pos i)))))
             (when (> l max-payload) (protocol-fail "frame too large"))
             (setf len l pos (+ pos 8)))))
    (when (> len max-payload) (protocol-fail "frame too large"))
    (when (and (>= opcode 8) (or (not fin) (> len 125))) (protocol-fail "bad control frame"))
    (when (< (- end pos) (+ 4 len)) (return-from ws-parse-frame nil))
    (let ((m0 (aref buf pos)) (m1 (aref buf (+ pos 1))) (m2 (aref buf (+ pos 2))) (m3 (aref buf (+ pos 3)))
          (ps (+ pos 4)))
      (declare (optimize (speed 3) (safety 0)) (type ufix ps))
      (loop for i of-type ufix from 0 below len
            for k of-type ufix from ps
            do (setf (aref buf k) (logxor (aref buf k) (case (logand i 3) (0 m0) (1 m1) (2 m2) (t m3)))))
      (values fin opcode ps (+ ps len) (+ ps len)))))

(defun ws-frame-header-length (payload-length)
  (cond ((< payload-length 126) 2) ((< payload-length 65536) 4) (t 10)))

(defun write-ws-frame-header (out pos opcode payload-length)
  "Write an unmasked FIN frame header into OUT at POS; returns the next position."
  (setf (aref out pos) (logior #x80 opcode))
  (cond ((< payload-length 126)
         (setf (aref out (1+ pos)) payload-length) (+ pos 2))
        ((< payload-length 65536)
         (setf (aref out (1+ pos)) 126
               (aref out (+ pos 2)) (ldb (byte 8 8) payload-length)
               (aref out (+ pos 3)) (ldb (byte 8 0) payload-length))
         (+ pos 4))
        (t
         (setf (aref out (1+ pos)) 127)
         (dotimes (i 8) (setf (aref out (+ pos 2 i)) (ldb (byte 8 (* 8 (- 7 i))) payload-length)))
         (+ pos 10))))

(defun ws-frame (opcode payload &optional (start 0) (end (length payload)))
  "A complete server frame carrying PAYLOAD[START,END)."
  (let* ((n (- end start))
         (out (make-octets (+ (ws-frame-header-length n) n)))
         (p (write-ws-frame-header out 0 opcode n)))
    (replace out payload :start1 p :start2 start :end2 end)
    out))

(defun ws-text-frame-from-obuf (b)
  (ws-frame +op-text+ (obuf-data b) 0 (obuf-fill b)))

(defun ws-close-frame (code reason)
  (let ((b (make-obuf 32)))
    (obuf-byte b (ldb (byte 8 8) code)) (obuf-byte b (ldb (byte 8 0) code))
    (obuf-ascii b reason)
    (ws-frame +op-close+ (obuf-data b) 0 (min 125 (obuf-fill b)))))
