;;;; src/util.lisp — octet buffers, hex, UTF-8, time, logging.
;;;;
;;;; Everything a relay does is bytes in, bytes out.  The hot paths (JSON reader,
;;;; canonical serializer, frame writer) all write into an OBUF, a growable
;;;; (unsigned-byte 8) buffer that is reset and reused rather than reallocated,
;;;; so a steady-state request allocates little beyond what it returns.

(in-package #:beacon)

(deftype octets () '(simple-array (unsigned-byte 8) (*)))
(deftype ufix () '(integer 0 #.most-positive-fixnum))

(declaim (inline make-octets))
(defun make-octets (n)
  (make-array n :element-type '(unsigned-byte 8) :initial-element 0))

(defun ascii-octets (string)
  (let ((o (make-octets (length string))))
    (dotimes (i (length string) o)
      (setf (aref o i) (char-code (char string i))))))

(defun octets-string= (a b)
  (declare (type octets a b))
  (and (= (length a) (length b))
       (loop for i of-type ufix below (length a)
             always (= (aref a i) (aref b i)))))

;;; ---- OBUF: a growable byte buffer ----------------------------------------

(defstruct (obuf (:constructor %make-obuf (data)))
  (data (make-octets 0) :type octets)
  (fill 0 :type ufix))

(defun make-obuf (&optional (size 256)) (%make-obuf (make-octets size)))

(declaim (inline obuf-reset))
(defun obuf-reset (b) (setf (obuf-fill b) 0) b)

(defun obuf-grow (b need)
  (declare (type obuf b) (type ufix need))
  (let* ((old (obuf-data b))
         (new (make-octets (max need (* 2 (length old)) 64))))
    (replace new old :end2 (obuf-fill b))
    (setf (obuf-data b) new)))

(declaim (inline obuf-ensure))
(defun obuf-ensure (b n)
  (declare (type obuf b) (type ufix n))
  (let ((need (+ (obuf-fill b) n)))
    (when (> need (length (obuf-data b))) (obuf-grow b need))))

(declaim (inline obuf-byte))
(defun obuf-byte (b byte)
  (declare (type obuf b) (type (unsigned-byte 8) byte))
  (obuf-ensure b 1)
  (setf (aref (obuf-data b) (obuf-fill b)) byte)
  (incf (obuf-fill b))
  b)

(defun obuf-octets (b src &optional (start 0) (end (length src)))
  (declare (type obuf b) (type octets src) (type ufix start end))
  (let ((n (- end start)))
    (obuf-ensure b n)
    (replace (obuf-data b) src :start1 (obuf-fill b) :start2 start :end2 end)
    (incf (obuf-fill b) n)
    b))

(defun obuf-ascii (b string)
  (declare (type obuf b) (type string string))
  (obuf-ensure b (length string))
  (let ((d (obuf-data b)) (f (obuf-fill b)))
    (dotimes (i (length string))
      (setf (aref d (+ f i)) (logand #xff (char-code (char string i)))))
    (incf (obuf-fill b) (length string))
    b))

(defun obuf-uint (b n)
  "Append the decimal representation of the non-negative integer N."
  (declare (type obuf b) (type unsigned-byte n))
  (if (zerop n)
      (obuf-byte b 48)
      (let ((digits (make-array 24 :element-type '(unsigned-byte 8))) (k 0))
        (declare (dynamic-extent digits) (type fixnum k))
        (if (typep n 'fixnum)
            (loop while (plusp n) do
              (multiple-value-bind (q r) (floor n 10)
                (setf (aref digits k) (+ 48 r) n q) (incf k)))
            (return-from obuf-uint (obuf-ascii b (princ-to-string n))))
        (obuf-ensure b k)
        (loop for i from (1- k) downto 0 do (obuf-byte b (aref digits i)))
        b)))

(defun obuf-int (b n)
  (declare (type integer n))
  (when (minusp n) (obuf-byte b 45) (setf n (- n)))
  (obuf-uint b n))

(defun obuf-copy (b &optional (start 0))
  "A fresh octet vector holding the buffer contents from START."
  (subseq (obuf-data b) start (obuf-fill b)))

;;; ---- hex -------------------------------------------------------------------

(declaim (type (simple-array (unsigned-byte 8) (16)) +hex-digits+))
(defparameter +hex-digits+ (ascii-octets "0123456789abcdef"))

(defun obuf-hex (b octets &optional (start 0) (end (length octets)))
  (declare (type obuf b) (type octets octets) (type ufix start end))
  (obuf-ensure b (* 2 (- end start)))
  (let ((d (obuf-data b)) (f (obuf-fill b)))
    (loop for i from start below end
          for byte = (aref octets i)
          do (setf (aref d f) (aref +hex-digits+ (ash byte -4))
                   (aref d (1+ f)) (aref +hex-digits+ (logand byte 15)))
             (incf f 2))
    (setf (obuf-fill b) f)
    b))

(defun hex-encode (octets &optional (start 0) (end (length octets)))
  "Lowercase hex string of OCTETS[START,END)."
  (declare (type octets octets))
  (let ((s (make-string (* 2 (- end start)) :element-type 'base-char)))
    (loop for i from start below end
          for j from 0 by 2
          for byte = (aref octets i)
          do (setf (char s j) (code-char (aref +hex-digits+ (ash byte -4)))
                   (char s (1+ j)) (code-char (aref +hex-digits+ (logand byte 15)))))
    s))

(declaim (inline lower-hex-value))
(defun lower-hex-value (code)
  "Value of a LOWERCASE hex digit's char-code, or NIL.  NIP-01 ids, pubkeys and
signatures are lowercase hex; uppercase is a different string and is rejected."
  (declare (type fixnum code))
  (cond ((<= 48 code 57) (- code 48))
        ((<= 97 code 102) (- code 87))
        (t nil)))

(defun hex-decode (string &optional expected-octets)
  "Decode a lowercase hex STRING to octets, or NIL if it is not lowercase hex of
the expected length."
  (let ((len (length string)))
    (when (or (oddp len) (and expected-octets (/= len (* 2 expected-octets))))
      (return-from hex-decode nil))
    (let ((out (make-octets (floor len 2))))
      (loop for i from 0 below len by 2
            for j from 0
            do (let ((hi (lower-hex-value (char-code (char string i))))
                     (lo (lower-hex-value (char-code (char string (1+ i))))))
                 (unless (and hi lo) (return-from hex-decode nil))
                 (setf (aref out j) (logior (ash hi 4) lo))))
      out)))

;;; ---- UTF-8 -----------------------------------------------------------------

(defun obuf-utf8 (b string)
  "Append the UTF-8 encoding of STRING."
  (declare (type obuf b) (type string string))
  (obuf-ensure b (length string))
  (loop for ch across string
        for c of-type fixnum = (char-code ch)
        do (cond ((< c #x80) (obuf-byte b c))
                 ((< c #x800)
                  (obuf-byte b (logior #xC0 (ash c -6)))
                  (obuf-byte b (logior #x80 (logand c #x3F))))
                 ((< c #x10000)
                  (obuf-byte b (logior #xE0 (ash c -12)))
                  (obuf-byte b (logior #x80 (logand (ash c -6) #x3F)))
                  (obuf-byte b (logior #x80 (logand c #x3F))))
                 (t
                  (obuf-byte b (logior #xF0 (ash c -18)))
                  (obuf-byte b (logior #x80 (logand (ash c -12) #x3F)))
                  (obuf-byte b (logior #x80 (logand (ash c -6) #x3F)))
                  (obuf-byte b (logior #x80 (logand c #x3F))))))
  b)

(defun string-utf8 (string)
  (let ((b (make-obuf (+ 8 (length string)))))
    (obuf-utf8 b string)
    (obuf-copy b)))

(defun utf8-string (octets &optional (start 0) (end (length octets)))
  "Decode UTF-8.  Signals an error on malformed input."
  (sb-ext:octets-to-string octets :external-format :utf-8 :start start :end end))

;;; ---- time ------------------------------------------------------------------

(defconstant +unix-epoch+ 2208988800)

(defun unix-now ()
  "Seconds since 1970-01-01."
  (- (get-universal-time) +unix-epoch+))

(declaim (inline now-us))
(defun now-us ()
  "A monotonic-enough microsecond clock for latency measurement."
  (multiple-value-bind (sec usec) (sb-ext:get-time-of-day)
    (+ (* sec 1000000) usec)))

;;; ---- logging ---------------------------------------------------------------

(defvar *log-level* 1 "0 = errors only, 1 = info, 2 = debug.")
(defvar *log-stream* *error-output*)
(defvar *log-lock* (sb-thread:make-mutex :name "log"))

(defun log-msg (level fmt &rest args)
  (when (<= level *log-level*)
    (let ((line (apply #'format nil fmt args)))
      (sb-thread:with-mutex (*log-lock*)
        (multiple-value-bind (s m h) (decode-universal-time (get-universal-time) 0)
          (format *log-stream* "~2,'0d:~2,'0d:~2,'0d ~a~%" h m s line))
        (force-output *log-stream*)))))

;;; ---- a bounded blocking queue ----------------------------------------------
;;; The pipeline stages (verify pool -> writer -> fanout) hand work across
;;; threads through these.  BATCH-POP takes everything that is waiting, which is
;;; what lets the writer group-commit: under load one fsync covers many events.

(defstruct (bqueue (:constructor %make-bqueue))
  (head nil :type list)
  (tail nil :type list)
  (count 0 :type fixnum)
  (limit most-positive-fixnum :type fixnum)
  (lock (sb-thread:make-mutex :name "bqueue"))
  (nonempty (sb-thread:make-waitqueue))
  (closed nil))

(defun make-bqueue (&key (limit most-positive-fixnum)) (%make-bqueue :limit limit))

(defun bqueue-push (q item)
  "Enqueue ITEM.  Returns NIL (without enqueuing) when the queue is full or closed —
the caller decides how to shed load; a relay must never block an I/O thread."
  (sb-thread:with-mutex ((bqueue-lock q))
    (when (or (bqueue-closed q) (>= (bqueue-count q) (bqueue-limit q)))
      (return-from bqueue-push nil))
    (let ((cell (list item)))
      (if (bqueue-tail q)
          (setf (cdr (bqueue-tail q)) cell (bqueue-tail q) cell)
          (setf (bqueue-head q) cell (bqueue-tail q) cell)))
    (incf (bqueue-count q))
    (sb-thread:condition-notify (bqueue-nonempty q))
    t))

(defun bqueue-pop-batch (q &key (max most-positive-fixnum) (timeout nil))
  "Wait until Q is non-empty (or TIMEOUT seconds pass, or Q closes), then remove
and return up to MAX items, oldest first.  Returns NIL on timeout / close."
  (sb-thread:with-mutex ((bqueue-lock q))
    (loop while (and (null (bqueue-head q)) (not (bqueue-closed q)))
          do (unless (sb-thread:condition-wait (bqueue-nonempty q) (bqueue-lock q)
                                               :timeout timeout)
               (return-from bqueue-pop-batch nil)))
    (let ((items '()) (n 0))
      (declare (type fixnum n))
      (loop while (and (bqueue-head q) (< n max))
            do (push (pop (bqueue-head q)) items) (incf n))
      (unless (bqueue-head q) (setf (bqueue-tail q) nil))
      (decf (bqueue-count q) n)
      (nreverse items))))

(defun bqueue-pop (q &key timeout)
  (first (bqueue-pop-batch q :max 1 :timeout timeout)))

(defun bqueue-close (q)
  (sb-thread:with-mutex ((bqueue-lock q))
    (setf (bqueue-closed q) t)
    (sb-thread:condition-broadcast (bqueue-nonempty q))))
