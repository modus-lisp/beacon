;;;; src/json.lisp — a byte-level JSON reader and the two string escapers.
;;;;
;;;; The reader works directly on the octets of a WebSocket text frame: no
;;;; intermediate string, UTF-8 decoded as it goes.  Values:
;;;;
;;;;   object  -> list of (key . value), keys are strings, order preserved
;;;;   array   -> simple-vector
;;;;   string  -> string
;;;;   number  -> integer, or double-float when it has a fraction/exponent
;;;;   true / false / null -> :true / :false / :null
;;;;
;;;; Two escapers, because NIP-01 needs two:
;;;;   CANONICAL — the event-id serialization.  Escapes exactly \b \t \n \f \r
;;;;               \" \\ and writes every other character verbatim, as NIP-01
;;;;               mandates, so the id we compute is the id the author signed.
;;;;   STRICT    — everything we send.  Additionally escapes the remaining C0
;;;;               controls as \u00XX, because verbatim control bytes are not
;;;;               valid JSON and some clients' parsers reject them.  Both decode
;;;;               to the same string, so the event a client parses is the event
;;;;               whose id it can recompute.

(in-package #:beacon)

(define-condition json-error (error)
  ((message :initarg :message :reader json-error-message))
  (:report (lambda (c s) (format s "bad JSON: ~a" (json-error-message c)))))

(defun json-fail (fmt &rest args)
  (error 'json-error :message (apply #'format nil fmt args)))

(defconstant +max-json-depth+ 64)

(defun json-parse (data &optional (start 0) (end (length data)))
  "Parse one JSON value from DATA[START,END) (octets).  Trailing whitespace is
allowed, anything else after the value is an error."
  (declare (optimize (speed 3) (safety 1))
           (type octets data) (type ufix start end))
  (let ((pos start)
        (sbuf (make-string 64)))
    (declare (type ufix pos) (type (simple-array character (*)) sbuf))
    (labels ((peek () (if (< pos end) (aref data pos) (json-fail "unexpected end")))
             (skip-ws ()
               (loop while (and (< pos end)
                                (let ((c (aref data pos)))
                                  (or (= c 32) (= c 9) (= c 10) (= c 13))))
                     do (incf pos)))
             (expect-lit (lit value)
               (declare (type simple-string lit))
               (unless (<= (+ pos (length lit)) end) (json-fail "unexpected end"))
               (dotimes (i (length lit))
                 (unless (= (aref data (+ pos i)) (char-code (schar lit i)))
                   (json-fail "bad literal at ~d" pos)))
               (incf pos (length lit))
               value)
             (value (depth)
               (declare (type fixnum depth))
               (when (> depth +max-json-depth+) (json-fail "nesting too deep"))
               (skip-ws)
               (let ((c (peek)))
                 (case c
                   (34 (incf pos) (str))              ; "
                   (123 (incf pos) (obj depth))       ; {
                   (91 (incf pos) (arr depth))        ; [
                   (116 (expect-lit "true" :true))
                   (102 (expect-lit "false" :false))
                   (110 (expect-lit "null" :null))
                   (t (if (or (= c 45) (<= 48 c 57)) (num) (json-fail "unexpected byte ~d at ~d" c pos))))))
             (obj (depth)
               (let ((items '()))
                 (skip-ws)
                 (when (= (peek) 125) (incf pos) (return-from obj '()))
                 (loop
                   (skip-ws)
                   (unless (= (peek) 34) (json-fail "object key must be a string"))
                   (incf pos)
                   (let ((k (str)))
                     (skip-ws)
                     (unless (= (peek) 58) (json-fail "expected ':'"))
                     (incf pos)
                     (push (cons k (value (1+ depth))) items))
                   (skip-ws)
                   (case (peek)
                     (44 (incf pos))
                     (125 (incf pos) (return (nreverse items)))
                     (t (json-fail "expected ',' or '}'"))))))
             (arr (depth)
               (let ((items '()) (n 0))
                 (declare (type fixnum n))
                 (skip-ws)
                 (when (= (peek) 93) (incf pos) (return-from arr (vector)))
                 (loop
                   (push (value (1+ depth)) items) (incf n)
                   (skip-ws)
                   (case (peek)
                     (44 (incf pos))
                     (93 (incf pos)
                      (let ((v (make-array n)))
                        (loop for i from (1- n) downto 0 do (setf (svref v i) (pop items)))
                        (return v)))
                     (t (json-fail "expected ',' or ']'"))))))
             (num ()
               (let ((s pos) (neg nil) (int 0) (frac nil))
                 (declare (type ufix s))
                 (when (= (peek) 45) (setf neg t) (incf pos))
                 (unless (and (< pos end) (<= 48 (aref data pos) 57)) (json-fail "bad number"))
                 (if (= (aref data pos) 48)
                     (incf pos)
                     (loop while (and (< pos end) (<= 48 (aref data pos) 57))
                           do (setf int (+ (* int 10) (- (aref data pos) 48))) (incf pos)))
                 (when (and (< pos end) (= (aref data pos) 46))
                   (setf frac t) (incf pos)
                   (unless (and (< pos end) (<= 48 (aref data pos) 57)) (json-fail "bad fraction"))
                   (loop while (and (< pos end) (<= 48 (aref data pos) 57)) do (incf pos)))
                 (when (and (< pos end) (member (aref data pos) '(101 69)))
                   (setf frac t) (incf pos)
                   (when (and (< pos end) (member (aref data pos) '(43 45))) (incf pos))
                   (unless (and (< pos end) (<= 48 (aref data pos) 57)) (json-fail "bad exponent"))
                   (loop while (and (< pos end) (<= 48 (aref data pos) 57)) do (incf pos)))
                 (if frac
                     (let ((*read-default-float-format* 'double-float))
                       (let ((x (ignore-errors
                                 (coerce (let ((*read-eval* nil))
                                           (read-from-string (map 'string #'code-char (subseq data s pos))))
                                         'double-float))))
                         (or x (json-fail "number out of range"))))
                     (if neg (- int) int))))
             (put (n code)
               (declare (type ufix n) (type fixnum code))
               (when (>= n (length sbuf))
                 (let ((new (make-string (* 2 (length sbuf)))))
                   (replace new sbuf) (setf sbuf new)))
               (setf (schar sbuf n) (code-char code)))
             (cont ()
               (unless (< pos end) (json-fail "truncated UTF-8"))
               (let ((b (aref data pos)))
                 (unless (= (logand b #xC0) #x80) (json-fail "bad UTF-8 continuation"))
                 (incf pos)
                 (logand b #x3F)))
             (hex4 ()
               (unless (<= (+ pos 4) end) (json-fail "truncated \\u escape"))
               (let ((v 0))
                 (declare (type fixnum v))
                 (dotimes (i 4)
                   (let* ((c (aref data (+ pos i)))
                          (d (cond ((<= 48 c 57) (- c 48)) ((<= 97 c 102) (- c 87))
                                   ((<= 65 c 70) (- c 55)) (t (json-fail "bad \\u escape")))))
                     (setf v (+ (* v 16) d))))
                 (incf pos 4)
                 v))
             (str ()
               (let ((n 0))
                 (declare (type ufix n))
                 (loop
                   (unless (< pos end) (json-fail "unterminated string"))
                   (let ((b (aref data pos)))
                     (cond
                       ((= b 34) (incf pos) (return (subseq sbuf 0 n)))
                       ((= b 92)
                        (incf pos)
                        (let ((e (peek)))
                          (incf pos)
                          (put n (case e
                                   (34 34) (92 92) (47 47) (98 8) (102 12) (110 10) (114 13) (116 9)
                                   (117 (let ((u (hex4)))
                                          (cond ((<= #xD800 u #xDBFF)
                                                 (unless (and (< (+ pos 1) end) (= (aref data pos) 92)
                                                              (= (aref data (1+ pos)) 117))
                                                   (json-fail "lone surrogate"))
                                                 (incf pos 2)
                                                 (let ((lo (hex4)))
                                                   (unless (<= #xDC00 lo #xDFFF) (json-fail "bad surrogate pair"))
                                                   (+ #x10000 (ash (- u #xD800) 10) (- lo #xDC00))))
                                                ((<= #xDC00 u #xDFFF) (json-fail "lone surrogate"))
                                                (t u))))
                                   (t (json-fail "bad escape"))))
                          (incf n)))
                       ((< b 32) (json-fail "control character in string"))
                       ((< b #x80) (put n b) (incf n) (incf pos))
                       (t
                        (incf pos)
                        (let ((code
                                (cond ((= (logand b #xE0) #xC0)
                                       (let ((c (logior (ash (logand b #x1F) 6) (cont))))
                                         (when (< c #x80) (json-fail "overlong UTF-8")) c))
                                      ((= (logand b #xF0) #xE0)
                                       (let* ((c1 (cont)) (c2 (cont))
                                              (c (logior (ash (logand b #x0F) 12) (ash c1 6) c2)))
                                         (when (or (< c #x800) (<= #xD800 c #xDFFF)) (json-fail "bad UTF-8"))
                                         c))
                                      ((= (logand b #xF8) #xF0)
                                       (let* ((c1 (cont)) (c2 (cont)) (c3 (cont))
                                              (c (logior (ash (logand b #x07) 18) (ash c1 12) (ash c2 6) c3)))
                                         (when (or (< c #x10000) (> c #x10FFFF)) (json-fail "bad UTF-8"))
                                         c))
                                      (t (json-fail "bad UTF-8 lead byte")))))
                          (put n code) (incf n)))))))))
      (let ((v (value 0)))
        (skip-ws)
        (unless (= pos end) (json-fail "trailing data"))
        v))))

(defun json-parse-string (string)
  (json-parse (string-utf8 string)))

;;; ---- writing -----------------------------------------------------------------

(defun obuf-json-string (b string &key canonical)
  "Append STRING as a quoted JSON string, UTF-8 encoded.  CANONICAL selects the
NIP-01 id-serialization escape set (see the file header)."
  (declare (type obuf b) (type string string))
  (obuf-byte b 34)
  (loop for ch across string
        for c of-type fixnum = (char-code ch)
        do (case c
             (8 (obuf-byte b 92) (obuf-byte b 98))
             (9 (obuf-byte b 92) (obuf-byte b 116))
             (10 (obuf-byte b 92) (obuf-byte b 110))
             (12 (obuf-byte b 92) (obuf-byte b 102))
             (13 (obuf-byte b 92) (obuf-byte b 114))
             (34 (obuf-byte b 92) (obuf-byte b 34))
             (92 (obuf-byte b 92) (obuf-byte b 92))
             (t (cond ((and (< c 32) (not canonical))
                       (obuf-ascii b "\\u00")
                       (obuf-byte b (aref +hex-digits+ (ash c -4)))
                       (obuf-byte b (aref +hex-digits+ (logand c 15))))
                      ((< c #x80) (obuf-byte b c))
                      (t (obuf-utf8 b (string ch)))))))
  (obuf-byte b 34)
  b)

(defun json-get (object key)
  "Value of KEY in a parsed JSON object (alist), or NIL."
  (cdr (assoc key object :test #'string=)))
