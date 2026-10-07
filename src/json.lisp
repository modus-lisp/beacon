;;;; src/json.lisp — JSON in, via json-simple, and the two string escapers.
;;;;
;;;; Reading is json-simple's parser (github.com/modus-lisp/json-simple), which
;;;; works on the octets of a WebSocket text frame in place (:start/:end), with
;;;; the representation a relay needs:
;;;;
;;;;   object  -> list of (key . value), keys are strings, order preserved
;;;;   array   -> simple-vector
;;;;   string  -> string (always valid Unicode: lone surrogates are rejected)
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
;;;; They write UTF-8 straight into an OBUF; json-simple:write-json-string is
;;;; the same pair of rules for character streams (its \u00XX hex is uppercase).

(in-package #:beacon)

(deftype json-error () 'json-simple:json-parse-error)

(defun json-error-message (e) (princ-to-string e))

(defconstant +max-json-depth+ 64)

(defun json-parse (data &optional (start 0) (end (length data)))
  "Parse one JSON value from DATA[START,END) (octets).  Trailing whitespace is
allowed, anything else after the value is an error."
  (json-simple:parse data :start start :end end :max-depth +max-json-depth+
                          :object-type :alist :true :true :false :false :null :null))

(defun json-parse-string (string)
  (json-simple:parse string :max-depth +max-json-depth+
                            :object-type :alist :true :true :false :false :null :null))

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
