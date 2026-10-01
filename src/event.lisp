;;;; src/event.lisp — NIP-01 events: parse, validate, canonical id, stored form.
;;;;
;;;; An incoming event is untrusted JSON.  PARSE-EVENT checks every field's type
;;;; and shape, recomputes the id from the canonical serialization, and produces
;;;; the bytes we will store and send: one STRICT JSON object with a fixed key
;;;; order.  Every client that asks for the event gets exactly those bytes, so a
;;;; query result is a copy, never a re-serialization.  (The signature is checked
;;;; separately, in the verify pool — it is the expensive part.)

(in-package #:beacon)

(define-condition invalid-event (error)
  ((reason :initarg :reason :reader invalid-event-reason))
  (:report (lambda (c s) (format s "invalid: ~a" (invalid-event-reason c)))))

(defun reject (fmt &rest args)
  (error 'invalid-event :reason (apply #'format nil fmt args)))

(defstruct (event (:constructor %make-event))
  (id nil :type (or null octets))          ; 32 bytes
  (pubkey nil :type (or null octets))      ; 32 bytes, x-only
  (sig nil :type (or null octets))         ; 64 bytes
  (created-at 0 :type (unsigned-byte 32))
  (kind 0 :type (unsigned-byte 16))
  (tags #() :type simple-vector)           ; of simple-vectors of strings
  (content "" :type string)
  (json nil :type (or null octets))        ; the stored/sent form
  (d-tag nil)                              ; addressable identifier ("" when absent)
  (expiration 0 :type (unsigned-byte 32))  ; NIP-40, 0 = never
  (tag-hashes nil))                        ; (simple-array u64) of indexed tag keys

(defun event-id-hex (e) (hex-encode (event-id e)))

;;; ---- kind classes (NIP-01) -------------------------------------------------

(declaim (inline replaceable-kind-p ephemeral-kind-p addressable-kind-p))
(defun replaceable-kind-p (k) (or (= k 0) (= k 3) (<= 10000 k 19999)))
(defun ephemeral-kind-p (k) (<= 20000 k 29999))
(defun addressable-kind-p (k) (<= 30000 k 39999))

;;; ---- limits ----------------------------------------------------------------

(defvar *max-tags* 2500)
(defvar *max-tag-elements* 50)
(defvar *max-content-chars* (* 256 1024))

;;; ---- canonical serialization and id ------------------------------------------

(defun obuf-tags (b tags &key canonical)
  (obuf-byte b 91)
  (loop for tag across tags for i from 0 do
    (when (plusp i) (obuf-byte b 44))
    (obuf-byte b 91)
    (loop for item across tag for j from 0 do
      (when (plusp j) (obuf-byte b 44))
      (obuf-json-string b item :canonical canonical))
    (obuf-byte b 93))
  (obuf-byte b 93))

(defun canonical-bytes (b pubkey created-at kind tags content)
  "Write [0,<pubkey>,<created_at>,<kind>,<tags>,<content>] into obuf B."
  (obuf-ascii b "[0,\"")
  (obuf-hex b pubkey)
  (obuf-ascii b "\",")
  (obuf-uint b created-at) (obuf-byte b 44)
  (obuf-uint b kind) (obuf-byte b 44)
  (obuf-tags b tags :canonical t) (obuf-byte b 44)
  (obuf-json-string b content :canonical t)
  (obuf-byte b 93))

(defun compute-event-id (pubkey created-at kind tags content &optional (b (make-obuf 512)))
  (obuf-reset b)
  (canonical-bytes b pubkey created-at kind tags content)
  (sha256 (obuf-data b) 0 (obuf-fill b)))

(defun stored-json (e &optional (b (make-obuf 512)))
  (obuf-reset b)
  (obuf-ascii b "{\"id\":\"") (obuf-hex b (event-id e))
  (obuf-ascii b "\",\"pubkey\":\"") (obuf-hex b (event-pubkey e))
  (obuf-ascii b "\",\"created_at\":") (obuf-uint b (event-created-at e))
  (obuf-ascii b ",\"kind\":") (obuf-uint b (event-kind e))
  (obuf-ascii b ",\"tags\":") (obuf-tags b (event-tags e))
  (obuf-ascii b ",\"content\":") (obuf-json-string b (event-content e))
  (obuf-ascii b ",\"sig\":\"") (obuf-hex b (event-sig e))
  (obuf-ascii b "\"}")
  (obuf-copy b))

;;; ---- indexed tags --------------------------------------------------------------
;;; NIP-01 indexes single-letter tag names: a filter "#e": [...] matches events
;;; with a tag ["e", <value>, ...].  Only the FIRST value of each tag is indexed.
;;; A key is SipHash(letter || utf8(value)) under the store's secret key.

(defun tag-key-hash (letter-code value-octets &optional (start 0) (end (length value-octets)))
  (siphash64 value-octets start end letter-code))

(defun single-letter-tag-p (name)
  (and (= (length name) 1)
       (let ((c (char-code (char name 0))))
         (or (<= 97 c 122) (<= 65 c 90)))))

(defun compute-tag-hashes (tags)
  (let ((hashes '()) (b (make-obuf 128)))
    (loop for tag across tags
          when (and (>= (length tag) 2) (single-letter-tag-p (svref tag 0)))
            do (obuf-reset b)
               (obuf-utf8 b (svref tag 1))
               (pushnew (tag-key-hash (char-code (char (svref tag 0) 0)) (obuf-data b) 0 (obuf-fill b))
                        hashes))
    (make-array (length hashes) :element-type 'u64 :initial-contents (nreverse hashes))))

(defun find-tag-value (tags name)
  (loop for tag across tags
        when (and (>= (length tag) 2) (string= (svref tag 0) name))
          do (return (svref tag 1))))

;;; ---- parsing -------------------------------------------------------------------

(defun %hex-field (obj key octets)
  (let ((v (json-get obj key)))
    (unless (stringp v) (reject "~a must be a string" key))
    (or (hex-decode v octets) (reject "~a must be ~d lowercase hex characters" key (* 2 octets)))))

(defun %int-field (obj key max)
  (let ((v (json-get obj key)))
    (unless (and (integerp v) (<= 0 v max)) (reject "~a must be an integer in [0, ~d]" key max))
    v))

(defun parse-event (obj)
  "Build a validated EVENT from a parsed JSON object, checking the id (but not
the signature).  Signals INVALID-EVENT with a client-facing reason."
  (unless (listp obj) (reject "event must be a JSON object"))
  (let* ((id (%hex-field obj "id" 32))
         (pubkey (%hex-field obj "pubkey" 32))
         (sig (%hex-field obj "sig" 64))
         (created-at (%int-field obj "created_at" #xffffffff))
         (kind (%int-field obj "kind" 65535))
         (tags (json-get obj "tags"))
         (content (json-get obj "content")))
    (unless (simple-vector-p tags) (reject "tags must be an array"))
    (when (> (length tags) *max-tags*) (reject "too many tags"))
    (loop for tag across tags do
      (unless (simple-vector-p tag) (reject "each tag must be an array"))
      (when (> (length tag) *max-tag-elements*) (reject "tag too long"))
      (loop for x across tag do (unless (stringp x) (reject "tag elements must be strings"))))
    (unless (stringp content) (reject "content must be a string"))
    (when (> (length content) *max-content-chars*) (reject "content too large"))
    (let ((computed (compute-event-id pubkey created-at kind tags content)))
      (unless (octets-string= computed id) (reject "event id does not match its content")))
    (let* ((exp-str (find-tag-value tags "expiration"))
           (expiration (or (and exp-str (every #'digit-char-p exp-str) (plusp (length exp-str))
                                (< (length exp-str) 11)
                                (min (parse-integer exp-str) #xffffffff))
                           0))
           (e (%make-event :id id :pubkey pubkey :sig sig :created-at created-at :kind kind
                           :tags tags :content content :expiration expiration
                           :d-tag (when (addressable-kind-p kind)
                                    (or (find-tag-value tags "d") ""))
                           :tag-hashes (compute-tag-hashes tags))))
      (setf (event-json e) (stored-json e))
      e)))

(defun parse-event-json (octets)
  "Parse and validate an event from JSON OCTETS (or a string)."
  (parse-event (if (stringp octets) (json-parse-string octets) (json-parse octets))))
