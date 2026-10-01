;;;; src/log.lisp — the append-only event log.
;;;;
;;;; The log is the only persistent state (plus a 16-byte hash key).  Indexes
;;;; live in memory and are rebuilt from the log at startup, so the log carries a
;;;; small BINARY HEADER per record holding everything the indexes need —
;;;; created_at, kind, id, pubkey, the d-tag and tag key hashes — and startup
;;;; never parses JSON.  The JSON follows the header and is what clients receive.
;;;;
;;;; Record layout (little-endian):
;;;;    0 u32  total record length L (header + json + crc)
;;;;    4 u8   type: 1 = event, 2 = tombstone (the id at 24 is deleted)
;;;;    5 u8   format version (1)
;;;;    6 u16  number of tag hashes T
;;;;    8 u32  created_at
;;;;   12 u16  kind
;;;;   14 u16  reserved
;;;;   16 u32  expiration (0 = none)
;;;;   20 u32  json length J
;;;;   24      id      (32)
;;;;   56      pubkey  (32)
;;;;   88 u64  d-tag hash (addressable kinds), else 0
;;;;   96      T x u64 tag key hashes
;;;;   96+8T   json (J bytes)
;;;;   L-4 u32 CRC32 of bytes [0, L-4)
;;;;
;;;; Crash safety: a record is only meaningful once its CRC checks.  A crash
;;;; mid-append leaves a torn tail; replay stops at the first bad record and
;;;; truncates the file there.  Nothing is ever rewritten in place.

(in-package #:beacon)

(defconstant +rec-event+ 1)
(defconstant +rec-tombstone+ 2)
(defconstant +rec-header+ 96)

(declaim (inline get-u16 get-u32 get-u64))
(defun get-u16 (o i) (declare (type octets o) (type ufix i))
  (logior (aref o i) (ash (aref o (+ i 1)) 8)))
(defun get-u32 (o i) (declare (type octets o) (type ufix i))
  (logior (aref o i) (ash (aref o (+ i 1)) 8) (ash (aref o (+ i 2)) 16) (ash (aref o (+ i 3)) 24)))
(defun get-u64 (o i) (declare (type octets o) (type ufix i))
  (logior (get-u32 o i) (ash (get-u32 o (+ i 4)) 32)))

(defun obuf-u16 (b v) (obuf-byte b (ldb (byte 8 0) v)) (obuf-byte b (ldb (byte 8 8) v)))
(defun obuf-u32 (b v) (dotimes (i 4) (obuf-byte b (ldb (byte 8 (* 8 i)) v))))
(defun obuf-u64 (b v) (dotimes (i 8) (obuf-byte b (ldb (byte 8 (* 8 i)) v))))

(defun d-string-hash (d)
  "Hash of an addressable event's d-tag.  Deliberately the same as the tag key
of [\"d\", d], so a filter's #d values name replaceable slots directly."
  (let ((b (make-obuf 64)))
    (obuf-utf8 b d)
    (max 1 (tag-key-hash (char-code #\d) (obuf-data b) 0 (obuf-fill b)))))

(defun d-tag-hash (e)
  (if (event-d-tag e) (d-string-hash (event-d-tag e)) 0))

(defun encode-event-record (b e)
  "Append E's log record to obuf B.  Returns the record's length."
  (let* ((start (obuf-fill b))
         (hashes (event-tag-hashes e))
         (json (event-json e))
         (len (+ +rec-header+ (* 8 (length hashes)) (length json) 4)))
    (obuf-u32 b len)
    (obuf-byte b +rec-event+) (obuf-byte b 1)
    (obuf-u16 b (length hashes))
    (obuf-u32 b (event-created-at e))
    (obuf-u16 b (event-kind e)) (obuf-u16 b 0)
    (obuf-u32 b (event-expiration e))
    (obuf-u32 b (length json))
    (obuf-octets b (event-id e))
    (obuf-octets b (event-pubkey e))
    (obuf-u64 b (d-tag-hash e))
    (loop for h across hashes do (obuf-u64 b h))
    (obuf-octets b json)
    (obuf-u32 b (crc32 (obuf-data b) start (obuf-fill b)))
    len))

(defun encode-tombstone-record (b id)
  (let ((start (obuf-fill b)))
    (obuf-u32 b (+ +rec-header+ 4))
    (obuf-byte b +rec-tombstone+) (obuf-byte b 1)
    (obuf-u16 b 0)
    (dotimes (i 16) (obuf-byte b 0))       ; created_at .. json length
    (obuf-octets b id)
    (dotimes (i 40) (obuf-byte b 0))       ; pubkey, d-tag hash
    (obuf-u32 b (crc32 (obuf-data b) start (obuf-fill b)))
    (+ +rec-header+ 4)))

;;; Accessors over a record held in an octet vector at offset O.
(defun rec-type (r o) (aref r (+ o 4)))
(defun rec-ntags (r o) (get-u16 r (+ o 6)))
(defun rec-created-at (r o) (get-u32 r (+ o 8)))
(defun rec-kind (r o) (get-u16 r (+ o 12)))
(defun rec-expiration (r o) (get-u32 r (+ o 16)))
(defun rec-json-length (r o) (get-u32 r (+ o 20)))
(defun rec-dhash (r o) (get-u64 r (+ o 88)))
(defun rec-json-start (r o) (+ o +rec-header+ (* 8 (rec-ntags r o))))
(defun rec-tag-hash (r o i) (get-u64 r (+ o +rec-header+ (* 8 i))))

;;; ---- the writer side ---------------------------------------------------------

(defstruct (event-log (:constructor %make-event-log))
  (path nil)
  (out nil)                        ; output fd-stream, appending
  (size 0 :type (integer 0)))      ; bytes durably framed so far (= next offset)

(defun fd-of (stream) (sb-sys:fd-stream-fd stream))

(defun log-append (log b &key (sync t))
  "Write obuf B's contents at the end of the log.  With SYNC, fsync before
returning — the group commit point."
  (let ((out (event-log-out log)))
    (write-sequence (obuf-data b) out :end (obuf-fill b))
    (finish-output out)
    (when sync (sb-posix:fsync (fd-of out)))
    (incf (event-log-size log) (obuf-fill b))))

(defun log-sync (log)
  (finish-output (event-log-out log))
  (sb-posix:fsync (fd-of (event-log-out log))))

(defun close-event-log (log)
  (when (event-log-out log)
    (finish-output (event-log-out log))
    (close (event-log-out log))
    (setf (event-log-out log) nil)))

;;; ---- the reader side -----------------------------------------------------------
;;; Each reading thread owns a stream on the log (CL streams are not shared across
;;; threads).  The OS page cache keeps hot records in RAM.

(defstruct (log-reader (:constructor %make-log-reader))
  (in nil)
  (buf (make-octets 4096) :type octets))

(defun open-log-reader (path)
  (%make-log-reader :in (open path :element-type '(unsigned-byte 8) :direction :input)))

(defun close-log-reader (r) (close (log-reader-in r)))

(defun read-record (reader offset length)
  "Read LENGTH bytes at OFFSET into READER's buffer (reused).  Returns the buffer;
the record starts at index 0."
  (let ((buf (log-reader-buf reader)) (in (log-reader-in reader)))
    (when (< (length buf) length)
      (setf buf (make-octets (max length (* 2 (length buf)))) (log-reader-buf reader) buf))
    (file-position in offset)
    (let ((got (read-sequence buf in :end length)))
      (unless (= got length) (error "short read from the event log at ~d" offset)))
    buf))

;;; ---- replay ---------------------------------------------------------------------

(defvar *replay-chunk* (* 4 1024 1024) "Bytes read per refill during replay.")

(defun replay-log (path fn)
  "Call (FN record-octets start offset length) for every valid record of the
log at PATH, in order.  Returns the length of the valid prefix — the caller
truncates the file there if it is shorter than the file."
  (with-open-file (in path :element-type '(unsigned-byte 8) :direction :input :if-does-not-exist nil)
    (unless in (return-from replay-log 0))
    (let* ((chunk *replay-chunk*)
           (buf (make-octets (* 2 chunk)))
           (have 0) (pos 0)     ; bytes in BUF, read cursor in BUF
           (base 0)             ; file offset of BUF[0]
           (file-len (file-length in)))
      (flet ((fill-to (need)
               ;; ensure BUF[pos, pos+need) is loaded; NIL at end of file
               (when (> (+ pos need) have)
                 (replace buf buf :start2 pos :end2 have)
                 (decf have pos) (incf base pos) (setf pos 0)
                 (when (> need (length buf))
                   (let ((nb (make-octets (+ need chunk)))) (replace nb buf :end2 have) (setf buf nb)))
                 (setf have (read-sequence buf in :start have)))   ; returns an END INDEX, not a count
               (<= (+ pos need) have)))
        (loop
          (let ((off (+ base pos)))
            (when (>= off file-len) (return off))
            (unless (fill-to 4) (return off))
            (let ((len (get-u32 buf pos)))
              (unless (and (>= len (+ +rec-header+ 4)) (<= (+ off len) file-len) (fill-to len))
                (return off))
              (unless (and (= (crc32 buf pos (+ pos len -4)) (get-u32 buf (+ pos len -4)))
                           (member (rec-type buf pos) (list +rec-event+ +rec-tombstone+)))
                (return off))
              (funcall fn buf pos off len)
              (incf pos len))))))))

(defun truncate-file (path length)
  (with-open-file (s path :direction :io :element-type '(unsigned-byte 8) :if-exists :overwrite)
    (sb-posix:ftruncate (fd-of s) length)))

(defun open-event-log (path)
  "Open the log at PATH for appending (creating it).  The caller has already
replayed and truncated it."
  (let ((out (open path :element-type '(unsigned-byte 8) :direction :output
                        :if-exists :append :if-does-not-exist :create)))
    (%make-event-log :path path :out out :size (file-length out))))
