;;;; src/hash.lisp — SHA-256, SHA-1, base64, SipHash-2-4, CRC32.
;;;;
;;;; SHA-256 is on the ingest hot path twice per event (the event id, then the
;;;; BIP340 challenge), so it is written for SBCL's modular 32-bit arithmetic and
;;;; conses nothing per block.  It also exposes a MIDSTATE: the BIP340 challenge
;;;; hash begins with the same 64-byte block (SHA256(tag) || SHA256(tag)) for
;;;; every event, so that block is compressed once at load time.
;;;;
;;;; SHA-1 and base64 exist only for the WebSocket handshake.  SipHash-2-4 is the
;;;; keyed hash behind every in-memory index: keyed with a per-store secret so a
;;;; client cannot grind tag values or pubkeys that collide in our tables.

(in-package #:beacon)

(deftype u32 () '(unsigned-byte 32))
(deftype u64 () '(unsigned-byte 64))

(defmacro u32+ (&rest xs) `(ldb (byte 32 0) (+ ,@xs)))
(defmacro rotr32 (x n) `(logior (ash ,x ,(- n)) (ldb (byte 32 0) (ash ,x ,(- 32 n)))))
(defmacro rotl32 (x n) `(logior (ldb (byte 32 0) (ash ,x ,n)) (ash ,x ,(- n 32))))

;;; ---- SHA-256 ---------------------------------------------------------------

(declaim (type (simple-array u32 (64)) +sha256-k+))
(defparameter +sha256-k+
  (make-array 64 :element-type 'u32 :initial-contents
   '(#x428a2f98 #x71374491 #xb5c0fbcf #xe9b5dba5 #x3956c25b #x59f111f1 #x923f82a4 #xab1c5ed5
     #xd807aa98 #x12835b01 #x243185be #x550c7dc3 #x72be5d74 #x80deb1fe #x9bdc06a7 #xc19bf174
     #xe49b69c1 #xefbe4786 #x0fc19dc6 #x240ca1cc #x2de92c6f #x4a7484aa #x5cb0a9dc #x76f988da
     #x983e5152 #xa831c66d #xb00327c8 #xbf597fc7 #xc6e00bf3 #xd5a79147 #x06ca6351 #x14292967
     #x27b70a85 #x2e1b2138 #x4d2c6dfc #x53380d13 #x650a7354 #x766a0abb #x81c2c92e #x92722c85
     #xa2bfe8a1 #xa81a664b #xc24b8b70 #xc76c51a3 #xd192e819 #xd6990624 #xf40e3585 #x106aa070
     #x19a4c116 #x1e376c08 #x2748774c #x34b0bcb5 #x391c0cb3 #x4ed8aa4a #x5b9cca4f #x682e6ff3
     #x748f82ee #x78a5636f #x84c87814 #x8cc70208 #x90befffa #xa4506ceb #xbef9a3f7 #xc67178f2)))

(defstruct (sha256-ctx (:constructor %make-sha256-ctx))
  (h (make-array 8 :element-type 'u32) :type (simple-array u32 (8)))
  (w (make-array 64 :element-type 'u32) :type (simple-array u32 (64)))
  (buf (make-octets 64) :type (simple-array (unsigned-byte 8) (64)))
  (buflen 0 :type (integer 0 64))
  (total 0 :type (unsigned-byte 62)))

(defun sha256-reset (ctx)
  (let ((h (sha256-ctx-h ctx)))
    (setf (aref h 0) #x6a09e667 (aref h 1) #xbb67ae85 (aref h 2) #x3c6ef372
          (aref h 3) #xa54ff53a (aref h 4) #x510e527f (aref h 5) #x9b05688c
          (aref h 6) #x1f83d9ab (aref h 7) #x5be0cd19))
  (setf (sha256-ctx-buflen ctx) 0 (sha256-ctx-total ctx) 0)
  ctx)

(defun make-sha256-ctx () (sha256-reset (%make-sha256-ctx)))

(defun sha256-copy-state (from to)
  "Make TO continue from FROM's state (midstate reuse)."
  (replace (sha256-ctx-h to) (sha256-ctx-h from))
  (replace (sha256-ctx-buf to) (sha256-ctx-buf from))
  (setf (sha256-ctx-buflen to) (sha256-ctx-buflen from)
        (sha256-ctx-total to) (sha256-ctx-total from))
  to)

(defun sha256-compress (ctx data offset)
  "Compress the 64-byte block DATA[OFFSET, OFFSET+64) into CTX's state."
  (declare (optimize (speed 3) (safety 0) (debug 0))
           (type octets data) (type ufix offset))
  (let ((w (sha256-ctx-w ctx)) (h (sha256-ctx-h ctx)) (k +sha256-k+))
    (dotimes (i 16)
      (let ((j (+ offset (* 4 i))))
        (setf (aref w i) (logior (ash (aref data j) 24) (ash (aref data (+ j 1)) 16)
                                 (ash (aref data (+ j 2)) 8) (aref data (+ j 3))))))
    (loop for i of-type fixnum from 16 below 64 do
      (let* ((w15 (aref w (- i 15))) (w2 (aref w (- i 2)))
             (s0 (logxor (rotr32 w15 7) (rotr32 w15 18) (ash w15 -3)))
             (s1 (logxor (rotr32 w2 17) (rotr32 w2 19) (ash w2 -10))))
        (declare (type u32 w15 w2 s0 s1))
        (setf (aref w i) (u32+ (aref w (- i 16)) s0 (aref w (- i 7)) s1))))
    (let ((a (aref h 0)) (b (aref h 1)) (c (aref h 2)) (d (aref h 3))
          (e (aref h 4)) (f (aref h 5)) (g (aref h 6)) (hh (aref h 7)))
      (declare (type u32 a b c d e f g hh))
      (dotimes (i 64)
        (let* ((s1 (logxor (rotr32 e 6) (rotr32 e 11) (rotr32 e 25)))
               (ch (logxor (logand e f) (logand (logxor e #xffffffff) g)))
               (t1 (u32+ hh s1 ch (aref k i) (aref w i)))
               (s0 (logxor (rotr32 a 2) (rotr32 a 13) (rotr32 a 22)))
               (maj (logxor (logand a b) (logand a c) (logand b c)))
               (t2 (u32+ s0 maj)))
          (declare (type u32 s1 ch t1 s0 maj t2))
          (setf hh g g f f e e (u32+ d t1) d c c b b a a (u32+ t1 t2))))
      (setf (aref h 0) (u32+ (aref h 0) a) (aref h 1) (u32+ (aref h 1) b)
            (aref h 2) (u32+ (aref h 2) c) (aref h 3) (u32+ (aref h 3) d)
            (aref h 4) (u32+ (aref h 4) e) (aref h 5) (u32+ (aref h 5) f)
            (aref h 6) (u32+ (aref h 6) g) (aref h 7) (u32+ (aref h 7) hh))))
  ctx)

(defun sha256-update (ctx data &optional (start 0) (end (length data)))
  (declare (type octets data) (type ufix start end))
  (incf (sha256-ctx-total ctx) (- end start))
  (let ((buf (sha256-ctx-buf ctx)) (pos start))
    (declare (type ufix pos))
    ;; finish a partial block first
    (when (plusp (sha256-ctx-buflen ctx))
      (let* ((have (sha256-ctx-buflen ctx)) (take (min (- 64 have) (- end pos))))
        (replace buf data :start1 have :start2 pos :end2 (+ pos take))
        (incf pos take)
        (setf (sha256-ctx-buflen ctx) (+ have take))
        (when (= (sha256-ctx-buflen ctx) 64)
          (sha256-compress ctx buf 0)
          (setf (sha256-ctx-buflen ctx) 0))))
    (loop while (<= (+ pos 64) end)
          do (sha256-compress ctx data pos) (incf pos 64))
    (when (< pos end)
      (replace buf data :start1 0 :start2 pos :end2 end)
      (setf (sha256-ctx-buflen ctx) (- end pos))))
  ctx)

(defun sha256-final (ctx &optional (out (make-octets 32)) (out-start 0))
  (declare (type octets out))
  (let* ((bits (* 8 (sha256-ctx-total ctx)))
         (buf (sha256-ctx-buf ctx))
         (n (sha256-ctx-buflen ctx)))
    (setf (aref buf n) #x80)
    (fill buf 0 :start (1+ n))
    (when (> (1+ n) 56)
      (sha256-compress ctx buf 0)
      (fill buf 0))
    (dotimes (i 8)
      (setf (aref buf (- 63 i)) (ldb (byte 8 (* 8 i)) bits)))
    (sha256-compress ctx buf 0)
    (let ((h (sha256-ctx-h ctx)))
      (dotimes (i 8)
        (let ((v (aref h i)) (j (+ out-start (* 4 i))))
          (setf (aref out j) (ldb (byte 8 24) v) (aref out (+ j 1)) (ldb (byte 8 16) v)
                (aref out (+ j 2)) (ldb (byte 8 8) v) (aref out (+ j 3)) (ldb (byte 8 0) v)))))
    out))

(defun sha256 (data &optional (start 0) (end (length data)))
  "SHA-256 of DATA[START,END) — a fresh 32-byte vector."
  (let ((ctx (make-sha256-ctx)))
    (sha256-update ctx data start end)
    (sha256-final ctx)))

;;; ---- SHA-1 (WebSocket handshake only) ---------------------------------------

(defun sha1 (data)
  (declare (type octets data))
  (let* ((len (length data))
         (padlen (* 64 (ceiling (+ len 9) 64)))
         (m (make-octets padlen))
         (w (make-array 80 :element-type 'u32))
         (h0 #x67452301) (h1 #xEFCDAB89) (h2 #x98BADCFE) (h3 #x10325476) (h4 #xC3D2E1F0))
    (declare (type u32 h0 h1 h2 h3 h4))
    (replace m data)
    (setf (aref m len) #x80)
    (dotimes (i 8) (setf (aref m (- padlen 1 i)) (ldb (byte 8 (* 8 i)) (* 8 len))))
    (loop for blk from 0 below padlen by 64 do
      (dotimes (i 16)
        (let ((j (+ blk (* 4 i))))
          (setf (aref w i) (logior (ash (aref m j) 24) (ash (aref m (+ j 1)) 16)
                                   (ash (aref m (+ j 2)) 8) (aref m (+ j 3))))))
      (loop for i from 16 below 80 do
        (let ((x (logxor (aref w (- i 3)) (aref w (- i 8)) (aref w (- i 14)) (aref w (- i 16)))))
          (setf (aref w i) (rotl32 x 1))))
      (let ((a h0) (b h1) (c h2) (d h3) (e h4))
        (declare (type u32 a b c d e))
        (dotimes (i 80)
          (multiple-value-bind (f k)
              (cond ((< i 20) (values (logior (logand b c) (logand (logxor b #xffffffff) d)) #x5A827999))
                    ((< i 40) (values (logxor b c d) #x6ED9EBA1))
                    ((< i 60) (values (logior (logand b c) (logand b d) (logand c d)) #x8F1BBCDC))
                    (t (values (logxor b c d) #xCA62C1D6)))
            (let ((tmp (u32+ (rotl32 a 5) f e k (aref w i))))
              (setf e d d c c (rotl32 b 30) b a a tmp))))
        (setf h0 (u32+ h0 a) h1 (u32+ h1 b) h2 (u32+ h2 c) h3 (u32+ h3 d) h4 (u32+ h4 e))))
    (let ((out (make-octets 20)))
      (loop for v in (list h0 h1 h2 h3 h4) for j from 0 by 4
            do (setf (aref out j) (ldb (byte 8 24) v) (aref out (+ j 1)) (ldb (byte 8 16) v)
                     (aref out (+ j 2)) (ldb (byte 8 8) v) (aref out (+ j 3)) (ldb (byte 8 0) v)))
      out)))

;;; ---- base64 ----------------------------------------------------------------

(defparameter +b64+ "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/")

(defun base64-encode (data)
  (declare (type octets data))
  (with-output-to-string (s)
    (loop for i from 0 below (length data) by 3
          for n = (- (length data) i)
          for b0 = (aref data i)
          for b1 = (if (> n 1) (aref data (+ i 1)) 0)
          for b2 = (if (> n 2) (aref data (+ i 2)) 0)
          for v = (logior (ash b0 16) (ash b1 8) b2)
          do (write-char (char +b64+ (ldb (byte 6 18) v)) s)
             (write-char (char +b64+ (ldb (byte 6 12) v)) s)
             (write-char (if (> n 1) (char +b64+ (ldb (byte 6 6) v)) #\=) s)
             (write-char (if (> n 2) (char +b64+ (ldb (byte 6 0) v)) #\=) s))))

;;; ---- SipHash-2-4 -----------------------------------------------------------

(defmacro u64+ (a b) `(ldb (byte 64 0) (+ ,a ,b)))
(defmacro rotl64 (x n) `(logior (ldb (byte 64 0) (ash ,x ,n)) (ash ,x ,(- n 64))))

(defmacro %sipround (v0 v1 v2 v3)
  `(progn
     (setf ,v0 (u64+ ,v0 ,v1) ,v1 (rotl64 ,v1 13) ,v1 (logxor ,v1 ,v0) ,v0 (rotl64 ,v0 32))
     (setf ,v2 (u64+ ,v2 ,v3) ,v3 (rotl64 ,v3 16) ,v3 (logxor ,v3 ,v2))
     (setf ,v0 (u64+ ,v0 ,v3) ,v3 (rotl64 ,v3 21) ,v3 (logxor ,v3 ,v0))
     (setf ,v2 (u64+ ,v2 ,v1) ,v1 (rotl64 ,v1 17) ,v1 (logxor ,v1 ,v2) ,v2 (rotl64 ,v2 32))))

(declaim (type u64 *sip-k0* *sip-k1*))
(defvar *sip-k0* #x0706050403020100)
(defvar *sip-k1* #x0f0e0d0c0b0a0908)

(defun siphash64 (data &optional (start 0) (end (length data)) (prefix-byte nil)
                       (k0 *sip-k0*) (k1 *sip-k1*))
  "SipHash-2-4 of [PREFIX-BYTE] || DATA[START,END) under key (K0 K1).
PREFIX-BYTE lets a tag hash fold in the tag letter without copying the value."
  (declare (optimize (speed 3) (safety 0))
           (type octets data) (type ufix start end) (type u64 k0 k1))
  (let* ((v0 (logxor k0 #x736f6d6570736575))
         (v1 (logxor k1 #x646f72616e646f6d))
         (v2 (logxor k0 #x6c7967656e657261))
         (v3 (logxor k1 #x7465646279746573))
         (len (+ (- end start) (if prefix-byte 1 0)))
         (pos 0))
    (declare (type u64 v0 v1 v2 v3) (type ufix len pos))
    (flet ((byte-at (i)
             (declare (type ufix i))
             (if prefix-byte
                 (if (zerop i) (the (unsigned-byte 8) prefix-byte) (aref data (+ start i -1)))
                 (aref data (+ start i)))))
      (declare (inline byte-at))
      (loop while (<= (+ pos 8) len) do
        (let ((m 0))
          (declare (type u64 m))
          (dotimes (i 8) (setf m (logior m (ash (byte-at (+ pos i)) (* 8 i)))))
          (setf v3 (logxor v3 m))
          (%sipround v0 v1 v2 v3) (%sipround v0 v1 v2 v3)
          (setf v0 (logxor v0 m))
          (incf pos 8)))
      (let ((m (ash (ldb (byte 8 0) len) 56)))
        (declare (type u64 m))
        (loop for i from 0 below (- len pos)
              do (setf m (logior m (ash (byte-at (+ pos i)) (* 8 i)))))
        (setf v3 (logxor v3 m))
        (%sipround v0 v1 v2 v3) (%sipround v0 v1 v2 v3)
        (setf v0 (logxor v0 m))))
    (setf v2 (logxor v2 #xff))
    (%sipround v0 v1 v2 v3) (%sipround v0 v1 v2 v3)
    (%sipround v0 v1 v2 v3) (%sipround v0 v1 v2 v3)
    (logxor v0 v1 v2 v3)))

(defun set-hash-key (key16)
  "Install the store's 16-byte secret as the SipHash key."
  (flet ((le64 (o) (loop for i below 8 sum (ash (aref key16 (+ o i)) (* 8 i)))))
    (setf *sip-k0* (le64 0) *sip-k1* (le64 8))))

;;; ---- CRC32 (IEEE) ----------------------------------------------------------

(declaim (type (simple-array u32 (256)) +crc-table+))
(defparameter +crc-table+
  (let ((tab (make-array 256 :element-type 'u32)))
    (dotimes (n 256 tab)
      (let ((c n))
        (dotimes (k 8) (setf c (if (logbitp 0 c) (logxor #xEDB88320 (ash c -1)) (ash c -1))))
        (setf (aref tab n) c)))))

(defun crc32 (data &optional (start 0) (end (length data)))
  (declare (optimize (speed 3) (safety 0)) (type octets data) (type ufix start end))
  (let ((c #xffffffff) (tab +crc-table+))
    (declare (type u32 c))
    (loop for i of-type ufix from start below end
          do (setf c (logxor (aref tab (logand (logxor c (aref data i)) #xff)) (ash c -8))))
    (logxor c #xffffffff)))
