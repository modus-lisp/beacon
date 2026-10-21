;;;; src/nip44.lisp -- NIP-44 v2 decryption, for encrypted UDP datagrams.
;;;;
;;;; An encrypted datagram is the sender's ephemeral x-only pubkey (32 bytes)
;;;; followed by a NIP-44 v2 payload: version 2, a 32-byte nonce, the ChaCha20
;;;; ciphertext of the padded plaintext, and a 32-byte HMAC-SHA256 over nonce and
;;;; ciphertext.  The conversation key is HKDF-extract("nip44-v2", x of
;;;; relay_secret * lift_x(ephemeral)); the message keys are HKDF-expand of that
;;;; key with the nonce.  README, "UDP ingest".
;;;;
;;;; Everything here is beacon's own: SHA-256 from hash.lisp, ChaCha20 (RFC 8439)
;;;; below, HMAC and HKDF on top of SHA-256.  The one curve operation is
;;;; CT-MUL-POINT, because the multiplier is the relay's secret key and the
;;;; variable-time multiply leaks it through timing.  The official vectors
;;;; (nip44.vectors.json) are in test/test.lisp.

(in-package #:beacon)

;;; ---- ChaCha20 (RFC 8439) -------------------------------------------------------

(defun %le32 (octets i)
  (logior (aref octets i) (ash (aref octets (+ i 1)) 8)
          (ash (aref octets (+ i 2)) 16) (ash (aref octets (+ i 3)) 24)))

(declaim (inline %rotl32))
(defun %rotl32 (x n)
  (logand #xffffffff (logior (ash x n) (ash x (- n 32)))))

(defun %quarter-round (s a b c d)
  (declare (type (simple-array (unsigned-byte 32) (16)) s) (type (integer 0 15) a b c d))
  (flet ((add (x y) (logand #xffffffff (+ x y))))
    (setf (aref s a) (add (aref s a) (aref s b)))
    (setf (aref s d) (%rotl32 (logxor (aref s d) (aref s a)) 16))
    (setf (aref s c) (add (aref s c) (aref s d)))
    (setf (aref s b) (%rotl32 (logxor (aref s b) (aref s c)) 12))
    (setf (aref s a) (add (aref s a) (aref s b)))
    (setf (aref s d) (%rotl32 (logxor (aref s d) (aref s a)) 8))
    (setf (aref s c) (add (aref s c) (aref s d)))
    (setf (aref s b) (%rotl32 (logxor (aref s b) (aref s c)) 7))))

(defun chacha20-xor (key nonce data &key (counter 0))
  "DATA XOR the ChaCha20 keystream for the 32-byte KEY and 12-byte NONCE, starting at
block COUNTER (RFC 8439).  Returns a fresh octet vector."
  (declare (type octets key nonce data))
  (let* ((n (length data))
         (out (make-octets n))
         (state (make-array 16 :element-type '(unsigned-byte 32)))
         (work (make-array 16 :element-type '(unsigned-byte 32)))
         (keystream (make-octets 64)))
    (setf (aref state 0) #x61707865 (aref state 1) #x3320646e
          (aref state 2) #x79622d32 (aref state 3) #x6b206574)
    (dotimes (i 8) (setf (aref state (+ 4 i)) (%le32 key (* 4 i))))
    (dotimes (i 3) (setf (aref state (+ 13 i)) (%le32 nonce (* 4 i))))
    (dotimes (blk (ceiling n 64))
      (setf (aref state 12) (logand #xffffffff (+ counter blk)))
      (replace work state)
      (dotimes (r 10)                         ; ten double rounds
        (%quarter-round work 0 4 8 12) (%quarter-round work 1 5 9 13)
        (%quarter-round work 2 6 10 14) (%quarter-round work 3 7 11 15)
        (%quarter-round work 0 5 10 15) (%quarter-round work 1 6 11 12)
        (%quarter-round work 2 7 8 13) (%quarter-round work 3 4 9 14))
      (dotimes (i 16)
        (let ((w (logand #xffffffff (+ (aref work i) (aref state i)))))
          (dotimes (b 4) (setf (aref keystream (+ (* 4 i) b)) (ldb (byte 8 (* 8 b)) w)))))
      (let ((base (* blk 64)))
        (dotimes (j (min 64 (- n base)))
          (setf (aref out (+ base j)) (logxor (aref data (+ base j)) (aref keystream j))))))
    out))

;;; ---- HMAC-SHA256 and HKDF -------------------------------------------------------

(defun %cat (&rest vectors)
  (let* ((n (reduce #'+ vectors :key #'length))
         (out (make-octets n))
         (pos 0))
    (dolist (v vectors out)
      (replace out v :start1 pos)
      (incf pos (length v)))))

(defun hmac-sha256 (key message)
  "HMAC-SHA256 (RFC 2104) with a 64-byte block."
  (let* ((key (if (> (length key) 64) (sha256 key) key))
         (k (make-octets 64)))
    (replace k key)
    (let ((ipad (map '(vector (unsigned-byte 8)) (lambda (b) (logxor b #x36)) k))
          (opad (map '(vector (unsigned-byte 8)) (lambda (b) (logxor b #x5c)) k)))
      (sha256 (%cat opad (sha256 (%cat ipad message)))))))

(defun hkdf-extract (salt ikm)
  (hmac-sha256 salt ikm))

(defun hkdf-expand (prk info length)
  "RFC 5869 expand with SHA-256: LENGTH octets of output keying material."
  (let ((okm (make-octets length)) (t-prev (make-octets 0)) (pos 0))
    (loop for i from 1 while (< pos length) do
      (let ((tn (hmac-sha256 prk (%cat t-prev info (make-array 1 :element-type '(unsigned-byte 8)
                                                                 :initial-element i)))))
        (replace okm tn :start1 pos)
        (incf pos (length tn))
        (setf t-prev tn)))
    okm))

;;; ---- NIP-44 v2 -----------------------------------------------------------------

(defun nip44-conversation-key (secret peer-xonly)
  "The 32-byte conversation key between SECRET (an integer) and PEER-XONLY (32 octets).
The peer point is lifted from its x coordinate and must lie on the curve, which
LIFT-X guarantees; the product is taken in constant time."
  (secp:secp-init)
  (let* ((point (or (schnorr:lift-x (bytes->int peer-xonly))
                    (error "nip44: peer is not a curve point")))
         (product (secp:ct-mul-point secret point)))
    (when (secp:secp-inf-p product) (error "nip44: shared point is at infinity"))
    (hkdf-extract (ascii-octets "nip44-v2") (secp:int-to-bytes32 (car product)))))

(defun nip44-calc-padded-len (len)
  "The padded length NIP-44 gives a plaintext of LEN bytes (LEN >= 1)."
  (if (<= len 32)
      32
      (let* ((next-power (ash 1 (integer-length (1- len))))
             (chunk (if (<= next-power 256) 32 (floor next-power 8))))
        (* chunk (1+ (floor (1- len) chunk))))))

(defun %nip44-unpad (padded)
  "The plaintext in PADDED (a 2-byte big-endian length, the text, zero padding).
Signals unless the length and padding are exactly what NIP-44 produces."
  (let ((len (logior (ash (aref padded 0) 8) (aref padded 1))))
    (unless (and (plusp len)
                 (= (length padded) (+ 2 (nip44-calc-padded-len len)))
                 (every #'zerop (subseq padded (+ 2 len))))
      (error "nip44: invalid padding"))
    (subseq padded 2 (+ 2 len))))

(defun %constant-time-equal (a b)
  (and (= (length a) (length b))
       (zerop (let ((diff 0))
                (dotimes (i (length a) diff)
                  (setf diff (logior diff (logxor (aref a i) (aref b i)))))))))

(defun nip44-decrypt (conversation-key payload)
  "The plaintext octets of the NIP-44 v2 PAYLOAD (version byte first).  Signals on any
size, version, MAC or padding failure; the MAC is checked before anything is
decrypted."
  (let ((n (length payload)))
    (unless (<= 99 n 65603) (error "nip44: invalid payload size ~d" n))
    (unless (= (aref payload 0) 2) (error "nip44: unsupported version ~d" (aref payload 0)))
    (let* ((nonce (subseq payload 1 33))
           (ciphertext (subseq payload 33 (- n 32)))
           (mac (subseq payload (- n 32)))
           (okm (hkdf-expand conversation-key nonce 76))
           (chacha-key (subseq okm 0 32))
           (chacha-nonce (subseq okm 32 44))
           (hmac-key (subseq okm 44 76)))
      (unless (%constant-time-equal mac (hmac-sha256 hmac-key (%cat nonce ciphertext)))
        (error "nip44: bad MAC"))
      (%nip44-unpad (chacha20-xor chacha-key chacha-nonce ciphertext)))))

(defun nip44-open-datagram (secret datagram n)
  "The plaintext octets of an encrypted UDP datagram of N bytes: an ephemeral x-only
pubkey, then a NIP-44 v2 payload, both addressed to SECRET.  Signals on failure."
  (nip44-decrypt (nip44-conversation-key secret (subseq datagram 0 32))
                 (subseq datagram 32 n)))
