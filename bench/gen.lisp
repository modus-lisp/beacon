;;;; bench/gen.lisp — synthetic but realistically shaped Nostr traffic.
;;;;
;;;; Activity is skewed the way real relays see it: a few authors write most
;;;; notes, a few hashtags carry most tagged notes, replies and reactions point
;;;; at recent notes, contact lists are long and replaced often.  Events are
;;;; built directly as EVENT structs with a correct id but a FAKE signature —
;;;; the store never checks signatures, and a million real ones would take an
;;;; hour to make.  (The network benchmark signs for real.)

(defpackage #:beacon.bench
  (:use #:cl)
  (:import-from #:beacon
                #:%make-event #:event-id #:event-pubkey #:event-json #:compute-event-id
                #:stored-json #:compute-tag-hashes #:make-octets #:hex-encode #:unix-now
                #:addressable-kind-p #:find-tag-value #:now-us))

(in-package #:beacon.bench)

(defstruct (world (:constructor %make-world))
  (authors nil)             ; vector of 32-byte pubkeys
  (hashtags nil)            ; vector of strings
  (recent (make-array 4096 :initial-element nil))  ; ring of (id . pubkey) of recent notes
  (recent-n 0)
  (clock 0)                 ; created_at of the next event
  (rng (sb-ext:seed-random-state 42)))

(defun random-octets (n rng)
  (let ((o (make-octets n))) (dotimes (i n o) (setf (aref o i) (random 256 rng)))))

(defun make-world (&key (authors 200000) (hashtags 2000) (start (- (unix-now) (* 365 86400))) (seed 42))
  (let ((rng (sb-ext:seed-random-state seed)))
    (%make-world :authors (coerce (loop repeat authors collect (random-octets 32 rng)) 'simple-vector)
                 :hashtags (coerce (loop for i below hashtags collect (format nil "tag~d" i)) 'simple-vector)
                 :clock start :rng rng)))

(defun skewed (n rng &optional (power 3))
  "An index in [0,N) with heavy weight on small indexes."
  (min (1- n) (floor (* n (expt (random 1d0 rng) power)))))

(defun pick-author (w) (svref (world-authors w) (skewed (length (world-authors w)) (world-rng w))))

(defun recent-note (w)
  (let ((n (min (world-recent-n w) (length (world-recent w)))))
    (when (plusp n)
      (svref (world-recent w) (mod (- (world-recent-n w) 1 (skewed n (world-rng w) 2)) (length (world-recent w)))))))

(defun remember-note (w id pubkey)
  (setf (svref (world-recent w) (mod (world-recent-n w) (length (world-recent w)))) (cons id pubkey))
  (incf (world-recent-n w)))

(defparameter +words+ #("the" "relay" "lisp" "nostr" "bitcoin" "coffee" "today" "is" "a" "good" "day"
                        "for" "building" "things" "gm" "pv" "zap" "note" "thread" "why" "how" "what"))

(defun text (w n)
  (with-output-to-string (s)
    (dotimes (i n) (when (plusp i) (write-char #\Space s))
      (write-string (svref +words+ (random (length +words+) (world-rng w))) s))))

(defun make-fake-event (pubkey created-at kind tags content)
  (let* ((tv (coerce (mapcar (lambda (tg) (coerce tg 'simple-vector)) tags) 'simple-vector))
         (id (compute-event-id pubkey created-at kind tv content))
         (e (%make-event :id id :pubkey pubkey :sig (make-octets 64) :created-at created-at
                         :kind kind :tags tv :content content
                         :d-tag (when (addressable-kind-p kind) (or (find-tag-value tv "d") ""))
                         :tag-hashes (compute-tag-hashes tv))))
    (setf (event-json e) (stored-json e))
    e))

(defun next-event (w)
  "One event, advancing the world's clock a little."
  (let* ((rng (world-rng w))
         (r (random 100 rng))
         (author (pick-author w))
         (ts (incf (world-clock w) (random 2 rng))))
    (flet ((ref-tags ()
             (let ((n (recent-note w)))
               (if n (list (list "e" (hex-encode (car n))) (list "p" (hex-encode (cdr n)))) '()))))
      (multiple-value-bind (kind tags content)
          (cond
            ((< r 55)                                    ; a note: some replies, some hashtags
             (values 1
                     (append (when (< (random 10 rng) 3) (ref-tags))
                             (when (< (random 10 rng) 2)
                               (list (list "t" (svref (world-hashtags w) (skewed (length (world-hashtags w)) rng))))))
                     (text w (+ 5 (random 40 rng)))))
            ((< r 80) (values 7 (ref-tags) "+"))         ; reaction
            ((< r 85) (values 6 (ref-tags) ""))          ; repost
            ((< r 89) (values 1111 (ref-tags) (text w 10)))
            ((< r 94) (values 9735 (append (ref-tags) (list (list "bolt11" "lnbc1..."))) ""))
            ((< r 97) (values 0 '() (format nil "{\"name\":\"~a\"}" (text w 1))))
            ((< r 99)                                    ; contact list: long, replaced often
             (values 3 (loop repeat (+ 20 (random 300 rng))
                             collect (list "p" (hex-encode (pick-author w))))
                     ""))
            (t (values 30023 (list (list "d" (format nil "post-~d" (random 20 rng))) (list "title" "x"))
                       (text w 80))))
        (let ((e (make-fake-event author ts kind tags content)))
          (when (= kind 1) (remember-note w (event-id e) author))
          e)))))
