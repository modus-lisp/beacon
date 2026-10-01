;;;; src/index.lisp — the in-memory indexes.
;;;;
;;;; Two properties drive every choice in this file.
;;;;
;;;; 1. ONE WRITER, MANY LOCK-FREE READERS.  Only the writer thread mutates.  An
;;;;    event becomes visible when the writer bumps the published COUNT, after
;;;;    every structure that mentions it is written; readers take COUNT first and
;;;;    never look at a serial >= the COUNT they took.  Growth never mutates an
;;;;    array a reader may hold: the writer copies into a bigger array and swaps
;;;;    the reference, and the old array stays valid for whoever still has it.
;;;;
;;;; 2. NO BOXED OBJECT PER EVENT.  SBCL's collector stops every thread, and a
;;;;    full collection's cost scales with the number of live boxed objects.
;;;;    Millions of events are therefore held as columns of unboxed integers
;;;;    (the collector never scans their contents), and posting lists are either
;;;;    nodes in two big unboxed arrays or, once long, one unboxed vector each.
;;;;    The boxed-object count is O(distinct long lists), not O(events).
;;;;
;;;; SERIALS.  Every stored event has a serial: its position in the columns.  At
;;;; startup the log is replayed and serials are assigned in created_at order, so
;;;; every posting list is built sorted.  After startup new events append; they
;;;; are nearly sorted (live events carry "now").  The query executor does not
;;;; assume sortedness — it relies on per-block created_at bounds, which are
;;;; always correct — but it is fastest when the order is good.

(in-package #:beacon)

(defconstant +blk-shift+ 6)
(defconstant +blk+ (ash 1 +blk-shift+))     ; entries per block (64)
(defconstant +promote-at+ 32)               ; a linked list longer than this becomes a plist
(defconstant +plist-flag+ (ash 1 61))       ; a posting handle that names a plist

(defconstant +flag-deleted+ 1)

(declaim (inline barrier-write barrier-read))
(defun barrier-write () (sb-thread:barrier (:write)))
(defun barrier-read () (sb-thread:barrier (:read)))

(defmacro u32-vector (n) `(make-array ,n :element-type '(unsigned-byte 32) :initial-element 0))
(defmacro u64-vector (n) `(make-array ,n :element-type '(unsigned-byte 64) :initial-element 0))

(defun grow-vector (old new-length)
  (let ((new (make-array new-length :element-type (array-element-type old) :initial-element 0)))
    (replace new old)
    new))

;;; ---- columns ----------------------------------------------------------------

(defstruct (columns (:constructor %make-columns))
  (off nil :type (simple-array (unsigned-byte 64) (*)))      ; log offset of the record
  (len nil :type (simple-array (unsigned-byte 32) (*)))      ; record length
  (created nil :type (simple-array (unsigned-byte 32) (*)))
  (kind nil :type (simple-array (unsigned-byte 16) (*)))
  (author nil :type (simple-array (unsigned-byte 64) (*)))   ; keyed hash of the pubkey
  (idpre nil :type (simple-array (unsigned-byte 64) (*)))    ; first 8 bytes of the id (raw)
  (expire nil :type (simple-array (unsigned-byte 32) (*)))   ; NIP-40, 0 = never
  (flags nil :type (simple-array (unsigned-byte 8) (*))))

(defun make-columns (n)
  (%make-columns :off (u64-vector n) :len (u32-vector n) :created (u32-vector n)
                 :kind (make-array n :element-type '(unsigned-byte 16) :initial-element 0)
                 :author (u64-vector n) :idpre (u64-vector n) :expire (u32-vector n)
                 :flags (make-array n :element-type '(unsigned-byte 8) :initial-element 0)))

(defun grow-columns (c n)
  (%make-columns :off (grow-vector (columns-off c) n) :len (grow-vector (columns-len c) n)
                 :created (grow-vector (columns-created c) n) :kind (grow-vector (columns-kind c) n)
                 :author (grow-vector (columns-author c) n) :idpre (grow-vector (columns-idpre c) n)
                 :expire (grow-vector (columns-expire c) n) :flags (grow-vector (columns-flags c) n)))

;;; ---- open-addressing hash tables over u64 keys -----------------------------------
;;; Key 0 means empty, so a key that hashes to 0 is stored as 1.  Values are kept
;;; below 2^62 so reading one never conses a bignum.

(defstruct (htab (:constructor %make-htab))
  (keys nil :type (simple-array (unsigned-byte 64) (*)))
  (vals nil :type (simple-array (unsigned-byte 64) (*)))
  (mask 0 :type fixnum)
  (count 0 :type fixnum))

(defun make-htab (&optional (size 1024))
  (let ((n (ash 1 (integer-length (max 16 (1- size))))))
    (%make-htab :keys (u64-vector n) :vals (u64-vector n) :mask (1- n))))

(defstruct (table (:constructor %make-table))
  (ht (make-htab) :type htab))

(defun make-table (&optional (size 1024)) (%make-table :ht (make-htab size)))

(declaim (inline nz-key))
(defun nz-key (k) (declare (type (unsigned-byte 64) k)) (if (zerop k) 1 k))

(defun table-get (table key)
  "The value stored under KEY, or 0."
  (declare (optimize (speed 3) (safety 0)) (type (unsigned-byte 64) key))
  (let* ((ht (table-ht table))
         (keys (htab-keys ht)) (vals (htab-vals ht)) (mask (htab-mask ht))
         (k (nz-key key)))
    (declare (type (simple-array (unsigned-byte 64) (*)) keys vals) (type fixnum mask)
             (type (unsigned-byte 64) k))
    (loop for i of-type fixnum = (logand k mask) then (logand (1+ i) mask)
          for slot of-type (unsigned-byte 64) = (aref keys i)
          do (cond ((= slot k) (barrier-read) (return (aref vals i)))
                   ((zerop slot) (return 0))))))

(defun %htab-put (ht k val)
  (declare (optimize (speed 3) (safety 0)) (type (unsigned-byte 64) k val))
  (let ((keys (htab-keys ht)) (vals (htab-vals ht)) (mask (htab-mask ht)))
    (declare (type (simple-array (unsigned-byte 64) (*)) keys vals) (type fixnum mask))
    (loop for i of-type fixnum = (logand k mask) then (logand (1+ i) mask)
          for slot of-type (unsigned-byte 64) = (aref keys i)
          do (cond ((= slot k) (setf (aref vals i) val) (return nil))
                   ((zerop slot)
                    ;; value first, then the key that makes it findable
                    (setf (aref vals i) val)
                    (barrier-write)
                    (setf (aref keys i) k)
                    (incf (htab-count ht))
                    (return t))))))

(defun table-put (table key val)
  "Store VAL under KEY (writer only)."
  (let ((ht (table-ht table)) (k (nz-key key)))
    (when (> (* 2 (1+ (htab-count ht))) (length (htab-keys ht)))
      (let ((new (make-htab (* 2 (length (htab-keys ht))))))
        (loop for i below (length (htab-keys ht))
              for kk = (aref (htab-keys ht) i)
              unless (zerop kk) do (%htab-put new kk (aref (htab-vals ht) i)))
        (barrier-write)
        (setf (table-ht table) new ht new)))
    (%htab-put ht k val)))

(defun table-count (table) (htab-count (table-ht table)))

;;; ---- plists: long posting lists ----------------------------------------------------
;;; DATA holds serials in insertion order.  Per block of 64 entries, BMAX/BMIN are
;;; the created_at bounds and PMAX is the running maximum of BMAX over blocks
;;; 0..b — the newest event anywhere at or before block b.  A backwards scan can
;;; stop the moment PMAX falls below what it still needs.

(defstruct (plist (:constructor %make-plist))
  (data (u32-vector 64) :type (simple-array (unsigned-byte 32) (*)))
  (bmax (u32-vector 1) :type (simple-array (unsigned-byte 32) (*)))
  (bmin (u32-vector 1) :type (simple-array (unsigned-byte 32) (*)))
  (pmax (u32-vector 1) :type (simple-array (unsigned-byte 32) (*)))
  (count 0 :type fixnum))

(defun make-plist (&optional (capacity 64))
  (let ((nb (ceiling capacity +blk+)))
    (%make-plist :data (u32-vector (* nb +blk+)) :bmax (u32-vector nb) :bmin (u32-vector nb)
                 :pmax (u32-vector nb))))

(defun plist-append (pl serial created)
  (declare (type plist pl) (type (unsigned-byte 32) serial created))
  (let ((c (plist-count pl)))
    (when (>= c (length (plist-data pl)))
      (let* ((n (* 2 (length (plist-data pl)))) (nb (ceiling n +blk+)))
        (setf (plist-bmax pl) (grow-vector (plist-bmax pl) nb)
              (plist-bmin pl) (grow-vector (plist-bmin pl) nb)
              (plist-pmax pl) (grow-vector (plist-pmax pl) nb)
              (plist-data pl) (grow-vector (plist-data pl) n))))
    (let ((b (ash c (- +blk-shift+)))
          (bmax (plist-bmax pl)) (bmin (plist-bmin pl)) (pmax (plist-pmax pl)))
      (setf (aref (plist-data pl) c) serial)
      (if (zerop (logand c (1- +blk+)))
          (setf (aref bmax b) created (aref bmin b) created)
          (setf (aref bmax b) (max created (aref bmax b))
                (aref bmin b) (min created (aref bmin b))))
      (setf (aref pmax b) (if (zerop b) (aref bmax b) (max (aref bmax b) (aref pmax (1- b)))))
      (barrier-write)
      (setf (plist-count pl) (1+ c)))))

;;; ---- posting lists: short ones linked, long ones promoted -----------------------------
;;; A posting handle (the value in a posting table) is
;;;   0                          empty
;;;   (count << 32) | head       a linked list of COUNT nodes, newest first
;;;   +PLIST-FLAG+ | index       plist number INDEX
;;; Nodes live in two growable unboxed arrays shared by every short list.

(defstruct (nodes (:constructor %make-nodes))
  (serial (u32-vector 1024) :type (simple-array (unsigned-byte 32) (*)))
  (next (u32-vector 1024) :type (simple-array (unsigned-byte 32) (*)))
  (fill 1 :type fixnum))                ; node 0 is the list terminator

(defstruct (postings (:constructor %make-postings))
  (table (make-table 4096) :type table)
  (nodes (%make-nodes) :type nodes)
  (plists (make-array 64 :initial-element nil) :type simple-vector)
  (nplists 0 :type fixnum))

(defun make-postings () (%make-postings))

(defun postings-plist (p handle)
  (svref (postings-plists p) (logand handle (1- +plist-flag+))))

(defun %new-node (p serial next)
  (let* ((nd (postings-nodes p)) (i (nodes-fill nd)))
    (when (>= i (length (nodes-serial nd)))
      (let ((n (* 2 (length (nodes-serial nd)))))
        (setf nd (%make-nodes :serial (grow-vector (nodes-serial nd) n)
                              :next (grow-vector (nodes-next nd) n) :fill i))
        (barrier-write)
        (setf (postings-nodes p) nd)))
    (setf (aref (nodes-serial nd) i) serial (aref (nodes-next nd) i) next)
    (setf (nodes-fill nd) (1+ i))
    i))

(defun postings-add (p key serial created-of)
  "Append SERIAL to KEY's list.  CREATED-OF maps a serial to its created_at (for
plist block bounds)."
  (let ((h (table-get (postings-table p) key)))
    (cond
      ((logtest h +plist-flag+)
       (plist-append (postings-plist p h) serial (funcall created-of serial)))
      ((< (ash h -32) +promote-at+)
       (let ((node (%new-node p serial (logand h #xffffffff))))
         (barrier-write)
         (table-put (postings-table p) key (logior (ash (1+ (ash h -32)) 32) node))))
      (t
       ;; promote: copy the linked list (newest first) into a plist (oldest first)
       (let* ((nd (postings-nodes p))
              (serials (loop for i = (logand h #xffffffff) then (aref (nodes-next nd) i)
                             until (zerop i) collect (aref (nodes-serial nd) i)))
              (pl (make-plist 128)))
         (dolist (s (nreverse serials)) (plist-append pl s (funcall created-of s)))
         (plist-append pl serial (funcall created-of serial))
         (when (>= (postings-nplists p) (length (postings-plists p)))
           (setf (postings-plists p) (grow-vector-boxed (postings-plists p) (* 2 (length (postings-plists p)))))
           (barrier-write))
         (let ((idx (postings-nplists p)))
           (setf (svref (postings-plists p) idx) pl)
           (setf (postings-nplists p) (1+ idx))
           (barrier-write)
           (table-put (postings-table p) key (logior +plist-flag+ idx))))))))

(defun grow-vector-boxed (old n)
  (let ((new (make-array n :initial-element nil))) (replace new old) new))

;;; ---- the index ---------------------------------------------------------------------

(defstruct (index (:constructor %make-index))
  (count 0 :type fixnum)                      ; published: serials [0, count) are visible
  (columns (make-columns 1024) :type columns)
  (ids (make-table 4096) :type table)         ; id hash -> serial
  (all (make-plist 1024) :type plist)         ; every serial
  (kinds (make-array 65536 :initial-element nil) :type simple-vector)  ; kind -> plist
  (authors (make-postings) :type postings)    ; pubkey hash -> postings
  (tags (make-postings) :type postings)       ; tag key hash -> postings
  (replaceable (make-table 1024) :type table) ; replaceable key -> serial+1
  (deleted-ids (make-table 256) :type table)  ; NIP-09: id hash -> deleter's pubkey hash
  (deleted-addrs (make-table 256) :type table) ; NIP-09 "a": replaceable key -> deletion created_at+1
  (live 0 :type fixnum))                      ; visible, not deleted

(defun make-index () (%make-index))

(defun index-created-of (idx)
  (lambda (s) (aref (columns-created (index-columns idx)) s)))

(defun replaceable-key (author-hash kind dhash)
  "Keyed hash of (author, kind, d-tag): the identity of a replaceable or
addressable event slot."
  (let ((b (make-octets 18)))
    (dotimes (i 8) (setf (aref b i) (ldb (byte 8 (* 8 i)) author-hash)
                         (aref b (+ 10 i)) (ldb (byte 8 (* 8 i)) dhash)))
    (setf (aref b 8) (ldb (byte 8 0) kind) (aref b 9) (ldb (byte 8 8) kind))
    (siphash64 b)))

(defun id-prefix (id &optional (start 0))
  "The first 8 bytes of an id as an integer (below 2^62 is not guaranteed, so
this is only ever compared against the column, both as u64)."
  (let ((v 0)) (dotimes (i 8 v) (setf v (logior (ash v 8) (aref id (+ start i)))))))

(defun index-find-id (idx id &optional (start 0))
  "Serial of the stored event with ID (octets at START), or NIL.  Deleted events
are still found — the caller decides what a deleted hit means."
  (let ((v (table-get (index-ids idx) (siphash64 id start (+ start 32)))))
    (unless (zerop v)
      (let ((serial (1- v)))
        (when (and (< serial (index-count idx))
                   (= (aref (columns-idpre (index-columns idx)) serial) (id-prefix id start)))
          serial)))))

(defun index-add (idx &key off len created kind author-hash id id-start expire tag-hashes)
  "Add one event at serial COUNT and publish it.  Writer only.  Returns the serial."
  (let* ((s (index-count idx))
         (c (index-columns idx)))
    (when (>= s (length (columns-off c)))
      (setf c (grow-columns c (* 2 (length (columns-off c)))))
      (barrier-write)
      (setf (index-columns idx) c))
    (setf (aref (columns-off c) s) off
          (aref (columns-len c) s) len
          (aref (columns-created c) s) created
          (aref (columns-kind c) s) kind
          (aref (columns-author c) s) author-hash
          (aref (columns-idpre c) s) (id-prefix id id-start)
          (aref (columns-expire c) s) expire
          (aref (columns-flags c) s) 0)
    (let ((created-of (index-created-of idx)))
      ;; the columns must be visible before any list mentions the serial
      (barrier-write)
      (table-put (index-ids idx) (siphash64 id id-start (+ id-start 32)) (1+ s))
      (plist-append (index-all idx) s created)
      (let ((kl (or (svref (index-kinds idx) kind)
                    (setf (svref (index-kinds idx) kind) (make-plist 64)))))
        (plist-append kl s created))
      (postings-add (index-authors idx) author-hash s created-of)
      (loop for h across tag-hashes do (postings-add (index-tags idx) h s created-of)))
    (barrier-write)
    (setf (index-count idx) (1+ s))
    (incf (index-live idx))
    s))

(defun index-delete (idx serial)
  "Mark SERIAL deleted (writer only).  Lists keep the entry; readers skip it."
  (let ((flags (columns-flags (index-columns idx))))
    (unless (logtest (aref flags serial) +flag-deleted+)
      (setf (aref flags serial) (logior (aref flags serial) +flag-deleted+))
      (decf (index-live idx))
      t)))

(declaim (inline serial-deleted-p))
(defun serial-deleted-p (cols serial)
  (logtest (aref (columns-flags cols) serial) +flag-deleted+))
