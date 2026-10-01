;;;; src/index.lisp — the in-memory indexes.
;;;;
;;;; Three properties drive every choice in this file.
;;;;
;;;; 1. ONE WRITER, MANY LOCK-FREE READERS.  Only the writer thread mutates.  An
;;;;    event becomes visible when the writer bumps the published COUNT, after
;;;;    every structure that mentions it is written; readers take COUNT first and
;;;;    never look at a serial >= the COUNT they took.  Nothing a reader may be
;;;;    holding is ever mutated in a way that changes what it already showed.
;;;;
;;;; 2. NO BOXED OBJECT PER EVENT.  SBCL's collector stops every thread, and a
;;;;    full collection's cost scales with the number of live boxed objects.
;;;;    Millions of events are therefore held as columns of unboxed integers
;;;;    (the collector never scans their contents), and posting lists are either
;;;;    nodes in shared unboxed arrays or, once long, one unboxed vector each.
;;;;    The boxed-object count is O(distinct long lists), not O(events).
;;;;
;;;; 3. NO STEP IS PROPORTIONAL TO THE SIZE OF THE STORE.  Amortized O(1) is not
;;;;    enough for latency: a vector that doubles copies everything it holds, and
;;;;    at five million events that one insert took most of a second (measured,
;;;;    under load).  So big vectors are CHUNKED — appending allocates a fresh
;;;;    64K-entry chunk and never copies data — and hash tables resize
;;;;    INCREMENTALLY: the old and new tables coexist and each insert migrates a
;;;;    few slots.  The largest single step anywhere is copying one chunk.
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

(defun grow-vector-boxed (old n)
  (let ((new (make-array n :initial-element nil))) (replace new old) new))

;;; ---- chunked vectors -------------------------------------------------------------
;;; Element I lives in chunk I>>16 at I&#xFFFF.  Chunk 0 starts small and doubles
;;; up to 64K entries (so the thousands of modest posting lists stay modest);
;;; every later chunk is allocated full-size.  Growing the DIRECTORY copies only
;;; pointers.  A reader that loaded an older directory or an older chunk 0 still
;;; sees every element below the count it took.

(defconstant +chunk-shift+ 16)
(defconstant +chunk-size+ (ash 1 +chunk-shift+))
(defconstant +chunk-mask+ (1- +chunk-size+))

(defstruct (cvec (:constructor %make-cvec))
  (chunks #() :type simple-vector)
  (element-type t))

(defun make-cvec (element-type &optional (initial 64))
  (%make-cvec :chunks (vector (make-array initial :element-type element-type :initial-element 0))
              :element-type element-type))

(defun cvec-ensure (cv i)
  "Make index I addressable (writer only)."
  (declare (type cvec cv) (type ufix i))
  (let* ((ci (ash i (- +chunk-shift+)))
         (chunks (cvec-chunks cv)))
    (cond
      ((zerop ci)
       (let ((c0 (svref chunks 0)))
         (when (>= i (length c0))
           (let ((new (grow-vector c0 (min +chunk-size+ (max (* 2 (length c0)) (1+ i))))))
             (barrier-write)
             (setf (svref chunks 0) new)))))
      (t
       ;; chunk 0 must be full-size before any later chunk exists
       (when (< (length (svref chunks 0)) +chunk-size+)
         (let ((new (grow-vector (svref chunks 0) +chunk-size+)))
           (barrier-write)
           (setf (svref chunks 0) new)))
       (when (>= ci (length chunks))
         (setf chunks (grow-vector-boxed chunks (max (* 2 (length chunks)) (1+ ci))))
         (barrier-write)
         (setf (cvec-chunks cv) chunks))
       (unless (svref chunks ci)
         (let ((new (make-array +chunk-size+ :element-type (cvec-element-type cv) :initial-element 0)))
           (barrier-write)
           (setf (svref chunks ci) new)))))
    cv))

(defmacro cvref (cv i type)
  "Element I of chunked vector CV, whose elements are of TYPE.  A plain AREF
form, so it is SETF-able; I is evaluated twice, so pass a variable."
  `(aref (the (simple-array ,type (*)) (svref (cvec-chunks ,cv) (ash (the ufix ,i) (- +chunk-shift+))))
         (logand ,i +chunk-mask+)))

;;; ---- columns ----------------------------------------------------------------

(defstruct (columns (:constructor %make-columns))
  (off (make-cvec '(unsigned-byte 64)) :type cvec)      ; log offset of the record
  (len (make-cvec '(unsigned-byte 32)) :type cvec)      ; record length
  (created (make-cvec '(unsigned-byte 32)) :type cvec)
  (kind (make-cvec '(unsigned-byte 16)) :type cvec)
  (author (make-cvec '(unsigned-byte 62)) :type cvec)   ; keyed hash of the pubkey
  (idpre (make-cvec '(unsigned-byte 62)) :type cvec)    ; top bits of the id's first 8 bytes
  (expire (make-cvec '(unsigned-byte 32)) :type cvec)   ; NIP-40, 0 = never
  (flags (make-cvec '(unsigned-byte 8)) :type cvec))

(defun make-columns () (%make-columns))

(macrolet ((def (name slot type)
             `(progn
                (declaim (inline ,name (setf ,name)))
                (defun ,name (cols serial) (cvref (,slot cols) serial ,type))
                (defun (setf ,name) (v cols serial) (setf (cvref (,slot cols) serial ,type) v)))))
  (def col-off columns-off (unsigned-byte 64))
  (def col-len columns-len (unsigned-byte 32))
  (def col-created columns-created (unsigned-byte 32))
  (def col-kind columns-kind (unsigned-byte 16))
  (def col-author columns-author (unsigned-byte 62))
  (def col-idpre columns-idpre (unsigned-byte 62))
  (def col-expire columns-expire (unsigned-byte 32))
  (def col-flags columns-flags (unsigned-byte 8)))

(defun columns-ensure (cols serial)
  (dolist (cv (list (columns-off cols) (columns-len cols) (columns-created cols) (columns-kind cols)
                    (columns-author cols) (columns-idpre cols) (columns-expire cols) (columns-flags cols)))
    (cvec-ensure cv serial)))

;;; ---- open-addressing hash tables over 62-bit keys, resized incrementally ---------------
;;; Key 0 means empty, so a key of 0 is stored as 1.  When the live table is half
;;; full a twice-as-large one becomes live and the old one is kept as OLD; every
;;; later insert migrates a few of OLD's slots, and lookups consult the live
;;; table first and OLD second.  The writer never moves a key OLD has already
;;; shown a reader, so a reader holding either table answers correctly.

(defstruct (htab (:constructor %make-htab))
  (keys nil :type (simple-array (unsigned-byte 64) (*)))
  (vals nil :type (simple-array (unsigned-byte 64) (*)))
  (mask 0 :type fixnum)
  (count 0 :type fixnum))

(defun make-htab (&optional (size 1024))
  (let ((n (ash 1 (integer-length (max 16 (1- size))))))
    (%make-htab :keys (u64-vector n) :vals (u64-vector n) :mask (1- n))))

(defstruct (table (:constructor %make-table))
  (ht (make-htab) :type htab)
  (old nil :type (or null htab))
  (migrated 0 :type fixnum))

(defun make-table (&optional (size 1024)) (%make-table :ht (make-htab size)))

(declaim (inline nz-key))
(defun nz-key (k) (declare (type (unsigned-byte 62) k)) (if (zerop k) 1 k))

(defun htab-get (ht k)
  "Value under K in HT, or 0."
  (declare (optimize (speed 3) (safety 0)) (type htab ht) (type (unsigned-byte 62) k))
  (let ((keys (htab-keys ht)) (vals (htab-vals ht)) (mask (htab-mask ht)))
    (declare (type (simple-array (unsigned-byte 64) (*)) keys vals) (type fixnum mask))
    (loop for i of-type fixnum = (logand k mask) then (logand (1+ i) mask)
          for slot of-type (unsigned-byte 64) = (aref keys i)
          do (cond ((= slot k) (barrier-read) (return (aref vals i)))
                   ((zerop slot) (return 0))))))

(defun table-get (table key)
  "The value stored under KEY, or 0."
  (declare (type (unsigned-byte 62) key))
  (let* ((k (nz-key key))
         (ht (table-ht table)))
    (barrier-read)
    (let ((old (table-old table)))
      (let ((v (htab-get ht k)))
        (if (or (plusp v) (null old)) v (htab-get old k))))))

(defun %htab-put (ht k val &key (overwrite t))
  (declare (optimize (speed 3) (safety 0)) (type (unsigned-byte 62) k val))
  (let ((keys (htab-keys ht)) (vals (htab-vals ht)) (mask (htab-mask ht)))
    (declare (type (simple-array (unsigned-byte 64) (*)) keys vals) (type fixnum mask))
    (loop for i of-type fixnum = (logand k mask) then (logand (1+ i) mask)
          for slot of-type (unsigned-byte 64) = (aref keys i)
          do (cond ((= slot k) (when overwrite (setf (aref vals i) val)) (return nil))
                   ((zerop slot)
                    ;; value first, then the key that makes it findable
                    (setf (aref vals i) val)
                    (barrier-write)
                    (setf (aref keys i) k)
                    (incf (htab-count ht))
                    (return t))))))

(defconstant +migrate-per-put+ 16)

(defun %migrate-some (table)
  (let ((old (table-old table)))
    (when old
      (let* ((ht (table-ht table)) (keys (htab-keys old)) (vals (htab-vals old))
             (start (table-migrated table))
             (end (min (length keys) (+ start +migrate-per-put+))))
        (loop for i from start below end
              for k = (aref keys i)
              unless (zerop k)
                ;; never overwrite: a key already in the live table is newer
                do (%htab-put ht k (aref vals i) :overwrite nil))
        (setf (table-migrated table) end)
        (when (= end (length keys))
          (barrier-write)
          (setf (table-old table) nil))))))

(defun table-put (table key val)
  "Store VAL under KEY (writer only)."
  (let ((k (nz-key key)))
    (%migrate-some table)
    (let ((ht (table-ht table)))
      (when (> (* 2 (1+ (htab-count ht))) (length (htab-keys ht)))
        ;; finish any migration still running, then start a new one
        (loop while (table-old table) do (%migrate-some table))
        (let ((new (make-htab (* 2 (length (htab-keys ht))))))
          (setf (table-migrated table) 0 (table-old table) ht)
          (barrier-write)
          (setf (table-ht table) new ht new)))
      (%htab-put ht k val))))

(defun table-count (table)
  (+ (htab-count (table-ht table)) (let ((o (table-old table))) (if o (htab-count o) 0))))

;;; ---- plists: long posting lists ----------------------------------------------------
;;; DATA (chunked) holds serials in insertion order.  Per block of 64 entries,
;;; BMAX/BMIN are the created_at bounds and PMAX is the running maximum of BMAX
;;; over blocks 0..b — the newest event anywhere at or before block b.  A
;;; backwards scan can stop the moment PMAX falls below what it still needs.  The
;;; block arrays are 1/64 the size of the data, so they are simply grown.

(defstruct (plist (:constructor %make-plist))
  (data (make-cvec '(unsigned-byte 32) 64) :type cvec)
  (bmax (u32-vector 1) :type (simple-array (unsigned-byte 32) (*)))
  (bmin (u32-vector 1) :type (simple-array (unsigned-byte 32) (*)))
  (pmax (u32-vector 1) :type (simple-array (unsigned-byte 32) (*)))
  (count 0 :type fixnum))

(defun make-plist () (%make-plist))

(declaim (inline plist-ref))
(defun plist-ref (pl i) (cvref (plist-data pl) i (unsigned-byte 32)))

(defun plist-append (pl serial created)
  (declare (type plist pl) (type (unsigned-byte 32) serial created))
  (let* ((c (plist-count pl))
         (b (ash c (- +blk-shift+))))
    (cvec-ensure (plist-data pl) c)
    (when (>= b (length (plist-bmax pl)))
      (let ((nb (* 2 (length (plist-bmax pl)))))
        (setf (plist-bmax pl) (grow-vector (plist-bmax pl) nb)
              (plist-bmin pl) (grow-vector (plist-bmin pl) nb)
              (plist-pmax pl) (grow-vector (plist-pmax pl) nb))))
    (let ((bmax (plist-bmax pl)) (bmin (plist-bmin pl)) (pmax (plist-pmax pl)))
      (setf (cvref (plist-data pl) c (unsigned-byte 32)) serial)
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
;;; Nodes live in two chunked unboxed vectors shared by every short list.

(defstruct (postings (:constructor %make-postings))
  (table (make-table 4096) :type table)
  (node-serial (make-cvec '(unsigned-byte 32) 1024) :type cvec)
  (node-next (make-cvec '(unsigned-byte 32) 1024) :type cvec)
  (nnodes 1 :type fixnum)                 ; node 0 is the list terminator
  (plists (make-array 64 :initial-element nil) :type simple-vector)
  (nplists 0 :type fixnum))

(defun make-postings () (%make-postings))

(defun postings-plist (p handle)
  (svref (postings-plists p) (logand handle (1- +plist-flag+))))

(declaim (inline node-serial node-next))
(defun node-serial (p i) (cvref (postings-node-serial p) i (unsigned-byte 32)))
(defun node-next (p i) (cvref (postings-node-next p) i (unsigned-byte 32)))

(defun %new-node (p serial next)
  (let ((i (postings-nnodes p)))
    (cvec-ensure (postings-node-serial p) i)
    (cvec-ensure (postings-node-next p) i)
    (setf (cvref (postings-node-serial p) i (unsigned-byte 32)) serial
          (cvref (postings-node-next p) i (unsigned-byte 32)) next)
    (setf (postings-nnodes p) (1+ i))
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
       (let* ((serials (loop for i = (logand h #xffffffff) then (node-next p i)
                             until (zerop i) collect (node-serial p i)))
              (pl (make-plist)))
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

;;; ---- the index ---------------------------------------------------------------------

(defstruct (index (:constructor %make-index))
  (count 0 :type fixnum)                      ; published: serials [0, count) are visible
  (columns (make-columns) :type columns)
  (ids (make-table 4096) :type table)         ; id hash -> serial+1
  (all (make-plist) :type plist)              ; every serial
  (kinds (make-array 65536 :initial-element nil) :type simple-vector)  ; kind -> plist
  (authors (make-postings) :type postings)    ; pubkey hash -> postings
  (tags (make-postings) :type postings)       ; tag key hash -> postings
  (replaceable (make-table 1024) :type table) ; replaceable key -> serial+1
  (deleted-ids (make-table 256) :type table)  ; NIP-09: id hash -> who deleted it
  (deleted-addrs (make-table 256) :type table) ; NIP-09 "a": replaceable key -> deletion created_at+1
  (live 0 :type fixnum))                      ; visible, not deleted

(defun make-index () (%make-index))

(defun index-created-of (idx)
  (let ((cols (index-columns idx)))
    (lambda (s) (col-created cols s))))

(defun replaceable-key (author-hash kind dhash)
  "Keyed hash of (author, kind, d-tag): the identity of a replaceable or
addressable event slot."
  (let ((b (make-octets 18)))
    (dotimes (i 8) (setf (aref b i) (ldb (byte 8 (* 8 i)) author-hash)
                         (aref b (+ 10 i)) (ldb (byte 8 (* 8 i)) dhash)))
    (setf (aref b 8) (ldb (byte 8 0) kind) (aref b 9) (ldb (byte 8 8) kind))
    (keyed-hash b)))

(defun id-prefix (id &optional (start 0))
  "The top 62 bits of an id's first 8 bytes — a fixnum.  Together with the
62-bit keyed hash that finds the slot, a false match needs ~124 bits to line up."
  (declare (type octets id) (type ufix start))
  (let ((v 0))
    (declare (type (unsigned-byte 64) v))
    (dotimes (i 8) (setf v (logior (ash v 8) (aref id (+ start i)))))
    (ash v -2)))

(defun index-find-id (idx id &optional (start 0))
  "Serial of the stored event with ID (octets at START), or NIL.  Deleted events
are still found — the caller decides what a deleted hit means."
  (let ((v (table-get (index-ids idx) (keyed-hash id start (+ start 32)))))
    (unless (zerop v)
      (let ((serial (1- v)))
        (when (and (< serial (index-count idx))
                   (= (col-idpre (index-columns idx) serial) (id-prefix id start)))
          serial)))))

(defun index-add (idx &key off len created kind author-hash id id-start expire tag-hashes)
  "Add one event at serial COUNT and publish it.  Writer only.  Returns the serial."
  (let* ((s (index-count idx))
         (c (index-columns idx)))
    (columns-ensure c s)
    (setf (col-off c s) off
          (col-len c s) len
          (col-created c s) created
          (col-kind c s) kind
          (col-author c s) author-hash
          (col-idpre c s) (id-prefix id id-start)
          (col-expire c s) expire
          (col-flags c s) 0)
    (let ((created-of (index-created-of idx)))
      ;; the columns must be visible before any list mentions the serial
      (barrier-write)
      (table-put (index-ids idx) (keyed-hash id id-start (+ id-start 32)) (1+ s))
      (plist-append (index-all idx) s created)
      (let ((kl (or (svref (index-kinds idx) kind)
                    (setf (svref (index-kinds idx) kind) (make-plist)))))
        (plist-append kl s created))
      (postings-add (index-authors idx) author-hash s created-of)
      (loop for h across tag-hashes do (postings-add (index-tags idx) h s created-of)))
    (barrier-write)
    (setf (index-count idx) (1+ s))
    (incf (index-live idx))
    s))

(defun index-delete (idx serial)
  "Mark SERIAL deleted (writer only).  Lists keep the entry; readers skip it."
  (let ((cols (index-columns idx)))
    (unless (logtest (col-flags cols serial) +flag-deleted+)
      (setf (col-flags cols serial) (logior (col-flags cols serial) +flag-deleted+))
      (decf (index-live idx))
      t)))

(declaim (inline serial-deleted-p))
(defun serial-deleted-p (cols serial)
  (logtest (col-flags cols serial) +flag-deleted+))
