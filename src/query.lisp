;;;; src/query.lisp — answering filters from the indexes.
;;;;
;;;; For each filter the planner picks ONE candidate source, the cheapest that is
;;;; guaranteed to contain every match:
;;;;
;;;;   ids                       direct id lookups
;;;;   authors x replaceable     direct slot lookups (kind 0 / 3 / 10002 profile
;;;;     kinds [x #d]            fetches — the most common query there is)
;;;;   authors | one #tag | kinds   the posting lists of each value, whichever
;;;;                              dimension has the fewest entries in total
;;;;   (nothing)                 every event
;;;;
;;;; Candidates are checked against the rest of the filter — columns first
;;;; (kind, author, created_at, deleted, expiry are all in RAM), and only then
;;;; tag conditions, which need the record header from the log.  Results are the
;;;; LIMIT newest, kept in a bounded heap.  Long lists are scanned backwards a
;;;; block at a time, and the scan stops as soon as a block's running-maximum
;;;; created_at says nothing older can make the cut.

(in-package #:beacon)

(defvar *default-limit* 500 "LIMIT used when a filter gives none.")
(defvar *max-limit* 5000 "Upper bound on any filter's LIMIT.")
(defvar *max-scan* 2000000 "Candidates examined per filter before giving up.")
(defvar *max-direct-lookups* 10000)

;;; ---- a bounded min-heap keyed by (created, serial) ------------------------------------

(defstruct (topk (:constructor %make-topk))
  (created nil :type (simple-array (unsigned-byte 32) (*)))
  (serial nil :type (simple-array (unsigned-byte 32) (*)))
  (n 0 :type fixnum)
  (k 0 :type fixnum))

(defun make-topk (k) (%make-topk :created (u32-vector (max 1 k)) :serial (u32-vector (max 1 k)) :k k))

(declaim (inline topk-less))
(defun topk-less (c1 s1 c2 s2) (or (< c1 c2) (and (= c1 c2) (< s1 s2))))

(defun topk-full-p (h) (>= (topk-n h) (topk-k h)))

(defun topk-would-accept-p (h created serial)
  (or (not (topk-full-p h))
      (and (plusp (topk-k h))
           (topk-less (aref (topk-created h) 0) (aref (topk-serial h) 0) created serial))))

(defun topk-push (h created serial)
  (let ((cs (topk-created h)) (ss (topk-serial h)))
    (flet ((swap (i j) (rotatef (aref cs i) (aref cs j)) (rotatef (aref ss i) (aref ss j)))
           (less (i j) (topk-less (aref cs i) (aref ss i) (aref cs j) (aref ss j))))
      (cond
        ((not (topk-full-p h))
         (let ((i (topk-n h)))
           (setf (aref cs i) created (aref ss i) serial)
           (incf (topk-n h))
           (loop while (plusp i)
                 do (let ((p (floor (1- i) 2)))
                      (if (less i p) (progn (swap i p) (setf i p)) (return))))))
        ((topk-would-accept-p h created serial)
         (setf (aref cs 0) created (aref ss 0) serial)
         (let ((i 0) (n (topk-n h)))
           (loop (let* ((l (+ 1 (* 2 i))) (r (1+ l)) (m i))
                   (when (and (< l n) (less l m)) (setf m l))
                   (when (and (< r n) (less r m)) (setf m r))
                   (if (= m i) (return) (progn (swap i m) (setf i m)))))))))))

(defun topk-floor (h)
  "created_at below which nothing can enter a full heap, or NIL if not full."
  (and (topk-full-p h) (plusp (topk-k h)) (aref (topk-created h) 0)))

;;; ---- compiled filters ---------------------------------------------------------------------

(defstruct (cfilter (:constructor %make-cfilter))
  (filter nil)
  (kinds nil)                     ; list of kinds or NIL
  (authors nil)                   ; hash-set of author hashes or NIL
  (tags nil)                      ; list of (simple-array u64) — one per tag condition
  (since 0) (until #xffffffff)
  (limit 0))

(defun compile-filter (f)
  (%make-cfilter
   :filter f
   :kinds (filter-kinds f)
   :authors (when (filter-authors f)
              (let ((h (make-hash-table :test 'eql :size (* 2 (length (filter-authors f))))))
                (dolist (a (filter-authors f) h) (setf (gethash (keyed-hash a) h) t))))
   :tags (mapcar #'cdr (filter-tags f))
   :since (filter-since f) :until (filter-until f)
   :limit (min *max-limit* (or (filter-limit f) *default-limit*))))

(defun cheap-match-p (cf cols serial now)
  "Every condition decidable from the columns."
  (declare (type columns cols) (type fixnum serial))
  (let ((created (col-created cols serial))
        (exp (col-expire cols serial)))
    (and (not (serial-deleted-p cols serial))
         (or (zerop exp) (> exp now))
         (<= (cfilter-since cf) created (cfilter-until cf))
         (or (null (cfilter-kinds cf)) (member (col-kind cols serial) (cfilter-kinds cf)))
         (or (null (cfilter-authors cf)) (gethash (col-author cols serial) (cfilter-authors cf))))))

(defun record-tags-match-p (store serial tag-sets)
  "Do the stored event's tag keys satisfy every set in TAG-SETS?  Reads only the
record header."
  (let* ((cols (index-columns (store-index store)))
         (reader (store-reader store))
         (off (col-off cols serial))
         (head (read-record reader off (min (col-len cols serial) 512)))
         (nt (rec-ntags head 0)))
    (when (> (+ +rec-header+ (* 8 nt)) 512)
      (setf head (read-record reader off (+ +rec-header+ (* 8 nt)))))
    (every (lambda (want)
             (loop for i below nt thereis (find (rec-tag-hash head 0 i) want)))
           tag-sets)))

;;; ---- candidate sources ------------------------------------------------------------------

(defun posting-size (p handle)
  (cond ((zerop handle) 0)
        ((logtest handle +plist-flag+) (plist-count (postings-plist p handle)))
        (t (ash handle -32))))

(defun choose-source (idx f)
  "-> (values kind items) where KIND is :ids :slots :postings :kinds :all.
For :postings, ITEMS is (postings-object . handles); TAG-USED is the tag set
that drove it (so it need not be re-checked), returned as a third value."
  (let ((best nil) (best-size most-positive-fixnum) (best-tag nil))
    (flet ((consider (kind items size &optional tag)
             (when (< size best-size) (setf best (cons kind items) best-size size best-tag tag))))
      (when (filter-ids f)
        (return-from choose-source (values :ids (filter-ids f) nil)))
      ;; replaceable slots: every kind replaceable (or addressable with #d given)
      (when (and (filter-authors f) (filter-kinds f))
        (let* ((dset (cdr (assoc (char-code #\d) (filter-tags f))))
               (ok (every (lambda (k) (or (replaceable-kind-p k) (and dset (addressable-kind-p k))))
                          (filter-kinds f)))
               (n (* (length (filter-authors f)) (length (filter-kinds f)) (if dset (length dset) 1))))
          (when (and ok (<= n *max-direct-lookups*))
            (return-from choose-source
              (values :slots
                      (loop for a in (filter-authors f)
                            for ah = (keyed-hash a)
                            nconc (loop for k in (filter-kinds f)
                                        nconc (if (addressable-kind-p k)
                                                  (loop for d across dset
                                                        collect (replaceable-key ah k (max 1 d)))
                                                  (list (replaceable-key ah k 0)))))
                      nil)))))
      (when (filter-authors f)
        (let* ((p (index-authors idx))
               (hs (mapcar (lambda (a) (table-get (postings-table p) (keyed-hash a))) (filter-authors f))))
          (consider :postings (cons p hs) (loop for h in hs sum (posting-size p h)))))
      (dolist (tc (filter-tags f))
        (let* ((p (index-tags idx))
               (hs (map 'list (lambda (h) (table-get (postings-table p) h)) (cdr tc))))
          (consider :postings (cons p hs) (loop for h in hs sum (posting-size p h)) (cdr tc))))
      (when (filter-kinds f)
        (let ((pls (remove nil (mapcar (lambda (k) (svref (index-kinds idx) k)) (filter-kinds f)))))
          (consider :kinds pls (loop for pl in pls sum (plist-count pl)))))
      (if best
          (values (car best) (cdr best) best-tag)
          (values :all (list (index-all idx)) nil)))))

;;; ---- the executor ---------------------------------------------------------------------------

(defun run-filter (store f snapshot &key (now (unix-now)) count-only)
  "Serials matching filter F among serials below SNAPSHOT: the newest LIMIT of
them as a list (newest first), or with COUNT-ONLY their number."
  (let* ((idx (store-index store))
         (cols (index-columns idx))
         (cf (compile-filter f))
         (limit (if count-only most-positive-fixnum (cfilter-limit cf)))
         (heap (unless count-only (make-topk limit)))
         (count 0) (scanned 0)
         (seen nil))
    (when (or (filter-impossible f) (zerop limit))
      (return-from run-filter (if count-only 0 '())))
    (multiple-value-bind (source items tag-used) (choose-source idx f)
      (let ((tag-sets (remove tag-used (cfilter-tags cf))))
        (labels ((consider (s)
                   (declare (type fixnum s))
                   (when (and (< s snapshot)
                              (cheap-match-p cf cols s now)
                              (or count-only (topk-would-accept-p heap (col-created cols s) s))
                              (or (null tag-sets) (record-tags-match-p store s tag-sets))
                              (or (null seen) (not (gethash s seen))))
                     (when seen (setf (gethash s seen) t))
                     (if count-only
                         (incf count)
                         (topk-push heap (col-created cols s) s))))
                 (budget-left-p () (< (incf scanned) *max-scan*))
                 (scan-plist (pl)
                   ;; newest blocks first; stop when nothing older can qualify
                   (let* ((n (prog1 (plist-count pl) (barrier-read)))
                          (bl (plist-blocks pl)))
                     (loop for b from (ash (1- n) (- +blk-shift+)) downto 0
                           for bmax = (aref bl (* 3 b)) for bmin = (aref bl (+ 1 (* 3 b)))
                           for pmax = (aref bl (+ 2 (* 3 b)))
                           do
                       (let ((floor (if count-only nil (topk-floor heap))))
                         (when (or (< pmax (cfilter-since cf))
                                   (and floor (< pmax floor)))
                           (return)))
                       (unless (or (> bmin (cfilter-until cf))
                                   (< bmax (cfilter-since cf)))
                         (loop for i from (min (1- n) (+ (ash b +blk-shift+) (1- +blk+)))
                                 downto (ash b +blk-shift+)
                               do (unless (budget-left-p) (return-from scan-plist))
                                  (consider (plist-ref pl i)))))))
                 (scan-handle (p h)
                   (cond ((zerop h))
                         ((logtest h +plist-flag+) (scan-plist (postings-plist p h)))
                         (t (loop for i = (logand h #xffffffff) then (node-next p i)
                                  until (zerop i)
                                  do (consider (node-serial p i)))))))
          (ecase source
            (:ids (dolist (id items)
                    (let ((s (index-find-id idx id))) (when s (consider s)))))
            (:slots (dolist (rkey items)
                      (let ((v (table-get (index-replaceable idx) rkey)))
                        (when (plusp v) (consider (1- v))))))
            (:postings
             (let ((p (car items)) (hs (cdr items)))
               (when (> (count-if-not #'zerop hs) 1) (setf seen (make-hash-table :test 'eql :size 256)))
               (dolist (h hs) (scan-handle p h))))
            ((:kinds :all) (dolist (pl items) (scan-plist pl)))))))
    (if count-only
        count
        (let ((out '()))
          ;; drain the min-heap: smallest first, so pushing yields newest first
          (loop while (plusp (topk-n heap))
                do (push (aref (topk-serial heap) 0) out)
                   (let ((last (1- (topk-n heap))))
                     (setf (aref (topk-created heap) 0) (aref (topk-created heap) last)
                           (aref (topk-serial heap) 0) (aref (topk-serial heap) last))
                     (decf (topk-n heap))
                     (let ((i 0) (n (topk-n heap)) (cs (topk-created heap)) (ss (topk-serial heap)))
                       (loop (let* ((l (+ 1 (* 2 i))) (r (1+ l)) (m i))
                               (when (and (< l n) (topk-less (aref cs l) (aref ss l) (aref cs m) (aref ss m))) (setf m l))
                               (when (and (< r n) (topk-less (aref cs r) (aref ss r) (aref cs m) (aref ss m))) (setf m r))
                               (if (= m i) (return)
                                   (progn (rotatef (aref cs i) (aref cs m)) (rotatef (aref ss i) (aref ss m))
                                          (setf i m))))))))
          out))))

(defun store-query (store filters &key (snapshot (index-count (store-index store))) (now (unix-now)))
  "Serials matching any of FILTERS, newest first, each filter contributing at
most its LIMIT, without duplicates."
  (let ((seen (and (cdr filters) (make-hash-table :test 'eql :size 256))) (all '())
        (cols (index-columns (store-index store))))
    (dolist (f filters)
      (dolist (s (run-filter store f snapshot :now now))
        (unless (and seen (gethash s seen))
          (when seen (setf (gethash s seen) t))
          (push s all))))
    (if (cdr filters)
        (sort all (lambda (a b) (let ((ca (col-created cols a)) (cb (col-created cols b)))
                                  (or (> ca cb) (and (= ca cb) (> a b))))))
        (nreverse all))))

(defun store-count (store filters &key (snapshot (index-count (store-index store))) (now (unix-now)))
  "NIP-45: how many events match any of FILTERS (summed per filter when there
are several; overlaps are counted once only when one filter is given)."
  (loop for f in filters sum (run-filter store f snapshot :now now :count-only t)))
