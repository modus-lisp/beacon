;;;; src/filter.lisp — NIP-01 filters.
;;;;
;;;; A filter is a conjunction: ids, authors and kinds are sets; each "#x" key is a
;;;; set of values for the single-letter tag x; since/until bound created_at.  A
;;;; REQ carries several filters and matches their union.  Tag conditions are
;;;; compared by keyed hash, exactly as the index stores them, so live matching
;;;; and stored-query matching can never disagree.

(in-package #:beacon)

(defstruct (filter (:constructor %make-filter))
  (ids nil :type list)         ; octets(32)
  (authors nil :type list)     ; octets(32)
  (kinds nil :type list)       ; fixnums
  (tags nil :type list)        ; ((letter-code . (simple-array u64)) ...)
  (since 0 :type (integer 0))
  (until #xffffffff :type (integer 0))
  (limit nil)
  (impossible nil))            ; e.g. NIP-50 search, which we do not implement

(define-condition invalid-filter (error)
  ((reason :initarg :reason :reader invalid-filter-reason))
  (:report (lambda (c s) (format s "invalid filter: ~a" (invalid-filter-reason c)))))

(defun bad-filter (fmt &rest args)
  (error 'invalid-filter :reason (apply #'format nil fmt args)))

(defvar *max-filter-values* 1000)

(defun %filter-list (v key)
  (unless (simple-vector-p v) (bad-filter "~a must be an array" key))
  (when (> (length v) *max-filter-values*) (bad-filter "~a has too many values" key))
  (coerce v 'list))

(defun %hex32-list (v key)
  (remove-duplicates
   (mapcar (lambda (x)
             (or (and (stringp x) (hex-decode x 32))
                 (bad-filter "~a must be 64-character lowercase hex" key)))
           (%filter-list v key))
   :test #'octets-string=))

(defun parse-filter (obj)
  (unless (listp obj) (bad-filter "a filter must be a JSON object"))
  (let ((f (%make-filter)))
    (loop for (key . v) in obj do
      (cond
        ((string= key "ids") (setf (filter-ids f) (%hex32-list v key)))
        ((string= key "authors") (setf (filter-authors f) (%hex32-list v key)))
        ((string= key "kinds")
         (setf (filter-kinds f)
               (remove-duplicates
                (mapcar (lambda (k) (if (and (integerp k) (<= 0 k 65535)) k (bad-filter "kinds must be integers")))
                        (%filter-list v key)))))
        ((and (= (length key) 2) (char= (char key 0) #\#) (single-letter-tag-p (subseq key 1)))
         (let* ((letter (char-code (char key 1)))
                (b (make-obuf 64))
                (hashes (remove-duplicates
                         (mapcar (lambda (x)
                                   (unless (stringp x) (bad-filter "~a values must be strings" key))
                                   (obuf-reset b) (obuf-utf8 b x)
                                   (tag-key-hash letter (obuf-data b) 0 (obuf-fill b)))
                                 (%filter-list v key)))))
           ;; A repeated "#x" key (not valid JSON practice) simply adds another
           ;; condition, i.e. it is ANDed.
           (push (cons letter (coerce hashes '(simple-array u64 (*)))) (filter-tags f))))
        ((string= key "since")
         (unless (and (integerp v) (>= v 0)) (bad-filter "since must be a non-negative integer"))
         (setf (filter-since f) (min v #xffffffff)))
        ((string= key "until")
         (unless (and (integerp v) (>= v 0)) (bad-filter "until must be a non-negative integer"))
         (setf (filter-until f) (min v #xffffffff)))
        ((string= key "limit")
         (unless (and (integerp v) (>= v 0)) (bad-filter "limit must be a non-negative integer"))
         (setf (filter-limit f) v))
        ((string= key "search") (setf (filter-impossible f) t))
        (t nil)))                       ; unknown keys are ignored
    ;; An explicitly empty set matches nothing (NIP-01: "ids": [] selects no events).
    (loop for (key . v) in obj
          when (and (member key '("ids" "authors" "kinds") :test #'string=)
                    (simple-vector-p v) (zerop (length v)))
            do (setf (filter-impossible f) t))
    (dolist (tc (filter-tags f))
      (when (zerop (length (cdr tc))) (setf (filter-impossible f) t)))
    (when (> (filter-since f) (filter-until f)) (setf (filter-impossible f) t))
    f))

;;; ---- matching an in-memory event (live fanout) -----------------------------------

(defun hashes-intersect-p (want have)
  (declare (type (simple-array u64 (*)) want have))
  (loop for w across want thereis (find w have)))

(defun filter-matches-event-p (f e)
  (and (not (filter-impossible f))
       (<= (filter-since f) (event-created-at e) (filter-until f))
       (or (null (filter-kinds f)) (member (event-kind e) (filter-kinds f)))
       (or (null (filter-authors f)) (member (event-pubkey e) (filter-authors f) :test #'octets-string=))
       (or (null (filter-ids f)) (member (event-id e) (filter-ids f) :test #'octets-string=))
       (every (lambda (tc) (hashes-intersect-p (cdr tc) (event-tag-hashes e)))
              (filter-tags f))))
