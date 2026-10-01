;;;; bench/store-bench.lisp — load N events into a store, restart it, time queries.
;;;;
;;;;   sbcl --dynamic-space-size 32GB --load bench/store-bench.lisp \
;;;;        --eval '(beacon.bench:store-bench :n 5000000 :dir "/tmp/beacon-bench/")'

(in-package #:beacon.bench)

(defun gc-full () (sb-ext:gc :full t))
(defun heap-mb () (/ (sb-kernel:dynamic-usage) 1048576.0))

(defun percentile (sorted p)
  (if (zerop (length sorted)) 0
      (aref sorted (min (1- (length sorted)) (floor (* p (length sorted)))))))

(defun time-queries (store name filter-fn &key (n 300))
  "Run N queries built by FILTER-FN, each reading every result's JSON as a relay
would to send it.  Reports latency percentiles in microseconds."
  (let ((lat (make-array n :element-type 'fixnum)) (results 0))
    (dotimes (i n)
      (let* ((filters (list (beacon::parse-filter (beacon::json-parse-string (funcall filter-fn)))))
             (t0 (now-us))
             (serials (beacon:store-query store filters)))
        (dolist (s serials) (beacon::read-event-json store s))
        (setf (aref lat i) (- (now-us) t0))
        (incf results (length serials))))
    (let ((sorted (sort lat #'<)))
      (format t "~&  ~28a p50 ~7:d us   p99 ~7:d us   max ~8:d us   avg results ~,1f~%"
              name (percentile sorted 0.5) (percentile sorted 0.99) (aref sorted (1- n))
              (/ results n)))))

(defun store-bench (&key (n 1000000) (dir "/tmp/beacon-bench/") (threads 16) (batch 5000)
                         (authors 200000) (fresh t))
  (setf (sb-ext:bytes-consed-between-gcs) (* 512 1024 1024))
  (when fresh (uiop:delete-directory-tree (uiop:ensure-directory-pathname dir) :validate t :if-does-not-exist :ignore))
  (let* ((world0 (make-world :authors authors))
         (author-vec (world-authors world0))
         (store (beacon:open-store dir :sync nil))
         (q (beacon::make-bqueue :limit 4))
         (per-thread (ceiling n threads))
         (stored 0) (dup 0) (rej 0)
         (t0 (now-us)))
    (format t "~&loading ~:d events (~d generator threads, ~:d authors)...~%" n threads authors)
    (let ((gens (loop for k below threads
                      collect (let ((k k))
                                (sb-thread:make-thread
                                 (lambda ()
                                   (let ((w (make-world :authors 1 :seed (+ 1000 k))))
                                     (setf (world-authors w) author-vec)
                                     (loop with left = per-thread
                                           while (plusp left)
                                           do (let ((m (min batch left)))
                                                (loop until (beacon::bqueue-push q (loop repeat m collect (next-event w)))
                                                      do (sleep 0.001))
                                                (decf left m))))))))))
      (loop with done = 0
            while (< done (* per-thread threads))
            do (let ((events (beacon::bqueue-pop q :timeout 1)))
                 (when events
                   (incf done (length events))
                   (dolist (r (beacon::store-insert-batch store events))
                     (case (car r) (:stored (incf stored)) (:duplicate (incf dup)) (t (incf rej))))
                   (when (zerop (mod done 1000000))
                     (format t "~&  ~:d events, ~,0f/s~%" done (/ done (/ (- (now-us) t0) 1d6)))))))
      (mapc #'sb-thread:join-thread gens))
    (let ((secs (/ (- (now-us) t0) 1d6)))
      (format t "~&loaded: ~:d stored, ~:d duplicate, ~:d rejected (replaced etc.) in ~,1f s = ~,0f events/s~%"
              stored dup rej secs (/ (+ stored dup rej) secs)))
    (gc-full)
    (format t "live events ~:d   heap after full GC ~,0f MB   log ~,0f MB~%"
            (beacon:store-event-count store) (heap-mb)
            (/ (beacon::event-log-size (beacon::store-log store)) 1048576.0))
    (beacon:close-store store)
    ;; restart
    (setf store nil) (gc-full)
    (let ((t1 (now-us)))
      (setf store (beacon:open-store dir :sync nil))
      (format t "reopen (replay + index rebuild): ~,2f s~%" (/ (- (now-us) t1) 1d6)))
    (gc-full)
    (format t "heap after reopen + full GC ~,0f MB~%" (heap-mb))
    (let ((gc0 sb-ext:*gc-run-time*))
      (gc-full)
      (format t "one full GC with the store loaded: ~,0f ms~%"
              (/ (* 1000 (- sb-ext:*gc-run-time* gc0)) internal-time-units-per-second))
      (let ((gc1 sb-ext:*gc-run-time*))
        (sb-ext:gc)
        (format t "one nursery GC with the store loaded: ~,1f ms~%"
                (/ (* 1000 (- sb-ext:*gc-run-time* gc1)) internal-time-units-per-second))))
    ;; queries
    (let* ((w (make-world :authors 1 :seed 7))
           (rng (world-rng w))
           (now (unix-now))
           (pk (lambda () (hex-encode (svref author-vec (skewed (length author-vec) rng)))))
           (some-note-ids
             (coerce (mapcar (lambda (s) (multiple-value-bind (buf st en) (beacon::read-event-json store s)
                                           (beacon::json-get (beacon::json-parse buf st en) "id")))
                             (beacon::store-query store (list (beacon::parse-filter (beacon::json-parse-string "{\"kinds\":[1],\"limit\":2000}")))))
                     'simple-vector))
           (newest (let ((s (first (beacon::store-query store (list (beacon::parse-filter (beacon::json-parse-string "{\"limit\":1}")))))))
                     (beacon::col-created (beacon::index-columns (beacon::store-index store)) s))))
      (declare (ignorable now))
      (format t "~&query latency (each includes reading every result's JSON):~%")
      (time-queries store "profile {authors:[1],kinds:[0]}"
                    (lambda () (format nil "{\"authors\":[\"~a\"],\"kinds\":[0]}" (funcall pk))))
      (time-queries store "contacts x50 authors"
                    (lambda () (format nil "{\"authors\":[~{\"~a\"~^,~}],\"kinds\":[3]}" (loop repeat 50 collect (funcall pk)))))
      (time-queries store "author feed limit 20"
                    (lambda () (format nil "{\"authors\":[\"~a\"],\"kinds\":[1],\"limit\":20}" (funcall pk))))
      (time-queries store "home feed 300 authors, 100"
                    (lambda () (format nil "{\"authors\":[~{\"~a\"~^,~}],\"kinds\":[1,6],\"limit\":100}" (loop repeat 300 collect (funcall pk)))))
      (time-queries store "global kinds:[1] limit 50"
                    (lambda () "{\"kinds\":[1],\"limit\":50}"))
      (time-queries store "thread #e + kinds 1,7"
                    (lambda () (format nil "{\"#e\":[\"~a\"],\"kinds\":[1,7,9735]}" (svref some-note-ids (random (length some-note-ids) rng)))))
      (time-queries store "notifications #p limit 50"
                    (lambda () (format nil "{\"#p\":[\"~a\"],\"limit\":50}" (funcall pk))))
      (time-queries store "hashtag #t limit 50"
                    (lambda () (format nil "{\"#t\":[\"tag~d\"],\"kinds\":[1],\"limit\":50}" (skewed 2000 rng))))
      (time-queries store "ids x20"
                    (lambda () (format nil "{\"ids\":[~{\"~a\"~^,~}]}" (loop repeat 20 collect (svref some-note-ids (random (length some-note-ids) rng))))))
      (time-queries store "since 1h, kinds [7], limit 500"
                    (lambda () (format nil "{\"kinds\":[7],\"since\":~d,\"limit\":500}" (- newest 3600)))))
    (beacon:close-store store)))
