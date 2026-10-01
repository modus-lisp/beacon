;;;; bench/serve.lisp — run a relay for load testing, logging stats every 10 s.
;;;;   sbcl --dynamic-space-size 32GB --load bench/serve.lisp --eval '(beacon.bench::serve :dir "/tmp/beacon-bench-5m/")'
(load "~/quicklisp/setup.lisp")
(let ((*compile-verbose* nil)) (ql:quickload :beacon :silent t))
(defpackage #:beacon.bench (:use #:cl))
(require :sb-sprof)
(in-package #:beacon.bench)
(defun serve (&key (dir "/tmp/beacon-bench/") (port 47777) (io-threads 8) (verify-threads 32)
                   (query-threads 16) (sync :interval))
  (setf (sb-ext:bytes-consed-between-gcs) (* 256 1024 1024))
  (let ((relay (beacon:start-relay
                (beacon:make-config :port port :dir dir :io-threads io-threads :verify-threads verify-threads
                                    :query-threads query-threads :sync sync
                                    :events-per-second 1000000 :event-burst 1000000
                                    :reqs-per-second 1000000 :req-burst 1000000))))
    ;; watchdog: show what an I/O thread is doing when an iteration runs long
    (sb-thread:make-thread
     (lambda ()
       (loop (sleep 0.05)
             (loop for io across (beacon::server-iothreads (beacon::relay-server relay))
                   for since = (beacon::iothread-busy-since io)
                   when (and (plusp since) (> (- (beacon::now-us) since) 200000))
                     do (format t "~&=== io thread busy ~d ms ===~%" (round (- (beacon::now-us) since) 1000))
                        (sb-thread:interrupt-thread (beacon::iothread-thread io)
                                                    (lambda () (sb-debug:print-backtrace :count 25) (force-output)))
                        (sleep 1))))
     :name "watchdog")
    ;; touch /tmp/beacon-prof-alloc (or -cpu) to profile 10 s of live traffic
    (sb-thread:make-thread
     (lambda ()
       (loop (sleep 0.5)
             (dolist (mode '(:alloc :cpu))
               (let ((f (format nil "/tmp/beacon-prof-~(~a~)" mode)))
                 (when (probe-file f)
                   (delete-file f)
                   (with-open-file (out (format nil "/tmp/beacon-prof-~(~a~).out" mode) :direction :output :if-exists :supersede)
                     (let ((*standard-output* out))
                       (sb-sprof:with-profiling (:mode mode :threads :all :max-samples 200000
                                                 :sample-interval 0.001 :report :graph)
                         (sleep 10)))))))))
     :name "profiler")
    (loop (sleep 10)
          (format t "~&~a ~a~%" (get-universal-time) (sb-ext:octets-to-string (beacon::relay-stats-json relay)))
          (force-output))))
