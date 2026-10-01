;;;; bench/serve.lisp — run a relay for load testing, logging stats every 10 s.
;;;;   sbcl --dynamic-space-size 32GB --load bench/serve.lisp --eval '(beacon.bench::serve :dir "/tmp/beacon-bench-5m/")'
(load "~/quicklisp/setup.lisp")
(let ((*compile-verbose* nil)) (ql:quickload :beacon :silent t))
(defpackage #:beacon.bench (:use #:cl))
(in-package #:beacon.bench)
(defun serve (&key (dir "/tmp/beacon-bench/") (port 47777) (io-threads 8) (verify-threads 32)
                   (query-threads 16) (sync t))
  (setf (sb-ext:bytes-consed-between-gcs) (* 256 1024 1024))
  (let ((relay (beacon:start-relay
                (beacon:make-config :port port :dir dir :io-threads io-threads :verify-threads verify-threads
                                    :query-threads query-threads :sync sync
                                    :events-per-second 1000000 :event-burst 1000000
                                    :reqs-per-second 1000000 :req-burst 1000000))))
    (loop (sleep 10)
          (format t "~&~a ~a~%" (get-universal-time) (sb-ext:octets-to-string (beacon::relay-stats-json relay)))
          (force-output))))
