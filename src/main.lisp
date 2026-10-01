;;;; src/main.lisp — command line.
;;;;
;;;;   beacon [options]            serve
;;;;   beacon compact --dir D      rewrite D's log without dead events (offline)
;;;;
;;;; Options: --host H  --port P  --dir D  --io-threads N  --verify-threads N
;;;;          --query-threads N  --fsync always|interval|never  --fsync-interval-ms N
;;;;          --name S  --description S
;;;;          --pubkey HEX  --contact S  --events-per-second N  --event-burst N
;;;;          --max-connections N  --log-level 0|1|2

(in-package #:beacon)

(defun parse-args (args)
  (let ((plist '()) (command :serve))
    (loop while args do
      (let ((a (pop args)))
        (flet ((val () (or (pop args) (error "~a needs a value" a)))
               (int () (parse-integer (or (pop args) (error "~a needs a number" a)))))
          (cond
            ((string= a "compact") (setf command :compact))
            ((string= a "--host") (setf (getf plist :host) (val)))
            ((string= a "--port") (setf (getf plist :port) (int)))
            ((string= a "--dir") (setf (getf plist :dir) (val)))
            ((string= a "--io-threads") (setf (getf plist :io-threads) (int)))
            ((string= a "--verify-threads") (setf (getf plist :verify-threads) (int)))
            ((string= a "--query-threads") (setf (getf plist :query-threads) (int)))
            ((string= a "--no-fsync") (setf (getf plist :sync) :never))
            ((string= a "--fsync")
             (setf (getf plist :sync) (let ((v (val)))
                                        (cond ((string= v "always") :always) ((string= v "interval") :interval)
                                              ((string= v "never") :never) (t (error "--fsync always|interval|never"))))))
            ((string= a "--fsync-interval-ms") (setf (getf plist :fsync-interval-ms) (int)))
            ((string= a "--name") (setf (getf plist :name) (val)))
            ((string= a "--description") (setf (getf plist :description) (val)))
            ((string= a "--pubkey") (setf (getf plist :pubkey) (val)))
            ((string= a "--contact") (setf (getf plist :contact) (val)))
            ((string= a "--events-per-second") (setf (getf plist :events-per-second) (int)))
            ((string= a "--event-burst") (setf (getf plist :event-burst) (int)))
            ((string= a "--reqs-per-second") (setf (getf plist :reqs-per-second) (int)))
            ((string= a "--req-burst") (setf (getf plist :req-burst) (int)))
            ((string= a "--max-connections") (setf (getf plist :max-connections) (int)))
            ((string= a "--log-level") (setf *log-level* (int)))
            (t (error "unknown argument ~a" a))))))
    (values command plist)))

(defun main (&optional (args (uiop:command-line-arguments)))
  (multiple-value-bind (command plist) (parse-args args)
    (ecase command
      (:compact
       (let ((kept (compact-store (or (getf plist :dir) "./beacon-data/"))))
         (format t "compacted: ~:d events kept~%" kept)))
      (:serve
       ;; a relay holds millions of objects in unboxed arrays and makes short-lived
       ;; garbage per message; a larger nursery means fewer stop-the-world pauses
       (setf (sb-ext:bytes-consed-between-gcs) (* 256 1024 1024))
       (let ((relay (start-relay (apply #'make-config plist))))
         (handler-case
             (loop (sleep 60)
                   (log-msg 1 "~a" (sb-ext:octets-to-string (relay-stats-json relay))))
           (sb-sys:interactive-interrupt ()
             (log-msg 1 "stopping")
             (stop-relay relay))))))))
