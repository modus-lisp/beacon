;;;; test/network.lisp — the relay over real sockets, driven by cl-nostr.
;;;;
;;;; cl-nostr is an independent client (its own event serialization, its own
;;;; WebSocket client over seal), so these tests check beacon against something
;;;; that did not grow up with it.  Raw WebSocket traffic, for the messages
;;;; cl-nostr has no API for (COUNT, malformed input), goes through
;;;; seal.websocket directly.

(in-package #:beacon.test)

(defvar *relay* nil)

(defun relay-url () (format nil "ws://127.0.0.1:~d/" (relay-port *relay*)))

(defun wait-until (fn &key (timeout 10))
  (let ((deadline (+ (get-internal-real-time) (* timeout internal-time-units-per-second))))
    (loop (when (funcall fn) (return t))
          (when (> (get-internal-real-time) deadline) (return nil))
          (sleep 0.01))))

(defun nkey () (cl-nostr.keys:generate-keypair))

(defun note (kp content &key (kind 1) tags)
  (cl-nostr.event:build-event kp kind content :tags tags))

(defun publish-sync (r event)
  "Publish and wait for the OK.  -> (values accepted message)."
  (let ((done nil) (acc nil) (msg nil))
    (cl-nostr.relay:publish r event :on-ok (lambda (a m) (setf acc a msg m done t)))
    (wait-until (lambda () done))
    (values acc msg done)))

(defun fetch (r filters &key (timeout 10))
  "Stored events for FILTERS (cl-nostr filter structs) until EOSE."
  (let ((events '()) (eose nil))
    (let ((sub (cl-nostr.relay:subscribe r filters
                                         :on-event (lambda (e rl) (declare (ignore rl)) (push e events))
                                         :on-eose (lambda (rl) (declare (ignore rl)) (setf eose t)))))
      (wait-until (lambda () eose) :timeout timeout)
      (cl-nostr.relay:unsubscribe r sub))
    (values (nreverse events) eose)))

(defun raw-ws ()
  (seal.websocket:connect (relay-url)))

(defun raw-exchange (ws text &key (timeout 5))
  "Send TEXT, return the first reply as a parsed vector."
  (seal.websocket:send-text ws text)
  (let ((reply nil))
    (let ((th (sb-thread:make-thread (lambda () (setf reply (ignore-errors (seal.websocket:receive-text ws)))))))
      (wait-until (lambda () reply) :timeout timeout)
      (unless reply (ignore-errors (sb-thread:terminate-thread th))))
    (and reply (com.inuoe.jzon:parse reply))))

(defun http-get (path &key accept)
  (let ((s (make-instance 'sb-bsd-sockets:inet-socket :type :stream :protocol :tcp)))
    (sb-bsd-sockets:socket-connect s #(127 0 0 1) (relay-port *relay*))
    (let ((stream (sb-bsd-sockets:socket-make-stream s :input t :output t :element-type 'character
                                                       :external-format :latin-1)))
      (format stream "GET ~a HTTP/1.1~c~cHost: x~c~c~@[Accept: ~a~c~c~]~c~c" path #\Return #\Newline #\Return #\Newline
              accept #\Return #\Newline #\Return #\Newline)
      (force-output stream)
      (prog1 (with-output-to-string (out)
               (loop for line = (read-line stream nil) while line do (write-line line out)))
        (close stream)))))

(defun run-network-tests ()
  (let ((dir (fresh-dir "network")))
    (setf *relay* (start-relay (make-config :port 0 :dir (namestring dir) :io-threads 2
                                            :verify-threads 2 :query-threads 2 :sync nil
                                            :events-per-second 100000 :event-burst 100000)))
    (unwind-protect
         (let* ((alice (nkey)) (bob (nkey))
                (r (cl-nostr.relay:connect-relay (relay-url))))
           (unwind-protect
                (progn
                  ;; publish + read back
                  (let ((e (note alice "hello beacon")))
                    (multiple-value-bind (ok msg done) (publish-sync r e)
                      (check "publish acknowledged" done)
                      (check (format nil "publish accepted (~a)" msg) ok))
                    (multiple-value-bind (ok msg) (publish-sync r e)
                      (check "duplicate accepted" ok)
                      (check "duplicate says so" (and msg (search "duplicate" msg))))
                    (let ((got (fetch r (cl-nostr.filter:make-filter
                                         :authors (list (cl-nostr.keys:public-hex alice))))))
                      (check "fetch by author" (= 1 (length got)))
                      (check "fetched event verifies (cl-nostr's own check)"
                             (and got (cl-nostr.event:verify-event (first got))))
                      (check "fetched event is byte-identical in meaning"
                             (and got (string= (cl-nostr.event:event-id (first got)) (cl-nostr.event:event-id e))))))
                  ;; bad signature
                  (let* ((e (note alice "forged")))
                    (setf (cl-nostr.event:event-sig e)
                          (concatenate 'string (subseq (cl-nostr.event:event-sig e) 0 126)
                                       (if (string= (subseq (cl-nostr.event:event-sig e) 126) "00") "11" "00")))
                    (multiple-value-bind (ok msg) (publish-sync r e)
                      (check "bad signature rejected" (not ok))
                      (check "bad signature reason" (and msg (search "invalid" msg)))))
                  ;; unicode + escapes round trip
                  (let ((e (note bob (format nil "naïve ☃ \"quoted\" back\\slash tab	 ~a" (code-char #x1F600))
                                 :tags '(("t" "unicode") ("p" "deadbeef")))))
                    (publish-sync r e)
                    (let ((got (fetch r (cl-nostr.filter:make-filter :tags '(("t" . ("unicode")))))))
                      (check "unicode event round-trips"
                             (and got (string= (cl-nostr.event:event-content (first got)) (cl-nostr.event:event-content e))
                                  (cl-nostr.event:verify-event (first got))))))
                  ;; live delivery to a second connection
                  (let ((r2 (cl-nostr.relay:connect-relay (relay-url))) (live '()) (eose nil))
                    (unwind-protect
                         (progn
                           (cl-nostr.relay:subscribe r2 (cl-nostr.filter:make-filter :kinds '(1) :authors (list (cl-nostr.keys:public-hex bob)))
                                                     :on-event (lambda (e rl) (declare (ignore rl)) (push e live))
                                                     :on-eose (lambda (rl) (declare (ignore rl)) (setf eose t)))
                           (wait-until (lambda () eose))
                           (let ((before (length live)))
                             (publish-sync r (note bob "live one"))
                             (check "live event delivered" (wait-until (lambda () (> (length live) before)) :timeout 5))))
                      (cl-nostr.relay:close-relay r2)))
                  ;; GAP-FREE: subscribe in the middle of a publish stream
                  (let* ((carol (nkey)) (n 300)
                         (events (loop for i below n collect (note carol (format nil "stream ~d" i))))
                         (r2 (cl-nostr.relay:connect-relay (relay-url)))
                         (seen (make-hash-table :test 'equal)) (dups 0))
                    (unwind-protect
                         (let ((pub (sb-thread:make-thread
                                     (lambda () (dolist (e events) (cl-nostr.relay:publish r e))))))
                           (sleep 0.05)
                           (cl-nostr.relay:subscribe r2 (cl-nostr.filter:make-filter :authors (list (cl-nostr.keys:public-hex carol)) :limit 5000)
                                                     :on-event (lambda (e rl) (declare (ignore rl))
                                                                 (if (gethash (cl-nostr.event:event-id e) seen)
                                                                     (incf dups)
                                                                     (setf (gethash (cl-nostr.event:event-id e) seen) t))))
                           (sb-thread:join-thread pub)
                           (check (format nil "gap-free: all ~d events seen (got ~d)" n (hash-table-count seen))
                                  (wait-until (lambda () (= n (hash-table-count seen))) :timeout 20))
                           (check (format nil "gap-free: no duplicates (~d)" dups) (zerop dups)))
                      (cl-nostr.relay:close-relay r2)))
                  ;; raw protocol: COUNT, CLOSED, NOTICE
                  (let ((ws (raw-ws)))
                    (unwind-protect
                         (progn
                           (let ((reply (raw-exchange ws (format nil "[\"COUNT\",\"c1\",{\"authors\":[\"~a\"]}]" (cl-nostr.keys:public-hex alice)))))
                             (check "COUNT reply" (and reply (string= (aref reply 0) "COUNT")
                                                       (= 1 (gethash "count" (aref reply 2))))))
                           (let ((reply (raw-exchange ws "[\"REQ\",\"s1\",{\"ids\":[\"nothex\"]}]")))
                             (check "bad filter -> CLOSED" (and reply (string= (aref reply 0) "CLOSED") (string= (aref reply 1) "s1"))))
                           (let ((reply (raw-exchange ws "not json")))
                             (check "garbage -> NOTICE" (and reply (string= (aref reply 0) "NOTICE"))))
                           (let ((reply (raw-exchange ws "[\"EVENT\",{\"id\":\"x\"}]")))
                             (check "malformed event -> OK false" (and reply (string= (aref reply 0) "OK") (null (aref reply 2))))))
                      (ignore-errors (seal.websocket:close-socket ws))))
                  ;; NIP-11
                  (let ((resp (http-get "/" :accept "application/nostr+json")))
                    (check "NIP-11 document" (and (search "200 OK" resp) (search "\"supported_nips\"" resp)
                                                  (search "Access-Control-Allow-Origin" resp))))
                  (let ((resp (http-get "/stats")))
                    (check "stats endpoint" (search "\"stored\"" resp))))
             (cl-nostr.relay:close-relay r)))
      (stop-relay *relay*))
    ;; the events are durable: reopen the store and count them
    (let ((store (open-store dir)))
      (check "events survive a restart" (>= (store-event-count store) 300))
      (close-store store))))
