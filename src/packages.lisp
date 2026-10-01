;;;; src/packages.lisp

(defpackage #:beacon
  (:use #:cl)
  (:local-nicknames (#:secp #:secp256k1-fast) (#:schnorr #:secp256k1-fast.schnorr))
  (:export
   ;; running a relay
   #:start-relay #:stop-relay #:relay-port #:relay-store #:main
   #:make-config #:config
   ;; the store, usable without the network
   #:open-store #:close-store #:store-insert #:store-query #:store-count
   #:store-event-count #:compact-store
   ;; events
   #:parse-event-json #:event-id-hex #:event-json
   #:event-kind #:event-pubkey #:event-tags #:event-content #:event-created-at
   ;; hashing (exported for tests and tools)
   #:sha256 #:sha1 #:base64-encode #:siphash64 #:keyed-hash #:crc32
   #:hex-encode #:hex-decode))
