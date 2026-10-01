;;;; beacon.asd

(defsystem "beacon"
  :description "A Nostr relay in pure Common Lisp: an append-only event log,
                in-memory unboxed indexes, a parallel signature-verify pool,
                a single group-commit writer, and indexed live fanout."
  :version "0.1.0"
  :author "ynniv"
  :license "MIT"
  :depends-on ("secp256k1-fast"      ; BIP340 Schnorr (the curve multiply)
               "sb-bsd-sockets"      ; listening socket (SBCL contrib)
               "sb-posix")           ; fsync, pipe (SBCL contrib)
  :serial t
  :components
  ((:module "src"
    :serial t
    :components
    ((:file "packages")
     (:file "util")       ; octet buffers, hex, utf-8, time, logging
     (:file "hash")       ; SHA-256 (midstate), SHA-1, base64, SipHash-2-4, CRC32
     (:file "json")       ; byte-level JSON reader + NIP-01 writer
     (:file "event")      ; parse / validate / canonical id / stored form
     (:file "verify")     ; BIP340 verify with a decoded-pubkey cache
     (:file "filter")     ; NIP-01 filters: parse, match
     (:file "log")        ; the append-only event log on disk
     (:file "index")      ; in-memory unboxed indexes (single writer, lock-free readers)
     (:file "store")      ; open/replay, insert (replaceable, deletion, expiry)
     (:file "query")      ; planner + top-k executor over the indexes
     (:file "platform")   ; sockets, poll(2), nonblocking read/write
     (:file "websocket")  ; HTTP upgrade, frames, NIP-11
     (:file "server")     ; I/O threads, connections, write queues
     (:file "relay")      ; the Nostr protocol: EVENT REQ CLOSE COUNT, fanout
     (:file "main"))))    ; configuration + entry point
  :in-order-to ((test-op (test-op "beacon/test"))))

(defsystem "beacon/test"
  :depends-on ("beacon" "cl-nostr")   ; cl-nostr: an independent client to test against
  :components ((:module "test" :serial t :components ((:file "test") (:file "network"))))
  :perform (test-op (o c) (uiop:symbol-call '#:beacon.test '#:run)))
