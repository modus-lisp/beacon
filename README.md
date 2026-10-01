# beacon

A **Nostr relay in pure Common Lisp**: no FFI, no foreign libraries, no
LMDB/RocksDB/SQLite underneath. Built to stay **low-latency under heavy load
with millions of stored events**, and measured doing it (below).

Siblings: [cl-nostr](../cl-nostr) is the client (and this relay's independent
test oracle); [secp256k1-fast](../secp256k1-fast) supplies the BIP340 curve
arithmetic.

## ⚠️ Status

New, unaudited research software. The protocol surface is NIP-01, 09, 11, 40
and 45; there is no NIP-42 AUTH, no NIP-50 search, no permessage-deflate, and
no TLS (put it behind a reverse proxy for `wss://`). No warranty (see
[LICENSE](LICENSE)).

## Run it

```sh
./run.sh --port 7777 --dir ./beacon-data --name "my relay"
./run.sh compact --dir ./beacon-data     # offline: drop replaced/deleted/expired events
./run-tests.sh                           # the test suite
```

Options (`src/main.lisp`): `--host`, `--port`, `--dir`, `--io-threads`,
`--verify-threads`, `--query-threads`, `--fanout-threads`,
`--fsync always|interval|never`, `--fsync-interval-ms`, `--events-per-second`,
`--event-burst`, `--reqs-per-second`, `--req-burst`, `--max-connections`,
`--name`, `--description`, `--pubkey`, `--contact`, `--log-level`.
`GET /stats` returns counters, latency percentiles and GC pauses as JSON.

## Design

```
I/O threads ──EVENT──▶ verify pool ──▶ writer (group commit) ──▶ fanout shards
     │                                     │ OK                    │ live EVENTs
     └──REQ/COUNT──▶ query pool ──stored EVENTs, EOSE──────────────┘
```

**Storage is an append-only log plus in-memory indexes.** The log
(`events.log`) is the only persistent state: CRC-framed records, each a small
binary header (created_at, kind, id, pubkey, d-tag hash, tag key hashes)
followed by the event's JSON exactly as it is sent to clients. A query result
is a copy of stored bytes, never a re-serialization. Startup replays the
headers without parsing any JSON, assigns serials in `created_at` order and
rebuilds the indexes, so every posting list starts out sorted.

**The indexes contain no per-event heap object.** SBCL's collector stops every
thread, and its cost scales with the live boxed objects it has to copy. So
events are columns of unboxed integers, short posting lists are nodes in shared
unboxed arrays, and long ones are three objects each. With 5 million events the
heap is about 1.1 GB, and a *full* collection takes ~80 ms. The ones that
happen while serving are mostly nursery collections, and the longest seen
under the load below was 20–35 ms.

**No single step is proportional to the size of the store.** Big vectors are
chunked (appending never copies data) and hash tables resize incrementally (old
and new tables coexist; each insert migrates a few slots). Before this, one
doubling at 5M events stalled the writer for most of a second.

**One writer, lock-free readers.** The writer thread publishes a serial count
after everything mentioning the event is written; readers take the count first
and never look past it. Queries run on their own pool against that snapshot,
concurrently with ingest.

**Signature verification runs in parallel and is cheap per author.** Most of
`schnorr-verify`'s cost was lifting the x-only pubkey to a curve point (a
bignum `mod-expt`, ~175 KB of garbage). beacon caches the lifted point per
author and calls the double-scalar multiply directly.

**Group commit with an explicit durability policy.** The writer takes
everything waiting and appends it in one write. `--fsync interval` (the
default) acknowledges after `write(2)` and fsyncs every 50 ms. A *process* crash
loses nothing; a *machine* crash can lose up to one interval. `--fsync always`
acknowledges only after fsync; `never` leaves it to the kernel.

**Queries pick one candidate source** — ids; replaceable slots (so
`{"authors":[…],"kinds":[0]}` is a hash lookup); the smallest of the authors /
one `#tag` / kinds posting lists; or everything — and keep the `limit` newest
in a bounded heap. Long lists are scanned backwards a block of 64 at a time.
Each block carries its min/max `created_at` and a running max, so the scan
stops as soon as nothing older can make the cut.

**Live delivery is indexed and sharded.** A new event is matched only against
subscriptions registered under its id, author, tag keys or kind (plus filters
with none of those), not against every subscription. Each fanout shard
exclusively owns the subscriptions of its connections, so there is no lock: an
earlier version had one, and a watchdog backtrace caught I/O threads waiting on
it for three seconds. Subscriptions are **gap-free**: a query runs against the
snapshot its shard reported when it registered the subscription, matches that
arrive meanwhile are parked, and they are delivered after `EOSE`.

**Sending allocates nothing in the common case.** Frames are built in a
per-thread scratch buffer and written straight to the non-blocking socket;
only bytes the kernel refuses are copied into the connection's queue. A
connection whose queue passes 32 MB is dropped as a slow consumer.

**Platform seam.** Everything OS-specific is in `src/platform.lisp`: SBCL's own
sb-bsd-sockets for the listener, sb-unix for `poll(2)` / `read` / `write` on
raw descriptors, sb-posix for fsync. A modus port replaces that file.

## Measured

On a shared 2×64-core EPYC 7C13 box (about 2.1 GHz under its frequency
scaling, other jobs running). The store held **5 million events** (a skewed
synthetic mix: notes, replies, reactions, zaps, contact lists, long-form). The
load generator runs in a separate process, publishes **open-loop** (latency
counted from the *scheduled* send time, so a stall is not hidden), signs every
event for real, and reports its own GC so client pauses are not blamed on the
relay. `--fsync interval`.

| load | publish → OK p50 / p99 / max | live delivery p50 / p99 / max | REQ → EOSE p50 / p99 / max |
|---|---|---|---|
| 2,000 events/s · 50 listeners · 16 queriers | 0.64 / 11 / 36 ms | 1.7 / 17 / 55 ms (51k deliveries/s) | 0.9 / 14 / 53 ms (7,600 queries/s) |
| 16,000 events/s · 10 listeners · 8 queriers | 0.70 / 18 / 44 ms | 0.8 / 20 / 51 ms (81k deliveries/s) | 0.5 / 14 / 40 ms (4,100 queries/s) |
| 2,000 events/s · 500 listeners · 16 queriers | 0.70 / 17 / 37 ms | 0.9 / 18 / 38 ms (25k deliveries/s) | 0.4 / 12 / 47 ms (9,800 queries/s) |

The query mix: profile and contact-list fetches, author feeds, 300-author home
feeds, threads (`#e`), notifications (`#p`), hashtags and the global feed.
Single-query latencies with no load, 5M events (`bench/store-bench.lisp`,
including reading every result's JSON): profile 10 µs, thread 7 µs, hashtag
143 µs, global feed 100 µs, notifications 260 µs, 300-author home feed ~2–6 ms.

Other numbers: bulk insert into the store ~200k events/s (writer alone);
restart replays 5M events in ~27 s; ~220 bytes of RAM per event.

With `--fsync always` on this (busy, shared) disk, publish p99 is dominated by
fsync spikes from other tenants; the relay-side stages are unchanged.

## Testing

`./run-tests.sh` runs:

- the primitives against published vectors (SHA-256, SHA-1, SipHash, CRC32,
  BIP340), and the JSON reader on hostile input;
- the chunked vectors and incrementally-resized tables across 64K-chunk and
  resize boundaries, checking lookups *during* migration;
- the store against a **brute-force reference model** — random events, random
  filters, the same answers before and after a restart, at 3k and 100k events;
- replay of a log through 4 KB chunks (hundreds of refills, records straddling
  every boundary);
- the relay over real sockets, driven by **cl-nostr**: publish, duplicate, bad
  signature, unicode round trip, live delivery, a subscriber that joins
  mid-stream and must see every one of 300 events exactly once, COUNT, CLOSED,
  NOTICE, NIP-11, and durability across a restart.

Each structural test has been shown to fail with the bug it targets put back
(the model test with `until` ignored, the replay test with the original
`read-sequence` bug, the table test with lookups that skip the old table).

## Benchmarks

```sh
QL='(load (merge-pathnames "quicklisp/setup.lisp" (user-homedir-pathname)))'

# store only: load 5M synthetic events, restart, measure GC and query latency
sbcl --dynamic-space-size 32GB --eval "$QL" --eval '(ql:quickload :beacon)' \
     --load bench/gen.lisp --load bench/store-bench.lisp \
     --eval '(beacon.bench::store-bench :n 5000000 :dir "/tmp/beacon-bench/")' --quit

# a relay over that store …
sbcl --dynamic-space-size 32GB --load bench/serve.lisp \
     --eval '(beacon.bench::serve :dir "/tmp/beacon-bench/" :port 47777)'

# … and, in another process, the load
sbcl --dynamic-space-size 32GB --eval "$QL" --eval '(ql:quickload :beacon/test)' \
     --load bench/gen.lisp --load bench/load.lisp \
     --eval '(beacon.bench::load-run :port 47777 :publishers 16 :publish-rate 1000 :listeners 10 :queriers 8 :seconds 15)'
```

- `bench/gen.lisp` — the synthetic event mix
- `bench/store-bench.lisp` — bulk load, restart time, GC cost, query latency
- `bench/serve.lisp` — a relay for load tests, with a watchdog that prints an
  I/O thread's backtrace when an iteration runs over 200 ms, and an on-demand
  profiler (`touch /tmp/beacon-prof-alloc` or `-cpu`)
- `bench/load.lisp` — the network load generator described above

## License

MIT — see [LICENSE](LICENSE).
