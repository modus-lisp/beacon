#!/bin/sh
# Run the relay.  Options are beacon's own (see src/main.lisp), e.g.
#   ./run.sh --port 7777 --dir ./beacon-data --name "my relay"
# BEACON_HEAP sets SBCL's heap (default 16GB; ~250 bytes per stored event).
exec sbcl --dynamic-space-size "${BEACON_HEAP:-16GB}" --noinform --disable-debugger \
     --eval '(load (merge-pathnames "quicklisp/setup.lisp" (user-homedir-pathname)))' \
     --eval '(let ((*compile-verbose* nil)) (ql:quickload :beacon :silent t))' \
     --eval '(beacon:main)' --end-toplevel-options "$@"
