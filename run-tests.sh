#!/bin/sh
# Run the test suite; exits non-zero on any failure.
exec ${LISP:-sbcl} --dynamic-space-size 8GB --noinform --non-interactive \
     --eval '(load (merge-pathnames "quicklisp/setup.lisp" (user-homedir-pathname)))' \
     --eval '(let ((*compile-verbose* nil)) (ql:quickload :beacon/test :silent t))' \
     --eval '(sb-ext:exit :code (if (beacon.test:run) 0 1) :abort t)'
