#lang racket/base

(require make/setup-extension)

(provide pre-installer)

(define (pre-installer collections-top-path packet-socket-path)
  (pre-install packet-socket-path
	       (build-path packet-socket-path "private")
	       "packet-socket-extension.c"
	       "."
	       '()
	       '()
	       '()
	       '()
	       '()
	       '()
	       (lambda (thunk) (thunk))
	       #t))
