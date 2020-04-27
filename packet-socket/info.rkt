#lang setup/infotab

(define name "packet-socket")
(define blurb (list `(p "Access to raw Ethernet frames from Racket")))
(define primary-file "main.rkt")
(define categories '(net))

(define pre-install-collection "private/install.rkt")
(define compile-omit-files '("private/install.rkt"))
