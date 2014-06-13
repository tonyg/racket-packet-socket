#lang racket/base
;; Simple access to packet sockets

(provide raw-interface?
	 raw-interface-names
	 raw-interface-open
	 raw-interface-close
	 raw-interface-read
	 raw-interface-write)

(require "private/packet-socket-extension.rkt")

(struct raw-interface (fd) #:transparent)

;; -> (Option (Listof String))
;; #f if the platform doesn't support it.
(define (raw-interface-names)
  (enumerate-interfaces))

;; String -> (Option Handle)
;; #f if the platform doesn't support it, the interface can't be
;; found, or some other error occurs.
(define (raw-interface-open interface-name)
  (define fd (create-and-bind-socket (string->bytes/utf-8 interface-name)))
  (and fd (raw-interface fd)))

;; Handle -> Boolean
(define (raw-interface-close handle)
  (close-socket (raw-interface-fd handle)))

;; Handle -> (Option Bytes)
;; #f if the platform doesn't support it.
(define (raw-interface-read handle)
  (define buffer (make-bytes 1522)) ;; Ethernet frame size
  (define len (socket-read (raw-interface-fd handle) buffer))
  (subbytes buffer 0 len))

;; Handle Bytes -> Void
;; #f if the platform doesn't support it.
(define (raw-interface-write handle bs)
  (socket-write (raw-interface-fd handle) bs))
