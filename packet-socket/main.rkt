#lang racket/base
;; Simple access to packet sockets

(provide raw-interface?
	 raw-interface-names
	 raw-interface-open
	 raw-interface-hwaddr
	 raw-interface-close
	 raw-interface-read
	 raw-interface-write)

(require racket/match)
(require (only-in racket/list remove-duplicates))
(require "private/packet-socket-extension.rkt")

(struct raw-interface (name hwaddr [fd #:mutable] buflen [buffered-packets #:mutable])
	#:transparent)

;; -> (Option (Listof String))
;; #f if the platform doesn't support it.
(define (raw-interface-names)
  (define names (enumerate-interfaces))
  (and names (remove-duplicates names)))

;; Handle -> Void
;; Errors if the handle is closed
(define (check-open f handle)
  (unless (number? (raw-interface-fd handle))
    (error f "Attempt to use closed handle ~v" handle)))

;; String -> (Option Handle)
;; #f if the platform doesn't support it, the interface can't be
;; found, or some other error occurs.
(define (raw-interface-open interface-name)
  (define interface-name-bytes (string->bytes/utf-8 interface-name))
  (match (create-and-bind-socket interface-name-bytes)
    [#f #f]
    [fd (match (socket-read-buffer-length fd)
	  [-1 (begin (socket-close fd) #f)]
	  [buflen (raw-interface interface-name
				 (socket-hwaddr fd interface-name-bytes)
				 fd
				 buflen
				 '())])]))

;; Handle -> Boolean
(define (raw-interface-close handle)
  (check-open 'raw-interface-close handle)
  (socket-close (raw-interface-fd handle))
  (set-raw-interface-fd! handle #f))

;; Handle -> (Option Bytes)
;; #f if the platform doesn't support it.
(define (raw-interface-read handle)
  (match (raw-interface-buffered-packets handle)
    ['()
     (define buffer (make-bytes (raw-interface-buflen handle)))
     (define subpacketspecs (socket-read (raw-interface-fd handle) buffer))
     (define buffered-packets (for/list [(subpacketspec subpacketspecs)]
				(match-define (cons offset len) subpacketspec)
				(subbytes buffer offset (+ offset len))))
     (set-raw-interface-buffered-packets! handle buffered-packets)
     (raw-interface-read handle)]
    [(cons packet rest)
     (set-raw-interface-buffered-packets! handle rest)
     packet]))

;; Handle Bytes -> Void
;; #f if the platform doesn't support it.
(define (raw-interface-write handle bs)
  (check-open 'raw-interface-write handle)
  (socket-write (raw-interface-fd handle) bs))
