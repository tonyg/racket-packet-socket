#lang racket/base
;; Simple access to packet sockets

(provide raw-interface?
	 raw-interface-names
	 raw-interface-open
	 raw-interface-hwaddr
	 raw-interface-close
	 raw-interface-read
	 raw-interface-write)

(require (only-in racket/list remove-duplicates))
(require racket/match)
(require racket/runtime-path)
(require ffi/unsafe)
(require ffi/unsafe/define)
(require ffi/unsafe/port)

(define-runtime-path packet-socket-path ".")

(struct raw-interface (name ;; String
                       hwaddr ;; Bytes
                       [fd #:mutable] ;; int - mutable for closing
                       buflen ;; int
                       [buffered-packets #:mutable]) ;; (Listof Bytes)
  #:transparent)

(define-ffi-definer define-ext
  (ffi-lib (build-path packet-socket-path
                       "private"
                       "compiled"
                       "native"
                       (system-library-subpath)
                       "packet-socket-extension.so")))

(define-ext packet_socket_enumerate_interfaces (_fun (_fun _string -> _void) -> _int))
(define-ext packet_socket_create_and_bind (_fun _string -> _int))
(define-ext packet_socket_read_buffer_length (_fun _int -> _long))
(define-ext packet_socket_close (_fun _int -> _int))
(define-ext packet_socket_hwaddr (_fun _int
                                       _string
                                       (b : _bytes)
                                       (len : (_ptr io _ssize) = (bytes-length b))
                                       -> (ans : _int)
                                       -> (values ans len)))
(define-ext packet_socket_read (_fun #:save-errno 'posix
                                     _int
                                     (b : _bytes)
                                     (len : _long = (bytes-length b))
                                     (truncated : (_ptr o _int))
                                     -> (ans : _long)
                                     -> (values ans (not (zero? truncated)))))
(define-ext packet_socket_extract_packet (_fun (buf : _bytes)
                                               _size
                                               _int
                                               (base : (_ptr o _int))
                                               (len : (_ptr o _int))
                                               -> (state : _int)
                                               -> (values state (subbytes buf base (+ base len)))))
(define-ext write (_fun #:save-errno 'posix
                        _int
                        (buf : _bytes)
                        (len : _size = (bytes-length buf))
                        -> _ssize))

;; -> (Option (Listof String))
;; #f if the platform doesn't support it.
(define (raw-interface-names)
  (define names '())
  (and (zero? (packet_socket_enumerate_interfaces (lambda (i) (set! names (cons i names)))))
       (remove-duplicates (reverse names))))

;; Handle -> Void
;; Errors if the handle is closed
(define (check-open f handle)
  (unless (number? (raw-interface-fd handle))
    (error f "Attempt to use closed handle ~v" handle)))

;; String -> (Option Handle)
;; #f if the platform doesn't support it, the interface can't be
;; found, or some other error occurs.
(define (raw-interface-open interface-name)
  (match (packet_socket_create_and_bind interface-name)
    [-1 #f]
    [fd (match (packet_socket_read_buffer_length fd)
	  [-1 (begin (packet_socket_close fd) #f)]
	  [buflen
           (define hwaddr-buf (make-bytes 256)) ;; should be plenty?
           (define-values (ans len) (packet_socket_hwaddr fd interface-name hwaddr-buf))
           (match ans
             [-1 (begin (packet_socket_close fd) #f)]
             [-2 (error 'raw-interface-open
                        "hwaddr-buf too small: ~a bytes needed, but ~a bytes given"
                        len
                        (bytes-length hwaddr-buf))]
             [0 (raw-interface interface-name
                               (subbytes hwaddr-buf 0 len)
                               fd
                               buflen
                               '())])])]))

;; Handle -> Boolean
(define (raw-interface-close handle)
  (check-open 'raw-interface-close handle)
  (packet_socket_close (raw-interface-fd handle))
  (set-raw-interface-fd! handle #f))

;; Handle -> (Option Bytes)
;; #f if the platform doesn't support it.
(define (raw-interface-read handle)
  (match (raw-interface-buffered-packets handle)
    ['()
     (define buffer (make-bytes (raw-interface-buflen handle)))
     (let retry ()
       (define-values (bytes-read ?truncated) (packet_socket_read (raw-interface-fd handle) buffer))
       (when ?truncated
         (error 'raw-interface-read "Read yielded truncated packet"))
       (match bytes-read
         [-2 ;; block and retry
          (semaphore-wait (unsafe-socket->semaphore (raw-interface-fd handle) 'read))
          (retry)]
         [-1 ;; error
          (error 'raw-interface-read "Read yielded errno ~a" (saved-errno))]
         [_other
          (define buffered-packets
            (let loop ((acc '()) (old-state 0))
              (define-values (state packet)
                (packet_socket_extract_packet buffer bytes-read old-state))
              (let ((acc (cons packet acc)))
                (if (< state bytes-read)
                    (loop acc state)
                    (reverse acc)))))
          (set-raw-interface-buffered-packets! handle buffered-packets)
          (raw-interface-read handle)]))]
    [(cons packet rest)
     (set-raw-interface-buffered-packets! handle rest)
     packet]))

;; Handle Bytes -> Void
(define (raw-interface-write handle bs)
  (check-open 'raw-interface-write handle)
  (match (write (raw-interface-fd handle) bs)
    [-1
     (error 'raw-interface-write "Write yielded errno ~a" (saved-errno))]
    [count
     (void)]))
