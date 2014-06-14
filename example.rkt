#lang racket

(require packet-socket)

(require (only-in file/sha1 bytes->hex-string))
(require bitsyntax)
(require "dump-bytes.rkt")

(define device-names (raw-interface-names))
(printf "Device names: ~a\n" device-names)

(when (null? device-names)
  (error 'example "No available network devices."))

(define device-name
  (let loop ((candidates '("wlan0" "eth0" "en0" "en1")))
    (match candidates
      ['() (car device-names)] ;; whatever is left
      [(cons candidate rest)
       (if (member candidate device-names)
	   candidate
	   (loop rest))])))

(define h (raw-interface-open device-name))
(when (not h)
  (error 'example "Couldn't open device ~v" device-name))
(printf "Opened device ~a, yielding handle ~v\n" device-name h)

(define (pretty-bytes bs)
  (bytes->hex-string (bit-string->bytes bs)))

(define (pretty-ip ip)
  (bit-string-case (bit-string (ip :: integer bytes 4))
    ([ a b c d ] (format "~a.~a.~a.~a" a b c d))))

(define (dump bs)
  (dump-bytes! (bit-string->bytes bs)))

(define (analyze-tcp-options opts)
  (bit-string-case opts
    ([ ]
     (void))
    ([ (= 0) (rest :: binary) ]
     (printf "      end of option list\n")
     (analyze-tcp-options rest))
    ([ (= 1) (rest :: binary) ]
     (printf "      NOP option\n")
     (analyze-tcp-options rest))
    ([ kind len (body :: binary bytes (- len 2)) (rest :: binary) ]
     (printf "      option ~a: ~a\n" kind (pretty-bytes body))
     (analyze-tcp-options rest))))

(define (analyze-ipv4-data protocol data)
  (case protocol
    [(6) ;; TCP
     (bit-string-case data
       ([ (source-port :: integer bytes 2)
	  (target-port :: integer bytes 2)
	  (sequence-number :: integer bytes 4)
	  (acknowledgement-number :: integer bytes 4)
	  (data-offset :: integer bits 4)
	  (reserved :: integer bits 3)
	  (ns :: integer bits 1)
	  (cwr :: integer bits 1)
	  (ece :: integer bits 1)
	  (urg :: integer bits 1)
	  (ack :: integer bits 1)
	  (psh :: integer bits 1)
	  (rst :: integer bits 1)
	  (syn :: integer bits 1)
	  (fin :: integer bits 1)
	  (window-size :: integer bytes 2)
	  (checksum :: integer bytes 2)
	  (urgent-pointer :: integer bytes 2)
	  (rest :: binary) ]
	(define-syntax-rule (flag v) (if (zero? v) "" (format " ~a" 'v)))
	(printf"     TCP ~a -> ~a (seq ~a, ack ~a, dofs ~a, reserved ~a, flags~a~a~a~a~a~a~a~a~a, window ~a, cksum ~a, urg ~a)\n"
	       source-port
	       target-port
	       sequence-number
	       acknowledgement-number
	       data-offset
	       reserved
	       (flag ns)
	       (flag cwr)
	       (flag ece)
	       (flag urg)
	       (flag ack)
	       (flag psh)
	       (flag rst)
	       (flag syn)
	       (flag fin)
	       window-size
	       checksum
	       urgent-pointer)
	(bit-string-case rest
	  ([ (opts :: binary bytes (- (* data-offset 4) 20))
	     (data :: binary) ]
	   (printf "    options:\n")
	   (analyze-tcp-options opts)
	   (printf "    data:\n")
	   (dump data))))
       ([ (other :: binary) ]
	(printf "    unknown TCP packet:\n")
	(dump other)))]
    [else
     (printf "    unknown IPv4 protocol:\n")
     (dump data)]))

(let loop ()
  (flush-output)
  (bit-string-case (raw-interface-read h)
    ([ (target-mac-addr :: binary bytes 6)
       (source-mac-addr :: binary bytes 6)
       (ether-type :: integer bytes 2)
       (body :: binary) ]
     (printf "PACKET: ~a -> ~a (type ~a)\n"
	     (pretty-bytes source-mac-addr)
	     (pretty-bytes target-mac-addr)
	     (number->string ether-type 16))
     (case ether-type
       [(#x0800) ;; IP
	(define IP-VERSION 4)
	(define IP-MINIMUM-HEADER-LENGTH 5)
	(bit-string-case body
	  ([ (= IP-VERSION :: bits 4)
	     (header-length :: bits 4)
	     service-type
	     (total-length :: bits 16)
	     (id :: bits 16)
	     (flags :: bits 3)
	     (fragment-offset :: bits 13)
	     ttl
	     protocol
	     (header-checksum :: bits 16)
	     (source-ip :: bits 32)
	     (destination-ip :: bits 32)
	     (rest :: binary) ]
	   (printf "  IPv4 ~a -> ~a (protocol ~a, service-type ~a, id ~a, flags ~a, total-length ~a, ttl ~a, fragment ~a, cksum ~a)\n"
		   (pretty-ip source-ip)
		   (pretty-ip destination-ip)
		   protocol
		   service-type
		   id
		   flags
		   total-length
		   ttl
		   fragment-offset
		   header-checksum)
	   (if (and (>= header-length 5)
		    (>= (bit-string-length body) (* header-length 4)))
	       (let ((options-length (* 4 (- header-length IP-MINIMUM-HEADER-LENGTH))))
		 (bit-string-case rest
		   ([ (opts :: binary bytes options-length)
		      (data :: binary) ]
		    (printf "  options:\n")
		    (dump opts)
		    (printf "  data:\n")
		    (analyze-ipv4-data protocol data))))
	       (begin (printf "  invalid header length; rest:\n")
		      (dump rest))))
	  ([ (unknown :: binary) ]
	   (printf "  Unknown IP packet:\n")
	   (dump unknown)))]
       [else
	(printf "  Unknown ethertype ~a; body:\n" (number->string ether-type 16))
	(dump body)]))
    ([ (packet :: binary) ]
     (printf "UNKNOWN:\n")
     (dump packet)))
  (loop))

;; (raw-interface-close h)
