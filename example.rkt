#lang racket

(require packet-socket)
(require (only-in file/sha1 bytes->hex-string))

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

(let loop ()
  (flush-output)
  (define p (raw-interface-read h))
  (printf "PACKET: ~a\n" (bytes->hex-string p))
  (loop))

;; (raw-interface-close h)
