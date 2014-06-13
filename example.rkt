#lang racket/base

(require packet-socket)

(define device-name "wlan0")

(raw-interface-names)

(define h (raw-interface-open device-name))
h
(when (not h)
  (error 'example "Couldn't open device ~v" device-name))

(let loop ()
  (define p (raw-interface-read h))
  (write p)
  (newline)
  (flush-output)
  (loop))

;; (raw-interface-close h)
