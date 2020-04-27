#lang racket/base

(require (only-in dynext/link current-use-mzdyn link-extension)
         (only-in racket/file make-directory*))

(provide pre-installer)

(define (pre-installer collections-top-path packet-socket-path)
  (define private (build-path packet-socket-path "private"))
  (define native (build-path private "compiled" "native" (system-library-subpath)))
  (make-directory* native)
  (parameterize ((current-use-mzdyn #f))
    (link-extension
     #f
     (list (build-path private "packet-socket-extension.c"))
     (build-path native "packet-socket-extension.so"))))

(module+ main
  (require racket/runtime-path)
  (define-runtime-path packet-socket-path "..")
  (pre-installer (find-executable-path (find-system-path 'exec-file)
                                       (find-system-path 'collects-dir))
                 packet-socket-path))

