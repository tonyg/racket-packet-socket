# Access to raw Ethernet frames from Racket

If Racket needs a packet from a socket or a port,  
you might just find it's nowhere near as easy as you thought.  
Up in complicated ioctls you'll be caught,  
Ensuring error-freedom is particularly fraught!

Dashing to the rescue is this polished little package:  
A tiny C extension, with a pinch of Racket hackage,  
Relieves you of your burden and returns you to your slackage,  
And competently fixes Racket's packet socket lackage.

— [tonyg](http://leastfixedpoint.com/), with [apologies to Gene Ziegler](http://web.archive.org/web/20130301230602/http://geneziegler.com/clocktower/drseuss.html)

## What?

Read and write raw Ethernet frames from Racket programs. 

## How?

```racket
(require packet-socket)

(display (raw-interface-names))
(newline)

(define handle (raw-interface-open "eth0:1"))
(unless handle (error 'example "Couldn't open the device"))

(define packet (raw-interface-read handle)) ;; blocks

(raw-interface-write handle packet)

(raw-interface-close handle)
```

You will need to take care of Ethernet frame headers, footers,
checksums and addressing yourself. You may find the Racket package
[bitsyntax](https://github.com/tonyg/racket-bitsyntax) useful to you
in manipulating binary data structures.

You will also need to give the Racket executable `CAP_NET_RAW`
capability on Linux in order to create packet sockets. One approach to
this could be:

```sh
sudo setcap cap_net_raw+p+i+e `which racket`
```

Be warned that ethernet has a 64-byte minimum packet size. Less four
bytes for the checksum, two for the ethertype, and twelve for the
sender and target MAC addresses, that leaves 46 bytes of payload in
such a minimum-sized packet. If you are expecting to receive packets
with *fewer than 46 bytes of payload*, then make sure to handle the
zero-padding that gets added to the end by the ethernet! For example,
IPv4 packets have an explicit whole-packet length indicator for just
such a situation.

## Who?

Copyright (c) 2014 [Jonathan Schuster](https://github.com/schuster)  
Copyright (c) 2014-2020 [Tony Garnock-Jones](https://leastfixedpoint.com/)

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.

## Bugs

 - BPF exists not only on OSX, but also on many other BSDs. The
   `#ifdefs` in the support code should be widened to allow it to run
   there as well.
