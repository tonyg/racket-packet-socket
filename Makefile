PACKAGENAME=packet-socket
COLLECTS=packet-socket

all: setup

clean:
	find . -name compiled -type d | xargs rm -rf

setup:
	raco setup --check-pkg-deps --unused-pkg-deps $(COLLECTS)

link:
	raco pkg install --link -n $(PACKAGENAME) $$(pwd)

unlink:
	raco pkg remove $(PACKAGENAME)
