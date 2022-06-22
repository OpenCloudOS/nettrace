ROOT ?= $(abspath ../)
bpf_progs = progs/probe progs/trace
progs = droptrace
prog-droptrace = droptrace.c parse_sym.c $(COMMON_SHARED) drop_reason.h

include ../common.mk

progs/common.h:
	cd progs && wget $(REMOTE_ROOT)/droptrace/$@

$(foreach i,$(bpf_progs),$(i).c): progs/common.h
	cd progs && wget $(REMOTE_ROOT)/droptrace/$@

droptrace.c: drop_reason.h

all: $(progs)

install: all
	@mkdir -p $(PREFIX)/usr/bin/ && cp droptrace $(PREFIX)/usr/bin/

pack: all
	@mkdir -p $(PREFIX) && cp droptrace $(PREFIX)

clean:
	rm -rf drop_reason.h droptrace vmlinux.h progs/*.skel.h progs/*.o
