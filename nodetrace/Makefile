ROOT = ../
progs = mark watch
bpf_progs = progs/ntrace

prog-mark = mark.c $(COMMON_SHARED)
prog-watch = watch.c $(COMMON_SHARED)

include ../common.mk

all: $(progs)

clean:
	rm -rf progs/*.skel.h progs/*.o vmlinux.h watch mark
