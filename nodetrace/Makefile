progs := mark watch
bpf_progs := progs/ntrace

prog-mark = mark.c $(COMMON_SHARED)
prog-watch = watch.c $(COMMON_SHARED)

include ../common.mk

all: $(progs)

install: $(progs)
	@mkdir -p $(PREFIX)/usr/bin/
	@cp mark $(PREFIX)/usr/bin/nodetrace-mark
	@cp watch $(PREFIX)/usr/bin/nodetrace-watch

clean:
	rm -rf progs/*.skel.h progs/*.o vmlinux.h watch mark
