ROOT ?= $(abspath ../)
bpf_progs := progs/kprobe progs/tracing
progs := nettrace
prog-nettrace-origin = trace.c $(COMMON_SHARED) \
		       trace_probe.c trace_tracing.c analysis.c \
		       $(COMPONENT)/parse_sym.c trace_group.c

prog-nettrace = $(prog-nettrace-origin) nettrace.c

include ../common.mk

progs/kprobe_trace.h:
	python3 gen_trace.py probe > progs/kprobe_trace.h

trace_group.c: trace.yaml
	python3 gen_trace.py > trace_group.c

progs/kprobe.c: progs/kprobe_trace.h

nettrace.c: $(prog-nettrace-origin)
	@make drop_reason.h
	@if [ ! -f 'drop_reason.h' ]; then touch drop_reason.h; fi

all: $(progs)

install: all
	@mkdir -p ${PREFIX}/usr/bin/
	@cp nettrace ${PREFIX}/usr/bin/

pack: all
	@cp nettrace ${PREFIX}/

clean:
	rm -rf $(progs) trace_group.c progs/kprobe_trace.h \
		$(bpf_progs) progs/*.o progs/*.skel.h \
		vmlinux.h drop_reason.h

