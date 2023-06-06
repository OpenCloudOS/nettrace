ROOT		?= $(abspath ../)
bpf_progs	:= progs/kprobe
progs		:= nettrace
prog-nettrace-origin = \
		trace.c $(COMMON_SHARED) trace_probe.c trace_tracing.c \
		analysis.c $(COMPONENT)/parse_sym.c trace_group.c \
		dropreason.c
prog-nettrace	= $(prog-nettrace-origin) nettrace.c

ifndef COMPAT
	bpf_progs += progs/tracing progs/feat_args_ext
endif

BPF_EXTRA_DEP := kheaders.h
include ../common.mk

ifdef COMPAT
ifneq ($(shell grep -c get_stackid $(HEADERS)/include/uapi/linux/bpf.h),0)
	CFLAGS += -DBPF_FEAT_STACK_TRACE
endif
ifneq ($(shell grep -c "sk_protocol.*8" $(HEADERS)/include/net/sock.h),0)
	BPF_CFLAGS += -DBPF_FEAT_SK_PRPTOCOL_LEGACY
endif
else
	CFLAGS += -DBPF_FEAT_STACK_TRACE
endif

progs/kprobe_trace.h:
	python3 gen_trace.py probe > progs/kprobe_trace.h

trace_group.c: trace.yaml
	python3 gen_trace.py > trace_group.c

progs/*.c: progs/kprobe_trace.h
	@:

nettrace.c: $(prog-nettrace-origin)

all: $(progs)

install: all
	@mkdir -p ${PREFIX}/usr/bin/
	@cp nettrace ${PREFIX}/usr/bin/

pack: all
	@cp nettrace ${PREFIX}/

clean:
	rm -rf $(progs) trace_group.c progs/kprobe_trace.h \
		$(bpf_progs) progs/*.o progs/*.skel.h \
		kheaders.h
