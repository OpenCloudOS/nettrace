ROOT		?= $(abspath ../)
bpf_progs	:= progs/tracing
bpf_progs_ext	:= progs/kprobe
progs		:= nettrace
prog-nettrace-origin = \
		trace.c $(COMMON_SHARED) trace_probe.c trace_tracing.c \
		analysis.c $(COMPONENT)/parse_sym.c trace_group.c \
		dropreason.c
prog-nettrace	= $(prog-nettrace-origin) nettrace.c

BPF_EXTRA_DEP := kheaders.h
include ../common.mk

progs/kprobe_trace.h:
	python3 gen_trace.py probe > progs/kprobe_trace.h

trace_group.c: trace.yaml
	python3 gen_trace.py > trace_group.c

progs/kprobe.c: progs/kprobe_trace.h

kprobe_gen_cmd = @make BPF_CFLAGS="$(BPF_CFLAGS) $(1)" \
		SKEL_FLAGS="name $(2)" \
		progs/kprobe.skel.h; \
		mv progs/kprobe.skel.h progs/$(2).skel.h

ifndef COMPAT
	CFLAGS += -DSTACK_TRACE
$(bpf_progs_ext):
	rm -rf progs/kprobe*.skel.h
	$(call kprobe_gen_cmd,-DCORE_FULL,kprobe_core)
	make progs/kprobe.skel.h
else
ifneq ($(shell grep -c get_stackid $(HEADERS)/include/uapi/linux/bpf.h),0)
	CFLAGS += -DSTACK_TRACE
endif
$(bpf_progs_ext): %: %.skel.h
	@:
endif

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
