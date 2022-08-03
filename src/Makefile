ROOT ?= $(abspath ../)
bpf_progs := progs/kprobe progs/tracing
progs := nettrace
prog-nettrace-origin = trace.c $(COMMON_SHARED) \
		       trace_probe.c trace_tracing.c analysis.c \
		       $(COMPONENT)/parse_sym.c trace_group.c \
		       drop_reason.h

prog-nettrace = $(prog-nettrace-origin) nettrace.c

ifdef COMPAT
CFLAGS += -DMAP_CONFIG
endif

ifdef KERN_VER
CFLAGS += -DKERN_VER=$(KERN_VER)
endif

include ../common.mk

NFT_HEADER	:= $(HEADERS)/include/net/netfilter/nf_tables.h
ifeq ($(shell grep xt_action_param $(NFT_HEADER)),)
	BPF_CFLAGS += -DNFT_HIGH_VERSION
endif

progs/kprobe_trace.h:
	python3 gen_trace.py probe > progs/kprobe_trace.h

trace_group.c: trace.yaml
	python3 gen_trace.py > trace_group.c

progs/kprobe.c: progs/kprobe_trace.h

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
		vmlinux.h drop_reason.h kheaders.h

