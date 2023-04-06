ROOT		?= $(abspath ../)
bpf_progs	:= progs/tracing progs/kprobe
progs		:= nettrace
prog-nettrace-origin = \
		trace.c $(COMMON_SHARED) trace_probe.c trace_tracing.c \
		analysis.c $(COMPONENT)/parse_sym.c trace_group.c \
		dropreason.c
prog-nettrace	= $(prog-nettrace-origin) nettrace.c


ifdef BPF_FEATS
BPF_FEATS	:= $(strip $(subst ,, $(BPF_FEATS)))
else
# the default BPF features that enabled
BPF_FEATS	:= stack_trace
endif

bpf-feats-all	:= jiffies stack_trace
bpf-feats	:= $(BPF_FEATS)

ifeq ($(bpf-feats),all)
	bpf-feats := $(bpf-feats-all)
endif


BPF_EXTRA_DEP := kheaders.h
include ../common.mk

ifdef COMPAT
	bpf-feats :=
ifneq ($(shell grep -c get_stackid $(HEADERS)/include/uapi/linux/bpf.h),0)
	bpf-feats += stack_trace
endif
ifneq ($(shell grep -c "sk_protocol.*8" $(HEADERS)/include/net/sock.h),0)
	BPF_CFLAGS += -DBPF_FEAT_SK_PRPTOCOL_LEGACY
endif
endif

CFLAGS += $(foreach feat,$(bpf-feats),\
	-DBPF_FEAT_$(shell echo $(feat) | tr '[:lower:]' '[:upper:]'))

progs/kprobe_trace.h:
	python3 gen_trace.py probe > progs/kprobe_trace.h

trace_group.c: trace.yaml
	python3 gen_trace.py > trace_group.c

progs/kprobe.c: progs/kprobe_trace.h
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
