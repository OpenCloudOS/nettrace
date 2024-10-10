ROOT		?= $(abspath ../)
bpf_progs	:= progs/kprobe
progs		:= nettrace
prog-nettrace-origin = \
		trace.c $(COMMON_SHARED) trace_probe.c trace_tracing.c \
		analysis.c $(COMPONENT)/parse_sym.c trace_group.c \
		dropreason.c
prog-nettrace	= $(prog-nettrace-origin) nettrace.c

ifdef COMPAT
	NO_GLOBAL_DATA	:= 1
	NO_BTF		:= 1
	INLINE		:= 1
endif

ifndef NO_BTF
	bpf_progs += progs/tracing progs/feat_args_ext
endif

BPF_EXTRA_DEP := kheaders.h progs/core.c progs/core.h
include ../common.mk

cmd_kversion := awk -F '=' 'NR>10{exit;}		\
		$$1~/^VERSION/{				\
			sub(/ /, "", $$2); a=$$2;	\
		}					\
		$$1~/^PATCHLEVEL/{			\
			sub(/ /, "", $$2); b=$$2	\
		}					\
		$$1~/^SUBLEVEL/{			\
			sub(/ /, "", $$2); c=$$2	\
		}					\
		END{printf "%s.%s.%s\n", a, b, c}'	\
		$(HEADERS)/Makefile

str_count	= $(shell grep -c $2 $(HEADERS)/$1 2>/dev/null)
struct_field	= $(shell awk 'BEGIN{start=0}/struct $2 {/{start=1} \
		  /$3/{if (start==1) print 1} \
		  /}/{start=0}' $(HEADERS)/$1 2>/dev/null)

ifdef NO_BTF
ifeq ($(call str_count,include/uapi/linux/bpf.h,BPF_PROG_TYPE_TRACEPOINT),0)
$(error BPF_PROG_TYPE_TRACEPOINT not supported by your kernel!)
endif

ifneq ($(call str_count,include/uapi/linux/bpf.h,get_stackid),0)
	CFLAGS += -D__F_STACK_TRACE
endif

ifneq ($(call str_count,include/net/sock.h,sk_protocol.*8),0)
	BPF_CFLAGS += -D__F_SK_PRPTOCOL_LEGACY
endif

ifeq ($(call str_count,include/net/sock.h,__sk_flags_offset),0)
	BPF_CFLAGS += -D__F_NO_SK_FLAGS_OFFSET
endif

ifeq ($(call str_count,include/linux/netfilter.h,nf_hook_entries),0)
	BPF_CFLAGS += -D__F_NO_NF_HOOK_ENTRIES
endif

ifeq ($(call str_count,include/uapi/linux/bpf.h,bpf_probe_read_str),0)
	BPF_CFLAGS += -D__F_NO_PROBE_READ_STR
endif

ifeq ($(call struct_field,include/net/netfilter/nf_tables.h,nft_chain,\*name),)
	CFLAGS += -D__F_NFT_NAME_ARRAY
endif

	__KERN_VER := $(shell $(cmd_kversion))
	CFLAGS += -D__KERN_VER=$(__KERN_VER)
	CFLAGS += -D__KERN_MAJOR=$(shell echo $(__KERN_VER) | cut -c 1)
else
	CFLAGS += -D__F_STACK_TRACE
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
