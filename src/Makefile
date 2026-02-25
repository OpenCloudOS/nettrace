bpf_progs	:= progs/tracing progs/feat_args_ext
bpf_objs	:= $(addsuffix .o,$(bpf_progs))
bpf_skels	:= $(addsuffix .skel.h,$(bpf_progs))

trace_funcs	:= progs/trace_funcs.h
trace_group	:= trace_group.c

ROOT		?= $(abspath ../)
UTILS_DIR	:= $(ROOT)/src/utils
UTILS_SRC	:= $(UTILS_DIR)/net_utils.c $(UTILS_DIR)/bpf_utils.c \
		   $(UTILS_DIR)/arg_parse.c $(UTILS_DIR)/sys_utils.c
NETTRACE_SRCS	:= $(UTILS_SRC) \
		   trace.c output.c trace_tracing.c \
		   analysis.c $(trace_group) \
		   dropreason.c rstreason.c \
		   nettrace.c

CC		:= $(CROSS_COMPILE)gcc
CLANG		?= clang
READELF		?= readelf

include $(ROOT)/script/arch.mk

BPF_CFLAGS	:= -O2 -g -Wall -D__TARGET_ARCH_$(SRCARCH) -target bpf	\
		   -Wno-unused-function					\
		   -Wno-compare-distinct-pointer-types -Wuninitialized	\
		   -Wno-incompatible-pointer-types-discards-qualifiers	\
		   -Wno-unknown-attributes

ifeq ("$(shell pkg-config --print-requires-private libelf | grep libzstd)","libzstd")
LIBELF_ZSTD_FLAGS = -lzstd
endif

HOST_CFLAGS	:= -lbpf -lelf -lz $(LIBELF_ZSTD_FLAGS) -pthread -O2 -Wall \
		   -Wno-deprecated-declarations -DVERSION=$(VERSION)	\
		   -DRELEASE=$(RELEASE)

ifdef STATIC
HOST_CFLAGS	+= -static
endif

ifndef BPFTOOL
ifneq ("$(shell bpftool gen help 2>&1 | grep skeleton)","")
	BPFTOOL	:= bpftool
else
ifeq ("$(shell uname -m)","x86_64")
	BPFTOOL	:= $(ROOT)/script/bpftool-x86
endif
ifeq ("$(shell uname -m)","aarch64")
	BPFTOOL	:= $(ROOT)/script/bpftool-arm
endif
ifeq ("$(shell uname -m)","loongarch64")
	BPFTOOL	:= $(ROOT)/script/bpftool-loongarch
endif
endif
endif

.PHONY: all bpf install pack clean

$(trace_funcs): gen_trace.py
	python3 $< probe > $@

$(trace_group): trace.yaml gen_trace.py
	python3 gen_trace.py > $@

$(bpf_objs): %.o: %.c $(trace_funcs)
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@
	@$(READELF) -S $@ | grep BTF > /dev/null || ($(RM) $@ && exit 1)

$(bpf_skels): %.skel.h: %.o
	$(BPFTOOL) gen skeleton $< > $@ || ($(RM) $@ && exit 1)

bpf: $(bpf_skels) $(bpf_progs_ext)

nettrace: $(NETTRACE_SRCS) $(trace_funcs) $(bpf_skels) $(bpf_progs_ext)
	$(CC) $(NETTRACE_SRCS) -o $@ $(HOST_CFLAGS)

all: nettrace

install: all
	@mkdir -p ${PREFIX}/usr/bin/
	@cp nettrace ${PREFIX}/usr/bin/

pack: all
	@cp nettrace ${PREFIX}/

clean:
	$(RM) nettrace $(trace_group) $(trace_funcs) $(bpf_objs) $(bpf_skels)
