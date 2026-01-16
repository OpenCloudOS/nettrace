CFLAGS		+= -I./ -I$(ROOT)/shared/bpf/ -g
BPF_CFLAGS	= $(CFLAGS) -Wno-unused-function			\
		  -Wno-compare-distinct-pointer-types -Wuninitialized	\
		  -D__TARGET_ARCH_$(SRCARCH)

ifeq ("$(shell pkg-config --print-requires-private libelf | grep libzstd)","libzstd")
LIBELF_ZSTD_FLAGS = -lzstd
endif

HOST_CFLAGS	= \
		-lbpf -lelf -lz $(LIBELF_ZSTD_FLAGS) -O2 $(CFLAGS) -Wall \
		-Wno-deprecated-declarations -DVERSION=$(VERSION)	\
		-DRELEASE=$(RELEASE)					\
		-I$(ROOT)/shared/ -I$(ROOT)/utils

ifdef STATIC
HOST_CFLAGS	+= -static
endif

CC		:= $(CROSS_COMPILE)gcc

include $(ROOT)/script/arch.mk

ifdef STATIC
	HOST_CFLAGS	+= -static
endif

BPF_CFLAGS	+= -target bpf

ifndef BPFTOOL
ifneq ("$(shell bpftool gen help 2>&1 | grep skeleton)","")
	BPFTOOL		:= bpftool
else
ifeq ("$(shell uname -m)","x86_64")
	BPFTOOL		:= $(ROOT)/script/bpftool-x86
endif

ifeq ("$(shell uname -m)","aarch64")
	BPFTOOL		:= $(ROOT)/script/bpftool-arm
endif
ifeq ("$(shell uname -m)","loongarch64")
	BPFTOOL		:= $(ROOT)/script/bpftool-loongarch
endif
endif
endif

ifdef BPF_DEBUG
	CFLAGS		+= -DBPF_DEBUG
endif

progs/%.o: progs/%.c $(BPF_EXTRA_DEP)
	clang -O2 -S -Wall -fno-asynchronous-unwind-tables		\
	-Wno-incompatible-pointer-types-discards-qualifiers		\
	$< -emit-llvm -Wno-unknown-attributes $(BPF_CFLAGS) -Xclang	\
	-disable-llvm-passes -o - | 					\
	opt -O2 -mtriple=bpf-pc-linux | 				\
	llvm-dis |							\
	llc -march=bpf -filetype=obj -o $@
	@readelf -S $@ | grep BTF > /dev/null || (rm $@ && exit 1)

%.skel.h: %.o
	$(BPFTOOL) gen skeleton $< > $@ || (rm -r $@ && exit 1)

$(bpf_progs): %: %.skel.h
	@:

bpf: $(bpf_progs) $(bpf_progs_ext)

$(progs): %: %.c bpf
	@if [ -n "$(prog-$@)" ]; then				\
		echo $(CC) $(prog-$@) -o $@ $(HOST_CFLAGS);	\
		$(CC) $(prog-$@) -o $@ $(HOST_CFLAGS);		\
	else							\
		echo $(CC) $< -o $@ $(HOST_CFLAGS);		\
		$(CC) $< -o $@ $(HOST_CFLAGS);			\
	fi
