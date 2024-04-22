COMPONENT	:= $(ROOT)/component
COMMON_SHARED	:= $(ROOT)/shared/pkt_utils.c $(COMPONENT)/net_utils.c	\
		   $(COMPONENT)/arg_parse.c $(COMPONENT)/sys_utils.c	\
		   $(ROOT)/shared/bpf_utils.c

CFLAGS		+= -I./ -I$(ROOT)/shared/bpf/ -g
BPF_CFLAGS	= $(CFLAGS) -Wno-unused-function			\
		  -Wno-compare-distinct-pointer-types -Wuninitialized	\
		  -D__TARGET_ARCH_$(SRCARCH) -DBPF_NO_PRESERVE_ACCESS_INDEX
HOST_CFLAGS	= \
		-lbpf -lelf -lz -O2 -static $(CFLAGS)			\
		-Wno-deprecated-declarations -DVERSION=$(VERSION)	\
		-DRELEASE=$(RELEASE)					\
		-I$(ROOT)/shared/ -I$(ROOT)/component

REMOTE_ROOT	:= https://raw.githubusercontent.com/xmmgithub/nettrace-eBPF/master/
export REMOTE_ROOT

CC		:= $(CROSS_COMPILE)gcc

include $(ROOT)/script/arch.mk

HEADERS		:= $(if $(KERNEL),$(KERNEL),/lib/modules/$(shell uname -r)/build/)
NOSTDINC_FLAGS	+= -nostdinc -isystem $(shell $(CC) -print-file-name=include)
export HEADERS

USERINCLUDE	:= \
		-I$(HEADERS)/arch/$(SRCARCH)/include/uapi \
		-I$(HEADERS)/arch/$(SRCARCH)/include/generated/uapi \
		-I$(HEADERS)/include/uapi \
		-I$(HEADERS)/include/generated/uapi \
		-include $(HEADERS)/include/linux/kconfig.h \
		-I/usr/include/

LINUXINCLUDE	:= \
		-I$(HEADERS)/arch/$(SRCARCH)/include \
		-I$(HEADERS)/arch/$(SRCARCH)/include/generated \
		-I$(HEADERS)/include \
		$(USERINCLUDE)

KERNEL_CFLAGS	+= $(NOSTDINC_FLAGS) $(LINUXINCLUDE) \
		-D__KERNEL__ -Wno-unused-value -Wno-pointer-sign \
		-Wno-compare-distinct-pointer-types \
		-Wno-gnu-variable-sized-type-not-at-end \
		-Wno-address-of-packed-member -Wno-tautological-compare \
		-Wno-unknown-warning-option -Wno-frame-address

ifdef KERN_VER
	CFLAGS		+= -DKERN_VER=$(KERN_VER)
endif

ifdef NO_GLOBAL_DATA
	CFLAGS		+= -DBPF_NO_GLOBAL_DATA
endif

ifdef NO_BTF
ifeq ($(wildcard $(HEADERS)),)
$(error kernel headers not exist in COMPAT mode, please install it)
endif
	kheaders_cmd	:= ln -s vmlinux_header.h kheaders.h
	CFLAGS		+= -DNO_BTF
	BPF_CFLAGS	+= $(KERNEL_CFLAGS)
else
	kheaders_cmd	:= ln -s ../shared/bpf/vmlinux.h kheaders.h
	BPF_CFLAGS	+= -target bpf
endif

ifdef INLINE
	BPF_CFLAGS	+= -DINLINE_MODE
endif

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

kheaders.h:
	$(call kheaders_cmd)

progs/%.o: progs/%.c $(BPF_EXTRA_DEP)
	clang -O2 -c -S -Wall -fno-asynchronous-unwind-tables		\
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
