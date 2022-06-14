BPFTOOL ?= bpftool
VMLINUX ?= /sys/kernel/btf/vmlinux
CFLAGS += -I./ -I$(ROOT)/shared/bpf/
BPF_CFLAGS := $(CFLAGS)
HOST_CFLAGS := $(CFLAGS) -lbpf -lelf -lz -Wno-deprecated-declarations \
		 -g -O2 -static -I$(ROOT)/shared/ -I$(ROOT)/component
SHARED = $(ROOT)/shared
COMPONENT = $(ROOT)/component
COMMON_SHARED = $(SHARED)/pkt_utils.c $(COMPONENT)/net_utils.c \
		$(COMPONENT)/arg_parse.c
REMOTE_ROOT := https://raw.githubusercontent.com/OpenCloudOS/OpenCloudOS-Kernel/kernel5.4/master/tools/bpf/nettrace/
export REMOTE_ROOT


vmlinux.h:
	$(BPFTOOL) btf dump file $(VMLINUX) \
	format c > $@

progs/%.o: progs/%.c vmlinux.h
	clang -O2 -c -g -S -Wall -Wno-pointer-sign -Wno-unused-value	\
	-Wno-incompatible-pointer-types-discards-qualifiers		\
	-fno-asynchronous-unwind-tables					\
	$<  -emit-llvm -Wno-unknown-attributes $(BPF_CFLAGS) -o - |	\
	llc -march=bpf -filetype=obj -o $@

%.skel.h: %.o
	$(BPFTOOL) gen skeleton $< > $@

$(bpf_progs): %: %.skel.h
	@echo "bpf compile success"

bpf: $(bpf_progs)

$(progs): %: %.c bpf
	@if [ -n "$(prog-$@)" ]; then			\
		gcc $(prog-$@) -o $@ $(HOST_CFLAGS);	\
	else						\
		gcc $< -o $@ $(HOST_CFLAGS);		\
	fi
