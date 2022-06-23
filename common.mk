BPFTOOL ?= $(ROOT)/script/bpftool
VMLINUX ?= /sys/kernel/btf/vmlinux
CFLAGS += -I./ -I$(ROOT)/shared/bpf/
BPF_CFLAGS := $(CFLAGS)
HOST_CFLAGS := $(CFLAGS) -lbpf -lelf -lz -Wno-deprecated-declarations \
		 -g -O2 -static -I$(ROOT)/shared/ -I$(ROOT)/component
SHARED = $(ROOT)/shared
COMPONENT = $(ROOT)/component
COMMON_SHARED = $(SHARED)/pkt_utils.c $(COMPONENT)/net_utils.c \
		$(COMPONENT)/arg_parse.c $(COMPONENT)/sys_utils.c
REMOTE_ROOT := https://raw.githubusercontent.com/OpenCloudOS/OpenCloudOS-Kernel/kernel5.4/master/tools/bpf/nettrace/
export REMOTE_ROOT

vmlinux.h:
	$(BPFTOOL) btf dump file $(VMLINUX) \
	format c > $@

drop_reason.h: vmlinux.h
	rm -rf $@
	@awk 'BEGIN{ print "#ifndef _H_SKB_DROP_REASON"; \
		print "#define _H_SKB_DROP_REASON\n";\
		system("sed -e \"/enum skb_drop_reason {/,/}/!d\" $< >> $@");\
		print "\n#define __DEFINE_SKB_REASON(FN) \\";\
	}\
	/^enum skb_drop/ { dr=1; }\
	/^\};/ { dr=0; }\
	/^\tSKB_DROP_REASON_/ {\
		if (dr) {\
			sub(/SKB_DROP_REASON_/, "", $$1);\
			printf "\tFN(%s)\t\\\n", $$1;\
		}\
	}\
	END{ print "\n#endif" }' $< >> $@
	@echo generated drop_reason.h

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
	@if [ -n "$(prog-$@)" ]; then				\
		echo gcc $(prog-$@) -o $@ $(HOST_CFLAGS);	\
		gcc $(prog-$@) -o $@ $(HOST_CFLAGS);		\
	else							\
		echo gcc $< -o $@ $(HOST_CFLAGS);		\
		gcc $< -o $@ $(HOST_CFLAGS);			\
	fi
