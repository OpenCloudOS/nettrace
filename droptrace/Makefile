
ROOT = ../
bpf_progs = progs/droptrace
progs = droptrace
prog-droptrace = droptrace.c parse_sym.c $(COMMON_SHARED)

include ../common.mk

drop_reason: vmlinux.h
	echo '#ifndef _H_SKB_DROP_REASON\n#define _H_SKB_DROP_REASON' > drop_reason.h
	sed -e '/enum skb_drop_reason {/,/}/!d' vmlinux.h >> drop_reason.h
	echo '\n#define __DEFINE_SKB_REASON(FN) \' >> drop_reason.h
	cat drop_reason.h | awk '/SKB_DROP_REASON_/{printf "	FN(%s) \\\n", substr($$1, 17)}' >> drop_reason.h
	echo '\n#endif' >> drop_reason.h

all: drop_reason bpf
	make droptrace

clean:
	rm -rf drop_reason.h droptrace vmlinux.h progs/*.skel.h progs/*.o
